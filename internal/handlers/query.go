package handlers

import (
	"context"
	"iter"

	"nostr-relay/internal/storage"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"github.com/rs/zerolog/log"
)

func SetupQueryHandlers(relay *khatru.Relay, store *storage.BadgerStore) {
	// Store existing handlers to chain them
	existingOnRequest := relay.OnRequest

	// Query events - returns an iterator
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		return func(yield func(nostr.Event) bool) {
			// Apply default and max limits
			if filter.Limit == 0 {
				filter.Limit = 500
			} else if filter.Limit > 5000 {
				filter.Limit = 5000
			}

			events, err := store.QueryEvents(ctx, filter)
			if err != nil {
				log.Error().Err(err).Msg("Query error")
				return
			}

			// Get authenticated pubkey for filtering private events
			authedPubkey, authed := khatru.GetAuthed(ctx)

			// Filter events before sending
			filteredCount := 0
			sentCount := 0
			for _, event := range events {
				// NIP-59: Filter private message kinds (gift wrap, seal, DM)
				// Skip filtering for internal calls (e.g., deletion requests)
				if !khatru.IsInternalCall(ctx) && (event.Kind == 1059 || event.Kind == 13 || event.Kind == 14) {
					// Must be authenticated
					if !authed {
						log.Debug().
							Uint16("kind", uint16(event.Kind)).
							Str("event_id", event.ID.Hex()[:16]).
							Msg("Filtered private event - user not authenticated")
						filteredCount++
						continue
					}

					// For gift wraps, user must be the recipient (p tag)
					if event.Kind == 1059 {
						isRecipient := false
						for _, tag := range event.Tags {
							if len(tag) >= 2 && tag[0] == "p" && tag[1] == authedPubkey.Hex() {
								isRecipient = true
								break
							}
						}
						if !isRecipient {
							log.Debug().
								Uint16("kind", uint16(event.Kind)).
								Str("event_id", event.ID.Hex()[:16]).
								Msg("Filtered gift wrap - user is not recipient")
							filteredCount++
							continue
						}
					}
				}

				// Convert pointer to value and yield
				if !yield(*event) {
					break
				}
				sentCount++
			}

			log.Debug().
				Int("total", len(events)).
				Int("filtered", filteredCount).
				Int("sent", sentCount).
				Msg("Query returned events")
		}
	}

	// Apply filter restrictions in OnRequest
	relay.OnRequest = func(ctx context.Context, filter nostr.Filter) (bool, string) {
		// Chain existing handler first
		if existingOnRequest != nil {
			if reject, msg := existingOnRequest(ctx, filter); reject {
				return reject, msg
			}
		}
		return false, ""
	}

	// Count events
	relay.Count = func(ctx context.Context, filter nostr.Filter) (uint32, error) {
		events, err := store.QueryEvents(ctx, filter)
		if err != nil {
			return 0, err
		}
		return uint32(len(events)), nil
	}
}
