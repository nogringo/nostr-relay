package handlers

import (
	"context"

	"nostr-relay/internal/storage"

	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/zerolog/log"
)

func SetupQueryHandlers(relay *khatru.Relay, store *storage.BadgerStore) {
	// Query events
	relay.QueryEvents = append(relay.QueryEvents, func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
		ch := make(chan *nostr.Event)

		go func() {
			defer close(ch)

			events, err := store.QueryEvents(ctx, filter)
			if err != nil {
				log.Error().Err(err).Msg("Query error")
				return
			}

			// Get authenticated pubkey for filtering private events
			authedPubkey := khatru.GetAuthed(ctx)

			// Filter events before sending
			filteredCount := 0
			for _, event := range events {
				// NIP-59: Filter private message kinds (gift wrap, seal, DM)
				if event.Kind == 1059 || event.Kind == 13 || event.Kind == 14 {
					// Must be authenticated
					if authedPubkey == "" {
						log.Debug().
							Int("kind", event.Kind).
							Str("event_id", event.ID[:16]).
							Msg("Filtered private event - user not authenticated")
						filteredCount++
						continue
					}

					// For gift wraps, user must be the recipient (p tag)
					if event.Kind == 1059 {
						isRecipient := false
						for _, tag := range event.Tags {
							if len(tag) >= 2 && tag[0] == "p" && tag[1] == authedPubkey {
								isRecipient = true
								break
							}
						}
						if !isRecipient {
							log.Debug().
								Int("kind", event.Kind).
								Str("event_id", event.ID[:16]).
								Msg("Filtered gift wrap - user is not recipient")
							filteredCount++
							continue
						}
					}
				}

				select {
				case ch <- event:
				case <-ctx.Done():
					return
				}
			}

			log.Debug().
				Int("total", len(events)).
				Int("filtered", filteredCount).
				Int("sent", len(events)-filteredCount).
				Msg("Query returned events")
		}()

		return ch, nil
	})

	// Apply default and max limits
	relay.OverwriteFilter = append(relay.OverwriteFilter, func(ctx context.Context, filter *nostr.Filter) {
		if filter.Limit == 0 {
			filter.Limit = 500
		} else if filter.Limit > 5000 {
			filter.Limit = 5000
		}
	})

	// Count events
	relay.CountEvents = append(relay.CountEvents, func(ctx context.Context, filter nostr.Filter) (int64, error) {
		events, err := store.QueryEvents(ctx, filter)
		if err != nil {
			return 0, err
		}
		return int64(len(events)), nil
	})
}
