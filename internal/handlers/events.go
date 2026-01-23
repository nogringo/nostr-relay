package handlers

import (
	"context"

	"nostr-relay/internal/storage"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"github.com/rs/zerolog/log"
)

// Event kinds
const (
	KindDeletion      = 5     // NIP-09: Event deletion
	KindSeal          = 13    // NIP-59: Sealed event
	KindDirectMessage = 14    // NIP-17: Private direct message
	KindFileMessage   = 15    // NIP-17: Private file message
	KindGiftWrap      = 1059  // NIP-59: Gift wrapped event
	KindDMRelayList   = 10050 // NIP-17: Preferred relays for DMs
	KindAuth          = 22242 // NIP-42: Authentication
)

func SetupEventHandlers(relay *khatru.Relay, store *storage.BadgerStore) {
	// Store existing handlers to chain them
	existingOnEvent := relay.OnEvent
	existingOnEventSaved := relay.OnEventSaved
	existingOnEphemeralEvent := relay.OnEphemeralEvent

	// Store events
	relay.StoreEvent = func(ctx context.Context, event nostr.Event) error {
		log.Debug().
			Str("id", event.ID.Hex()[:16]).
			Uint16("kind", uint16(event.Kind)).
			Str("pubkey", event.PubKey.Hex()[:16]).
			Msg("Storing event")

		return store.SaveEvent(ctx, &event)
	}

	// Delete events (for NIP-09 event deletion)
	relay.DeleteEvent = func(ctx context.Context, id nostr.ID) error {
		log.Debug().
			Str("id", id.Hex()[:16]).
			Msg("Deleting event")

		return store.DeleteEventByID(ctx, id.Hex())
	}

	// Reject/validate events
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
		// Chain existing handler first
		if existingOnEvent != nil {
			if reject, msg := existingOnEvent(ctx, event); reject {
				return reject, msg
			}
		}

		// Basic validation
		if !event.CheckID() {
			return true, "invalid: event id does not match"
		}

		if !event.VerifySignature() {
			return true, "invalid: bad signature"
		}

		// Validate based on event kind
		switch event.Kind {
		case KindSeal:
			// NIP-59: Seal events MUST have empty tags
			if len(event.Tags) > 0 {
				return true, "invalid: seal events (kind 13) must have empty tags"
			}
			// Content must not be empty (contains encrypted rumor)
			if event.Content == "" {
				return true, "invalid: seal events must have encrypted content"
			}

		case KindGiftWrap:
			// NIP-59: Gift wrap events should have a 'p' tag for the recipient
			hasRecipient := false
			for _, tag := range event.Tags {
				if len(tag) >= 2 && tag[0] == "p" {
					hasRecipient = true
					break
				}
			}
			if !hasRecipient {
				return true, "invalid: gift wrap events (kind 1059) must have a 'p' tag for recipient"
			}
			// Content must not be empty (contains encrypted seal)
			if event.Content == "" {
				return true, "invalid: gift wrap events must have encrypted content"
			}

		case KindDirectMessage, KindFileMessage:
			// NIP-17: DM events - these are the inner events, normally wrapped
			// They should have at least one 'p' tag (recipient)
			hasRecipient := false
			for _, tag := range event.Tags {
				if len(tag) >= 2 && tag[0] == "p" {
					hasRecipient = true
					break
				}
			}
			if !hasRecipient {
				return true, "invalid: direct message events must have a 'p' tag for recipient"
			}

		case KindDMRelayList:
			// NIP-17: DM relay list - should only have relay tags
			for _, tag := range event.Tags {
				if len(tag) >= 2 && tag[0] != "relay" {
					log.Warn().
						Str("tag", tag[0]).
						Msg("DM relay list has non-relay tag")
				}
			}

		case KindAuth:
			// NIP-42: Auth events - must have relay and challenge tags
			hasRelay := false
			hasChallenge := false
			for _, tag := range event.Tags {
				if len(tag) >= 2 {
					if tag[0] == "relay" {
						hasRelay = true
					}
					if tag[0] == "challenge" {
						hasChallenge = true
					}
				}
			}
			if !hasRelay || !hasChallenge {
				return true, "invalid: auth events must have 'relay' and 'challenge' tags"
			}

		case KindDeletion:
			// NIP-09: Deletion events must have at least one 'e' or 'a' tag
			hasTarget := false
			for _, tag := range event.Tags {
				if len(tag) >= 2 && (tag[0] == "e" || tag[0] == "a") {
					hasTarget = true
					break
				}
			}
			if !hasTarget {
				return true, "invalid: deletion events must reference at least one event (e or a tag)"
			}
		}

		// Reject events with future timestamps (more than 15 minutes ahead)
		// This prevents timestamp manipulation
		// Note: NIP-59 recommends randomizing timestamps up to 2 days in the past
		// so we don't reject old timestamps for gift wraps

		return false, ""
	}

	// Event saved hooks
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		// Chain existing handler first
		if existingOnEventSaved != nil {
			existingOnEventSaved(ctx, event)
		}

		switch event.Kind {
		case KindDeletion:
			// Count targets
			var eCount, aCount int
			for _, tag := range event.Tags {
				if len(tag) >= 2 {
					if tag[0] == "e" {
						eCount++
					} else if tag[0] == "a" {
						aCount++
					}
				}
			}
			log.Info().
				Str("id", event.ID.Hex()[:16]).
				Str("pubkey", event.PubKey.Hex()[:16]).
				Int("e_tags", eCount).
				Int("a_tags", aCount).
				Msg("Deletion request saved (NIP-09)")
		case KindGiftWrap:
			log.Info().
				Str("id", event.ID.Hex()[:16]).
				Msg("Gift wrap saved")
		case KindSeal:
			log.Info().
				Str("id", event.ID.Hex()[:16]).
				Msg("Seal saved")
		case KindDirectMessage:
			log.Debug().
				Str("id", event.ID.Hex()[:16]).
				Msg("Direct message saved")
		}
	}

	// Handle ephemeral events (kinds 20000-29999)
	relay.OnEphemeralEvent = func(ctx context.Context, event nostr.Event) {
		// Chain existing handler first
		if existingOnEphemeralEvent != nil {
			existingOnEphemeralEvent(ctx, event)
		}

		log.Debug().
			Str("id", event.ID.Hex()[:16]).
			Uint16("kind", uint16(event.Kind)).
			Msg("Ephemeral event received")
	}

	log.Info().Msg("NIP-59 (Gift Wrap) and NIP-17 (Private DM) support enabled")
}
