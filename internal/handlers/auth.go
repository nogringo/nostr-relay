package handlers

import (
	"context"
	"time"

	"nostr-relay/config"

	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/zerolog/log"
)

// NIP-42 Authentication Handler
// Kind 22242 is used for client authentication

func SetupAuthHandlers(relay *khatru.Relay, cfg *config.Config) {
	// NIP-59: ALWAYS protect gift wraps - only recipient can query them
	// This is independent of RequireAuth setting
	relay.RejectFilter = append(relay.RejectFilter, func(ctx context.Context, filter nostr.Filter) (bool, string) {
		for _, kind := range filter.Kinds {
			// Kind 1059 (Gift Wrap) and Kind 13 (Seal) require auth
			if kind == 1059 || kind == 13 || kind == 14 {
				authedPubkey := khatru.GetAuthed(ctx)
				if authedPubkey == "" {
					khatru.RequestAuth(ctx)
					return true, "auth-required: authentication required to query private messages"
				}

				// For gift wraps, user must be the recipient (p tag)
				if kind == 1059 {
					if pTags, ok := filter.Tags["p"]; ok {
						for _, p := range pTags {
							if p == authedPubkey {
								return false, "" // OK - querying own gift wraps
							}
						}
					}
					// No p tag filter or not matching - reject
					return true, "restricted: can only query gift wraps addressed to you (use #p filter)"
				}
			}
		}
		return false, ""
	})

	// Require authentication for ALL operations if configured
	if cfg.RequireAuth {
		// Reject events from unauthenticated users
		relay.RejectEvent = append(relay.RejectEvent, func(ctx context.Context, event *nostr.Event) (bool, string) {
			// Allow ephemeral events without auth
			if event.Kind >= 20000 && event.Kind < 30000 {
				return false, ""
			}

			// Allow AUTH events (kind 22242)
			if event.Kind == 22242 {
				return false, ""
			}

			// Check if user is authenticated
			authedPubkey := khatru.GetAuthed(ctx)
			if authedPubkey == "" {
				khatru.RequestAuth(ctx)
				return true, "auth-required: authentication required to publish events"
			}

			// Ensure event author matches authenticated pubkey
			if authedPubkey != event.PubKey {
				return true, "invalid: event pubkey does not match authenticated user"
			}

			return false, ""
		})
	}

	// Log authentication events
	relay.OnEventSaved = append(relay.OnEventSaved, func(ctx context.Context, event *nostr.Event) {
		if event.Kind == 22242 {
			log.Debug().
				Str("pubkey", event.PubKey[:16]).
				Msg("AUTH event processed")
		}
	})

	log.Info().Bool("require_auth", cfg.RequireAuth).Msg("NIP-42 AUTH support enabled")
}

// ValidateAuthEvent validates a NIP-42 authentication event
func ValidateAuthEvent(event *nostr.Event, expectedChallenge string, relayURL string) bool {
	// Must be kind 22242
	if event.Kind != 22242 {
		return false
	}

	// Check timestamp (must be recent - within 10 minutes)
	eventTime := event.CreatedAt.Time()
	now := time.Now()
	if eventTime.Before(now.Add(-10*time.Minute)) || eventTime.After(now.Add(10*time.Minute)) {
		return false
	}

	// Verify required tags
	var hasRelay, hasChallenge bool
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "relay":
			if tag[1] == relayURL {
				hasRelay = true
			}
		case "challenge":
			if tag[1] == expectedChallenge {
				hasChallenge = true
			}
		}
	}

	return hasRelay && hasChallenge
}
