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
	// NIP-42: Send AUTH challenge on connection so clients can authenticate when they want
	relay.OnConnect = append(relay.OnConnect, func(ctx context.Context) {
		khatru.RequestAuth(ctx)
	})

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
				// User is authenticated - QueryEvents will filter to only return their gift wraps
				return false, ""
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

	// NIP-59: Prevent broadcasting gift wraps to non-recipients (real-time events)
	relay.PreventBroadcast = append(relay.PreventBroadcast, func(ws *khatru.WebSocket, event *nostr.Event) bool {
		// Only filter gift wraps
		if event.Kind != 1059 {
			return false
		}

		// Must be authenticated
		if ws.AuthedPublicKey == "" {
			log.Debug().
				Str("event_id", event.ID[:16]).
				Msg("Prevented gift wrap broadcast - user not authenticated")
			return true
		}

		// User must be the recipient (p tag)
		for _, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "p" && tag[1] == ws.AuthedPublicKey {
				return false // Allow broadcast - user is recipient
			}
		}

		log.Debug().
			Str("event_id", event.ID[:16]).
			Str("authed_pubkey", ws.AuthedPublicKey[:16]).
			Msg("Prevented gift wrap broadcast - user is not recipient")
		return true // Prevent broadcast
	})

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
