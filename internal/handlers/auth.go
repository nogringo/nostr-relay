package handlers

import (
	"context"
	"time"

	"nostr-relay/config"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"github.com/rs/zerolog/log"
)

// NIP-42 Authentication Handler
// Kind 22242 is used for client authentication

func SetupAuthHandlers(relay *khatru.Relay, cfg *config.Config) {
	// Store existing handlers to chain them
	existingOnConnect := relay.OnConnect
	existingOnRequest := relay.OnRequest
	existingOnCount := relay.OnCount
	existingOnEvent := relay.OnEvent
	existingPreventBroadcast := relay.PreventBroadcast
	existingOnEventSaved := relay.OnEventSaved

	// NIP-42: Send AUTH challenge on connection so clients can authenticate when they want
	relay.OnConnect = func(ctx context.Context) {
		if existingOnConnect != nil {
			existingOnConnect(ctx)
		}
		khatru.RequestAuth(ctx)
	}

	// NIP-59: ALWAYS protect gift wraps - only recipient can query them
	// This is independent of RequireAuth setting
	relay.OnRequest = func(ctx context.Context, filter nostr.Filter) (bool, string) {
		// Chain existing handler first
		if existingOnRequest != nil {
			if reject, msg := existingOnRequest(ctx, filter); reject {
				return reject, msg
			}
		}

		return requireAuthForPrivateMessageFilter(ctx, filter)
	}

	relay.OnCount = func(ctx context.Context, filter nostr.Filter) (bool, string) {
		// Chain existing handler first
		if existingOnCount != nil {
			if reject, msg := existingOnCount(ctx, filter); reject {
				return reject, msg
			}
		}

		return requireAuthForPrivateMessageFilter(ctx, filter)
	}

	// Require authentication for ALL operations if configured
	if cfg.RequireAuth {
		// Reject events from unauthenticated users
		relay.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
			// Chain existing handler first
			if existingOnEvent != nil {
				if reject, msg := existingOnEvent(ctx, event); reject {
					return reject, msg
				}
			}

			// Allow ephemeral events without auth
			if event.Kind >= 20000 && event.Kind < 30000 {
				return false, ""
			}

			// Allow AUTH events (kind 22242)
			if event.Kind == 22242 {
				return false, ""
			}

			// Check if user is authenticated
			authedPubkey, authed := khatru.GetAuthed(ctx)
			if !authed {
				khatru.RequestAuth(ctx)
				return true, "auth-required: authentication required to publish events"
			}

			// Ensure event author matches authenticated pubkey
			if authedPubkey != event.PubKey {
				return true, "invalid: event pubkey does not match authenticated user"
			}

			return false, ""
		}
	}

	// NIP-59: Prevent broadcasting gift wraps to non-recipients (real-time events)
	relay.PreventBroadcast = func(ws *khatru.WebSocket, filter nostr.Filter, event nostr.Event) bool {
		// Chain existing handler first
		if existingPreventBroadcast != nil {
			if existingPreventBroadcast(ws, filter, event) {
				return true
			}
		}

		// Only filter gift wraps
		if event.Kind != KindGiftWrap {
			return false
		}

		// Must be authenticated
		if len(ws.AuthedPublicKeys) == 0 {
			return true
		}

		// User must be the recipient (p tag)
		for _, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "p" {
				for _, authedPK := range ws.AuthedPublicKeys {
					if tag[1] == authedPK.Hex() {
						return false // Allow broadcast - user is recipient
					}
				}
			}
		}

		return true // Prevent broadcast
	}

	// Log authentication events
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		// Chain existing handler first
		if existingOnEventSaved != nil {
			existingOnEventSaved(ctx, event)
		}

		if event.Kind == 22242 {
			log.Debug().
				Str("pubkey", event.PubKey.Hex()[:16]).
				Msg("AUTH event processed")
		}
	}

	log.Info().Bool("require_auth", cfg.RequireAuth).Msg("NIP-42 AUTH support enabled")
}

func requireAuthForPrivateMessageFilter(ctx context.Context, filter nostr.Filter) (bool, string) {
	for _, kind := range filter.Kinds {
		// Kind 1059 (Gift Wrap), Kind 13 (Seal), and Kind 14 (DM) require auth.
		if kind == KindGiftWrap || kind == KindSeal || kind == KindDirectMessage {
			_, authed := khatru.GetAuthed(ctx)
			if !authed {
				khatru.RequestAuth(ctx)
				return true, "auth-required: authentication required to query private messages"
			}
			return false, ""
		}
	}
	return false, ""
}

// ValidateAuthEvent validates a NIP-42 authentication event
func ValidateAuthEvent(event nostr.Event, expectedChallenge string, relayURL string) bool {
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
