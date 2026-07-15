package main

import (
	"context"
	"iter"
	"slices"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

// restrictGiftWraps ensures a NIP-59 gift wrap (kind 1059) can only be
// published by an authenticated client, then retrieved by its recipient (the
// pubkey in the `p` tag), authenticated via NIP-42.
//
// A single websocket connection may authenticate as several pubkeys, so every
// check tests membership against the full set of authenticated keys, never just
// the last one.
func restrictGiftWraps(relay *khatru.Relay) {
	// 1) Publishing gift wraps must be authenticated. NIP-59 gift wraps are signed
	//    by ephemeral keys, so the authenticated pubkey intentionally does not
	//    need to match event.PubKey.
	prevOnEvent := relay.OnEvent
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (reject bool, msg string) {
		if prevOnEvent != nil {
			if reject, msg := prevOnEvent(ctx, event); reject {
				return reject, msg
			}
		}
		if event.Kind != nostr.KindGiftWrap || len(khatru.GetAllAuthed(ctx)) > 0 {
			return false, ""
		}
		return true, "auth-required: authenticate to publish gift wraps"
	}

	// 2) A request/count that touches gift wraps must be authenticated. If it
	//    names recipients, each must be one of the connection's own identities.
	gate := func(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
		if !slices.Contains(filter.Kinds, nostr.KindGiftWrap) {
			return false, ""
		}

		authed := khatru.GetAllAuthed(ctx)
		if len(authed) == 0 {
			khatru.RequestAuth(ctx)
			return true, "auth-required: authenticate to fetch gift wraps"
		}

		for _, p := range filter.Tags["p"] {
			if !isAuthedRecipient(authed, p) {
				return true, "restricted: you can only fetch your own gift wraps"
			}
		}
		return false, "" // QueryStored scopes the results to the authed recipient(s)
	}
	relay.OnRequest = gate
	relay.OnCount = gate

	// 3) Safety net: even via a broad query (no `kinds`, or `{}`), never return a
	//    kind 1059 event to anyone other than one of its authenticated recipients.
	base := relay.QueryStored
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		// Internal relay queries (deletions, NIP-40 expiration) are trusted.
		if khatru.IsInternalCall(ctx) {
			return base(ctx, filter)
		}

		return scopeGiftWraps(khatru.GetAllAuthed(ctx), base(ctx, filter))
	}

	// 4) Live path: a newly published gift wrap is pushed to every subscription
	//    whose filter matches it, bypassing QueryStored. Only deliver it over a
	//    connection authenticated as the recipient.
	relay.PreventBroadcast = func(ws *khatru.WebSocket, filter nostr.Filter, event nostr.Event) bool {
		if event.Kind != nostr.KindGiftWrap {
			return false // broadcast non-gift-wraps normally
		}
		p := event.Tags.Find("p")
		if p == nil {
			return true // malformed gift wrap → never broadcast
		}
		return !isAuthedRecipient(ws.AuthedPublicKeys, p[1])
	}

	// 5) Deletion: a gift wrap is signed by a throw-away ephemeral key, so NIP-09's
	//    default "only the author may delete" rule can never apply. NIP-59 instead
	//    lets the recipient delete it, proven by the deletion event's own signature:
	//    its pubkey must match the gift wrap's `p` tag. Every other kind keeps the
	//    default rule, since setting AllowDeleting overrides it for all events.
	relay.AllowDeleting = func(ctx context.Context, target, deletion nostr.Event) bool {
		if target.Kind == nostr.KindGiftWrap {
			p := target.Tags.Find("p")
			return p != nil && p[1] == deletion.PubKey.Hex()
		}
		return target.PubKey == deletion.PubKey
	}
}

// scopeGiftWraps drops every kind 1059 event whose recipient is not among the
// authenticated pubkeys, leaving all other events untouched.
func scopeGiftWraps(authed []nostr.PubKey, src iter.Seq[nostr.Event]) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		for evt := range src {
			if evt.Kind == nostr.KindGiftWrap {
				if p := evt.Tags.Find("p"); p == nil || !isAuthedRecipient(authed, p[1]) {
					continue
				}
			}
			if !yield(evt) {
				return
			}
		}
	}
}

// isAuthedRecipient reports whether pubkeyHex is among the authenticated pubkeys.
func isAuthedRecipient(authed []nostr.PubKey, pubkeyHex string) bool {
	for _, pk := range authed {
		if pk.Hex() == pubkeyHex {
			return true
		}
	}
	return false
}
