package main

import (
	"context"
	"iter"
	"log"
	"slices"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
)

// the `k` tag a NIP-09 request carries when it deletes gift wraps
const giftWrapKindTag = "1059"

// restrictGiftWraps ensures a NIP-59 gift wrap (kind 1059) can only be
// published by an authenticated client, then retrieved by its recipient (the
// pubkey in the `p` tag), authenticated via NIP-42. The deletion requests
// covering gift wraps are equally private: see visibleTo.
//
// A single websocket connection may authenticate as several pubkeys, so every
// check tests membership against the full set of authenticated keys, never just
// the last one.
func restrictGiftWraps(relay *khatru.Relay, store eventstore.Store) {
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

	// 2) A request/count that touches gift wraps, or the deletion requests
	//    covering them, must be authenticated. If it names recipients or authors,
	//    each must be one of the connection's own identities.
	gate := func(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
		authed := khatru.GetAllAuthed(ctx)

		if slices.Contains(filter.Kinds, nostr.KindGiftWrap) {
			// An unknown recipient is always resolvable by authenticating as them, so
			// this is "auth-required" and not "restricted", even when the connection
			// already carries other identities: clients treat "restricted:" as final.
			for _, p := range filter.Tags["p"] {
				if !isAuthedRecipient(authed, p) {
					return true, "auth-required: authenticate as this recipient to fetch their gift wraps"
				}
			}
			if len(authed) == 0 {
				return true, "auth-required: authenticate to fetch gift wraps"
			}
		}

		if slices.Contains(filter.Kinds, nostr.KindDeletion) && slices.Contains(filter.Tags["k"], giftWrapKindTag) {
			for _, author := range filter.Authors {
				if !slices.Contains(authed, author) {
					return true, "auth-required: authenticate as this author to fetch their gift wrap deletions"
				}
			}
			if len(authed) == 0 {
				return true, "auth-required: authenticate to fetch gift wrap deletions"
			}
		}

		return false, "" // QueryStored scopes the results to the authed pubkey(s)
	}
	relay.OnRequest = gate
	relay.OnCount = gate

	// 3) Safety net: even via a broad query (no `kinds`, or `{}`), never return a
	//    private event to anyone other than its authenticated owner.
	base := relay.QueryStored
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		// The NIP-40 expiration manager runs on the relay's own context, with no
		// connection behind it, and is trusted. The NIP-09 delete pipeline also
		// queries internally, but over the client's connection, and is not: the
		// OK it produces ("you are not the author" only when it found the target)
		// would otherwise tell a sender whether the gift wrap is still stored.
		// Gift wraps are therefore deleted in step 7 instead.
		if khatru.IsInternalCall(ctx) && khatru.GetConnection(ctx) == nil {
			return base(ctx, filter)
		}

		return scopeToAuthed(khatru.GetAllAuthed(ctx), base(ctx, filter))
	}

	// 4) Counting bypasses QueryStored entirely, so a bare COUNT would still tell
	//    a sender whether the gift wrap they know the id of is still stored. A
	//    filter that cannot match a private event keeps the store's fast count.
	baseCount := relay.Count
	relay.Count = func(ctx context.Context, filter nostr.Filter) (uint32, error) {
		if khatru.IsInternalCall(ctx) || !mayMatchPrivate(filter) {
			return baseCount(ctx, filter)
		}

		authed := khatru.GetAllAuthed(ctx)
		var n uint32
		for range scopeToAuthed(authed, store.QueryEvents(filter, maxSyncEvents)) {
			n++
		}
		return n, nil
	}

	// 5) Live path: a newly published event is pushed to every subscription whose
	//    filter matches it, bypassing QueryStored. Only deliver a private one over
	//    a connection authenticated as its owner.
	relay.PreventBroadcast = func(ws *khatru.WebSocket, filter nostr.Filter, event nostr.Event) bool {
		return !visibleTo(ws.AuthedPublicKeys, event)
	}

	// 6) Deletion: see deletersOf. Setting AllowDeleting overrides the default
	//    NIP-09 rule for all events, so it has to restate it for the other kinds.
	relay.AllowDeleting = func(ctx context.Context, target, deletion nostr.Event) bool {
		return slices.Contains(deletersOf(target), deletion.PubKey)
	}

	// 7) khatru's delete pipeline cannot reach the gift wraps QueryStored hides
	//    from the connection, so they are deleted here, where the request itself
	//    says who is asking. NIP-09 proves that by signature, which is why this
	//    needs no NIP-42. It runs once the request is stored, so the tombstone
	//    restrictDeletedEvents relies on is always there first.
	prevOnEventSaved := relay.OnEventSaved
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		if prevOnEventSaved != nil {
			prevOnEventSaved(ctx, event)
		}
		if event.Kind == nostr.KindDeletion {
			deleteGiftWraps(store, event)
		}
	}
}

// deleteGiftWraps removes the gift wraps a NIP-09 request covers: those whose
// recipient signed it, by the rule in deletersOf. A `k` tag is not required, the
// event found in the store is what decides.
func deleteGiftWraps(store eventstore.Store, request nostr.Event) {
	for tag := range request.Tags.FindAll("e") {
		id, err := nostr.IDFromHex(tag[1])
		if err != nil {
			continue
		}

		// The iterator must be drained before deleting: lmdb holds a read
		// transaction for the whole range while DeleteEvent needs a write one.
		var targets []nostr.ID
		for event := range store.QueryEvents(nostr.Filter{IDs: []nostr.ID{id}}, 1) {
			if event.Kind == nostr.KindGiftWrap && slices.Contains(deletersOf(event), request.PubKey) {
				targets = append(targets, event.ID)
			}
		}

		for _, target := range targets {
			if err := store.DeleteEvent(target); err != nil {
				log.Printf("NIP-59: deleting gift wrap %s failed: %v", target.Hex(), err)
			}
		}
	}
}

// deletersOf lists the pubkeys allowed to delete an event.
//
// A gift wrap is signed by a throw-away ephemeral key, so NIP-09's default "only
// the author may delete" rule can never apply. NIP-59 instead lets the recipient
// delete it, proven by the deletion event's own signature: its pubkey must match
// the gift wrap's `p` tag. Every other kind keeps the default rule.
//
// restrictDeletedEvents narrows its tombstone lookups with this, so it has to
// stay exactly the set AllowDeleting accepts.
func deletersOf(event nostr.Event) []nostr.PubKey {
	if event.Kind == nostr.KindGiftWrap {
		p := event.Tags.Find("p")
		if p == nil {
			return nil
		}
		recipient, err := nostr.PubKeyFromHex(p[1])
		if err != nil {
			return nil
		}
		return []nostr.PubKey{recipient}
	}
	return []nostr.PubKey{event.PubKey}
}

// visibleTo reports whether an event may be served to a connection holding
// these authenticated pubkeys.
//
// A gift wrap is for its recipient only. So is the NIP-09 request that deletes
// one: NIP-59 says "relays SHOULD only serve kind 5 events with a k tag of 1059
// to their author", otherwise the sender, who knows the gift wrap id, learns
// when the recipient deleted it. A request mixing `k` tags stays private too,
// which is why NIP-59 tells clients not to mix them.
func visibleTo(authed []nostr.PubKey, event nostr.Event) bool {
	switch {
	case event.Kind == nostr.KindGiftWrap:
		p := event.Tags.Find("p")
		return p != nil && isAuthedRecipient(authed, p[1])
	case event.Kind == nostr.KindDeletion && event.Tags.ContainsAny("k", []string{giftWrapKindTag}):
		return slices.Contains(authed, event.PubKey)
	}
	return true
}

// mayMatchPrivate reports whether a filter could match an event visibleTo keeps
// private. A filter without kinds matches every kind.
func mayMatchPrivate(filter nostr.Filter) bool {
	return len(filter.Kinds) == 0 ||
		slices.Contains(filter.Kinds, nostr.KindGiftWrap) ||
		slices.Contains(filter.Kinds, nostr.KindDeletion)
}

// scopeToAuthed drops every event these pubkeys may not see, leaving the rest
// untouched.
func scopeToAuthed(authed []nostr.PubKey, src iter.Seq[nostr.Event]) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		for evt := range src {
			if !visibleTo(authed, evt) {
				continue
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
