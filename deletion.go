package main

import (
	"context"
	"strconv"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
)

// how many deletion requests one lookup pulls before giving up
const deletionLookupLimit = 500

// how long a tag value lmdb still indexes, see getIndexKeysForEvent
const indexedTagValueLimit = 100

// restrictDeletedEvents makes a NIP-09 deletion final: once a valid deletion
// request covers an event, that event can never be stored again, whoever
// re-publishes it. NIP-09: "Relays SHOULD delete or stop publishing any
// referenced events that have an identical pubkey as the deletion request."
//
// The requests are the tombstones. They are kept forever, which NIP-09 asks for
// anyway ("Relays SHOULD continue to publish/share the deletion request events
// indefinitely"), so the guard needs no state of its own and survives a restart.
//
// It must block exactly what khatru's handleDeleteRequest would have deleted and
// nothing more: over-blocking would let one pubkey censor another's events.
func restrictDeletedEvents(relay *khatru.Relay, store eventstore.Store) {
	// NIP-09: "Publishing a deletion request event against a deletion request has
	// no effect." It is also what keeps a tombstone from being erased to bring
	// the event it covers back.
	prevAllowDeleting := relay.AllowDeleting
	allowDeleting := func(ctx context.Context, target, deletion nostr.Event) bool {
		if target.Kind == nostr.KindDeletion {
			return false
		}
		if prevAllowDeleting != nil {
			return prevAllowDeleting(ctx, target, deletion)
		}
		return target.PubKey == deletion.PubKey
	}
	relay.AllowDeleting = allowDeleting

	prevOnEvent := relay.OnEvent
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (reject bool, msg string) {
		if prevOnEvent != nil {
			if reject, msg := prevOnEvent(ctx, event); reject {
				return reject, msg
			}
		}
		if event.Kind == nostr.KindDeletion || event.Kind.IsEphemeral() {
			return false, ""
		}
		// nobody may delete it, so no request can ever cover it. Leaving this to
		// the lookups would query every pubkey's requests, since an empty
		// Authors means "any author" in a filter.
		if len(deletersOf(event)) == 0 {
			return false, ""
		}
		if deletedByID(ctx, store, allowDeleting, event) ||
			deletedByAddress(ctx, store, allowDeleting, event) {
			return true, "blocked: this event was deleted"
		}
		return false, ""
	}
}

// deletionAuthorizer is relay.AllowDeleting. It must stay a pure function of
// (target, deletion): the context here is the publisher's, not the one the
// deletion request arrived on.
type deletionAuthorizer func(ctx context.Context, target, deletion nostr.Event) bool

func deletedByID(ctx context.Context, store eventstore.Store, allowed deletionAuthorizer, event nostr.Event) bool {
	id := event.ID.Hex()
	filter := nostr.Filter{
		Kinds:   []nostr.Kind{nostr.KindDeletion},
		Authors: deletersOf(event),
		Tags:    nostr.TagMap{"e": []string{id}},
	}
	for request := range store.QueryEvents(filter, deletionLookupLimit) {
		// lmdb keys an "e" tag on the first 8 bytes of its value only
		if request.Tags.ContainsAny("e", []string{id}) && allowed(ctx, event, request) {
			return true
		}
	}
	return false
}

// deletedByAddress covers the `a` tags. NIP-09: "relays SHOULD delete all
// versions of the replaceable event up to the created_at timestamp of the
// deletion request event", so a newer version is a legitimate update.
func deletedByAddress(ctx context.Context, store eventstore.Store, allowed deletionAuthorizer, event nostr.Event) bool {
	if !event.Kind.IsReplaceable() && !event.Kind.IsAddressable() {
		return false
	}

	identifier := ""
	if event.Kind.IsAddressable() {
		identifier = event.Tags.GetD()
	}
	address := strconv.Itoa(int(event.Kind)) + ":" + event.PubKey.Hex() + ":" + identifier

	filter := nostr.Filter{
		Kinds:   []nostr.Kind{nostr.KindDeletion},
		Authors: deletersOf(event),
		Tags:    nostr.TagMap{"a": []string{address}},
		// only a bound on the scan, the cutoff below is what decides. The second
		// of slack is for slicestore, whose Since drops the events sitting right
		// on it while lmdb keeps them.
		Since: event.CreatedAt - 1,
	}
	if len(address) > indexedTagValueLimit {
		// a long identifier leaves the address out of the tag index entirely, so
		// it has to be found by walking this author's requests instead
		filter.Tags = nil
	}

	for request := range store.QueryEvents(filter, deletionLookupLimit) {
		if request.CreatedAt >= event.CreatedAt &&
			request.Tags.ContainsAny("a", []string{address}) &&
			allowed(ctx, event, request) {
			return true
		}
	}
	return false
}
