package main

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

func newQueryTestRelay(t *testing.T, events int) *khatru.Relay {
	t.Helper()
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	sk := nostr.Generate()
	for i := range events {
		save(t, store, signAt(t, sk, 1, nil, nostr.Timestamp(i+1)))
	}
	relay := khatru.NewRelay()
	relay.UseEventstore(store, maxQueryLimit)
	applyQueryLimits(relay, store)
	return relay
}

// A limitless query is served, but capped.
func TestQueryWithoutLimitIsCapped(t *testing.T) {
	relay := newQueryTestRelay(t, maxQueryLimit+50)

	got := collect(relay.QueryStored(context.Background(), nostr.Filter{}))
	if len(got) != maxQueryLimit {
		t.Errorf("got %d events, want the %d cap", len(got), maxQueryLimit)
	}
}

// A NIP-77 sync reconciles the whole set at once: capping it at the query limit
// would hide the older events from the client, which has no way to tell.
func TestSyncIsNotCappedByQueryLimit(t *testing.T) {
	const stored = maxQueryLimit + 50
	relay := newQueryTestRelay(t, stored)

	ctx := khatru.SetNegentropy(context.Background())
	got := collect(relay.QueryStored(ctx, nostr.Filter{}))
	if len(got) != stored {
		t.Errorf("sync saw %d events, want all %d", len(got), stored)
	}
}
