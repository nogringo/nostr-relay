package main

import (
	"context"
	"iter"
	"slices"
	"strings"
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

// scanTrackingStore tells whether one of its scans is still running.
type scanTrackingStore struct {
	*slicestore.SliceStore
	scanning bool
}

func (s *scanTrackingStore) QueryEvents(filter nostr.Filter, maxLimit int) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		s.scanning = true
		defer func() { s.scanning = false }()
		for evt := range s.SliceStore.QueryEvents(filter, maxLimit) {
			if !yield(evt) {
				return
			}
		}
	}
}

// An lmdb scan holds a read transaction, which a slow client would keep open
// for its whole download.
func TestQueryReadsResultsOutBeforeSending(t *testing.T) {
	store := &scanTrackingStore{SliceStore: &slicestore.SliceStore{}}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	sk := nostr.Generate()
	for i := range 10 {
		save(t, store.SliceStore, signAt(t, sk, 1, nil, nostr.Timestamp(i+1)))
	}
	relay := khatru.NewRelay()
	applyQueryLimits(relay, store)

	for range relay.QueryStored(context.Background(), nostr.Filter{}) {
		if store.scanning {
			t.Fatal("an event was handed out while the store scan was still open")
		}
	}
}

// Past readAheadBytes the results stream instead, and none may be lost.
func TestLargeQueryResultsAreAllReturned(t *testing.T) {
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	sk := nostr.Generate()
	var want []nostr.ID
	for i := range 8 {
		evt := nostr.Event{CreatedAt: nostr.Timestamp(8 - i), Kind: 1, Content: strings.Repeat("x", readAheadBytes/4)}
		if err := evt.Sign(sk); err != nil {
			t.Fatalf("sign: %v", err)
		}
		save(t, store, evt)
		want = append(want, evt.ID)
	}
	relay := khatru.NewRelay()
	applyQueryLimits(relay, store)

	var got []nostr.ID
	for evt := range relay.QueryStored(context.Background(), nostr.Filter{}) {
		got = append(got, evt.ID)
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %d events, want all %d newest first", len(got), len(want))
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
