package main

import (
	"context"
	"iter"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
)

// Max events a single query returns, and what a query without a limit gets.
const maxQueryLimit = 500

// A NIP-77 sync reconciles a whole set at once, so the query limit would
// silently truncate it to the newest events. Same ceiling as strfry's
// negentropy.maxSyncEvents; the session holds 40 bytes per event.
const maxSyncEvents = 1_000_000

// An lmdb scan holds a read transaction, and khatru sends each event to the
// client from inside it: a slow client would keep that snapshot open. Results up
// to this size are read out first; past it they stream, to bound memory.
const readAheadBytes = 1 << 20

// applyQueryLimits replaces the single cap UseEventstore installs, which ties
// syncs to 20x the query limit. Must run before hooks that wrap QueryStored.
func applyQueryLimits(relay *khatru.Relay, store eventstore.Store) {
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		if khatru.IsNegentropySession(ctx) {
			return store.QueryEvents(filter, maxSyncEvents)
		}
		return readAhead(store.QueryEvents(filter, maxQueryLimit))
	}
}

func readAhead(events iter.Seq[nostr.Event]) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		var ahead []nostr.Event
		size := 0
		for evt := range events {
			if size < readAheadBytes {
				ahead = append(ahead, evt)
				size += eventSize(evt)
				continue
			}
			if !yieldEach(ahead, yield) || !yield(evt) {
				return
			}
			ahead = nil
		}
		yieldEach(ahead, yield)
	}
}

func yieldEach(events []nostr.Event, yield func(nostr.Event) bool) bool {
	for _, evt := range events {
		if !yield(evt) {
			return false
		}
	}
	return true
}

func eventSize(evt nostr.Event) int {
	n := len(evt.Content)
	for _, tag := range evt.Tags {
		for _, value := range tag {
			n += len(value)
		}
	}
	return n
}
