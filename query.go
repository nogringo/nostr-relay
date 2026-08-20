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

// applyQueryLimits replaces the single cap UseEventstore installs, which ties
// syncs to 20x the query limit. Must run before hooks that wrap QueryStored.
func applyQueryLimits(relay *khatru.Relay, store eventstore.Store) {
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		if khatru.IsNegentropySession(ctx) {
			return store.QueryEvents(filter, maxSyncEvents)
		}
		return store.QueryEvents(filter, maxQueryLimit)
	}
}
