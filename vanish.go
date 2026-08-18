package main

import (
	"context"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
)

const (
	vanishAllRelays = "ALL_RELAYS"
	// how many events a single purge query pulls before deleting them
	vanishBatchSize = 500
	// upper bound on the number of vanish requests restored at startup
	vanishRestoreLimit = 100000
	vanishRetryDelay   = time.Minute
)

// vanishJob is a purge left to run for one pubkey: everything it authored up to
// `until`, minus the request itself, plus its whole gift wrap inbox.
type vanishJob struct {
	pubkey  nostr.PubKey
	until   nostr.Timestamp
	request nostr.ID
}

// vanishRequests implements NIP-62. A kind 62 event tagging this relay erases
// everything its author published up to the request's created_at, along with the
// gift wraps addressed to them, and those events can never come back.
//
// The purge runs in the background so the client gets its OK immediately, but
// the re-publishing guard is armed synchronously: there is no window where a
// half-purged pubkey would accept its old events again. The request itself is
// kept in the store, which is what lets an interrupted purge resume after a
// crash and what makes the guard survive a restart.
type vanishRequests struct {
	store eventstore.Store
	urls  []string // our own service URLs, normalized

	mu       sync.RWMutex
	vanished map[nostr.PubKey]nostr.Timestamp // guard: latest request per pubkey
	pending  map[nostr.PubKey]vanishJob       // purges still to run
	idle     chan struct{}                    // closed while there is nothing to purge

	signal chan struct{}
	cancel context.CancelFunc
}

func configureVanishRequests(relay *khatru.Relay, store eventstore.Store) (stop func()) {
	return attachVanishRequests(relay, store, splitCommaSeparated(os.Getenv("RELAY_URLS"))).stop
}

func attachVanishRequests(relay *khatru.Relay, store eventstore.Store, relayURLs []string) *vanishRequests {
	v := &vanishRequests{
		store:    store,
		urls:     normalizeRelayURLs(relayURLs),
		vanished: make(map[nostr.PubKey]nostr.Timestamp),
		pending:  make(map[nostr.PubKey]vanishJob),
		idle:     make(chan struct{}),
		signal:   make(chan struct{}, 1),
	}
	if len(v.urls) == 0 {
		log.Println("NIP-62: RELAY_URLS is unset, only ALL_RELAYS vanish requests will be honored")
	}
	v.restore()

	prevOnEvent := relay.OnEvent
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (reject bool, msg string) {
		if prevOnEvent != nil {
			if reject, msg := prevOnEvent(ctx, event); reject {
				return reject, msg
			}
		}
		return v.reject(event)
	}

	prevOnEventSaved := relay.OnEventSaved
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		if prevOnEventSaved != nil {
			prevOnEventSaved(ctx, event)
		}
		if event.Kind == kindVanish && v.isAddressedToUs(event) {
			v.record(event)
		}
	}

	// NIP-62: "Publishing a deletion request event (Kind 5) against a request to
	// vanish has no effect."
	prevAllowDeleting := relay.AllowDeleting
	relay.AllowDeleting = func(ctx context.Context, target, deletion nostr.Event) bool {
		if target.Kind == kindVanish {
			return false
		}
		if prevAllowDeleting != nil {
			return prevAllowDeleting(ctx, target, deletion)
		}
		return target.PubKey == deletion.PubKey
	}

	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	go v.run(ctx)

	return v
}

func (v *vanishRequests) stop() { v.cancel() }

// restore rebuilds the guard from the requests kept in the store and queues a
// purge for each of them. Replaying a finished purge only costs two empty
// queries, which is what makes resuming after a crash need no extra bookkeeping.
func (v *vanishRequests) restore() {
	n := 0
	for evt := range v.store.QueryEvents(nostr.Filter{Kinds: []nostr.Kind{kindVanish}}, vanishRestoreLimit) {
		n++
		if v.isAddressedToUs(evt) {
			v.record(evt)
		}
	}
	if n == vanishRestoreLimit {
		log.Printf("NIP-62: stopped restoring vanish requests at %d, some may be missing", n)
	}
}

func (v *vanishRequests) isAddressedToUs(event nostr.Event) bool {
	for tag := range event.Tags.FindAll("relay") {
		if tag[1] == vanishAllRelays || slices.Contains(v.urls, normalizeRelayURL(tag[1])) {
			return true
		}
	}
	return false
}

func (v *vanishRequests) record(request nostr.Event) {
	v.mu.Lock()
	if request.CreatedAt > v.vanished[request.PubKey] {
		v.vanished[request.PubKey] = request.CreatedAt
	}
	if job, ok := v.pending[request.PubKey]; !ok || request.CreatedAt > job.until {
		v.pending[request.PubKey] = vanishJob{
			pubkey:  request.PubKey,
			until:   request.CreatedAt,
			request: request.ID,
		}
		v.markBusy()
	}
	v.mu.Unlock()

	select {
	case v.signal <- struct{}{}:
	default:
	}
}

func (v *vanishRequests) threshold(pubkey nostr.PubKey) (nostr.Timestamp, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	ts, ok := v.vanished[pubkey]
	return ts, ok
}

func (v *vanishRequests) reject(event nostr.Event) (reject bool, msg string) {
	if event.Kind == kindVanish {
		// NIP-62: "The tag list MUST include at least one relay value."
		if event.Tags.Find("relay") == nil {
			return true, "invalid: a vanish request must tag at least one relay"
		}
		return false, ""
	}

	if ts, ok := v.threshold(event.PubKey); ok && event.CreatedAt <= ts {
		return true, "blocked: this pubkey requested to vanish from this relay"
	}

	if event.Kind == nostr.KindGiftWrap {
		if p := event.Tags.Find("p"); p != nil {
			recipient, err := nostr.PubKeyFromHex(p[1])
			if err == nil {
				if ts, ok := v.threshold(recipient); ok && event.CreatedAt <= ts {
					return true, "blocked: this recipient requested to vanish from this relay"
				}
			}
		}
	}

	return false, ""
}

func (v *vanishRequests) run(ctx context.Context) {
	for {
		v.drain()

		select {
		case <-ctx.Done():
			return
		case <-v.signal:
		case <-time.After(vanishRetryDelay):
		}
	}
}

func (v *vanishRequests) drain() {
	for {
		job, ok := v.next()
		if !ok {
			return
		}
		if err := v.purge(job); err != nil {
			// the job stays pending and is retried on the next wake-up
			log.Printf("NIP-62: purge of %s failed, will retry: %v", job.pubkey.Hex(), err)
			return
		}
		v.done(job)
	}
}

// next hands out a job to purge, and marks the worker idle when there is none.
// Both happen under the lock, so a request coming in cannot be seen as done.
func (v *vanishRequests) next() (vanishJob, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, job := range v.pending {
		return job, true
	}
	v.markIdle()
	return vanishJob{}, false
}

func (v *vanishRequests) done(job vanishJob) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if current, ok := v.pending[job.pubkey]; ok && current.until <= job.until {
		delete(v.pending, job.pubkey)
	}
}

func (v *vanishRequests) purge(job vanishJob) error {
	err := v.purgeMatching(nostr.Filter{
		Authors: []nostr.PubKey{job.pubkey},
		Until:   job.until,
	}, job.request)
	if err != nil {
		return err
	}

	// NIP-59 randomizes a gift wrap's created_at, so the inbox is emptied whole
	// rather than up to the request's timestamp.
	return v.purgeMatching(nostr.Filter{
		Kinds: []nostr.Kind{nostr.KindGiftWrap},
		Tags:  nostr.TagMap{"p": []string{job.pubkey.Hex()}},
	}, nostr.ID{})
}

// purgeMatching deletes every stored event matching filter, except keep.
func (v *vanishRequests) purgeMatching(filter nostr.Filter, keep nostr.ID) error {
	for {
		// The iterator must be drained before deleting: lmdb holds a read
		// transaction for the whole range while DeleteEvent needs a write one.
		ids := make([]nostr.ID, 0, vanishBatchSize)
		for event := range v.store.QueryEvents(filter, vanishBatchSize) {
			if event.ID != keep {
				ids = append(ids, event.ID)
			}
		}
		if len(ids) == 0 {
			return nil
		}

		for _, id := range ids {
			if err := v.store.DeleteEvent(id); err != nil {
				return err
			}
		}
	}
}

// markBusy and markIdle must be called with the lock held.
func (v *vanishRequests) markBusy() {
	select {
	case <-v.idle:
		v.idle = make(chan struct{})
	default:
	}
}

func (v *vanishRequests) markIdle() {
	select {
	case <-v.idle:
	default:
		close(v.idle)
	}
}

// waitIdle blocks until every queued purge is done. Used by the tests.
func (v *vanishRequests) waitIdle(ctx context.Context) error {
	v.mu.RLock()
	idle := v.idle
	v.mu.RUnlock()

	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func normalizeRelayURLs(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, url := range raw {
		if normalized := normalizeRelayURL(url); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

// normalizeRelayURL strips what does not identify a relay, so that
// "WSS://Relay.Example.com/" and "ws://relay.example.com" compare equal.
func normalizeRelayURL(raw string) string {
	url := strings.ToLower(strings.TrimSpace(raw))
	for _, scheme := range []string{"wss://", "ws://", "https://", "http://"} {
		if trimmed, found := strings.CutPrefix(url, scheme); found {
			url = trimmed
			break
		}
	}
	return strings.TrimSuffix(url, "/")
}
