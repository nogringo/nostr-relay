package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

const (
	// Per client IP: a burst, then one more per interval.
	connectionBurst    = 100
	connectionInterval = 5 * time.Second
	filterBurst        = 200
	filterInterval     = time.Second

	// Live filters one connection may hold, each matched against every new event.
	maxOpenFilters = 200

	// Index ranges one filter may make lmdb walk, see indexScans.
	maxFilterScans = 20_000
)

// clientIP is the address the reverse proxy appended to X-Forwarded-For, the
// entries before it come from the client. Empty when the proxy sends none:
// every client would then share the proxy's address, and one budget.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return ""
	}
	hops := strings.Split(values[len(values)-1], ",")
	return strings.TrimSpace(hops[len(hops)-1])
}

func limitConnections(relay *khatru.Relay) {
	limiter := newRateLimiter(connectionBurst, connectionInterval)
	relay.RejectConnection = func(r *http.Request) bool {
		ip := clientIP(r)
		return ip != "" && !limiter.allow(ip)
	}
}

// limitRequests bounds what REQ and NEG-OPEN filters may cost. Must run after
// restrictGiftWraps, which replaces OnRequest.
func limitRequests(relay *khatru.Relay) {
	limiter := newRateLimiter(filterBurst, filterInterval)

	open := openFilters{count: make(map[*khatru.WebSocket]int)}
	relay.OnListenerAdded = func(ws *khatru.WebSocket, _ int, _ string, _ nostr.Filter) { open.add(ws, 1) }
	relay.OnListenerRemoved = func(ws *khatru.WebSocket, _ int, _ string, _ nostr.Filter) { open.add(ws, -1) }

	prev := relay.OnRequest
	relay.OnRequest = func(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
		if prev != nil {
			if reject, msg := prev(ctx, filter); reject {
				return reject, msg
			}
		}
		if ip := clientIP(khatru.GetRequest(ctx)); ip != "" && !limiter.allow(ip) {
			return true, "rate-limited: slow down"
		}
		if indexScans(filter) > maxFilterScans {
			return true, "blocked: too many author, kind and tag combinations in one filter"
		}
		// the filters khatru turns into live listeners
		becomesListener := filter.IDs == nil && !khatru.IsNegentropySession(ctx)
		if becomesListener && open.of(khatru.GetConnection(ctx)) >= maxOpenFilters {
			return true, "blocked: too many open subscriptions on this connection"
		}
		return false, ""
	}
}

// indexScans is an upper bound on the index ranges lmdb walks for a filter: one
// per author and kind pair, or per tag value and kind.
func indexScans(filter nostr.Filter) int {
	widest := len(filter.Authors)
	for _, values := range filter.Tags {
		widest = max(widest, len(values))
	}
	return max(1, len(filter.Kinds)) * max(1, widest)
}

// rateLimiter lets each key through burst times, then once more per interval.
type rateLimiter struct {
	burst int
	mu    sync.Mutex
	used  map[string]int
}

func newRateLimiter(burst int, interval time.Duration) *rateLimiter {
	limiter := &rateLimiter{burst: burst, used: make(map[string]int)}
	go func() {
		for range time.Tick(interval) {
			limiter.mu.Lock()
			for key := range limiter.used {
				limiter.used[key]--
				if limiter.used[key] <= 0 {
					delete(limiter.used, key)
				}
			}
			limiter.mu.Unlock()
		}
	}()
	return limiter
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[key] >= l.burst {
		return false
	}
	l.used[key]++
	return true
}

// openFilters counts each connection's live listeners. khatru drops them all on
// disconnect, which brings the count, and the entry, back to zero.
type openFilters struct {
	mu    sync.Mutex
	count map[*khatru.WebSocket]int
}

func (o *openFilters) add(ws *khatru.WebSocket, delta int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.count[ws] += delta
	if o.count[ws] <= 0 {
		delete(o.count, ws)
	}
}

func (o *openFilters) of(ws *khatru.WebSocket) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.count[ws]
}
