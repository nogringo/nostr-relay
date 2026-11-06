package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/fasthttp/websocket"
)

func dialFrom(relayURL, forwardedFor string) (*websocket.Conn, *http.Response, error) {
	return websocket.DefaultDialer.Dial(relayURL, http.Header{"X-Forwarded-For": {forwardedFor}})
}

func dialRelayFrom(t *testing.T, relayURL, forwardedFor string) *testClient {
	t.Helper()
	conn, _, err := dialFrom(relayURL, forwardedFor)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", relayURL, forwardedFor, err)
	}
	t.Cleanup(func() { conn.Close() })
	return &testClient{t: t, conn: conn, url: relayURL}
}

// The client IP is the entry the proxy appended, whatever the client put before it.
func TestConnectionsRateLimitedPerClientIP(t *testing.T) {
	relayURL := startRelay(t)

	for range connectionBurst {
		conn, _, err := dialFrom(relayURL, "203.0.113.7")
		if err != nil {
			t.Fatalf("connection within the burst: %v", err)
		}
		conn.Close()
	}

	conn, resp, err := dialFrom(relayURL, "198.51.100.1, 203.0.113.7")
	if err == nil {
		conn.Close()
		t.Fatal("a connection past the burst was accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a connection past the burst: %v, want 429", err)
	}
}

// Without X-Forwarded-For every client comes from the proxy's address, so
// limiting it would have them all share one budget.
func TestConnectionsWithoutForwardedForAreNotRateLimited(t *testing.T) {
	relay, _ := newTestRelay(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.17.0.1:40000"

	for range connectionBurst + 1 {
		if relay.RejectConnection(r) {
			t.Fatal("a connection without X-Forwarded-For was rate limited")
		}
	}
}

func TestRequestsRateLimitedPerClientIP(t *testing.T) {
	client := dialRelayFrom(t, startRelay(t), "203.0.113.7")

	filters := make([]nostr.Filter, filterBurst+1)
	for i := range filters {
		filters[i] = nostr.Filter{IDs: []nostr.ID{{byte(i), byte(i >> 8)}}}
	}
	client.send(&nostr.ReqEnvelope{SubscriptionID: "burst", Filters: filters})

	closed := closedIn(client.readUntil("EOSE", "CLOSED"))
	if closed == nil || !strings.HasPrefix(closed.Reason, "rate-limited:") {
		t.Errorf("filters past the burst: got %+v, want CLOSED rate-limited", closed)
	}
}

// Every live filter is matched against each new event. Replacing a
// subscription gives its filters back.
func TestOpenFiltersCappedPerConnection(t *testing.T) {
	client := dialRelay(t, startRelay(t))
	notes := nostr.Filter{Kinds: []nostr.Kind{nostr.KindTextNote}}

	client.send(&nostr.ReqEnvelope{SubscriptionID: "feed", Filters: slices.Repeat([]nostr.Filter{notes}, maxOpenFilters)})
	if closed := closedIn(client.readUntil("EOSE", "CLOSED")); closed != nil {
		t.Fatalf("filters up to the cap: CLOSED %q", closed.Reason)
	}

	if closed, _ := client.fetch("more", notes); closed == nil || !strings.HasPrefix(closed.Reason, "blocked:") {
		t.Errorf("a filter past the cap: got %+v, want CLOSED blocked", closed)
	}

	if closed, _ := client.fetch("feed", notes); closed != nil {
		t.Errorf("replacing the subscription should free its filters, got CLOSED %q", closed.Reason)
	}
}

// lmdb walks one index range per author and kind pair.
func TestFilterWithTooManyCombinationsRejected(t *testing.T) {
	client := dialRelay(t, startRelay(t))

	filter := nostr.Filter{
		Kinds:   make([]nostr.Kind, 100),
		Authors: make([]nostr.PubKey, maxFilterScans/100+1),
	}
	for i := range filter.Kinds {
		filter.Kinds[i] = nostr.Kind(i)
	}
	for i := range filter.Authors {
		filter.Authors[i] = nostr.GetPublicKey(nostr.Generate())
	}

	if closed, _ := client.fetch("wide", filter); closed == nil || !strings.HasPrefix(closed.Reason, "blocked:") {
		t.Errorf("got %+v, want CLOSED blocked", closed)
	}
}
