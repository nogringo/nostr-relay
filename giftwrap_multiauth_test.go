package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip42"
	"github.com/fasthttp/websocket"
)

// testClient is a raw NIP-01 websocket client. The client library in
// fiatjaf.com/nostr authenticates only once per connection (sync.Once), so
// driving the socket by hand is the only way to exercise several NIP-42
// identities sharing one connection.
type testClient struct {
	t    *testing.T
	conn *websocket.Conn
	url  string
}

func dialRelay(t *testing.T, relayURL string) *testClient {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(relayURL, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", relayURL, err)
	}
	t.Cleanup(func() { conn.Close() })
	return &testClient{t: t, conn: conn, url: relayURL}
}

func (c *testClient) send(env nostr.Envelope) {
	c.t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		c.t.Fatalf("marshal %s: %v", env.Label(), err)
	}
	if err := c.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		c.t.Fatalf("write %s: %v", env.Label(), err)
	}
}

// readUntil drains messages until one of the stop labels arrives, returning
// everything read (the terminator included).
func (c *testClient) readUntil(stop ...string) []nostr.Envelope {
	c.t.Helper()
	var got []nostr.Envelope
	for {
		c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			c.t.Fatalf("read (waiting for %v, got %s so far): %v", stop, labels(got), err)
		}
		env, err := nostr.ParseMessage(string(raw))
		if err != nil {
			c.t.Fatalf("parse %q: %v", raw, err)
		}
		got = append(got, env)
		for _, label := range stop {
			if env.Label() == label {
				return got
			}
		}
	}
}

func labels(envs []nostr.Envelope) string {
	out := make([]string, len(envs))
	for i, e := range envs {
		out[i] = e.Label()
	}
	return "[" + strings.Join(out, " ") + "]"
}

func challengeIn(envs []nostr.Envelope) string {
	for _, e := range envs {
		if auth, ok := e.(*nostr.AuthEnvelope); ok && auth.Challenge != nil {
			return *auth.Challenge
		}
	}
	return ""
}

func closedIn(envs []nostr.Envelope) *nostr.ClosedEnvelope {
	for _, e := range envs {
		if closed, ok := e.(*nostr.ClosedEnvelope); ok {
			return closed
		}
	}
	return nil
}

func eventIDsIn(envs []nostr.Envelope) []nostr.ID {
	var ids []nostr.ID
	for _, e := range envs {
		if evt, ok := e.(*nostr.EventEnvelope); ok {
			ids = append(ids, evt.Event.ID)
		}
	}
	return ids
}

func (c *testClient) authenticate(sk nostr.SecretKey, challenge string) {
	c.t.Helper()
	authEvent := nip42.CreateUnsignedAuthEvent(challenge, nostr.GetPublicKey(sk), c.url)
	if err := authEvent.Sign(sk); err != nil {
		c.t.Fatalf("sign auth event: %v", err)
	}
	c.send(&nostr.AuthEnvelope{Event: authEvent})

	got := c.readUntil("OK")
	ok := got[len(got)-1].(*nostr.OKEnvelope)
	if !ok.OK {
		c.t.Fatalf("AUTH rejected: %s", ok.Reason)
	}
}

// fetchGiftWraps issues a REQ for the gift wraps addressed to recipient and
// returns the terminating CLOSED (nil when the subscription reached EOSE), the
// AUTH challenge received along the way (empty when none) and the event ids.
func (c *testClient) fetchGiftWraps(subID string, recipient nostr.PubKey) (*nostr.ClosedEnvelope, string, []nostr.ID) {
	c.t.Helper()
	c.send(&nostr.ReqEnvelope{
		SubscriptionID: subID,
		Filters: []nostr.Filter{{
			Kinds: []nostr.Kind{nostr.KindGiftWrap},
			Tags:  nostr.TagMap{"p": {recipient.Hex()}},
		}},
	})
	got := c.readUntil("EOSE", "CLOSED")
	return closedIn(got), challengeIn(got), eventIDsIn(got)
}

// A single websocket connection may carry several NIP-42 identities. Once A is
// authenticated, a REQ for B's gift wraps must still lead B to authenticate and
// get its own inbox, instead of being turned away for good.
func TestGiftWrapSecondIdentityOnSameConnection(t *testing.T) {
	relay, store := newTestRelay(t)
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	skA, skB := nostr.Generate(), nostr.Generate()
	a, b := nostr.GetPublicKey(skA), nostr.GetPublicKey(skB)
	senderSK := nostr.Generate()

	gwA := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", a.Hex()}})
	gwB := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", b.Hex()}})
	for _, evt := range []nostr.Event{gwA, gwB} {
		if err := store.SaveEvent(evt); err != nil {
			t.Fatal(err)
		}
	}

	client := dialRelay(t, relayURL)

	closed, challenge, _ := client.fetchGiftWraps("a-anon", a)
	if closed == nil || !strings.HasPrefix(closed.Reason, "auth-required:") {
		t.Fatalf("first query should ask for auth, got %+v", closed)
	}
	if challenge == "" {
		t.Fatal("relay did not send a NIP-42 challenge")
	}
	client.authenticate(skA, challenge)

	if closed, _, ids := client.fetchGiftWraps("a-authed", a); closed != nil {
		t.Fatalf("A should read its own gift wraps, got CLOSED %q", closed.Reason)
	} else if !hasID(ids, gwA.ID) {
		t.Fatalf("A did not receive its gift wrap, got %v", ids)
	}

	// B now asks for its own inbox over the very same connection. A is already
	// authenticated, which must not make the relay treat B as an intruder.
	closed, challenge, _ = client.fetchGiftWraps("b-anon", b)
	if closed == nil || !strings.HasPrefix(closed.Reason, "auth-required:") {
		t.Fatalf("B must be invited to authenticate, got %+v", closed)
	}
	if challenge == "" {
		t.Fatal("relay did not send a NIP-42 challenge for the second identity")
	}
	client.authenticate(skB, challenge)

	if closed, _, ids := client.fetchGiftWraps("b-authed", b); closed != nil {
		t.Fatalf("B should read its own gift wraps, got CLOSED %q", closed.Reason)
	} else if !hasID(ids, gwB.ID) {
		t.Fatalf("B did not receive its gift wrap, got %v", ids)
	}

	// A must still be served: authenticating B does not evict A.
	if closed, _, ids := client.fetchGiftWraps("a-again", a); closed != nil {
		t.Fatalf("A should still read its gift wraps, got CLOSED %q", closed.Reason)
	} else if !hasID(ids, gwA.ID) {
		t.Fatalf("A lost access to its gift wrap after B authenticated, got %v", ids)
	}
}

func hasID(ids []nostr.ID, want nostr.ID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
