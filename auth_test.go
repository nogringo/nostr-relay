package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

// The challenge must arrive on its own, before the client sends anything, so a
// client that knows it will need auth can get it out of the way immediately.
func TestAuthChallengeSentOnConnect(t *testing.T) {
	relay, _ := newTestRelay(t)
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	client := dialRelay(t, relayURL)
	got := client.readUntil("AUTH")
	if challengeIn(got) == "" {
		t.Fatalf("no challenge on connect, got %s", labels(got))
	}
}

// Since the challenge is already sent on connect, a rejected gift-wrap REQ must
// not pile up extra copies of it: khatru re-sends one by itself for any
// "auth-required:" rejection, and that is the only one the client should get.
func TestRejectedRequestSendsNoExtraChallenge(t *testing.T) {
	relay, _ := newTestRelay(t)
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	client := dialRelay(t, relayURL)
	client.readUntil("AUTH")

	recipient := nostr.GetPublicKey(nostr.Generate())
	client.send(&nostr.ReqEnvelope{
		SubscriptionID: "probe",
		Filters: []nostr.Filter{{
			Kinds: []nostr.Kind{nostr.KindGiftWrap},
			Tags:  nostr.TagMap{"p": {recipient.Hex()}},
		}},
	})

	got := client.readUntil("CLOSED")
	if n := countLabel(got, "AUTH"); n != 1 {
		t.Fatalf("rejected REQ sent %d challenges, want 1: %s", n, labels(got))
	}
}

// The upfront challenge is a working one: authenticating with it must grant
// access without the client ever being turned away first.
func TestUpfrontChallengeAuthenticates(t *testing.T) {
	relay, store := newTestRelay(t)
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	gw := sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}})
	if err := store.SaveEvent(gw); err != nil {
		t.Fatal(err)
	}

	client := dialRelay(t, relayURL)
	challenge := challengeIn(client.readUntil("AUTH"))
	if challenge == "" {
		t.Fatal("no challenge on connect")
	}
	client.authenticate(sk, challenge)

	closed, _, ids := client.fetchGiftWraps("inbox", pk)
	if closed != nil {
		t.Fatalf("first query should succeed, got CLOSED %q", closed.Reason)
	}
	if !hasID(ids, gw.ID) {
		t.Fatalf("gift wrap not delivered, got %v", ids)
	}
}
