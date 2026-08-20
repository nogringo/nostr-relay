package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

const testRelayURL = "wss://relay.test"

func newVanishTestRelay(t *testing.T, relayURLs ...string) (*khatru.Relay, *slicestore.SliceStore, *vanishRequests) {
	t.Helper()
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	return newVanishTestRelayOver(t, store, relayURLs...)
}

// newVanishTestRelayOver wires a relay over an already populated store, which is
// what a restart sees.
func newVanishTestRelayOver(t *testing.T, store *slicestore.SliceStore, relayURLs ...string) (*khatru.Relay, *slicestore.SliceStore, *vanishRequests) {
	t.Helper()
	relay, v := wireRelay(t, store, relayURLs)
	return relay, store, v
}

// wireRelay applies the same hooks as main(), in the same order.
func wireRelay(t *testing.T, store eventstore.Store, relayURLs []string) (*khatru.Relay, *vanishRequests) {
	t.Helper()
	relay := khatru.NewRelay()
	relay.UseEventstore(store, 400)
	sendAuthChallengeOnConnect(relay)
	restrictGiftWraps(relay)
	v := attachVanishRequests(relay, store, relayURLs)
	t.Cleanup(v.stop)
	restrictDeletedEvents(relay, store)
	return relay, v
}

func waitPurged(t *testing.T, v *vanishRequests) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := v.waitIdle(ctx); err != nil {
		t.Fatalf("purge did not finish: %v", err)
	}
}

func save(t *testing.T, store *slicestore.SliceStore, evts ...nostr.Event) {
	t.Helper()
	for _, evt := range evts {
		if err := store.SaveEvent(evt); err != nil {
			t.Fatalf("save %s: %v", evt.ID.Hex(), err)
		}
	}
}

func stored(t *testing.T, store *slicestore.SliceStore) []nostr.Event {
	t.Helper()
	return collect(store.QueryEvents(nostr.Filter{}, 1000))
}

func vanishEvent(t *testing.T, sk nostr.SecretKey, at nostr.Timestamp, relays ...string) nostr.Event {
	t.Helper()
	tags := make(nostr.Tags, 0, len(relays))
	for _, url := range relays {
		tags = append(tags, nostr.Tag{"relay", url})
	}
	return signAt(t, sk, kindVanish, tags, at)
}

// The core NIP-62 promise: everything the pubkey authored up to the request's
// created_at is really gone, deletion events included. Newer events and other
// people's events are untouched, and the request itself is kept for bookkeeping.
func TestVanishDeletesAuthorEvents(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	otherSK := nostr.Generate()
	now := nostr.Now()

	note := signAt(t, sk, 1, nil, now-100)
	deletion := signAt(t, sk, nostr.KindDeletion, nostr.Tags{{"e", note.ID.Hex()}}, now-50)
	profile := signAt(t, sk, 0, nil, now-10)
	later := signAt(t, sk, 1, nil, now+100)
	foreign := signAt(t, otherSK, 1, nil, now-100)
	vanish := vanishEvent(t, sk, now, testRelayURL)

	save(t, store, note, deletion, profile, later, foreign, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	got := stored(t, store)
	for _, gone := range []nostr.Event{note, deletion, profile} {
		if has(got, gone.ID) {
			t.Errorf("kind %d event from the vanished pubkey should be deleted", gone.Kind)
		}
	}
	if !has(got, later.ID) {
		t.Error("an event created after the request must survive")
	}
	if !has(got, foreign.ID) {
		t.Error("another pubkey's event must survive")
	}
	if !has(got, vanish.ID) {
		t.Error("the vanish request itself is kept for bookkeeping")
	}
}

// NIP-62: relays SHOULD delete the gift wraps p-tagging the vanished pubkey,
// which is the whole inbox, whatever the (randomized) created_at of each wrap.
func TestVanishDeletesGiftWrapInbox(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	someoneElse := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()
	now := nostr.Now()

	mine := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}}, now-100)
	mineNewer := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}}, now+100)
	theirs := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", someoneElse.Hex()}}, now-100)
	vanish := vanishEvent(t, sk, now, testRelayURL)

	save(t, store, mine, mineNewer, theirs, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	got := stored(t, store)
	if has(got, mine.ID) || has(got, mineNewer.ID) {
		t.Error("every gift wrap addressed to the vanished pubkey must be deleted")
	}
	if !has(got, theirs.ID) {
		t.Error("someone else's gift wrap must survive")
	}
}

// A vanish request is addressed to specific relays. One that names another relay
// is stored like any event but must not touch anything here.
func TestVanishIgnoresRequestForAnotherRelay(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	now := nostr.Now()
	note := signAt(t, sk, 1, nil, now-100)
	vanish := vanishEvent(t, sk, now, "wss://someone-else.example.com")

	save(t, store, note, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	if !has(stored(t, store), note.ID) {
		t.Error("a request addressed to another relay must not delete anything here")
	}
	if reject, _ := relay.OnEvent(context.Background(), note); reject {
		t.Error("a request addressed to another relay must not block re-publishing either")
	}
}

// ALL_RELAYS is the global form: it applies even to a relay that does not know
// its own public URL.
func TestVanishAllRelays(t *testing.T) {
	relay, store, v := newVanishTestRelay(t) // no RELAY_URLS configured

	sk := nostr.Generate()
	now := nostr.Now()
	note := signAt(t, sk, 1, nil, now-100)
	vanish := vanishEvent(t, sk, now, "ALL_RELAYS")

	save(t, store, note, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	if has(stored(t, store), note.ID) {
		t.Error("ALL_RELAYS must be honored by every relay")
	}
}

// The relay tag is matched on the URL itself, not on its spelling.
func TestVanishRelayURLMatching(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		tagged     string
		want       bool
	}{
		{"identical", "wss://relay.test", "wss://relay.test", true},
		{"trailing slash", "wss://relay.test", "wss://relay.test/", true},
		{"upper case", "wss://relay.test", "WSS://Relay.Test", true},
		{"ws instead of wss", "wss://relay.test", "ws://relay.test", true},
		{"https scheme", "wss://relay.test", "https://relay.test", true},
		{"another host", "wss://relay.test", "wss://relay.example.com", false},
		{"another path", "wss://relay.test", "wss://relay.test/inbox", false},
	}

	sk := nostr.Generate()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay, store, v := newVanishTestRelay(t, tc.configured)
			now := nostr.Now()
			note := signAt(t, sk, 1, nil, now-100)
			vanish := vanishEvent(t, sk, now, tc.tagged)

			save(t, store, note, vanish)
			relay.OnEventSaved(context.Background(), vanish)
			waitPurged(t, v)

			if deleted := !has(stored(t, store), note.ID); deleted != tc.want {
				t.Errorf("purged = %v, want %v", deleted, tc.want)
			}
		})
	}
}

// NIP-62: "The tag list MUST include at least one relay value."
func TestVanishWithoutRelayTagIsRejected(t *testing.T) {
	relay, _, _ := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	untargeted := signAt(t, sk, kindVanish, nostr.Tags{{"p", nostr.GetPublicKey(sk).Hex()}}, nostr.Now())
	targeted := vanishEvent(t, sk, nostr.Now(), testRelayURL)

	reject, msg := relay.OnEvent(context.Background(), untargeted)
	if !reject {
		t.Error("a vanish request without a relay tag must be rejected")
	}
	if !strings.HasPrefix(msg, "invalid:") {
		t.Errorf("reason = %q, want an invalid: prefix", msg)
	}
	if reject, _ := relay.OnEvent(context.Background(), targeted); reject {
		t.Error("a properly tagged vanish request must be accepted")
	}
}

// NIP-62: "Relays MUST ensure the deleted events cannot be re-broadcasted into
// the relay." Only what the request covers is blocked: the pubkey stays free to
// publish anew afterwards.
func TestVanishBlocksRepublishing(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	otherSK := nostr.Generate()
	now := nostr.Now()
	vanish := vanishEvent(t, sk, now, testRelayURL)

	save(t, store, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	cases := []struct {
		name       string
		event      nostr.Event
		wantReject bool
	}{
		{"an event from before the request", signAt(t, sk, 1, nil, now-100), true},
		{"an event at the exact request timestamp", signAt(t, sk, 1, nil, now), true},
		{"an event created after the request", signAt(t, sk, 1, nil, now+100), false},
		{"another pubkey's old event", signAt(t, otherSK, 1, nil, now-100), false},
		{"the vanish request itself", vanish, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := relay.OnEvent(context.Background(), tc.event)
			if reject != tc.wantReject {
				t.Errorf("OnEvent reject = %v, want %v (%q)", reject, tc.wantReject, msg)
			}
			if reject && !strings.HasPrefix(msg, "blocked:") {
				t.Errorf("reason = %q, want a blocked: prefix", msg)
			}
		})
	}
}

// The inbox must not be refillable with the wraps that were just deleted either.
// A wrap created after the request is a new message and goes through.
func TestVanishBlocksGiftWrapsToTheVanishedPubkey(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	senderSK := nostr.Generate()
	now := nostr.Now()
	vanish := vanishEvent(t, sk, now, testRelayURL)

	save(t, store, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	// gift wraps may only be published by an authenticated client (NIP-59)
	ctx := khatru.ForceSetAuthed(context.Background(), nostr.GetPublicKey(nostr.Generate()))

	old := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}}, now-100)
	if reject, msg := relay.OnEvent(ctx, old); !reject {
		t.Error("a gift wrap from before the request must not be re-broadcastable")
	} else if !strings.HasPrefix(msg, "blocked:") {
		t.Errorf("reason = %q, want a blocked: prefix", msg)
	}

	fresh := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}}, now+100)
	if reject, msg := relay.OnEvent(ctx, fresh); reject {
		t.Errorf("a gift wrap created after the request is a new message: %q", msg)
	}
}

// NIP-62: "Publishing a deletion request event (Kind 5) against a request to
// vanish has no effect."
func TestVanishCannotBeDeleted(t *testing.T) {
	relay, _, _ := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	senderSK := nostr.Generate()
	vanish := vanishEvent(t, sk, nostr.Now(), testRelayURL)
	undo := sign(t, sk, nostr.KindDeletion, nostr.Tags{{"e", vanish.ID.Hex()}})

	if relay.AllowDeleting(context.Background(), vanish, undo) {
		t.Error("a kind 5 against a vanish request must have no effect, even from its author")
	}

	// the NIP-09 / NIP-59 rules for every other kind are untouched
	note := sign(t, senderSK, 1, nil)
	if !relay.AllowDeleting(context.Background(), note, sign(t, senderSK, nostr.KindDeletion, nil)) {
		t.Error("an author must still be able to delete their own note")
	}
	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", nostr.GetPublicKey(sk).Hex()}})
	if !relay.AllowDeleting(context.Background(), giftWrap, undo) {
		t.Error("a recipient must still be able to delete their gift wrap")
	}
}

// A crash mid-purge leaves the request stored next to the events it did not get
// to delete. On restart the purge must resume on its own, and the re-publishing
// guard must be armed again.
func TestVanishResumesAfterRestart(t *testing.T) {
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	senderSK := nostr.Generate()
	now := nostr.Now()

	leftover := signAt(t, sk, 1, nil, now-100)
	leftoverWrap := signAt(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}}, now-100)
	vanish := vanishEvent(t, sk, now, testRelayURL)
	save(t, store, leftover, leftoverWrap, vanish)

	relay, _, v := newVanishTestRelayOver(t, store, testRelayURL)
	waitPurged(t, v)

	got := stored(t, store)
	if has(got, leftover.ID) || has(got, leftoverWrap.ID) {
		t.Error("an interrupted purge must resume at startup")
	}
	if !has(got, vanish.ID) {
		t.Error("the vanish request itself is kept for bookkeeping")
	}
	if reject, _ := relay.OnEvent(context.Background(), leftover); !reject {
		t.Error("the re-publishing guard must be restored from the stored request")
	}
}

// The client's OK must not wait for the purge, so the guard has to be armed by
// the time OnEventSaved returns, purge finished or not.
func TestVanishBlocksBeforeThePurgeCompletes(t *testing.T) {
	relay, store, _ := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	now := nostr.Now()
	note := signAt(t, sk, 1, nil, now-100)
	vanish := vanishEvent(t, sk, now, testRelayURL)

	save(t, store, note, vanish)
	relay.OnEventSaved(context.Background(), vanish)

	if reject, _ := relay.OnEvent(context.Background(), note); !reject {
		t.Error("re-publishing must be blocked as soon as the request is accepted")
	}
}

// End to end over a websocket: publish, vanish, and the events are no longer
// served, gift wrap inbox included.
func TestVanishOverWebsocket(t *testing.T) {
	relay, store, v := newVanishTestRelay(t) // ALL_RELAYS, the server URL is dynamic
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	senderSK := nostr.Generate()

	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", pk.Hex()}})
	save(t, store, giftWrap)

	client := dialRelay(t, relayURL)
	challenge := challengeIn(client.readUntil("AUTH"))
	client.authenticate(sk, challenge)

	note := sign(t, sk, 1, nil)
	if ok := client.publish(note); !ok.OK {
		t.Fatalf("publishing a note failed: %s", ok.Reason)
	}
	if _, _, ids := client.fetchGiftWraps("inbox", pk); !hasID(ids, giftWrap.ID) {
		t.Fatal("the gift wrap should be readable before the vanish request")
	}

	if ok := client.publish(vanishEvent(t, sk, nostr.Now(), "ALL_RELAYS")); !ok.OK {
		t.Fatalf("publishing the vanish request failed: %s", ok.Reason)
	}
	waitPurged(t, v)

	if _, _, ids := client.fetchGiftWraps("inbox-after", pk); len(ids) != 0 {
		t.Errorf("the gift wrap inbox should be empty, got %v", ids)
	}
	client.send(&nostr.ReqEnvelope{
		SubscriptionID: "notes",
		Filters:        []nostr.Filter{{Kinds: []nostr.Kind{1}, Authors: []nostr.PubKey{pk}}},
	})
	if ids := eventIDsIn(client.readUntil("EOSE", "CLOSED")); len(ids) != 0 {
		t.Errorf("the notes should be gone, got %v", ids)
	}

	if ok := client.publish(note); ok.OK {
		t.Error("re-publishing a deleted note must be refused")
	}
}
