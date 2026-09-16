package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

func startRelay(t *testing.T) (relayURL string) {
	t.Helper()
	relay, _ := newTestRelay(t)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	return "ws://" + strings.TrimPrefix(server.URL, "http://")
}

// dialAuthed opens a connection authenticated as sk.
func dialAuthed(t *testing.T, relayURL string, sk nostr.SecretKey) *testClient {
	t.Helper()
	client := dialRelay(t, relayURL)
	client.authenticate(sk, challengeIn(client.readUntil("AUTH")))
	return client
}

func (c *testClient) fetch(subID string, filter nostr.Filter) (*nostr.ClosedEnvelope, []nostr.ID) {
	c.t.Helper()
	c.send(&nostr.ReqEnvelope{SubscriptionID: subID, Filters: []nostr.Filter{filter}})
	got := c.readUntil("EOSE", "CLOSED")
	return closedIn(got), eventIDsIn(got)
}

func (c *testClient) count(subID string, filter nostr.Filter) uint32 {
	c.t.Helper()
	c.send(&nostr.CountEnvelope{SubscriptionID: subID, Filter: filter})
	got := c.readUntil("COUNT", "NOTICE", "CLOSED")
	resp, ok := got[len(got)-1].(*nostr.CountEnvelope)
	if !ok || resp.Count == nil {
		c.t.Fatalf("COUNT %s: got %s", subID, labels(got))
	}
	return *resp.Count
}

func giftWrapDeletion(t *testing.T, recipientSK nostr.SecretKey, wrap nostr.Event) nostr.Event {
	t.Helper()
	return sign(t, recipientSK, nostr.KindDeletion, nostr.Tags{{"e", wrap.ID.Hex()}, {"k", "1059"}})
}

// giftWrapScene has a sender deposit two gift wraps and the recipient delete one.
type giftWrapScene struct {
	recipientSK     nostr.SecretKey
	recipient       nostr.PubKey
	senderSK        nostr.SecretKey
	sender          *testClient
	recipientClient *testClient
	deleted, kept   nostr.Event
	deletion        nostr.Event
}

func newGiftWrapScene(t *testing.T, relayURL string) giftWrapScene {
	t.Helper()
	s := giftWrapScene{recipientSK: nostr.Generate(), senderSK: nostr.Generate()}
	s.recipient = nostr.GetPublicKey(s.recipientSK)
	wrapSK := nostr.Generate()

	s.sender = dialAuthed(t, relayURL, s.senderSK)
	s.recipientClient = dialAuthed(t, relayURL, s.recipientSK)

	s.deleted = sign(t, wrapSK, nostr.KindGiftWrap, nostr.Tags{{"p", s.recipient.Hex()}})
	s.kept = sign(t, wrapSK, nostr.KindGiftWrap, nostr.Tags{{"p", s.recipient.Hex()}, {"t", "kept"}})
	for _, wrap := range []nostr.Event{s.deleted, s.kept} {
		if ok := s.sender.publish(wrap); !ok.OK {
			t.Fatalf("publishing a gift wrap failed: %s", ok.Reason)
		}
	}

	s.deletion = giftWrapDeletion(t, s.recipientSK, s.deleted)
	if ok := s.recipientClient.publish(s.deletion); !ok.OK {
		t.Fatalf("the recipient's deletion failed: %s", ok.Reason)
	}
	return s
}

// NIP-59: "relays SHOULD only serve kind 5 events with a k tag of 1059 to their
// author". The sender knows the gift wrap id and must not learn it was deleted.
func TestGiftWrapDeletionServedOnlyToItsAuthor(t *testing.T) {
	relayURL := startRelay(t)
	s := newGiftWrapScene(t, relayURL)

	if _, ids := s.recipientClient.fetch("own", nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}}); hasID(ids, s.deleted.ID) {
		t.Fatal("the recipient's deletion should have removed the gift wrap")
	}

	filters := map[string]nostr.Filter{
		"by-id":     {Kinds: []nostr.Kind{nostr.KindDeletion}, Tags: nostr.TagMap{"e": {s.deleted.ID.Hex()}}},
		"by-author": {Authors: []nostr.PubKey{s.recipient}},
		"broad":     {},
	}
	anonymous := dialRelay(t, relayURL)
	for name, filter := range filters {
		for who, client := range map[string]*testClient{"sender": s.sender, "anonymous": anonymous} {
			if closed, ids := client.fetch(who+"-"+name, filter); closed == nil && hasID(ids, s.deletion.ID) {
				t.Errorf("%s got the recipient's gift wrap deletion with filter %s", who, name)
			}
		}
	}

	closed, ids := s.recipientClient.fetch("mine", nostr.Filter{Kinds: []nostr.Kind{nostr.KindDeletion}, Tags: nostr.TagMap{"k": {"1059"}}})
	if closed != nil {
		t.Fatalf("the author must read their own gift wrap deletions, got CLOSED %q", closed.Reason)
	}
	if !hasID(ids, s.deletion.ID) {
		t.Errorf("the author did not get their gift wrap deletion, got %v", ids)
	}

	closed, _ = anonymous.fetch("anon-k", nostr.Filter{Kinds: []nostr.Kind{nostr.KindDeletion}, Tags: nostr.TagMap{"k": {"1059"}}})
	if closed == nil || !strings.HasPrefix(closed.Reason, "auth-required:") {
		t.Errorf("asking for gift wrap deletions unauthenticated should ask for auth, got %+v", closed)
	}
	closed, _ = s.sender.fetch("sender-k", nostr.Filter{
		Kinds:   []nostr.Kind{nostr.KindDeletion},
		Authors: []nostr.PubKey{s.recipient},
		Tags:    nostr.TagMap{"k": {"1059"}},
	})
	if closed == nil || !strings.HasPrefix(closed.Reason, "auth-required:") {
		t.Errorf("asking for someone else's gift wrap deletions should ask for auth, got %+v", closed)
	}
}

// Live subscriptions bypass QueryStored, so the broadcast needs the same rule.
func TestGiftWrapDeletionNotBroadcastToOthers(t *testing.T) {
	relayURL := startRelay(t)

	recipientSK := nostr.Generate()
	recipient := nostr.GetPublicKey(recipientSK)
	recipientClient := dialAuthed(t, relayURL, recipientSK)
	watcher := dialAuthed(t, relayURL, nostr.Generate())

	watcher.send(&nostr.ReqEnvelope{SubscriptionID: "live", Filters: []nostr.Filter{{Kinds: []nostr.Kind{nostr.KindDeletion}}}})
	watcher.readUntil("EOSE")
	recipientClient.send(&nostr.ReqEnvelope{SubscriptionID: "live", Filters: []nostr.Filter{{Kinds: []nostr.Kind{nostr.KindDeletion}}}})
	recipientClient.readUntil("EOSE")

	wrap := sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	hidden := giftWrapDeletion(t, recipientSK, wrap)
	// the broadcast reaches the publisher before its own OK
	recipientClient.send(&nostr.EventEnvelope{Event: hidden})
	if ids := eventIDsIn(recipientClient.readUntil("OK")); !hasID(ids, hidden.ID) {
		t.Errorf("the author's own subscription should get the deletion, got %v", ids)
	}

	// broadcasting is synchronous, so the public deletion arriving first proves
	// the hidden one was never sent
	public := sign(t, recipientSK, nostr.KindDeletion, nostr.Tags{{"e", nostr.Generate().Hex()}})
	if ok := recipientClient.publish(public); !ok.OK {
		t.Fatalf("publishing the public deletion failed: %s", ok.Reason)
	}
	ids := eventIDsIn(watcher.readUntil("EVENT"))
	if hasID(ids, hidden.ID) {
		t.Error("a gift wrap deletion was broadcast to someone other than its author")
	}
	if !hasID(ids, public.ID) {
		t.Errorf("a deletion without k=1059 must stay public, got %v", ids)
	}
}

// NIP-59: "relays SHOULD answer a republished kind 1059 with the same OK message
// whether it was deleted or is still stored."
func TestRepublishedGiftWrapAnswersTheSameWhetherDeletedOrStored(t *testing.T) {
	relayURL := startRelay(t)
	s := newGiftWrapScene(t, relayURL)

	deleted := s.sender.publish(s.deleted)
	kept := s.sender.publish(s.kept)
	if deleted.OK != kept.OK || deleted.Reason != kept.Reason {
		t.Errorf("deleted answered (%v, %q), stored answered (%v, %q)", deleted.OK, deleted.Reason, kept.OK, kept.Reason)
	}

	_, ids := s.recipientClient.fetch("inbox", nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}})
	if hasID(ids, s.deleted.ID) {
		t.Error("the deleted gift wrap must not be stored again")
	}
	if !hasID(ids, s.kept.ID) {
		t.Errorf("the kept gift wrap should still be there, got %v", ids)
	}
}

// Probing with a deletion request must be as mute: khatru answers "you are not
// the author" when it finds the target and a bare OK when it finds nothing, so
// the delete pipeline may not see a gift wrap the connection cannot read either.
func TestGiftWrapDeletionProbeAnswersTheSame(t *testing.T) {
	relayURL := startRelay(t)
	s := newGiftWrapScene(t, relayURL)

	unknown := sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", s.recipient.Hex()}})
	probes := map[string]nostr.Event{
		"never stored":    giftWrapDeletion(t, s.senderSK, unknown),
		"still stored":    giftWrapDeletion(t, s.senderSK, s.kept),
		"already deleted": giftWrapDeletion(t, s.senderSK, s.deleted),
	}

	var first *nostr.OKEnvelope
	var firstName string
	for name, probe := range probes {
		ok := s.sender.publish(probe)
		if first == nil {
			first, firstName = ok, name
			continue
		}
		if ok.OK != first.OK || ok.Reason != first.Reason {
			t.Errorf("probing a %s gift wrap answered (%v, %q), %s answered (%v, %q)",
				name, ok.OK, ok.Reason, firstName, first.OK, first.Reason)
		}
	}

	if _, ids := s.recipientClient.fetch("inbox", nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}}); !hasID(ids, s.kept.ID) {
		t.Error("a deletion signed by someone other than the recipient must not delete the gift wrap")
	}
}

// NIP-09 proves who deletes by the request's signature, so the recipient's
// request stands on its own, whoever relays it and over any connection.
func TestGiftWrapDeletionNeedsNoAuth(t *testing.T) {
	relayURL := startRelay(t)
	s := newGiftWrapScene(t, relayURL)

	anonymous := dialRelay(t, relayURL)
	anonymous.readUntil("AUTH")
	if ok := anonymous.publish(giftWrapDeletion(t, s.recipientSK, s.kept)); !ok.OK {
		t.Errorf("the recipient's deletion relayed unauthenticated = %q", ok.Reason)
	}

	if _, ids := s.recipientClient.fetch("inbox", nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}}); hasID(ids, s.kept.ID) {
		t.Error("the gift wrap should be gone, the request carried the recipient's signature")
	}

	// the stored request is the tombstone, whichever path deleted the wrap
	if ok := s.sender.publish(s.kept); !ok.OK {
		t.Errorf("re-publishing it should look like a duplicate, got %q", ok.Reason)
	}
	if _, ids := s.recipientClient.fetch("inbox-again", nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}}); hasID(ids, s.kept.ID) {
		t.Error("a deleted gift wrap must not be stored again")
	}
}

// COUNT reads the store directly, so it could otherwise tell anyone whether a
// gift wrap is still there, or how many deletions its recipient made.
func TestCountHidesGiftWrapsAndTheirDeletions(t *testing.T) {
	relayURL := startRelay(t)
	s := newGiftWrapScene(t, relayURL)

	note := sign(t, s.recipientSK, 1, nil)
	if ok := s.recipientClient.publish(note); !ok.OK {
		t.Fatalf("publishing a note failed: %s", ok.Reason)
	}

	senderCounts := map[string]struct {
		filter nostr.Filter
		want   uint32
	}{
		"stored wrap by id":  {nostr.Filter{IDs: []nostr.ID{s.kept.ID}}, 0},
		"deleted wrap by id": {nostr.Filter{IDs: []nostr.ID{s.deleted.ID}}, 0},
		"every gift wrap":    {nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}}, 0},
		"deletion by id":     {nostr.Filter{IDs: []nostr.ID{s.deletion.ID}}, 0},
		"recipient's events": {nostr.Filter{Authors: []nostr.PubKey{s.recipient}}, 1},
	}
	for name, tc := range senderCounts {
		if got := s.sender.count(name, tc.filter); got != tc.want {
			t.Errorf("sender COUNT %s = %d, want %d", name, got, tc.want)
		}
	}

	recipientCounts := map[string]struct {
		filter nostr.Filter
		want   uint32
	}{
		"own gift wraps":     {nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}, Tags: nostr.TagMap{"p": {s.recipient.Hex()}}}, 1},
		"own wrap deletions": {nostr.Filter{Kinds: []nostr.Kind{nostr.KindDeletion}, Tags: nostr.TagMap{"k": {"1059"}}}, 1},
		"own events":         {nostr.Filter{Authors: []nostr.PubKey{s.recipient}}, 2},
	}
	for name, tc := range recipientCounts {
		if got := s.recipientClient.count(name, tc.filter); got != tc.want {
			t.Errorf("recipient COUNT %s = %d, want %d", name, got, tc.want)
		}
	}
}
