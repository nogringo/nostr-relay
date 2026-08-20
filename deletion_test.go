package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

// deleteFromStore reproduces khatru's delete pipeline: the request is stored and
// kept, the events it covers are gone.
func deleteFromStore(t *testing.T, store *slicestore.SliceStore, request nostr.Event, targets ...nostr.Event) {
	t.Helper()
	save(t, store, request)
	for _, evt := range targets {
		if err := store.DeleteEvent(evt.ID); err != nil {
			t.Fatalf("delete %s: %v", evt.ID.Hex(), err)
		}
	}
}

func deletionByID(t *testing.T, sk nostr.SecretKey, target nostr.Event) nostr.Event {
	t.Helper()
	return sign(t, sk, nostr.KindDeletion, nostr.Tags{{"e", target.ID.Hex()}})
}

// The bug this guards against: an event deleted through NIP-09 used to be
// storable again, because deleting it wiped every trace of it from the store.
func TestDeletedEventCannotBeRepublished(t *testing.T) {
	relay, store := newTestRelay(t)

	sk := nostr.Generate()
	note := sign(t, sk, 1, nil)
	untouched := sign(t, sk, 1, nostr.Tags{{"t", "kept"}})
	save(t, store, untouched)
	deleteFromStore(t, store, deletionByID(t, sk, note), note)

	cases := []struct {
		name       string
		event      nostr.Event
		wantReject bool
	}{
		{"the author cannot bring their deleted event back", note, true},
		{"nobody can bring it back, whoever re-publishes it", note, true},
		{"an event the author never deleted still goes through", untouched, false},
		{"a brand new event goes through", sign(t, sk, 1, nostr.Tags{{"t", "new"}}), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := relay.OnEvent(context.Background(), tc.event)
			if reject != tc.wantReject {
				t.Fatalf("OnEvent rejected = %v (%q), want %v", reject, msg, tc.wantReject)
			}
			if reject && !strings.HasPrefix(msg, "blocked:") {
				t.Errorf("reason %q should use the NIP-01 blocked prefix", msg)
			}
		})
	}
}

// khatru stores a deletion request before it checks who may delete what, so the
// store fills with requests that deleted nothing. Honoring those would let one
// pubkey censor another's events.
func TestThirdPartyDeletionRequestDoesNotBlock(t *testing.T) {
	relay, store := newTestRelay(t)

	sk, mallorySK := nostr.Generate(), nostr.Generate()
	pk := nostr.GetPublicKey(sk)

	note := sign(t, sk, 1, nil)
	article := sign(t, sk, 30023, nostr.Tags{{"d", "mine"}})
	addr := "30023:" + pk.Hex() + ":mine"

	save(t, store,
		sign(t, mallorySK, nostr.KindDeletion, nostr.Tags{{"e", note.ID.Hex()}}),
		sign(t, mallorySK, nostr.KindDeletion, nostr.Tags{{"a", addr}}),
	)

	for _, evt := range []nostr.Event{note, article} {
		if reject, msg := relay.OnEvent(context.Background(), evt); reject {
			t.Errorf("kind %d rejected on a stranger's deletion request: %s", evt.Kind, msg)
		}
	}
}

// A gift wrap is signed by a throw-away key, so its recipient is the one who may
// delete it. The guard has to agree with that rule, not with plain authorship.
func TestDeletedGiftWrapCannotBeRepublished(t *testing.T) {
	relay, store := newTestRelay(t)

	recipientSK, senderSK := nostr.Generate(), nostr.Generate()
	recipient := nostr.GetPublicKey(recipientSK)

	deleted := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	kept := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}, {"t", "kept"}})

	save(t, store, kept, sign(t, senderSK, nostr.KindDeletion, nostr.Tags{{"e", kept.ID.Hex()}}))
	deleteFromStore(t, store, deletionByID(t, recipientSK, deleted), deleted)

	ctx := khatru.ForceSetAuthed(context.Background(), recipient)
	if reject, _ := relay.OnEvent(ctx, deleted); !reject {
		t.Error("a gift wrap deleted by its recipient must not come back")
	}
	// the ephemeral author's own request deletes nothing, so it must not block
	if reject, msg := relay.OnEvent(ctx, kept); reject {
		t.Errorf("a gift wrap the recipient never deleted must go through: %s", msg)
	}

	// a gift wrap without a `p` tag has no one who may delete it, so no request
	// can cover it, not even one tagging its id
	malformed := sign(t, senderSK, nostr.KindGiftWrap, nil)
	save(t, store, deletionByID(t, recipientSK, malformed))
	if reject, msg := relay.OnEvent(ctx, malformed); reject {
		t.Errorf("a gift wrap nobody may delete must never be blocked: %s", msg)
	}
}

// NIP-09: "Publishing a deletion request event against a deletion request has no
// effect." Keeping the requests undeletable is also what keeps the guard honest.
func TestDeletionRequestIsNeverBlocked(t *testing.T) {
	relay, store := newTestRelay(t)

	sk := nostr.Generate()
	note := sign(t, sk, 1, nil)
	request := deletionByID(t, sk, note)
	deleteFromStore(t, store, request, note)

	if relay.AllowDeleting(context.Background(), request, deletionByID(t, sk, request)) {
		t.Error("a deletion request must never be deletable, not even by its author")
	}

	// a stored request tagging it changes nothing: the request was never deleted
	save(t, store, deletionByID(t, sk, request))
	if reject, msg := relay.OnEvent(context.Background(), request); reject {
		t.Errorf("a deletion request must stay publishable: %s", msg)
	}
}

// NIP-09: "relays SHOULD delete all versions of the replaceable event up to the
// created_at timestamp of the deletion request event", so a newer version still
// has to go through.
func TestDeletedAddressableEventComesBackOnlyIfNewer(t *testing.T) {
	relay, store := newTestRelay(t)

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	now := nostr.Now()

	deleted := signAt(t, sk, 30023, nostr.Tags{{"d", "article"}}, now-100)
	save(t, store, signAt(t, sk, nostr.KindDeletion,
		nostr.Tags{{"a", "30023:" + pk.Hex() + ":article"}, {"k", "30023"}}, now))

	cases := []struct {
		name       string
		event      nostr.Event
		wantReject bool
	}{
		{"an older version stays deleted", deleted, true},
		{"a version at the request's own timestamp stays deleted",
			signAt(t, sk, 30023, nostr.Tags{{"d", "article"}}, now), true},
		{"a newer version is a legitimate update",
			signAt(t, sk, 30023, nostr.Tags{{"d", "article"}}, now+1), false},
		{"another identifier is untouched",
			signAt(t, sk, 30023, nostr.Tags{{"d", "other"}}, now-100), false},
		{"another kind at the same identifier is untouched",
			signAt(t, sk, 30024, nostr.Tags{{"d", "article"}}, now-100), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reject, msg := relay.OnEvent(context.Background(), tc.event); reject != tc.wantReject {
				t.Errorf("OnEvent rejected = %v (%q), want %v", reject, msg, tc.wantReject)
			}
		})
	}
}

// A plain replaceable event has no identifier, so its address ends on an empty
// third field.
func TestDeletedReplaceableEventCannotBeRepublished(t *testing.T) {
	relay, store := newTestRelay(t)

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	now := nostr.Now()

	profile := signAt(t, sk, 0, nil, now-100)
	relayList := signAt(t, sk, 10002, nil, now-100)
	save(t, store, signAt(t, sk, nostr.KindDeletion,
		nostr.Tags{{"a", "0:" + pk.Hex() + ":"}}, now))

	if reject, _ := relay.OnEvent(context.Background(), profile); !reject {
		t.Error("a deleted profile must not come back")
	}
	if reject, msg := relay.OnEvent(context.Background(), relayList); reject {
		t.Errorf("another replaceable kind must go through: %s", msg)
	}
}

// The guard reads the deletion requests back from the store, so it needs no
// state of its own and a fresh process picks up where the old one left off.
func TestDeletionGuardSurvivesRestart(t *testing.T) {
	relay, store := newTestRelay(t)

	sk := nostr.Generate()
	note := sign(t, sk, 1, nil)
	deleteFromStore(t, store, deletionByID(t, sk, note), note)
	if reject, _ := relay.OnEvent(context.Background(), note); !reject {
		t.Fatal("the note should already be blocked before the restart")
	}

	restarted, _, _ := newVanishTestRelayOver(t, store, testRelayURL)
	if reject, msg := restarted.OnEvent(context.Background(), note); !reject {
		t.Errorf("a restarted relay must still refuse the deleted note: %q", msg)
	}
}

// A NIP-62 purge takes the vanishing author's deletion requests along with
// everything else, so the tombstones go. The vanish guard covers the same events
// by timestamp, so they stay blocked anyway.
func TestVanishedAuthorDeletionsStayBlocked(t *testing.T) {
	relay, store, v := newVanishTestRelay(t, testRelayURL)

	sk := nostr.Generate()
	now := nostr.Now()
	note := signAt(t, sk, 1, nil, now-100)
	request := signAt(t, sk, nostr.KindDeletion, nostr.Tags{{"e", note.ID.Hex()}}, now-50)
	deleteFromStore(t, store, request, note)

	vanish := vanishEvent(t, sk, now, testRelayURL)
	save(t, store, vanish)
	relay.OnEventSaved(context.Background(), vanish)
	waitPurged(t, v)

	if has(stored(t, store), request.ID) {
		t.Fatal("the purge should have taken the deletion request too")
	}
	if reject, _ := relay.OnEvent(context.Background(), note); !reject {
		t.Error("the deleted note must stay refused after the author vanished")
	}
}

// End to end over a websocket, running khatru's real delete pipeline rather than
// a store simulation.
func TestDeletedEventRefusedOverWebsocket(t *testing.T) {
	relay, _ := newTestRelay(t)
	server := httptest.NewServer(relay)
	defer server.Close()
	relayURL := "ws://" + strings.TrimPrefix(server.URL, "http://")

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	client := dialRelay(t, relayURL)
	client.readUntil("AUTH")

	note := sign(t, sk, 1, nil)
	if ok := client.publish(note); !ok.OK {
		t.Fatalf("publishing the note failed: %s", ok.Reason)
	}

	request := deletionByID(t, sk, note)
	if ok := client.publish(request); !ok.OK {
		t.Fatalf("publishing the deletion request failed: %s", ok.Reason)
	}

	client.send(&nostr.ReqEnvelope{
		SubscriptionID: "notes",
		Filters:        []nostr.Filter{{Kinds: []nostr.Kind{1}, Authors: []nostr.PubKey{pk}}},
	})
	if ids := eventIDsIn(client.readUntil("EOSE", "CLOSED")); len(ids) != 0 {
		t.Fatalf("the note should be gone, got %v", ids)
	}

	// NIP-09: "Relays SHOULD continue to publish/share the deletion request
	// events indefinitely."
	client.send(&nostr.ReqEnvelope{
		SubscriptionID: "requests",
		Filters:        []nostr.Filter{{Kinds: []nostr.Kind{nostr.KindDeletion}, Authors: []nostr.PubKey{pk}}},
	})
	if ids := eventIDsIn(client.readUntil("EOSE", "CLOSED")); !hasID(ids, request.ID) {
		t.Errorf("the deletion request must still be served, got %v", ids)
	}

	ok := client.publish(note)
	if ok.OK {
		t.Fatal("re-publishing a deleted note must be refused")
	}
	if !strings.HasPrefix(ok.Reason, "blocked:") {
		t.Errorf("reason %q should use the NIP-01 blocked prefix", ok.Reason)
	}

	client.send(&nostr.ReqEnvelope{
		SubscriptionID: "notes-again",
		Filters:        []nostr.Filter{{Kinds: []nostr.Kind{1}, Authors: []nostr.PubKey{pk}}},
	})
	if ids := eventIDsIn(client.readUntil("EOSE", "CLOSED")); len(ids) != 0 {
		t.Errorf("the note must not be back in the store, got %v", ids)
	}
}

// lmdb does not index a tag value longer than 100 bytes, and an address is 71
// bytes plus its identifier. slicestore matches every filter exactly, so only a
// real lmdb store can catch the tombstone becoming invisible.
func TestDeletedAddressableEventWithLongIdentifierOverLMDB(t *testing.T) {
	store := &lmdb.LMDBBackend{Path: t.TempDir()}
	if err := store.Init(); err != nil {
		t.Fatalf("lmdb init: %v", err)
	}
	t.Cleanup(store.Close)
	relay, _ := wireRelay(t, store, []string{testRelayURL})

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	now := nostr.Now()

	const longID = "a-very-long-article-identifier-that-goes-past-thirty-bytes"
	deleted := signAt(t, sk, 30023, nostr.Tags{{"d", longID + "-part-1"}}, now-100)
	sibling := signAt(t, sk, 30023, nostr.Tags{{"d", longID + "-part-2"}}, now-100)
	request := signAt(t, sk, nostr.KindDeletion,
		nostr.Tags{{"a", "30023:" + pk.Hex() + ":" + longID + "-part-1"}}, now)
	if err := store.SaveEvent(request); err != nil {
		t.Fatalf("save request: %v", err)
	}

	if reject, _ := relay.OnEvent(context.Background(), deleted); !reject {
		t.Error("a long identifier must not hide the deletion request")
	}
	// the two identifiers share their first 30 bytes, which is all lmdb indexes
	if reject, msg := relay.OnEvent(context.Background(), sibling); reject {
		t.Errorf("a sibling article sharing the identifier prefix must go through: %s", msg)
	}
}
