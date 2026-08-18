package main

import (
	"context"
	"iter"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

// newTestRelay wires the same hooks as main() but over an in-memory store.
func newTestRelay(t *testing.T) (*khatru.Relay, *slicestore.SliceStore) {
	t.Helper()
	relay, store, _ := newVanishTestRelay(t, testRelayURL)
	return relay, store
}

func sign(t *testing.T, sk nostr.SecretKey, kind nostr.Kind, tags nostr.Tags) nostr.Event {
	t.Helper()
	return signAt(t, sk, kind, tags, nostr.Now())
}

func signAt(t *testing.T, sk nostr.SecretKey, kind nostr.Kind, tags nostr.Tags, createdAt nostr.Timestamp) nostr.Event {
	t.Helper()
	evt := nostr.Event{
		PubKey:    nostr.GetPublicKey(sk),
		CreatedAt: createdAt,
		Kind:      kind,
		Tags:      tags,
		Content:   "x",
	}
	if err := evt.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return evt
}

func collect(seq iter.Seq[nostr.Event]) []nostr.Event {
	var out []nostr.Event
	for e := range seq {
		out = append(out, e)
	}
	return out
}

func seqOf(evts ...nostr.Event) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		for _, e := range evts {
			if !yield(e) {
				return
			}
		}
	}
}

func has(evts []nostr.Event, id nostr.ID) bool {
	for _, e := range evts {
		if e.ID == id {
			return true
		}
	}
	return false
}

// OnEvent guards writes: NIP-59 gift wraps are signed by random ephemeral keys,
// but the client that deposits one still has to authenticate with NIP-42 first.
func TestGiftWrapOnEventRequiresAuth(t *testing.T) {
	relay, _ := newTestRelay(t)

	authed := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()
	recipient := nostr.GetPublicKey(nostr.Generate())

	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	note := sign(t, senderSK, 1, nil)

	cases := []struct {
		name       string
		ctx        context.Context
		event      nostr.Event
		wantReject bool
	}{
		{
			name:       "unauthenticated gift wrap is rejected",
			ctx:        context.Background(),
			event:      giftWrap,
			wantReject: true,
		},
		{
			name:       "authenticated gift wrap is accepted even when auth key differs from ephemeral signer",
			ctx:        khatru.ForceSetAuthed(context.Background(), authed),
			event:      giftWrap,
			wantReject: false,
		},
		{
			name:       "non-gift-wrap event is untouched",
			ctx:        context.Background(),
			event:      note,
			wantReject: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reject, msg := relay.OnEvent(tc.ctx, tc.event)
			if reject != tc.wantReject {
				t.Errorf("OnEvent reject = %v, want %v", reject, tc.wantReject)
			}
			if tc.wantReject && msg != "auth-required: authenticate to publish gift wraps" {
				t.Errorf("OnEvent msg = %q", msg)
			}
		})
	}
}

// QueryStored is the safety net: even a broad filter (no kinds) that the store
// would happily return must never expose a kind 1059 to anyone but its recipient.
func TestGiftWrapQueryStored(t *testing.T) {
	relay, store := newTestRelay(t)

	recipientSK := nostr.Generate()
	recipient := nostr.GetPublicKey(recipientSK)
	other := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()

	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	note := sign(t, senderSK, 1, nil)
	if err := store.SaveEvent(giftWrap); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEvent(note); err != nil {
		t.Fatal(err)
	}

	broad := nostr.Filter{} // matches every kind, including 1059

	cases := []struct {
		name         string
		ctx          context.Context
		wantGiftWrap bool
	}{
		{"unauthenticated", context.Background(), false},
		{"authenticated as someone else", khatru.ForceSetAuthed(context.Background(), other), false},
		{"authenticated as the recipient", khatru.ForceSetAuthed(context.Background(), recipient), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := collect(relay.QueryStored(tc.ctx, broad))

			if has(got, giftWrap.ID) != tc.wantGiftWrap {
				t.Errorf("gift wrap visible=%v, want %v", has(got, giftWrap.ID), tc.wantGiftWrap)
			}
			if !has(got, note.ID) {
				t.Errorf("public note should always be returned")
			}
		})
	}
}

// PreventBroadcast guards the live path: a freshly published gift wrap may only
// be pushed to a connection authenticated as its recipient.
func TestGiftWrapPreventBroadcast(t *testing.T) {
	relay, _ := newTestRelay(t)

	recipient := nostr.GetPublicKey(nostr.Generate())
	other := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()

	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	note := sign(t, senderSK, 1, nil)
	malformed := sign(t, senderSK, nostr.KindGiftWrap, nil) // gift wrap without a `p` tag

	conn := func(pks ...nostr.PubKey) *khatru.WebSocket {
		return &khatru.WebSocket{AuthedPublicKeys: pks}
	}

	cases := []struct {
		name        string
		ws          *khatru.WebSocket
		event       nostr.Event
		wantPrevent bool
	}{
		{"recipient gets their gift wrap", conn(recipient), giftWrap, false},
		{"recipient among several authed identities gets it", conn(other, recipient), giftWrap, false},
		{"third party is blocked", conn(other), giftWrap, true},
		{"unauthenticated is blocked", conn(), giftWrap, true},
		{"malformed gift wrap is blocked", conn(recipient), malformed, true},
		{"non-gift-wrap is broadcast normally", conn(), note, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relay.PreventBroadcast(tc.ws, nostr.Filter{}, tc.event); got != tc.wantPrevent {
				t.Errorf("PreventBroadcast = %v, want %v", got, tc.wantPrevent)
			}
		})
	}
}

// A connection authenticated as several pubkeys gets the gift wraps of all of
// them at once (e.g. a broad `{}` fetch), and no one else's; public events pass
// through untouched.
func TestScopeGiftWrapsMultipleRecipients(t *testing.T) {
	a := nostr.GetPublicKey(nostr.Generate())
	b := nostr.GetPublicKey(nostr.Generate())
	c := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()

	gwA := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", a.Hex()}})
	gwB := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", b.Hex()}})
	gwC := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", c.Hex()}})
	note := sign(t, senderSK, 1, nil)

	got := collect(scopeGiftWraps([]nostr.PubKey{a, b}, seqOf(gwA, gwB, gwC, note)))

	if !has(got, gwA.ID) || !has(got, gwB.ID) {
		t.Error("should return the gift wraps for every authenticated pubkey (a and b)")
	}
	if has(got, gwC.ID) {
		t.Error("must not return a gift wrap addressed to a non-authenticated pubkey (c)")
	}
	if !has(got, note.ID) {
		t.Error("public events must pass through untouched")
	}
}

// AllowDeleting implements the NIP-59 deletion rule: a gift wrap is signed by a
// throw-away ephemeral key, so its recipient (the `p` tag), not its author, may
// delete it, proven by the deletion event's signature. Every other kind keeps the
// default NIP-09 rule that only the author may delete.
func TestGiftWrapAllowDeleting(t *testing.T) {
	relay, _ := newTestRelay(t)

	recipientSK := nostr.Generate()
	recipient := nostr.GetPublicKey(recipientSK)
	otherSK := nostr.Generate()
	senderSK := nostr.Generate() // stands in for the ephemeral gift-wrap key

	giftWrap := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	malformed := sign(t, senderSK, nostr.KindGiftWrap, nil) // gift wrap without a `p` tag
	note := sign(t, senderSK, 1, nil)

	byRecipient := sign(t, recipientSK, nostr.KindDeletion, nil)
	byOther := sign(t, otherSK, nostr.KindDeletion, nil)
	bySender := sign(t, senderSK, nostr.KindDeletion, nil)

	cases := []struct {
		name      string
		target    nostr.Event
		deletion  nostr.Event
		wantAllow bool
	}{
		{"recipient may delete their gift wrap", giftWrap, byRecipient, true},
		{"third party may not delete a gift wrap", giftWrap, byOther, false},
		{"even the original sender may not delete the gift wrap", giftWrap, bySender, false},
		{"malformed gift wrap (no p tag) is never deletable", malformed, byRecipient, false},
		{"author may delete their own non-gift-wrap event", note, bySender, true},
		{"non-author may not delete a non-gift-wrap event", note, byOther, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relay.AllowDeleting(context.Background(), tc.target, tc.deletion); got != tc.wantAllow {
				t.Errorf("AllowDeleting = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

// isAuthedRecipient must match against the whole set of authenticated pubkeys,
// since a single connection can authenticate as several.
func TestIsAuthedRecipient(t *testing.T) {
	a := nostr.GetPublicKey(nostr.Generate())
	b := nostr.GetPublicKey(nostr.Generate())
	c := nostr.GetPublicKey(nostr.Generate())

	if !isAuthedRecipient([]nostr.PubKey{a, b}, b.Hex()) {
		t.Error("should match a non-last authenticated pubkey")
	}
	if !isAuthedRecipient([]nostr.PubKey{a, b}, a.Hex()) {
		t.Error("should match the first authenticated pubkey")
	}
	if isAuthedRecipient([]nostr.PubKey{a, b}, c.Hex()) {
		t.Error("should not match a pubkey that did not authenticate")
	}
	if isAuthedRecipient(nil, a.Hex()) {
		t.Error("nothing matches when no one is authenticated")
	}
}

// OnRequest / OnCount gate explicit gift-wrap queries: the requester must be
// authenticated and may only ask for their own gift wraps (#p == authed pubkey).
func TestGiftWrapOnRequest(t *testing.T) {
	relay, _ := newTestRelay(t)

	recipientSK := nostr.Generate()
	recipient := nostr.GetPublicKey(recipientSK)
	other := nostr.GetPublicKey(nostr.Generate())

	giftWrapFilter := func(p nostr.PubKey) nostr.Filter {
		return nostr.Filter{
			Kinds: []nostr.Kind{nostr.KindGiftWrap},
			Tags:  nostr.TagMap{"p": {p.Hex()}},
		}
	}

	cases := []struct {
		name       string
		ctx        context.Context
		filter     nostr.Filter
		wantReject bool
	}{
		{
			name:       "recipient asking for own gift wraps",
			ctx:        khatru.ForceSetAuthed(context.Background(), recipient),
			filter:     giftWrapFilter(recipient),
			wantReject: false,
		},
		{
			name:       "authenticated user asking for someone else's gift wraps",
			ctx:        khatru.ForceSetAuthed(context.Background(), other),
			filter:     giftWrapFilter(recipient),
			wantReject: true,
		},
		{
			// no #p tag: allowed once authenticated; QueryStored still scopes
			// the returned events to the authenticated recipient.
			name:       "recipient querying all their gift wraps without a #p tag",
			ctx:        khatru.ForceSetAuthed(context.Background(), recipient),
			filter:     nostr.Filter{Kinds: []nostr.Kind{nostr.KindGiftWrap}},
			wantReject: false,
		},
		{
			name:       "non-gift-wrap query is untouched",
			ctx:        context.Background(),
			filter:     nostr.Filter{Kinds: []nostr.Kind{1}},
			wantReject: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reject, _ := relay.OnRequest(tc.ctx, tc.filter); reject != tc.wantReject {
				t.Errorf("OnRequest reject = %v, want %v", reject, tc.wantReject)
			}
			// OnCount must enforce the exact same gate.
			if reject, _ := relay.OnCount(tc.ctx, tc.filter); reject != tc.wantReject {
				t.Errorf("OnCount reject = %v, want %v", reject, tc.wantReject)
			}
		})
	}
}
