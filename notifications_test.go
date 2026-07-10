package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

func TestBuildInboundNotificationPayload(t *testing.T) {
	recipient := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()
	authed := nostr.GetPublicKey(nostr.Generate())
	relays := []string{"wss://relay.example.net"}

	event := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}, {"x", "1"}})
	event.Content = "encrypted payload"

	payload, ok := buildInboundNotificationPayload(khatru.ForceSetAuthed(context.Background(), authed), event, relays)
	if !ok {
		t.Fatal("expected a gift wrap notification payload")
	}

	if payload.RecipientPubkey != recipient.Hex() {
		t.Fatalf("recipientPubkey = %q, want %q", payload.RecipientPubkey, recipient.Hex())
	}
	if len(payload.Relays) != 1 || payload.Relays[0] != relays[0] {
		t.Fatalf("relays = %#v, want %#v", payload.Relays, relays)
	}
	if len(payload.AuthenticatedPubkeys) != 1 || payload.AuthenticatedPubkeys[0] != authed.Hex() {
		t.Fatalf("authenticatedPubkeys = %#v, want [%s]", payload.AuthenticatedPubkeys, authed.Hex())
	}
	if payload.Event.ID != event.ID || payload.Event.PubKey != event.PubKey || payload.Event.Kind != event.Kind {
		t.Fatal("payload event did not preserve the public event fields")
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Event map[string]json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.Event["content"]; ok {
		t.Fatal("gift wrap notification event must omit content")
	}
	if _, ok := decoded.Event["sig"]; ok {
		t.Fatal("gift wrap notification event must omit sig")
	}
}

func TestBuildInboundNotificationPayloadSkipsIrrelevantEvents(t *testing.T) {
	senderSK := nostr.Generate()
	relays := []string{"wss://relay.example.net"}

	cases := []struct {
		name  string
		event nostr.Event
	}{
		{"non-gift-wrap", sign(t, senderSK, 1, nil)},
		{"malformed gift wrap", sign(t, senderSK, nostr.KindGiftWrap, nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := buildInboundNotificationPayload(context.Background(), tc.event, relays); ok {
				t.Fatal("event should not produce an inbound notification")
			}
		})
	}
}

func TestSendInboundNotification(t *testing.T) {
	requests := make(chan *http.Request, 1)
	bodies := make(chan inboundNotificationPayload, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var payload inboundNotificationPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		requests <- r
		bodies <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	recipient := nostr.GetPublicKey(nostr.Generate())
	senderSK := nostr.Generate()
	event := sign(t, senderSK, nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})

	payload, ok := buildInboundNotificationPayload(context.Background(), event, []string{"wss://relay.example.net"})
	if !ok {
		t.Fatal("expected payload")
	}

	err := sendInboundNotification(inboundNotificationConfig{
		Endpoint: server.URL,
		Token:    "secret-token",
		Client:   server.Client(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}

	req := <-requests
	if req.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", req.Method)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("authorization = %q, want Bearer token", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	got := <-bodies
	if got.RecipientPubkey != recipient.Hex() {
		t.Fatalf("recipientPubkey = %q, want %q", got.RecipientPubkey, recipient.Hex())
	}
}

func TestAttachInboundNotifications(t *testing.T) {
	sent := make(chan inboundNotificationPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var payload inboundNotificationPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sent <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	relay := khatru.NewRelay()
	prevCalled := false
	relay.OnEventSaved = func(context.Context, nostr.Event) {
		prevCalled = true
	}
	attachInboundNotifications(relay, inboundNotificationConfig{
		Endpoint: server.URL,
		Token:    "secret-token",
		Relays:   []string{"wss://relay.example.net"},
		Client:   server.Client(),
	})

	recipient := nostr.GetPublicKey(nostr.Generate())
	event := sign(t, nostr.Generate(), nostr.KindGiftWrap, nostr.Tags{{"p", recipient.Hex()}})
	relay.OnEventSaved(context.Background(), event)

	if !prevCalled {
		t.Fatal("previous OnEventSaved hook was not called")
	}

	select {
	case payload := <-sent:
		if payload.RecipientPubkey != recipient.Hex() {
			t.Fatalf("recipientPubkey = %q, want %q", payload.RecipientPubkey, recipient.Hex())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inbound notification")
	}
}
