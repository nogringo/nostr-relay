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

func TestBuildAccountDeletionPayload(t *testing.T) {
	sk := nostr.Generate()
	event := sign(t, sk, kindVanish, nostr.Tags{{"relay", "wss://relay.example.net"}})

	payload, ok := buildAccountDeletionPayload(event)
	if !ok {
		t.Fatal("expected an account deletion payload")
	}

	if payload.Event.ID != event.ID || payload.Event.PubKey != event.PubKey || payload.Event.Kind != kindVanish {
		t.Fatal("payload event did not preserve the NIP-62 event")
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

	for _, field := range []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"} {
		if _, ok := decoded.Event[field]; !ok {
			t.Fatalf("account deletion event must include %q", field)
		}
	}
}

func TestBuildAccountDeletionPayloadSkipsIrrelevantEvents(t *testing.T) {
	event := sign(t, nostr.Generate(), nostr.KindTextNote, nil)

	if _, ok := buildAccountDeletionPayload(event); ok {
		t.Fatal("non-NIP-62 event should not produce an account deletion payload")
	}
}

func TestSendAccountDeletion(t *testing.T) {
	requests := make(chan *http.Request, 1)
	bodies := make(chan accountDeletionPayload, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var payload accountDeletionPayload
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

	event := sign(t, nostr.Generate(), kindVanish, nostr.Tags{{"relay", "wss://relay.example.net"}})
	payload, ok := buildAccountDeletionPayload(event)
	if !ok {
		t.Fatal("expected payload")
	}

	if err := sendAccountDeletion(accountDeletionConfig{
		Endpoint: server.URL,
		Client:   server.Client(),
	}, payload); err != nil {
		t.Fatal(err)
	}

	req := <-requests
	if req.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", req.Method)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("authorization = %q, want empty", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	got := <-bodies
	if got.Event.ID != event.ID || got.Event.PubKey != event.PubKey || got.Event.Content != event.Content || got.Event.Sig != event.Sig {
		t.Fatal("request body did not preserve the complete event")
	}
}

func TestSendAccountDeletionRejectsUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	}))
	defer server.Close()

	event := sign(t, nostr.Generate(), kindVanish, nil)
	payload, ok := buildAccountDeletionPayload(event)
	if !ok {
		t.Fatal("expected payload")
	}

	if err := sendAccountDeletion(accountDeletionConfig{
		Endpoint: server.URL,
		Client:   server.Client(),
	}, payload); err == nil {
		t.Fatal("expected unexpected status error")
	}
}

func TestAttachAccountDeletion(t *testing.T) {
	sent := make(chan accountDeletionPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var payload accountDeletionPayload
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
	attachAccountDeletion(relay, accountDeletionConfig{
		Endpoint: server.URL,
		Client:   server.Client(),
	})

	event := sign(t, nostr.Generate(), kindVanish, nostr.Tags{{"relay", "wss://relay.example.net"}})
	relay.OnEventSaved(context.Background(), event)

	if !prevCalled {
		t.Fatal("previous OnEventSaved hook was not called")
	}

	select {
	case payload := <-sent:
		if payload.Event.ID != event.ID {
			t.Fatalf("event id = %s, want %s", payload.Event.ID.Hex(), event.ID.Hex())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for account deletion forwarding")
	}
}
