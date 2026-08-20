package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"
)

// fetchRelayInfo asks a relay for its NIP-11 document the way a client does.
func fetchRelayInfo(t *testing.T, relay *khatru.Relay) map[string]any {
	t.Helper()
	server := httptest.NewServer(relay)
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("decode nip-11 document: %v", err)
	}
	return info
}

func newInfoTestRelay(t *testing.T) *khatru.Relay {
	t.Helper()
	store := &slicestore.SliceStore{}
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	relay := khatru.NewRelay()
	relay.UseEventstore(store, maxQueryLimit)
	relay.Negentropy = true
	applyRelayInfo(relay)
	restrictGiftWraps(relay)
	return relay
}

// The document must identify this relay, not the framework it is built on.
func TestRelayInfoIdentifiesThisSoftware(t *testing.T) {
	info := fetchRelayInfo(t, newInfoTestRelay(t))

	if got := info["software"]; got != "https://github.com/nogringo/nostr-relay" {
		t.Errorf("software = %v, want this repository", got)
	}
	got, _ := info["version"].(string)
	if got == "" || got == "n/a" {
		t.Errorf("version = %q, want a real version", got)
	}
}

// version.txt is the single place a release is bumped.
func TestRelayInfoVersionComesFromVersionFile(t *testing.T) {
	raw, err := os.ReadFile("version.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(raw))
	if want == "" {
		t.Fatal("version.txt is empty")
	}

	info := fetchRelayInfo(t, newInfoTestRelay(t))
	if got := info["version"]; got != want {
		t.Errorf("version = %v, want %q from version.txt", got, want)
	}
}

func supportedNIPs(t *testing.T, info map[string]any) []int {
	t.Helper()
	raw, ok := info["supported_nips"].([]any)
	if !ok {
		t.Fatalf("supported_nips missing: %v", info)
	}
	nips := make([]int, 0, len(raw))
	for _, n := range raw {
		f, ok := n.(float64)
		if !ok {
			t.Fatalf("non-numeric nip %v", n)
		}
		nips = append(nips, int(f))
	}
	return nips
}

// Clients pick a relay from this list, so it must match what the relay does.
func TestRelayInfoAdvertisesImplementedNIPs(t *testing.T) {
	nips := supportedNIPs(t, fetchRelayInfo(t, newInfoTestRelay(t)))

	for _, want := range []int{1, 9, 11, 40, 42, 45, 59, 62, 70, 77} {
		if !slices.Contains(nips, want) {
			t.Errorf("nip %d not advertised, got %v", want, nips)
		}
	}
	// No management API is wired, so every NIP-86 call would fail.
	if slices.Contains(nips, 86) {
		t.Errorf("nip 86 advertised but not implemented, got %v", nips)
	}
}

// The advertised limits are the ones the relay actually enforces.
func TestRelayInfoStatesRealLimits(t *testing.T) {
	info := fetchRelayInfo(t, newInfoTestRelay(t))

	limitation, ok := info["limitation"].(map[string]any)
	if !ok {
		t.Fatalf("limitation missing: %v", info)
	}
	if got := limitation["max_limit"]; got != float64(maxQueryLimit) {
		t.Errorf("max_limit = %v, want %d", got, maxQueryLimit)
	}
	// A query without a limit is capped at the same value.
	if got := limitation["default_limit"]; got != float64(maxQueryLimit) {
		t.Errorf("default_limit = %v, want %d", got, maxQueryLimit)
	}
	if got := limitation["max_message_length"]; got != float64(khatru.NewRelay().MaxMessageSize) {
		t.Errorf("max_message_length = %v, want the enforced read limit", got)
	}
}
