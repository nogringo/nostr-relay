package main

import (
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

func TestCountRefusedWhenDisabled(t *testing.T) {
	t.Setenv("NIP45_ENABLED", "false")
	client := dialRelay(t, startRelay(t))

	client.send(&nostr.CountEnvelope{SubscriptionID: "c", Filter: nostr.Filter{Kinds: []nostr.Kind{nostr.KindTextNote}}})
	closed := closedIn(client.readUntil("COUNT", "CLOSED"))
	if closed == nil || !strings.HasPrefix(closed.Reason, "unsupported:") {
		t.Errorf("COUNT while disabled should be CLOSED as unsupported, got %+v", closed)
	}
}

func TestCountAnsweredByDefault(t *testing.T) {
	client := dialRelay(t, startRelay(t))

	if got := client.count("c", nostr.Filter{Kinds: []nostr.Kind{nostr.KindTextNote}}); got != 0 {
		t.Errorf("COUNT on an empty relay = %d, want 0", got)
	}
}
