package main

import (
	"os"

	"fiatjaf.com/nostr/khatru"
)

// Off, khatru drops 45 from the NIP-11 document and answers COUNT with CLOSED.
// Must run after the hooks that wrap Count, or they would bring it back.
func configureCountFromEnv(relay *khatru.Relay) {
	if os.Getenv("NIP45_ENABLED") == "false" {
		relay.Count = nil
		relay.CountHLL = nil
	}
}
