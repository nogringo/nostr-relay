package main

import (
	"os"

	"fiatjaf.com/nostr/khatru"
)

// Off, khatru drops 77 from the NIP-11 document and answers NEG-OPEN with a NOTICE.
func configureNegentropyFromEnv(relay *khatru.Relay) {
	relay.Negentropy = os.Getenv("NIP77_ENABLED") != "false"
}
