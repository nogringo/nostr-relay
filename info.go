package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip19"
)

// applyRelayInfo fills the NIP-11 relay information document from RELAY_* env
// vars. Empty values are omitted from the document (omitempty), so unset vars
// simply leave the corresponding field out.
func applyRelayInfo(relay *khatru.Relay) {
	relay.Info.Name = os.Getenv("RELAY_NAME")
	relay.Info.Description = os.Getenv("RELAY_DESCRIPTION")
	relay.Info.Contact = os.Getenv("RELAY_CONTACT")
	relay.Info.Icon = os.Getenv("RELAY_ICON")
	relay.Info.Banner = os.Getenv("RELAY_BANNER")

	if raw := os.Getenv("RELAY_PUBKEY"); raw != "" {
		if pk, err := parsePubKey(raw); err == nil {
			relay.Info.PubKey = &pk
		} else {
			log.Printf("ignoring invalid RELAY_PUBKEY: %v", err)
		}
	}
}

// parsePubKey accepts a public key as hex or as an npub.
func parsePubKey(s string) (nostr.PubKey, error) {
	if strings.HasPrefix(s, "npub1") {
		_, value, err := nip19.Decode(s)
		if err != nil {
			return nostr.PubKey{}, err
		}
		pk, ok := value.(nostr.PubKey)
		if !ok {
			return nostr.PubKey{}, fmt.Errorf("%q is not an npub", s)
		}
		return pk, nil
	}
	return nostr.PubKeyFromHex(s)
}
