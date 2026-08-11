package main

import (
	"context"

	"fiatjaf.com/nostr/khatru"
)

// sendAuthChallengeOnConnect greets every new connection with its NIP-42
// challenge. khatru only sends it when a request is rejected, which costs the
// client a round trip before it can do anything protected.
func sendAuthChallengeOnConnect(relay *khatru.Relay) {
	prev := relay.OnConnect
	relay.OnConnect = func(ctx context.Context) {
		if prev != nil {
			prev(ctx)
		}
		khatru.RequestAuth(ctx)
	}
}
