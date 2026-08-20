package main

import (
	"fmt"
	"net/http"
	"os"

	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
)

func main() {
	relay := khatru.NewRelay()

	db := &lmdb.LMDBBackend{Path: "db"}
	if err := db.Init(); err != nil {
		panic(err)
	}
	defer db.Close()

	relay.UseEventstore(db, 400)
	relay.Negentropy = true
	applyRelayInfo(relay)
	sendAuthChallengeOnConnect(relay)
	restrictGiftWraps(relay)
	stopVanishRequests := configureVanishRequests(relay, db)
	defer stopVanishRequests()
	restrictDeletedEvents(relay, db)
	configureInboundNotificationsFromEnv(relay)
	configureAccountDeletionFromEnv(relay)

	// NIP-42 host validation trusts the Host the reverse proxy forwards, so the
	// relay must stay reachable only through that proxy: bind to loopback by
	// default, or to an isolated network (e.g. a container's) via LISTEN_ADDR.
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:3334"
	}
	fmt.Println("running on", addr)
	http.ListenAndServe(addr, relay)
}
