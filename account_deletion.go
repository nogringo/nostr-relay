package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

const kindVanish nostr.Kind = 62

const accountDeletionTimeout = 5 * time.Second

type accountDeletionConfig struct {
	Endpoint string
	Client   *http.Client
}

type accountDeletionPayload struct {
	Event nostr.Event `json:"event"`
}

func configureAccountDeletionFromEnv(relay *khatru.Relay) {
	cfg := accountDeletionConfig{
		Endpoint: os.Getenv("ACCOUNT_DELETION_URL"),
	}
	if cfg.Endpoint == "" {
		return
	}

	attachAccountDeletion(relay, cfg)
	log.Printf("account deletion forwarding enabled for %s", cfg.Endpoint)
}

func attachAccountDeletion(relay *khatru.Relay, cfg accountDeletionConfig) {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: accountDeletionTimeout}
	}

	prev := relay.OnEventSaved
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		if prev != nil {
			prev(ctx, event)
		}

		payload, ok := buildAccountDeletionPayload(event)
		if !ok {
			return
		}

		go func() {
			if err := sendAccountDeletion(cfg, payload); err != nil {
				log.Printf("account deletion forwarding failed for event %s pubkey %s: %v", event.ID.Hex(), event.PubKey.Hex(), err)
			}
		}()
	}
}

func buildAccountDeletionPayload(event nostr.Event) (accountDeletionPayload, bool) {
	if event.Kind != kindVanish {
		return accountDeletionPayload{}, false
	}

	return accountDeletionPayload{Event: event}, true
}

func sendAccountDeletion(cfg accountDeletionConfig, payload accountDeletionPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), accountDeletionTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	return nil
}
