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

const inboundNotificationTimeout = 5 * time.Second

type inboundNotificationConfig struct {
	Endpoint string
	Token    string
	Relays   []string
	Client   *http.Client
}

type inboundNotificationPayload struct {
	RecipientPubkey      string               `json:"recipientPubkey"`
	Relays               []string             `json:"relays"`
	Event                inboundGiftWrapEvent `json:"event"`
	AuthenticatedPubkeys []string             `json:"authenticatedPubkeys"`
}

type inboundGiftWrapEvent struct {
	ID        nostr.ID        `json:"id"`
	PubKey    nostr.PubKey    `json:"pubkey"`
	CreatedAt nostr.Timestamp `json:"created_at"`
	Kind      nostr.Kind      `json:"kind"`
	Tags      nostr.Tags      `json:"tags"`
}

func configureInboundNotificationsFromEnv(relay *khatru.Relay) {
	cfg := inboundNotificationConfig{
		Endpoint: os.Getenv("INBOUND_NOTIFICATIONS_URL"),
		Token:    os.Getenv("INBOUND_NOTIFICATIONS_TOKEN"),
		Relays:   splitCommaSeparated(os.Getenv("RELAY_URLS")),
	}
	if cfg.Endpoint == "" {
		return
	}
	if cfg.Token == "" {
		log.Println("inbound notifications disabled: INBOUND_NOTIFICATIONS_TOKEN is empty")
		return
	}
	if len(cfg.Relays) == 0 {
		log.Println("inbound notifications disabled: set RELAY_URLS")
		return
	}

	attachInboundNotifications(relay, cfg)
	log.Printf("inbound notifications enabled for %s", cfg.Endpoint)
}

func splitCommaSeparated(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func attachInboundNotifications(relay *khatru.Relay, cfg inboundNotificationConfig) {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: inboundNotificationTimeout}
	}

	prev := relay.OnEventSaved
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		if prev != nil {
			prev(ctx, event)
		}

		payload, ok := buildInboundNotificationPayload(ctx, event, cfg.Relays)
		if !ok {
			return
		}

		go func() {
			if err := sendInboundNotification(cfg, payload); err != nil {
				log.Printf("inbound notification failed for event %s: %v", event.ID.Hex(), err)
			}
		}()
	}
}

func buildInboundNotificationPayload(ctx context.Context, event nostr.Event, relays []string) (inboundNotificationPayload, bool) {
	if event.Kind != nostr.KindGiftWrap {
		return inboundNotificationPayload{}, false
	}

	p := event.Tags.Find("p")
	if p == nil {
		return inboundNotificationPayload{}, false
	}

	return inboundNotificationPayload{
		RecipientPubkey: p[1],
		Relays:          append([]string(nil), relays...),
		Event: inboundGiftWrapEvent{
			ID:        event.ID,
			PubKey:    event.PubKey,
			CreatedAt: event.CreatedAt,
			Kind:      event.Kind,
			Tags:      event.Tags,
		},
		AuthenticatedPubkeys: authedPubkeyHexes(ctx),
	}, true
}

func authedPubkeyHexes(ctx context.Context) []string {
	authed := khatru.GetAllAuthed(ctx)
	out := make([]string, 0, len(authed))
	for _, pk := range authed {
		out = append(out, pk.Hex())
	}
	return out
}

func sendInboundNotification(cfg inboundNotificationConfig, payload inboundNotificationPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), inboundNotificationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
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
