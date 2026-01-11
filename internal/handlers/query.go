package handlers

import (
	"context"

	"nostr-relay/internal/storage"

	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/zerolog/log"
)

func SetupQueryHandlers(relay *khatru.Relay, store *storage.BadgerStore) {
	// Query events
	relay.QueryEvents = append(relay.QueryEvents, func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
		ch := make(chan *nostr.Event)

		go func() {
			defer close(ch)

			events, err := store.QueryEvents(ctx, filter)
			if err != nil {
				log.Error().Err(err).Msg("Query error")
				return
			}

			log.Debug().
				Int("count", len(events)).
				Msg("Query returned events")

			for _, event := range events {
				select {
				case ch <- event:
				case <-ctx.Done():
					return
				}
			}
		}()

		return ch, nil
	})

	// Reject certain filters
	relay.RejectFilter = append(relay.RejectFilter, func(ctx context.Context, filter nostr.Filter) (bool, string) {
		// Reject filters that are too broad (no specific criteria)
		if len(filter.IDs) == 0 &&
			len(filter.Authors) == 0 &&
			len(filter.Kinds) == 0 &&
			len(filter.Tags) == 0 &&
			filter.Since == nil &&
			filter.Until == nil &&
			filter.Limit == 0 {
			return true, "error: filter too broad, please specify at least one criterion"
		}

		// Limit excessive requests
		if filter.Limit > 5000 {
			return true, "error: limit too high, max 5000"
		}

		return false, ""
	})

	// Count events
	relay.CountEvents = append(relay.CountEvents, func(ctx context.Context, filter nostr.Filter) (int64, error) {
		events, err := store.QueryEvents(ctx, filter)
		if err != nil {
			return 0, err
		}
		return int64(len(events)), nil
	})
}
