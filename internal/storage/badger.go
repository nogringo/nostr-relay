package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/rs/zerolog/log"

	"fiatjaf.com/nostr"
)

type BadgerStore struct {
	db *badger.DB
}

func NewBadgerStore(path string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Disable badger's verbose logging

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	store := &BadgerStore{db: db}

	// Start GC goroutine
	go store.runGC()

	log.Info().Str("path", path).Msg("BadgerDB initialized")
	return store, nil
}

func (s *BadgerStore) Close() error {
	return s.db.Close()
}

func (s *BadgerStore) runGC() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		for {
			err := s.db.RunValueLogGC(0.5)
			if err != nil {
				break
			}
		}
	}
}

// Key prefixes for different indexes
const (
	prefixEvent    = "e:" // e:<event_id> -> event JSON
	prefixByPubkey = "p:" // p:<pubkey>:<created_at>:<event_id> -> event_id
	prefixByKind   = "k:" // k:<kind>:<created_at>:<event_id> -> event_id
	prefixByTag    = "t:" // t:<tag>:<value>:<created_at>:<event_id> -> event_id
	prefixGiftWrap = "g:" // g:<recipient_pubkey>:<event_id> -> event_id (NIP-59)
)

func (s *BadgerStore) SaveEvent(ctx context.Context, event *nostr.Event) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	eventID := event.ID.Hex()
	pubkeyHex := event.PubKey.Hex()

	return s.db.Update(func(txn *badger.Txn) error {
		// Check if event already exists
		eventKey := []byte(prefixEvent + eventID)
		_, err := txn.Get(eventKey)
		if err == nil {
			return nil // Event already exists
		}

		// Store the event
		if err := txn.Set(eventKey, eventJSON); err != nil {
			return err
		}

		// Index by pubkey
		pubkeyKey := fmt.Sprintf("%s%s:%d:%s", prefixByPubkey, pubkeyHex, event.CreatedAt.Time().Unix(), eventID)
		if err := txn.Set([]byte(pubkeyKey), []byte(eventID)); err != nil {
			return err
		}

		// Index by kind
		kindKey := fmt.Sprintf("%s%d:%d:%s", prefixByKind, event.Kind, event.CreatedAt.Time().Unix(), eventID)
		if err := txn.Set([]byte(kindKey), []byte(eventID)); err != nil {
			return err
		}

		// Index tags (for NIP-59 gift wrap, we index the 'p' tag specially)
		for _, tag := range event.Tags {
			if len(tag) >= 2 {
				tagKey := fmt.Sprintf("%s%s:%s:%d:%s", prefixByTag, tag[0], tag[1], event.CreatedAt.Time().Unix(), eventID)
				if err := txn.Set([]byte(tagKey), []byte(eventID)); err != nil {
					return err
				}

				// Special index for gift wraps (kind 1059)
				if event.Kind == 1059 && tag[0] == "p" {
					giftKey := fmt.Sprintf("%s%s:%s", prefixGiftWrap, tag[1], eventID)
					if err := txn.Set([]byte(giftKey), []byte(eventID)); err != nil {
						return err
					}
				}
			}
		}

		return nil
	})
}

// ReplaceEvent applies NIP-01 replaceable/addressable semantics: only the newest
// event for a given (pubkey, kind) — or (pubkey, kind, d-tag) for addressable —
// is kept. Older versions are deleted; if the incoming event is older than the
// stored one, it is dropped.
func (s *BadgerStore) ReplaceEvent(ctx context.Context, event *nostr.Event) error {
	dTag := ""
	if event.Kind.IsAddressable() {
		for _, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "d" {
				dTag = tag[1]
				break
			}
		}
	}

	pubkeyHex := event.PubKey.Hex()
	prefix := prefixByPubkey + pubkeyHex + ":"

	var toDelete []*nostr.Event
	skip := false
	newID := event.ID.Hex()
	newTs := event.CreatedAt.Time().Unix()

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			var eventID string
			if err := it.Item().Value(func(val []byte) error {
				eventID = string(val)
				return nil
			}); err != nil {
				continue
			}

			existing, err := s.getEventByID(txn, eventID)
			if err != nil || existing == nil || existing.Kind != event.Kind {
				continue
			}

			if event.Kind.IsAddressable() {
				existingDTag := ""
				for _, tag := range existing.Tags {
					if len(tag) >= 2 && tag[0] == "d" {
						existingDTag = tag[1]
						break
					}
				}
				if existingDTag != dTag {
					continue
				}
			}

			existingTs := existing.CreatedAt.Time().Unix()
			existingID := existing.ID.Hex()
			if existingID == newID {
				skip = true
				return nil
			}
			// NIP-01: newer wins; ties broken by lower id
			if existingTs > newTs || (existingTs == newTs && existingID < newID) {
				skip = true
				return nil
			}
			toDelete = append(toDelete, existing)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if skip {
		return nil
	}

	for _, old := range toDelete {
		if err := s.DeleteEvent(ctx, old); err != nil {
			return err
		}
	}
	return s.SaveEvent(ctx, event)
}

func (s *BadgerStore) DeleteEvent(ctx context.Context, event *nostr.Event) error {
	eventID := event.ID.Hex()
	pubkeyHex := event.PubKey.Hex()

	return s.db.Update(func(txn *badger.Txn) error {
		eventKey := []byte(prefixEvent + eventID)

		// Check if event exists
		_, err := txn.Get(eventKey)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}

		// Delete main event
		if err := txn.Delete(eventKey); err != nil {
			return err
		}

		// Delete indexes (ignore errors - indexes may not exist)
		pubkeyKey := fmt.Sprintf("%s%s:%d:%s", prefixByPubkey, pubkeyHex, event.CreatedAt.Time().Unix(), eventID)
		_ = txn.Delete([]byte(pubkeyKey))

		kindKey := fmt.Sprintf("%s%d:%d:%s", prefixByKind, event.Kind, event.CreatedAt.Time().Unix(), eventID)
		_ = txn.Delete([]byte(kindKey))

		for _, tag := range event.Tags {
			if len(tag) >= 2 {
				tagKey := fmt.Sprintf("%s%s:%s:%d:%s", prefixByTag, tag[0], tag[1], event.CreatedAt.Time().Unix(), eventID)
				_ = txn.Delete([]byte(tagKey))

				if event.Kind == 1059 && tag[0] == "p" {
					giftKey := fmt.Sprintf("%s%s:%s", prefixGiftWrap, tag[1], eventID)
					_ = txn.Delete([]byte(giftKey))
				}
			}
		}

		return nil
	})
}

func (s *BadgerStore) DeleteEventByID(ctx context.Context, id string) error {
	// First get the event to clean up indexes
	event, err := s.GetEvent(ctx, id)
	if err != nil {
		return err
	}
	if event == nil {
		return nil // Event doesn't exist
	}
	return s.DeleteEvent(ctx, event)
}

func (s *BadgerStore) GetEvent(ctx context.Context, id string) (*nostr.Event, error) {
	var event nostr.Event

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(prefixEvent + id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &event)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func (s *BadgerStore) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	var events []*nostr.Event
	limit := filter.Limit
	if limit == 0 {
		limit = 500 // Default limit
	}

	err := s.db.View(func(txn *badger.Txn) error {
		// Determine the best index to use
		var prefix string
		switch {
		case len(filter.IDs) > 0:
			// Query by specific IDs
			for _, id := range filter.IDs {
				event, err := s.getEventByID(txn, id.Hex())
				if err == nil && event != nil && filter.Matches(*event) {
					events = append(events, event)
					if len(events) >= limit {
						return nil
					}
				}
			}
			return nil

		case len(filter.Authors) > 0:
			// Query by author pubkey
			for _, author := range filter.Authors {
				prefix = prefixByPubkey + author.Hex() + ":"
				if err := s.scanIndex(txn, prefix, filter, &events, limit); err != nil {
					return err
				}
				if len(events) >= limit {
					return nil
				}
			}
			return nil

		case len(filter.Kinds) > 0:
			// Query by kind
			for _, kind := range filter.Kinds {
				prefix = fmt.Sprintf("%s%d:", prefixByKind, kind)
				if err := s.scanIndex(txn, prefix, filter, &events, limit); err != nil {
					return err
				}
				if len(events) >= limit {
					return nil
				}
			}
			return nil

		case len(filter.Tags) > 0:
			// Query by tag
			for tagName, values := range filter.Tags {
				for _, value := range values {
					prefix = fmt.Sprintf("%s%s:%s:", prefixByTag, tagName, value)
					if err := s.scanIndex(txn, prefix, filter, &events, limit); err != nil {
						return err
					}
					if len(events) >= limit {
						return nil
					}
				}
			}
			return nil

		default:
			// Full scan (expensive, but necessary for broad queries)
			opts := badger.DefaultIteratorOptions
			opts.Prefix = []byte(prefixEvent)
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Rewind(); it.Valid() && len(events) < limit; it.Next() {
				item := it.Item()
				var event nostr.Event
				err := item.Value(func(val []byte) error {
					return json.Unmarshal(val, &event)
				})
				if err != nil {
					continue
				}
				if filter.Matches(event) {
					eventCopy := event
					events = append(events, &eventCopy)
				}
			}
			return nil
		}
	})

	return events, err
}

func (s *BadgerStore) getEventByID(txn *badger.Txn, id string) (*nostr.Event, error) {
	item, err := txn.Get([]byte(prefixEvent + id))
	if err != nil {
		return nil, err
	}

	var event nostr.Event
	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &event)
	})
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func (s *BadgerStore) scanIndex(txn *badger.Txn, prefix string, filter nostr.Filter, events *[]*nostr.Event, limit int) error {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(prefix)
	opts.Reverse = true // Most recent first

	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Seek([]byte(prefix + "\xff")); it.Valid() && len(*events) < limit; it.Next() {
		item := it.Item()

		var eventID string
		err := item.Value(func(val []byte) error {
			eventID = string(val)
			return nil
		})
		if err != nil {
			continue
		}

		event, err := s.getEventByID(txn, eventID)
		if err != nil || event == nil {
			continue
		}

		if filter.Matches(*event) {
			*events = append(*events, event)
		}
	}

	return nil
}

// GetAllEventIDs returns all event IDs for negentropy sync
func (s *BadgerStore) GetAllEventIDs(ctx context.Context) ([]string, error) {
	var ids []string

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefixEvent)
		opts.PrefetchValues = false // We only need keys

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			// Extract event ID from key (remove prefix)
			id := string(key[len(prefixEvent):])
			ids = append(ids, id)
		}

		return nil
	})

	return ids, err
}

// CountEvents returns the total number of events
func (s *BadgerStore) CountEvents() (int64, error) {
	var count int64

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefixEvent)
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}

		return nil
	})

	return count, err
}
