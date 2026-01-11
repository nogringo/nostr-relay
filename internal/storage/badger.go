package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/zerolog/log"
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
	prefixEvent     = "e:" // e:<event_id> -> event JSON
	prefixByPubkey  = "p:" // p:<pubkey>:<created_at>:<event_id> -> event_id
	prefixByKind    = "k:" // k:<kind>:<created_at>:<event_id> -> event_id
	prefixByTag     = "t:" // t:<tag>:<value>:<created_at>:<event_id> -> event_id
	prefixGiftWrap  = "g:" // g:<recipient_pubkey>:<event_id> -> event_id (NIP-59)
)

func (s *BadgerStore) SaveEvent(ctx context.Context, event *nostr.Event) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		// Check if event already exists
		eventKey := []byte(prefixEvent + event.ID)
		_, err := txn.Get(eventKey)
		if err == nil {
			return nil // Event already exists
		}

		// Store the event
		if err := txn.Set(eventKey, eventJSON); err != nil {
			return err
		}

		// Index by pubkey
		pubkeyKey := fmt.Sprintf("%s%s:%d:%s", prefixByPubkey, event.PubKey, event.CreatedAt.Time().Unix(), event.ID)
		if err := txn.Set([]byte(pubkeyKey), []byte(event.ID)); err != nil {
			return err
		}

		// Index by kind
		kindKey := fmt.Sprintf("%s%d:%d:%s", prefixByKind, event.Kind, event.CreatedAt.Time().Unix(), event.ID)
		if err := txn.Set([]byte(kindKey), []byte(event.ID)); err != nil {
			return err
		}

		// Index tags (for NIP-59 gift wrap, we index the 'p' tag specially)
		for _, tag := range event.Tags {
			if len(tag) >= 2 {
				tagKey := fmt.Sprintf("%s%s:%s:%d:%s", prefixByTag, tag[0], tag[1], event.CreatedAt.Time().Unix(), event.ID)
				if err := txn.Set([]byte(tagKey), []byte(event.ID)); err != nil {
					return err
				}

				// Special index for gift wraps (kind 1059)
				if event.Kind == 1059 && tag[0] == "p" {
					giftKey := fmt.Sprintf("%s%s:%s", prefixGiftWrap, tag[1], event.ID)
					if err := txn.Set([]byte(giftKey), []byte(event.ID)); err != nil {
						return err
					}
				}
			}
		}

		return nil
	})
}

func (s *BadgerStore) DeleteEvent(ctx context.Context, event *nostr.Event) error {
	return s.db.Update(func(txn *badger.Txn) error {
		eventKey := []byte(prefixEvent + event.ID)

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

		// Delete indexes (we need to delete all possible index entries)
		pubkeyKey := fmt.Sprintf("%s%s:%d:%s", prefixByPubkey, event.PubKey, event.CreatedAt.Time().Unix(), event.ID)
		txn.Delete([]byte(pubkeyKey))

		kindKey := fmt.Sprintf("%s%d:%d:%s", prefixByKind, event.Kind, event.CreatedAt.Time().Unix(), event.ID)
		txn.Delete([]byte(kindKey))

		for _, tag := range event.Tags {
			if len(tag) >= 2 {
				tagKey := fmt.Sprintf("%s%s:%s:%d:%s", prefixByTag, tag[0], tag[1], event.CreatedAt.Time().Unix(), event.ID)
				txn.Delete([]byte(tagKey))

				if event.Kind == 1059 && tag[0] == "p" {
					giftKey := fmt.Sprintf("%s%s:%s", prefixGiftWrap, tag[1], event.ID)
					txn.Delete([]byte(giftKey))
				}
			}
		}

		return nil
	})
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
				event, err := s.getEventByID(txn, id)
				if err == nil && event != nil && filter.Matches(event) {
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
				prefix = prefixByPubkey + author + ":"
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
				if filter.Matches(&event) {
					events = append(events, &event)
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

		if filter.Matches(event) {
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
