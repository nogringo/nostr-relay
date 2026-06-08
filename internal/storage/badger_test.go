package storage

import (
	"context"
	"errors"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
)

func TestSaveEventReturnsDuplicateError(t *testing.T) {
	store, err := NewBadgerStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewBadgerStore() error = %v", err)
	}
	defer store.Close()

	recipient := nostr.Generate().Public()
	event := nostr.Event{
		Kind:      nostr.KindGiftWrap,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{nostr.Tag{"p", recipient.Hex()}},
		Content:   "encrypted seal",
	}
	if err := event.Sign(nostr.Generate()); err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}

	if err := store.SaveEvent(context.Background(), &event); err != nil {
		t.Fatalf("first SaveEvent() error = %v", err)
	}

	err = store.SaveEvent(context.Background(), &event)
	if !errors.Is(err, eventstore.ErrDupEvent) {
		t.Fatalf("second SaveEvent() error = %v, want %v", err, eventstore.ErrDupEvent)
	}
}
