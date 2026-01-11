package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nostr-relay/config"
	"nostr-relay/internal/handlers"
	"nostr-relay/internal/storage"

	"github.com/fiatjaf/khatru"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Load configuration
	cfg := config.Load()

	log.Info().Msg("Starting Ultra Relay - NIP-17/42/59/77 support")

	// Initialize storage
	store, err := storage.NewBadgerStore(cfg.DataPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize storage")
	}
	defer store.Close()

	// Create relay
	relay := khatru.NewRelay()

	// Enable NIP-77 Negentropy (built-in khatru support)
	relay.Negentropy = true

	// Relay info (NIP-11)
	relay.Info.Name = cfg.RelayName
	relay.Info.Description = cfg.RelayDescription
	relay.Info.PubKey = cfg.RelayPubKey
	relay.Info.Contact = cfg.RelayContact
	relay.Info.SupportedNIPs = []any{1, 2, 4, 9, 11, 12, 15, 16, 17, 20, 22, 33, 40, 42, 45, 59, 77}
	relay.Info.Software = "https://github.com/nogringo/nostr-relay"
	relay.Info.Version = "0.2.0"

	// Setup all handlers
	handlers.SetupEventHandlers(relay, store)
	handlers.SetupQueryHandlers(relay, store)
	handlers.SetupAuthHandlers(relay, cfg)

	// Connection lifecycle logging
	relay.OnConnect = append(relay.OnConnect, func(ctx context.Context) {
		ip := khatru.GetIP(ctx)
		log.Debug().Str("ip", ip).Msg("Client connected")
	})

	relay.OnDisconnect = append(relay.OnDisconnect, func(ctx context.Context) {
		ip := khatru.GetIP(ctx)
		log.Debug().Str("ip", ip).Msg("Client disconnected")
	})

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      relay,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info().Msg("Shutting down relay...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Server shutdown error")
		}
	}()

	count, _ := store.CountEvents()
	log.Info().
		Str("addr", addr).
		Int64("events", count).
		Bool("negentropy", true).
		Msg("Relay listening")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("Server error")
	}

	log.Info().Msg("Relay stopped")
}
