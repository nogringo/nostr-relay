package config

import (
	"os"
	"strconv"
)

type Config struct {
	// Server
	Port     int
	Host     string
	DataPath string

	// Relay info
	RelayName        string
	RelayDescription string
	RelayPubKey      string
	RelayContact     string

	// Authentication
	RequireAuth bool

	// Limits
	MaxEventSize     int
	MaxSubscriptions int
	MaxFilters       int
	RateLimit        int // events per minute per IP
}

func Load() *Config {
	return &Config{
		Port:             getEnvInt("RELAY_PORT", 3334),
		Host:             getEnv("RELAY_HOST", "0.0.0.0"),
		DataPath:         getEnv("RELAY_DATA_PATH", "./data"),
		RelayName:        getEnv("RELAY_NAME", "Ultra Relay"),
		RelayDescription: getEnv("RELAY_DESCRIPTION", "High-performance Nostr relay with NIP-17/42/59/77"),
		RelayPubKey:      getEnv("RELAY_PUBKEY", ""),
		RelayContact:     getEnv("RELAY_CONTACT", ""),
		RequireAuth:      getEnvBool("RELAY_REQUIRE_AUTH", false),
		MaxEventSize:     getEnvInt("RELAY_MAX_EVENT_SIZE", 65536),
		MaxSubscriptions: getEnvInt("RELAY_MAX_SUBSCRIPTIONS", 20),
		MaxFilters:       getEnvInt("RELAY_MAX_FILTERS", 10),
		RateLimit:        getEnvInt("RELAY_RATE_LIMIT", 100),
	}
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
