# nostr-relay

A high-performance Nostr relay with full support for private messaging (NIP-17/59) and efficient sync (NIP-77).

## Features

- **NIP-59 Gift Wrap** - Full support with recipient-only access and deletion
- **NIP-77 Negentropy** - Efficient event synchronization
- **NIP-17 Private DMs** - Encrypted direct messages
- **NIP-42 AUTH** - Protected access to private content
- **NIP-09 Deletion** - Event deletion with gift wrap recipient support

## Supported NIPs

| NIP | Description | Status |
|-----|-------------|--------|
| 01 | Basic Protocol | ✅ |
| 02 | Follow List | ✅ |
| 04 | Encrypted DM (legacy) | ✅ |
| 09 | Event Deletion | ✅ |
| 11 | Relay Information | ✅ |
| 12 | Generic Tag Queries | ✅ |
| 16 | Event Treatment | ✅ |
| 17 | Private Direct Messages | ✅ |
| 20 | Command Results | ✅ |
| 22 | Event `created_at` | ✅ |
| 33 | Parameterized Replaceable | ✅ |
| 40 | Expiration | ✅ |
| 42 | Authentication | ✅ |
| 45 | Event Counts | ✅ |
| 59 | Gift Wrap | ✅ |
| 77 | Negentropy | ✅ |

## Quick Start

```bash
# Clone
git clone https://github.com/nogringo/nostr-relay
cd nostr-relay

# Run
go run ./cmd/relay

# Or build and run
make run
```

The relay listens on `ws://localhost:3334`

## Configuration

Configure via environment variables:

```bash
# Server
RELAY_PORT=3334
RELAY_HOST=0.0.0.0
RELAY_DATA_PATH=./data

# Relay Info (NIP-11)
RELAY_NAME="nostr-relay"
RELAY_DESCRIPTION="Privacy-focused Nostr relay"
RELAY_PUBKEY=<your_pubkey>
RELAY_CONTACT=<your_contact>

# Authentication
RELAY_REQUIRE_AUTH=false  # Set to true to require auth for all operations

# Limits
RELAY_MAX_EVENT_SIZE=65536
RELAY_MAX_SUBSCRIPTIONS=20
RELAY_MAX_FILTERS=10
RELAY_RATE_LIMIT=100
```

## Docker

```bash
# Build
docker build -t nostr-relay .

# Run
docker run -p 3334:3334 -v ./data:/app/data nostr-relay
```

## Security

### Gift Wrap Protection (NIP-59)

Gift wraps are **always** protected, regardless of `RELAY_REQUIRE_AUTH`:

- Querying kind 1059 requires AUTH
- Users can only query gift wraps addressed to them (`#p` filter)
- Recipients can delete their received gift wraps

```
REQ ["kinds": [1059]]                    -> auth-required
REQ ["kinds": [1059], "#p": ["<pubkey>"]] -> OK (if authenticated as pubkey)
```

### Deletion Rules (NIP-09)

| Event Type | Who Can Delete |
|------------|---------------|
| Regular events | Author only |
| Gift wraps (1059) | Recipient (tag p) |

## Architecture

```
nostr-relay/
├── cmd/relay/main.go           # Entry point
├── config/config.go            # Configuration
├── internal/
│   ├── handlers/
│   │   ├── auth.go             # NIP-42 AUTH
│   │   ├── events.go           # Event validation (NIP-09/17/59)
│   │   └── query.go            # Query handlers
│   └── storage/
│       └── badger.go           # BadgerDB storage
├── Dockerfile
├── Makefile
└── .env.example
```

## Development

```bash
# Build
make build

# Run in dev mode
make dev

# Run tests
make test

# Clean
make clean
```

## License

MIT

## Credits

Built with [khatru](https://github.com/fiatjaf/khatru) framework.
