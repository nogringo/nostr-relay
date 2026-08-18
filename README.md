# nostr-relay

> The only Nostr relay where you can delete the gift wraps sent to you.
> Strict NIP-59 access control, NIP-77 sync, general-purpose.

## Why this relay

Most Nostr relays don't bother with three things that matter for private
messaging. This one does.

### 1. Your gift wraps stay private

NIP-59 says relays *SHOULD* only serve `kind 1059` events to the marked
recipient. Most relays leak: they hand out gift wraps to anyone who asks.

This relay enforces it via NIP-42 AUTH:

- Querying `kind 1059` requires authentication.
- Even authenticated, you only get the gift wraps where you are the `p` tag.
- Non-recipients get silently filtered - no metadata leak.
- The AUTH challenge is sent on connect, so clients can authenticate upfront.

### 2. You can delete the gift wraps you received

NIP-59 says:

> *"relays SHOULD delete kind 1059 events whose p-tag matches the signer of
> NIP-09 deletions or NIP-62 vanish requests."*

The catch: gift wraps are signed by random ephemeral keys, so the standard
NIP-09 rule ("only the author can delete") means **nobody** can delete their
own inbox. This relay implements the SHOULD correctly: if you are the
recipient (`p` tag), your NIP-09 deletion request succeeds.

No other public relay implements this. If you find one,
open an issue - we'll
update this claim.

### 3. You can really vanish

A NIP-62 request (`kind 62`) tagging this relay, or `ALL_RELAYS`, erases
everything you published up to the request's `created_at`, your NIP-09 deletion
events included, plus every gift wrap addressed to you. Those events are then
refused if anyone tries to push them back. Set `RELAY_URLS` so the relay knows
which URLs designate it.

### 4. Efficient sync via NIP-77 Negentropy

Resync an inbox from scratch in seconds, not minutes. NIP-77 is built in
and on by default.

## Supported NIPs

General-purpose: this is not a single-purpose inbox relay. It speaks the
full protocol.

| NIP | Description | Status |
|-----|-------------|--------|
| 01 | Basic Protocol | OK |
| 02 | Follow List | OK |
| 04 | Encrypted DM (legacy) | OK |
| 09 | Event Deletion (with gift wrap recipient support) | OK |
| 11 | Relay Information | OK |
| 12 | Generic Tag Queries | OK |
| 16 | Event Treatment | OK |
| 17 | Private Direct Messages | OK |
| 20 | Command Results | OK |
| 22 | Event `created_at` | OK |
| 33 | Parameterized Replaceable | OK |
| 40 | Expiration | OK |
| 42 | Authentication | OK |
| 45 | Event Counts | OK |
| 59 | Gift Wrap (recipient-only access + deletion) | OK |
| 62 | Request to Vanish | OK |
| 77 | Negentropy | OK |
