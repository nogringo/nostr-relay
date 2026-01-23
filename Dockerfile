FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o nostr-relay ./cmd/relay

FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/nogringo/nostr-relay"
LABEL org.opencontainers.image.description="Privacy-focused Nostr relay with NIP-17/42/59/77"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=builder /app/nostr-relay .

RUN mkdir -p /app/data && \
    adduser -D -H nostr && \
    chown -R nostr:nostr /app

USER nostr

EXPOSE 3334

VOLUME ["/app/data"]

CMD ["./nostr-relay"]
