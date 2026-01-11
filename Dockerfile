FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o nostr-relay ./cmd/relay

# Final stage
FROM alpine:3.19

WORKDIR /app

# Copy binary
COPY --from=builder /app/nostr-relay .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 3334

# Run
CMD ["./nostr-relay"]
