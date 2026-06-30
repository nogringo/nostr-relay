# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# LMDB needs cgo; link statically so the binary runs on a bare base image.
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags='-s -w -extldflags "-static"' \
    -o /out/nostr-relay .

FROM alpine:3.21
RUN adduser -D -H relay
COPY --from=build /out/nostr-relay /usr/local/bin/nostr-relay
WORKDIR /data
RUN chown relay /data
USER relay
ENV LISTEN_ADDR=0.0.0.0:3334
EXPOSE 3334
ENTRYPOINT ["nostr-relay"]
