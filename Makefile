.PHONY: build run test clean

build:
	go build -o nostr-relay ./cmd/relay

run: build
	./nostr-relay

test:
	go test -v ./...

clean:
	rm -rf nostr-relay data/

dev:
	go run ./cmd/relay

docker-build:
	docker build -t nostr-relay .

docker-run:
	docker run -p 3334:3334 -v $(PWD)/data:/app/data nostr-relay
