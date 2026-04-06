.PHONY: build test clean install fmt vet lint

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-X github.com/nocktechnologies/nocklock/internal/version.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o nocklock ./cmd/nocklock

test:
	go test ./... -v

clean:
	rm -f nocklock nocklock.exe

install: build
	mv nocklock /usr/local/bin/

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
