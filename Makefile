.PHONY: build build-fence-fs build-all test clean clean-fence-fs install fmt vet lint

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-X github.com/nocktechnologies/nocklock/internal/version.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o nocklock ./cmd/nocklock

build-fence-fs:
	$(MAKE) -C internal/fence/fs/interposer build

build-all: build build-fence-fs

test:
	go test ./... -v

clean:
	rm -f nocklock nocklock.exe
	$(MAKE) -C internal/fence/fs/interposer clean

clean-fence-fs:
	$(MAKE) -C internal/fence/fs/interposer clean

install: build
	mv nocklock /usr/local/bin/

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
