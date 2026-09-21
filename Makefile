.PHONY: build build-fence-fs build-all test clean clean-fence-fs install install-egress-helper fmt vet lint

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-X github.com/nocktechnologies/nocklock/internal/version.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o nocklock ./cmd/nocklock

build-fence-fs:
	@if [ "$$(uname -s)" = "Linux" ]; then \
		$(MAKE) -C internal/fence/fs/interposer build; \
	else \
		echo "Skipping fence library build (Linux only, current OS: $$(uname -s))"; \
	fi

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

# The privileged Linux network-egress helper installs SEPARATELY from `install`:
# it writes a root-owned shim to /usr/libexec and a constrained NOPASSWD sudoers
# grant, so it must be run with sufficient privilege, e.g.
# `sudo make install-egress-helper`. The nocklock binary must already be at
# /usr/local/bin/nocklock (run `make install` first); the script checks and
# errors with the fix if it is missing.
install-egress-helper:
	scripts/install-egress-helper.sh

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
