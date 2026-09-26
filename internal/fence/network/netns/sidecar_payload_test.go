package netns

import (
	"os"
	"testing"
)

// TestReadSidecarPayloadRoundTrip confirms a JSON payload handed on the dedicated
// descriptor decodes back into the target struct.
func TestReadSidecarPayloadRoundTrip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()

	want := Request{Argv: []string{"/bin/cat"}, UID: 7, GID: 7}
	go func() {
		_, _ = w.Write([]byte(`{"argv":["/bin/cat"],"uid":7,"gid":7}`))
		_ = w.Close()
	}()

	var got Request
	if err := readSidecarPayloadFrom(r, &got); err != nil {
		t.Fatalf("readSidecarPayloadFrom: %v", err)
	}
	if len(got.Argv) != 1 || got.Argv[0] != want.Argv[0] || got.UID != want.UID || got.GID != want.GID {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// TestReadSidecarPayloadFailsClosed is the sidecar-leg negative control
// (acceptance #4): a sidecar must refuse to start when the payload descriptor is
// missing or not open, never silently fall back to reading its config from the
// caller's stdin.
func TestReadSidecarPayloadFailsClosed(t *testing.T) {
	t.Run("nil descriptor", func(t *testing.T) {
		var got Request
		if err := readSidecarPayloadFrom(nil, &got); err == nil {
			t.Fatal("expected error when the payload descriptor is absent")
		}
	})

	t.Run("closed descriptor", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		_ = w.Close()
		_ = r.Close() // closed before read: Stat must fail, so we fail closed.
		var got Request
		if err := readSidecarPayloadFrom(r, &got); err == nil {
			t.Fatal("expected error when the payload descriptor is closed")
		}
	})
}
