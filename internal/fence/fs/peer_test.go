package fs

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

const spoofedPeerReport = `{"type":"fs","action":"blocked","path":"/private/key","operation":"open","reason":"denied path","timestamp":"child time","pid":999,"uid":999,"gid":999,"peer":{"credentials_status":"captured","credentials":{"pid":999,"uid":999,"gid":999}},"connection_peer":{"credentials_status":"captured","credentials":{"pid":999,"uid":999,"gid":999},"executable":{"status":"observed","path":"/spoof"}},"executable":"/spoof","hasPeer":true,"version":999}`

func testConnectionPeer() connectionPeer {
	return connectionPeer{
		credentialsStatus: "captured",
		credentials:       peerCredentials{PID: 123, UID: 0, GID: 456},
		executable:        peerExecutable{Status: "observed", Path: "/collector/observed"},
	}
}

func TestConnectionPeerSlowCaptureDoesNotBlockOtherConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fence := &Fence{listener: listener, Config: &FenceConfig{WaitForAck: true}}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var captures atomic.Int32
	events := fence.listen(ctx, func(net.Conn) connectionPeer {
		if captures.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return testConnectionPeer()
	})
	var connections []net.Conn
	t.Cleanup(func() {
		unblock()
		cancel()
		listener.Close()
		for _, conn := range connections {
			conn.Close()
		}
		deadline := time.After(3 * time.Second)
		for {
			select {
			case _, ok := <-events:
				if !ok {
					return
				}
			case <-deadline:
				t.Error("slow-capture listener did not stop after release and connection cleanup")
				return
			}
		}
	})
	dial := func() net.Conn {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		return conn
	}
	first := dial()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first connection never entered peer capture")
	}
	exchange := func(conn net.Conn, name string) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		frame := strings.Replace(spoofedPeerReport, "/private/key", "/"+name, 1)
		if _, err := io.WriteString(conn, frame+"\n"); err != nil {
			t.Fatal(err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
			t.Fatalf("%s connection stalled behind slow peer capture: ACK=%v err=%v", name, ack, err)
		}
		select {
		case event := <-events:
			if event.Path != "/"+name || !event.hasPeer || event.peer != testConnectionPeer() {
				t.Fatalf("%s report lost its snapshot: %+v", name, event)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s acknowledged without a delivered report", name)
		}
	}
	exchange(dial(), "second") // Must finish while the first capture is still held.
	if captures.Load() != 2 {
		t.Fatalf("captured %d connections, want 2", captures.Load())
	}
	unblock()
	exchange(first, "first") // The delayed connection remains usable after release.
}

// runPeerReport drives the real parser and either dispatch path without Linux
// credentials. The caller supplies a collector snapshot, never child metadata.
func runPeerReport(t *testing.T, peer connectionPeer, synchronous bool, handle func(FenceEvent) error) FenceEvent {
	t.Helper()
	server, child := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	events := make(chan FenceEvent, 2)
	errs := make(chan error, 1)
	fence := &Fence{Config: &FenceConfig{WaitForAck: true}}
	if synchronous {
		fence.SetReportHandler(func(event FenceEvent) {
			errs <- handle(event)
			events <- event
		})
	}
	go func() {
		defer close(done)
		fence.handleConn(ctx, server, events, peer)
	}()
	t.Cleanup(func() {
		cancel()
		child.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("report parser did not stop after connection cleanup")
		}
	})
	if err := child.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// A malformed frame must not produce an event or ACK; the following valid
	// report is still delivered with the original collector snapshot.
	if _, err := io.WriteString(child, "{malformed}\n"+spoofedPeerReport+"\n"); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(child, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("report ACK: %v, %v", ack, err)
	}
	var event FenceEvent
	select {
	case event = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("valid report was not delivered")
	}
	if synchronous {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("ACK arrived before synchronous report handler completed")
		}
	} else if err := handle(event); err != nil {
		t.Fatal(err)
	}
	child.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("report parser did not finish")
	}
	if len(events) != 0 {
		t.Fatal("malformed input produced an extra report")
	}
	return event
}

func TestConnectionPeerCannotBeSpoofedByReport(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		name := "channel"
		if synchronous {
			name = "synchronous"
		}
		t.Run(name, func(t *testing.T) {
			peer := testConnectionPeer()
			event := runPeerReport(t, peer, synchronous, func(FenceEvent) error { return nil })
			if !event.hasPeer || event.peer != peer {
				t.Fatalf("child JSON changed collector peer: got %+v, want %+v", event.peer, peer)
			}
			var detail struct {
				Version int            `json:"version"`
				Report  map[string]any `json:"report"`
				Peer    struct {
					Status      string          `json:"credentials_status"`
					Credentials peerCredentials `json:"credentials"`
					Executable  peerExecutable  `json:"executable"`
				} `json:"connection_peer"`
			}
			if err := json.Unmarshal([]byte(event.Detail()), &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Version != 1 || detail.Peer.Status != "captured" || detail.Peer.Credentials != peer.credentials || detail.Peer.Executable != peer.executable {
				t.Fatalf("signed envelope lost collector provenance: %s", event.Detail())
			}
			if detail.Report["operation"] != "open" || detail.Report["path"] != "/private/key" || detail.Report["reason"] != "denied path" || detail.Report["timestamp"] != "child time" || len(detail.Report) != 6 {
				t.Fatalf("report fields changed or unknown spoof fields retained: %+v", detail.Report)
			}
			if strings.Contains(event.Detail(), "999") || strings.Contains(event.Detail(), "/spoof") || !strings.Contains(event.Detail(), `"uid":0`) {
				t.Fatalf("spoof metadata retained or valid UID zero omitted: %s", event.Detail())
			}
		})
	}
}

func TestConnectionPeerUnavailablePreservesReport(t *testing.T) {
	server, child := net.Pipe()
	defer server.Close()
	defer child.Close()
	peer := captureConnectionPeer(server) // Not a Unix socket: no credential lookup can succeed.
	for _, synchronous := range []bool{false, true} {
		event := runPeerReport(t, peer, synchronous, func(FenceEvent) error { return nil })
		if event.Operation != "open" || event.Path != "/private/key" || event.peer.credentialsStatus != "unavailable" {
			t.Fatalf("credential failure lost the report: %+v", event)
		}
		detail := event.Detail()
		if strings.Contains(detail, `"credentials":`) || !strings.Contains(detail, `"credentials_status":"unavailable"`) || !strings.Contains(detail, `"status":"credentials_unavailable"`) {
			t.Fatalf("credential failure fabricated an identity: %s", detail)
		}
	}
}

func TestConnectionPeerExecutableObservation(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		err        error
		status     string
	}{
		{"available", "/usr/bin/agent", nil, "observed"},
		{"exited", "", os.ErrNotExist, "unavailable"},
		{"inaccessible", "", os.ErrPermission, "unavailable"},
		{"empty", "", nil, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observePeerExecutable(123, func(path string) (string, error) {
				if path != "/proc/123/exe" {
					t.Fatalf("unexpected procfs path %q", path)
				}
				return tc.path, tc.err
			})
			if got.Status != tc.status || got.Path != tc.path {
				t.Fatalf("observation=%+v", got)
			}
		})
	}
}

func TestConnectionPeerSignedDetailAndLegacyTrail(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		name := "channel"
		if synchronous {
			name = "synchronous"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "audit.db")
			logger, err := logging.NewLogger(dbPath, "", logging.WithSigning(filepath.Join(dir, "keys", "key")))
			if err != nil {
				t.Fatal(err)
			}
			defer logger.Close()
			old := FenceEvent{Operation: "open", Path: "/old", Reason: "denied path"}.Detail()
			if old != "op=open path=/old reason=denied path" {
				t.Fatalf("legacy detail changed: %q", old)
			}
			row := logging.Event{Timestamp: time.Now(), EventType: logging.EventFileBlocked, Category: "filesystem", Detail: old, Blocked: true, SessionID: "peer-test"}
			if err := logger.Log(row); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var oldHash, oldSig string
			if err := db.QueryRow("SELECT entry_hash, entry_sig FROM events WHERE id=1").Scan(&oldHash, &oldSig); err != nil {
				t.Fatal(err)
			}
			if oldSig == "" {
				t.Fatal("legacy control was not signed")
			}
			before, err := logger.VerifyChainSigned(logger.SigningPublicKey(), true)
			if err != nil || !before.Intact || before.SigState != "authentic" {
				t.Fatalf("legacy trail: %+v, %v", before, err)
			}
			event := runPeerReport(t, testConnectionPeer(), synchronous, func(ev FenceEvent) error {
				row.Detail = ev.Detail()
				if synchronous {
					return logger.LogImmediate(row)
				}
				return logger.Log(row)
			})
			after, err := logger.VerifyChainSigned(logger.SigningPublicKey(), true)
			if err != nil || !after.Intact || after.SigState != "authentic" || after.SignedEntries != 2 {
				t.Fatalf("mixed trail: %+v, %v", after, err)
			}
			var hash, sig, detail string
			if err := db.QueryRow("SELECT entry_hash, entry_sig, detail FROM events WHERE id=1").Scan(&hash, &sig, &detail); err != nil {
				t.Fatal(err)
			}
			if hash != oldHash || sig != oldSig || detail != old {
				t.Fatal("appending provenance rewrote the legacy signed row")
			}
			if err := db.QueryRow("SELECT detail FROM events WHERE id=2").Scan(&detail); err != nil {
				t.Fatal(err)
			}
			if detail != event.Detail() {
				t.Fatalf("stored detail differs from collector envelope: %q", detail)
			}
			mutated := strings.Replace(detail, `"pid":123`, `"pid":999`, 1)
			if mutated == detail {
				t.Fatal("no signed collector PID to tamper")
			}
			if _, err := db.Exec("UPDATE events SET detail=? WHERE id=2", mutated); err != nil {
				t.Fatal(err)
			}
			broken, err := logger.VerifyChainSigned(logger.SigningPublicKey(), true)
			if err != nil {
				t.Fatal(err)
			}
			if broken.Intact {
				t.Fatalf("collector identity tampering was accepted: %+v", broken)
			}
		})
	}
}
