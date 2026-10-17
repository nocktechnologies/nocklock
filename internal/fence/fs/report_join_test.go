package fs

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The Listen channel closes only after every report handler call has
// returned, even when the context is cancelled while a handler runs. wrap
// relies on this: it cancels the fence and waits for the channel to close
// before it drains the proxy and reads audit.failure() for the verdict, so a
// look-back denial row the handler writes cannot land after the verdict.
func TestListenChannelClosesOnlyAfterReportHandlerReturns(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "f.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &Fence{Config: &FenceConfig{WaitForAck: true}, listener: ln}

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.SetReportHandler(func(FenceEvent) {
		once.Do(func() { close(entered) })
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := f.listen(ctx, func(net.Conn) connectionPeer { return unavailableConnectionPeer() })

	conn, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"type":"fs","action":"blocked","path":"/x","operation":"open"}` + "\n")); err != nil {
		t.Fatalf("write report: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("report handler never ran")
	}

	// Teardown starts while the handler is still running.
	cancel()
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("Listen channel closed while a report handler was still running")
		}
		t.Fatal("unexpected event on the Listen channel with a report handler set")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	_ = conn.Close()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("unexpected event on the Listen channel with a report handler set")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Listen channel did not close after the handler returned and the connection closed")
	}
}
