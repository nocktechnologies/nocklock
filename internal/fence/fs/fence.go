package fs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
)

// IsSupported returns true if the filesystem fence is supported on the current OS.
// Currently only Linux is supported, as the fence relies on LD_PRELOAD interposition.
func IsSupported() bool {
	return runtime.GOOS == "linux"
}

// CheckSupported returns an error if the filesystem fence is not supported
// on the current operating system. The error message includes the current OS
// and guidance on future platform support.
func CheckSupported() error {
	if IsSupported() {
		return nil
	}
	return fmt.Errorf(
		"filesystem fence is not supported on %s (requires Linux LD_PRELOAD); macOS support coming soon",
		runtime.GOOS,
	)
}

// FenceEvent represents a filesystem access event reported by the C library.
// Events are sent as newline-delimited JSON over the Unix domain socket.
type FenceEvent struct {
	Type      string `json:"type"`
	Action    string `json:"action"`
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// Fence manages the filesystem fence lifecycle, including the Unix domain
// socket used to receive events from the LD_PRELOAD interposer and the
// environment variables needed to activate interposition in child processes.
type Fence struct {
	Config     *FenceConfig
	SocketPath string
	LibPath    string // Path to compiled libfence_fs.so
	listener   net.Listener
}

// NewFence creates a filesystem fence with a Unix domain socket.
// Returns an error if the OS is not supported. The caller must call Close
// when the fence is no longer needed to clean up the socket and temp directory.
func NewFence(cfg *FenceConfig, libPath string) (*Fence, error) {
	if err := CheckSupported(); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "nocklock-fs-*")
	if err != nil {
		return nil, fmt.Errorf("cannot create temp dir for fence socket: %w", err)
	}

	socketPath := filepath.Join(tmpDir, "fence.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		// Clean up the temp dir on listen failure.
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("cannot listen on fence socket %s: %w", socketPath, err)
	}

	return &Fence{
		Config:     cfg,
		SocketPath: socketPath,
		LibPath:    libPath,
		listener:   listener,
	}, nil
}

// EnvVars returns the environment variables needed to activate the filesystem
// fence in a child process. The returned slice contains LD_PRELOAD pointing to
// the interposer library and NOCKLOCK_FS_ALLOWED with the serialized config.
func (f *Fence) EnvVars() []string {
	return []string{
		"LD_PRELOAD=" + f.LibPath,
		"NOCKLOCK_FS_ALLOWED=" + f.Config.Serialize(f.SocketPath),
	}
}

// Listen reads fence events from the Unix domain socket in background goroutines.
// It returns a channel that receives parsed FenceEvent values. The channel is
// closed when the provided context is cancelled or the listener is closed.
func (f *Fence) Listen(ctx context.Context) <-chan FenceEvent {
	ch := make(chan FenceEvent, 64)

	// Close listener when context is done.
	go func() {
		<-ctx.Done()
		f.listener.Close()
	}()

	// Accept connections and handle each in a separate goroutine.
	go func() {
		defer close(ch)
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				// Listener was closed (context cancelled or Close called).
				return
			}
			go f.handleConn(ctx, conn, ch)
		}
	}()

	return ch
}

// handleConn reads newline-delimited JSON events from a single connection
// and sends parsed events to the channel.
func (f *Fence) handleConn(ctx context.Context, conn net.Conn, ch chan<- FenceEvent) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var event FenceEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			// Skip malformed lines.
			continue
		}
		select {
		case ch <- event:
		case <-ctx.Done():
			return
		}
	}
}

// Close stops listening and removes the socket directory.
func (f *Fence) Close() error {
	// Close the listener (safe to call multiple times on most implementations).
	listenerErr := f.listener.Close()

	// Remove the temp directory containing the socket.
	dir := filepath.Dir(f.SocketPath)
	removeErr := os.RemoveAll(dir)

	if listenerErr != nil {
		return fmt.Errorf("error closing listener: %w", listenerErr)
	}
	if removeErr != nil {
		return fmt.Errorf("error removing socket directory: %w", removeErr)
	}
	return nil
}
