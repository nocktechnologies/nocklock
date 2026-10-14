// Command anchor-v2-fixture appends real signed rows for the isolated NCC
// acceptance harness. It is test data, not a shipped NockLock command.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	if os.Geteuid() == 0 {
		return fmt.Errorf("never run the anchor fixture as root")
	}
	if len(os.Args) != 4 && len(os.Args) != 5 {
		return fmt.Errorf("usage: anchor-v2-fixture <db> <project> <count | init-identity [legacy-digest]>")
	}
	root := os.Getenv("NOCKLOCK_NCC_TEST_ROOT")
	if root == "" {
		return fmt.Errorf("isolated NCC harness root is required")
	}
	if _, err := os.Stat(filepath.Join(root, "harness-private-directory")); err != nil {
		return fmt.Errorf("isolated NCC harness marker: %w", err)
	}
	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return err
	}
	for _, path := range []string{os.Args[1], os.Args[2], key} {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || !filepath.IsLocal(rel) {
			return fmt.Errorf("fixture path must stay inside isolated NCC scratch directory")
		}
	}
	initialize := os.Args[3] == "init-identity"
	count := 0
	if !initialize {
		count, err = strconv.Atoi(os.Args[3])
		if err != nil || count < 1 || count > 20 || len(os.Args) != 4 {
			return fmt.Errorf("fixture count must be between 1 and 20")
		}
	}
	l, err := logging.NewLogger(os.Args[1], os.Args[2], logging.WithSigning(key))
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := l.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	if initialize {
		digest := strings.Repeat("0", 64)
		if len(os.Args) == 5 {
			digest = os.Args[4]
		}
		_, err := l.InitializeChainIdentity(digest)
		return err
	}
	for i := 0; i < count; i++ {
		if err := l.Log(logging.Event{Timestamp: time.Now().UTC(), EventType: logging.EventFileBlocked, Category: "filesystem",
			Detail: "isolated anchor protocol fixture: " + filepath.Base(os.Args[2]), Blocked: true, SessionID: "anchor-ncc-acceptance"}); err != nil {
			return err
		}
	}
	return nil
}
