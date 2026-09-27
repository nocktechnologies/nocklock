// Command staticprobe applies a NockLock Landlock ruleset to itself and then
// exercises the fence boundary from inside it. It is built with CGO_ENABLED=0
// so it is a STATIC binary: the LD_PRELOAD interposer cannot load into it, which
// makes every result below attributable to the kernel ruleset alone.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: staticprobe ROOT AUDIT_DB DENIED_PATH")
		os.Exit(2)
	}
	root, auditDB, denied := os.Args[1], os.Args[2], os.Args[3]
	abi, err := landlock.DetectABI()
	if err != nil || abi == 0 {
		fmt.Fprintf(os.Stderr, "detect Landlock ABI: abi=%d err=%v\n", abi, err)
		os.Exit(1)
	}
	spec, err := landlock.RulesFromConfig(&fsfence.FenceConfig{
		Root:      root,
		Mode:      "read-write",
		DenyPaths: []string{denied},
	}, nil, abi)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build Landlock rules: %v\n", err)
		os.Exit(1)
	}
	if err := landlock.Apply(spec); err != nil {
		fmt.Fprintf(os.Stderr, "apply Landlock rules: %v\n", err)
		os.Exit(1)
	}

	// The fence root is usable: the child creates and removes an entry DIRECTLY
	// IN the root, not merely inside a subdirectory that already existed.
	created := filepath.Join(root, "created-by-child")
	checkAllowed("create file in fence root", os.WriteFile(created, []byte("agent output"), 0o600))
	checkAllowed("mkdir in fence root", os.Mkdir(filepath.Join(root, "dir-by-child"), 0o755))
	checkAllowed("remove file in fence root", os.Remove(created))
	checkAllowed("remove dir in fence root", os.Remove(filepath.Join(root, "dir-by-child")))

	// Negative control for the relocated audit trail. The event log lives
	// outside the fence root, so the root grant above does not reach it and no
	// mutation of the audit chain succeeds.
	checkDenied("write audit database", os.WriteFile(auditDB, []byte("forged"), 0o600))
	checkDenied("truncate audit database", os.Truncate(auditDB, 0))
	checkDenied("unlink audit database", os.Remove(auditDB))
	checkDenied("rename audit database", os.Rename(auditDB, auditDB+".moved"))
	checkDenied("create file in audit directory", os.WriteFile(filepath.Join(filepath.Dir(auditDB), "planted"), []byte("x"), 0o600))
	checkDenied("remove audit directory", os.Remove(filepath.Dir(auditDB)))

	checkDenied("write denied path", os.WriteFile(denied, []byte("blocked"), 0o600))
}

func checkAllowed(operation string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s should have been permitted, got: %v\n", operation, err)
		os.Exit(1)
	}
}

func checkDenied(operation string, err error) {
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		fmt.Fprintf(os.Stderr, "%s error = %v, want EACCES or EPERM\n", operation, err)
		os.Exit(1)
	}
}
