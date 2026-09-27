package main

import (
	"errors"
	"fmt"
	"os"
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

	checkDenied("truncate audit database", os.Truncate(auditDB, 0))
	checkDenied("unlink audit database", os.Remove(auditDB))
	checkDenied("write denied path", os.WriteFile(denied, []byte("blocked"), 0o600))
}

func checkDenied(operation string, err error) {
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		fmt.Fprintf(os.Stderr, "%s error = %v, want EACCES or EPERM\n", operation, err)
		os.Exit(1)
	}
}
