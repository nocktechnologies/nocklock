//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func TestAnchorEmitNilContextAndV2FileConfirmation(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedSignedChain(t, db, key, 1)
	emitRemoteAnchorNow(t, db, key)
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{{"nil", nil}, {"background", context.Background()}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.json")
			var out bytes.Buffer
			if err := runAnchorEmit(tc.ctx, &out, path); err != nil {
				t.Fatal(err)
			}
			anchor, err := logging.ReadAnchorV2(path)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("anchor written to %s (row_count=%d, head=%s)\n", path, anchor.RowCount, anchor.HeadHash)
			if out.String() != want {
				t.Fatalf("v2 file confirmation=%q want=%q", out.String(), want)
			}
		})
	}
}

func TestAnchorV2FileMissingKeyReportsNoKey(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedSignedChain(t, db, key, 1)
	anchor := emitRemoteAnchorNow(t, db, key)
	path := filepath.Join(t.TempDir(), "anchor.json")
	if err := logging.WriteAnchorV2(path, anchor); err != nil {
		t.Fatal(err)
	}
	var allowed bytes.Buffer
	if err := runVerifyAgainstAnchor(context.Background(), &allowed, path, ""); err != nil {
		t.Fatalf("valid-key control: %v %s", err, allowed.String())
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runVerifyAgainstAnchor(context.Background(), &out, path, ""); err == nil || !strings.HasPrefix(out.String(), "ANCHOR: NO_KEY — no public key available to authenticate the anchor") || !strings.Contains(out.String(), "--ed25519-pub") {
		t.Fatalf("missing key: %v %s", err, out.String())
	}
}
