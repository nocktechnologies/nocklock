package fs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// GenerateEffectiveProfile includes the mandatory home filename prefixes in the
// resolved policy. Prefix rules also protect names created after wrap starts.
func GenerateEffectiveProfile(fc *FenceConfig, hardened bool, tag string, proxyPort int) (string, int, error) {
	readPaths := slices.Concat(fc.ReadAllowPaths, fc.AllowPaths, fc.AllowRWPaths)
	profile, count, err := generateTaggedWriteConfinementProfile(fc.DenyPaths, fc.Root, fc.Mode, hardened, tag, proxyPort, fc.HomeReadRoot, readPaths, fc.AllowRWPaths, fc.ClaudeCodeCache)
	if err != nil {
		return "", 0, err
	}
	msg := ""
	if tag != "" {
		msg = " (with message " + sbplString(tag) + ")"
	}
	var b strings.Builder
	b.WriteString(profile)
	// Case-fold the additional matches explicitly: APFS can accept a spelling
	// different from the configured name. ASCII bracket classes work in SBPL.
	denyPath := func(path string) {
		filter := "(regex #" + sbplString("^"+caseFoldPattern(path)+"(/|$)") + ")"
		b.WriteString("(deny file-read* file-write* " + filter + msg + ")\n")
		if fc.HomeReadRoot != "" {
			b.WriteString("(deny file-read-data " + filter + msg + ")\n")
		}
	}
	for _, path := range fc.DenyPaths {
		denyPath(path)
	}
	for _, prefix := range fc.DenyPrefixes {
		if !filepath.IsAbs(prefix) {
			return "", 0, fmt.Errorf("credential prefix must be absolute")
		}
		filter := "(regex #" + sbplString("^"+caseFoldPattern(prefix)+".*") + ")"
		b.WriteString("(deny file-read* file-write* " + filter + msg + ")\n")
		if fc.HomeReadRoot != "" {
			b.WriteString("(deny file-read-data " + filter + msg + ")\n")
		}
		for p := filepath.Dir(prefix); filepath.Dir(p) != p; p = filepath.Dir(p) {
			b.WriteString("(deny file-write-unlink (literal " + sbplString(p) + ")" + msg + ")\n")
		}
	}
	if fc.OwnConfigDir != "" {
		// Seatbelt applies the last matching rule, so this follows every deny
		// above. Writes stay under the root write confinement.
		own, err := canonicalizeForProfile(fc.OwnConfigDir)
		if err != nil {
			return "", 0, fmt.Errorf("cannot canonicalize own config directory: %w", err)
		}
		b.WriteString("(allow file-read* (subpath " + sbplString(own) + "))\n")
		if fc.HomeReadRoot != "" {
			b.WriteString("(allow file-read-data (subpath " + sbplString(own) + "))\n")
		}
		// Configured denies inside the directory still win.
		for _, path := range fc.DenyPaths {
			if pathContains(strings.ToLower(own), strings.ToLower(path)) {
				denyPath(path)
			}
		}
	}
	return b.String(), count + len(fc.DenyPrefixes), nil
}

func caseFoldPattern(path string) string {
	var b strings.Builder
	for _, c := range path {
		if c >= 'a' && c <= 'z' {
			fmt.Fprintf(&b, "[%c%c]", c, c-'a'+'A')
		} else if c >= 'A' && c <= 'Z' {
			fmt.Fprintf(&b, "[%c%c]", c+'a'-'A', c)
		} else {
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
