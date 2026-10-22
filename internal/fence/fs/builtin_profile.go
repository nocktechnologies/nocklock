package fs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// GenerateEffectiveProfile includes the mandatory home filename prefixes in the
// resolved policy. Prefix rules also protect names created after wrap starts.
func GenerateEffectiveProfile(fc *FenceConfig, hardened bool, tag string, proxyPort int) (string, int, error) {
	profile, count, err := GenerateTaggedWriteConfinementProfile(fc.DenyPaths, fc.Root, fc.Mode, hardened, tag, proxyPort)
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
	for _, path := range fc.DenyPaths {
		b.WriteString("(deny file-read* file-write* (regex #" + sbplString("^"+caseFoldPattern(path)+"(/|$)") + ")" + msg + ")\n")
	}
	for _, prefix := range fc.DenyPrefixes {
		if !filepath.IsAbs(prefix) {
			return "", 0, fmt.Errorf("credential prefix must be absolute")
		}
		b.WriteString("(deny file-read* file-write* (regex #" + sbplString("^"+caseFoldPattern(prefix)+".*") + ")" + msg + ")\n")
		for p := filepath.Dir(prefix); filepath.Dir(p) != p; p = filepath.Dir(p) {
			b.WriteString("(deny file-write-unlink (literal " + sbplString(p) + ")" + msg + ")\n")
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
