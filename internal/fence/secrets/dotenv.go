package secrets

import (
	"context"
	"os"
	"regexp"
	"strings"
)

var dotEnvSecretName = regexp.MustCompile(`(?i)(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|DATABASE_URL)(?:_|$)`)

// dotEnvDefault captures the literal written inside a ${NAME:-default},
// ${NAME:=default} or ${NAME:+alternate} reference (colon optional).
var dotEnvDefault = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+](.*)\}$`)

// ScanDotEnv inspects .env and .env.* files in root and its immediate child
// directories, excluding dependency and build directories. It uses the bounded,
// no-symlink preflight scanner, returns metadata only and never changes the fence.
// A complete report covers only this shallow scope, not every project secret.
func ScanDotEnv(ctx context.Context, root string) ScanReport {
	s := scanner{ctx: ctx, dotenvOnly: true, report: ScanReport{Complete: true}, seen: make(map[string]bool)}
	r, err := os.OpenRoot(root)
	if err != nil {
		s.issue(".", "cannot open filesystem root for .env inspection")
		return s.report
	}
	defer r.Close()
	s.walk(r, ".", 0, nil)
	if s.ctx.Err() != nil && !s.stopped {
		s.issue(".", "inspection cancelled; rerun the shallow check")
	}
	return s.report
}

func dotEnvName(name string) bool {
	name = strings.ToLower(name)
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

func dotEnvEntry(name string, directory bool, parentDepth int) bool {
	if !directory {
		return dotEnvName(name)
	}
	if parentDepth != 0 {
		return false
	}
	switch strings.ToLower(name) {
	case ".git", "node_modules", "bower_components", "vendor", ".venv", "venv",
		"build", "dist", "target", "coverage", "__pycache__", ".cache", ".next", ".nuxt", ".output", ".yarn", ".pnpm-store":
		return false
	}
	return true
}

func (s *scanner) inspectDotEnv(data []byte, path string) {
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		value = dotEnvLiteral(strings.TrimSpace(value))
		if ok && dotEnvSecretName.MatchString(strings.TrimSpace(name)) && value != "" {
			s.report.Findings = append(s.report.Findings, Finding{"dotenv-secret-assignment", "file", scanLocation(path), i + 1})
		}
	}
}

// dotEnvLiteral returns the part of a value written in the file itself: the
// value, or the inline default of a ${NAME:-default} reference. A plain
// environment substitution returns "": it does not itself expose a key.
func dotEnvLiteral(value string) string {
	value = strings.Trim(value, "\"'")
	if !strings.HasPrefix(value, "$") {
		return value
	}
	if m := dotEnvDefault.FindStringSubmatch(value); m != nil {
		return dotEnvLiteral(m[1])
	}
	return ""
}
