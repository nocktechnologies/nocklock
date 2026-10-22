package secrets

import (
	"context"
	"os"
	"regexp"
	"strings"
)

var dotEnvSecretName = regexp.MustCompile(`(?i)(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|DATABASE_URL)(?:_|$)`)

// ScanDotEnv inspects only .env* files below root using the bounded, no-symlink
// preflight scanner. It returns metadata only and never changes the fence.
func ScanDotEnv(ctx context.Context, root string) ScanReport {
	s := scanner{ctx: ctx, dotenvOnly: true, report: ScanReport{Complete: true}, seen: make(map[string]bool)}
	r, err := os.OpenRoot(root)
	if err != nil {
		s.issue(".", "cannot open filesystem root for .env inspection")
		return s.report
	}
	defer r.Close()
	s.walk(r, ".", 0, nil)
	return s.report
}

func (s *scanner) inspectDotEnv(data []byte, path string) {
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		// Empty and environment-substituted values do not themselves expose a key.
		if ok && dotEnvSecretName.MatchString(strings.TrimSpace(name)) && value != "" && !strings.HasPrefix(value, "$") {
			s.report.Findings = append(s.report.Findings, Finding{"dotenv-secret-assignment", "file", scanLocation(path), i + 1})
		}
	}
}
