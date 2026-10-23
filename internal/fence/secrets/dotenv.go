package secrets

import (
	"context"
	"os"
	"regexp"
	"strings"
)

var dotEnvSecretName = regexp.MustCompile(`(?i)(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|DATABASE_URL)(?:_|$)`)

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
		value = dotEnvValue(value)
		if ok && dotEnvSecretName.MatchString(strings.TrimSpace(name)) && value != "" {
			s.report.Findings = append(s.report.Findings, Finding{"dotenv-secret-assignment", "file", scanLocation(path), i + 1})
		}
	}
}

// dotEnvValue returns the literal text of a raw .env value. A single-quoted
// value is literal, with no substitution. A double-quoted or unquoted value is
// parsed for references by dotEnvLiteral, and an unquoted value ends at an
// inline comment: whitespace then #.
func dotEnvValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value != "" && (value[0] == '\'' || value[0] == '"') {
		body, _, _ := strings.Cut(value[1:], value[:1])
		if value[0] == '\'' {
			return body
		}
		return dotEnvLiteral(body)
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
			raw = raw[:i]
			break
		}
	}
	return dotEnvLiteral(strings.TrimSpace(raw))
}

// dotEnvLiteral returns literal text written in the value itself: text outside
// any reference, or the inline default of a ${NAME:-default}, ${NAME:=default}
// or ${NAME:+alternate} reference (colon optional, nesting allowed). It returns
// "" for pure substitutions such as $A, ${A}${B} or ${A:-$B}${C}, and for an
// unbalanced reference. Each ${...} is matched by brace depth in one pass, so
// back-to-back references stay separate and deep nesting stays linear.
func dotEnvLiteral(value string) string {
	value = strings.Trim(value, "\"'")
	isName := func(c byte) bool {
		return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
	}
	literal := ""
	// One entry per open ${: true when its body is a literal default or
	// alternate in a literal context, false for a plain name or another
	// operator's argument such as a ${NAME?message}.
	var open []bool
	for i := 0; i < len(value); {
		switch {
		case value[i] == '}' && len(open) > 0:
			open = open[:len(open)-1]
			i++
		case strings.HasPrefix(value[i:], "${"):
			j := i + 2
			for j < len(value) && isName(value[j]) {
				j++
			}
			named := j > i+2
			if named && j < len(value) && value[j] == ':' {
				j++
			}
			defaulted := named && j < len(value) && strings.IndexByte("-=+", value[j]) >= 0
			if defaulted {
				j++
			}
			open = append(open, defaulted && (len(open) == 0 || open[len(open)-1]))
			i = j
		case value[i] == '$' && i+1 < len(value) && isName(value[i+1]):
			for i++; i < len(value) && isName(value[i]); i++ {
			}
		default:
			if literal == "" && (len(open) == 0 || open[len(open)-1]) {
				end := strings.IndexAny(value[i:], "${}")
				if end < 0 {
					end = len(value) - i
				}
				literal = value[i : i+end]
			}
			i++
		}
	}
	if len(open) > 0 {
		return ""
	}
	return literal
}
