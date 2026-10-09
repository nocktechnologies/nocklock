package config

import (
	"strings"
	"testing"
)

func TestValidateDefaultConfigPasses(t *testing.T) {
	cfg := DefaultConfig()
	errs := Validate(&cfg)
	for _, e := range errs {
		if e.Severity == "error" {
			t.Errorf("default config should pass validation, got error: %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateAuditForward(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audit.Forward = ForwardConfig{Enabled: true, URL: "https://cc.nocktechnologies.io", APIKeyEnv: "NOCKLOCK_FORWARD_KEY"}
	if errs := Validate(&cfg); hasError(errs, "audit.forward.url") || hasError(errs, "audit.forward.api_key_env") {
		t.Fatalf("valid forwarding config rejected: %v", errs)
	}
	for _, url := range []string{"", "http://example.com", "https://user:pass@example.com", "https://example.com/other", "https://example.com?key=secret"} {
		cfg.Audit.Forward.URL = url
		if !hasError(Validate(&cfg), "audit.forward.url") {
			t.Errorf("unsafe URL %q accepted", url)
		}
	}
	cfg.Audit.Forward.URL = "https://cc.nocktechnologies.io"
	cfg.Audit.Forward.APIKeyEnv = "AWS_SECRET_ACCESS_KEY"
	if !hasError(Validate(&cfg), "audit.forward.api_key_env") {
		t.Error("arbitrary operator credential name accepted")
	}
}

func TestValidateInvalidFilesystemMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.Mode = "full-access" // invalid
	errs := Validate(&cfg)
	if !hasError(errs, "filesystem.mode") {
		t.Error("expected validation error for invalid filesystem.mode")
	}
}

func TestValidateValidFilesystemModes(t *testing.T) {
	for _, mode := range []string{"read-write", "read-only", ""} {
		cfg := DefaultConfig()
		cfg.Filesystem.Mode = mode
		errs := Validate(&cfg)
		for _, e := range errs {
			if e.Severity == "error" && e.Field == "filesystem.mode" {
				t.Errorf("mode %q should be valid, got error: %s", mode, e.Message)
			}
		}
	}
}

func TestValidateLinuxEnforcement(t *testing.T) {
	for _, mode := range []string{"required", "preferred", "off", ""} {
		cfg := DefaultConfig()
		cfg.Filesystem.LinuxEnforcement = mode
		errs := Validate(&cfg)
		for _, e := range errs {
			if e.Severity == "error" && e.Field == "filesystem.linux_enforcement" {
				t.Errorf("linux_enforcement %q should be valid, got error: %s", mode, e.Message)
			}
		}
	}
}

func TestValidateInvalidLinuxEnforcement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.LinuxEnforcement = "optional"
	errs := Validate(&cfg)
	if !hasError(errs, "filesystem.linux_enforcement") {
		t.Error("expected validation error for invalid filesystem.linux_enforcement")
	}
}

func TestValidateInvalidLoggingLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Level = "verbose" // invalid
	errs := Validate(&cfg)
	if !hasError(errs, "logging.level") {
		t.Error("expected validation error for invalid logging.level")
	}
}

func TestValidateValidLoggingLevels(t *testing.T) {
	for _, level := range []string{"info", "debug", "warn", "error", ""} {
		cfg := DefaultConfig()
		cfg.Logging.Level = level
		errs := Validate(&cfg)
		for _, e := range errs {
			if e.Severity == "error" && e.Field == "logging.level" {
				t.Errorf("level %q should be valid, got error: %s", level, e.Message)
			}
		}
	}
}

func TestValidateCloudEnabledRequiresAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloud.Enabled = true
	cfg.Cloud.APIKey = "" // missing
	errs := Validate(&cfg)
	if !hasError(errs, "cloud.api_key") {
		t.Error("expected validation error: cloud.enabled=true requires api_key")
	}
}

func TestValidateCloudEnabledWithAPIKeyPasses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloud.Enabled = true
	cfg.Cloud.APIKey = "tok_test"
	errs := Validate(&cfg)
	for _, e := range errs {
		if e.Severity == "error" && e.Field == "cloud.api_key" {
			t.Errorf("cloud with valid api_key should pass, got: %s", e.Message)
		}
	}
}

func TestValidateDenyPathTraversal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, "../etc/passwd")
	errs := Validate(&cfg)
	if !hasError(errs, "filesystem.deny") {
		t.Error("expected validation error for path traversal in deny list")
	}
}

func TestValidateDenyCleanPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.Deny = []string{"/etc/passwd", "~/.ssh/", "/tmp/secrets"}
	errs := Validate(&cfg)
	for _, e := range errs {
		if e.Severity == "error" && e.Field == "filesystem.deny" {
			t.Errorf("clean deny paths should pass, got: %s", e.Message)
		}
	}
}

func TestValidateAllowPathTraversal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.Allow = append(cfg.Filesystem.Allow, "../../../tmp")
	errs := Validate(&cfg)
	if !hasError(errs, "filesystem.allow") {
		t.Error("expected validation error for path traversal in allow list")
	}
}

func TestValidateAllowRWPathTraversal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.AllowRW = []string{"../../state"}
	errs := Validate(&cfg)
	if !hasError(errs, "filesystem.allow_rw") {
		t.Error("expected validation error for path traversal in allow_rw list")
	}
}

func TestValidateRejectsEmptyAllowRW(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.AllowRW = []string{""}
	if errs := Validate(&cfg); !hasError(errs, "filesystem.allow_rw") {
		t.Fatal("expected validation error for empty allow_rw entry")
	}
}

func TestEffectivePolicySummary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.Allow = []string{"github.com", "api.anthropic.com"}
	cfg.Filesystem.Root = "/home/agent/project"
	cfg.Filesystem.Mode = "read-write"

	summary := cfg.EffectivePolicy()

	if !strings.Contains(summary, "2") {
		t.Error("effective policy should mention domain count (2)")
	}
	if !strings.Contains(summary, "github.com") {
		t.Error("effective policy should list allowed domains")
	}
	if !strings.Contains(summary, "read-write") {
		t.Error("effective policy should mention filesystem mode")
	}
	if !strings.Contains(summary, "linux_enforcement=required") {
		t.Error("effective policy should mention Linux enforcement mode")
	}
	if !strings.Contains(summary, "DENY") {
		t.Error("effective policy should mention default policy DENY")
	}
}

func TestEffectivePolicyAllowAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.AllowAll = true
	cfg.Network.AllowPrivateRanges = true

	summary := cfg.EffectivePolicy()

	if !strings.Contains(summary, "allow_all") && !strings.Contains(summary, "ALLOW ALL") {
		t.Error("effective policy should indicate allow_all is set")
	}
	if strings.Contains(summary, "private_ranges=") {
		t.Fatalf("effective policy should not show private range settings when allow_all disables the network fence, got:\n%s", summary)
	}
}

func TestEffectivePolicyShowsPrivateRangeSetting(t *testing.T) {
	cfg := DefaultConfig()

	summary := cfg.EffectivePolicy()
	if !strings.Contains(summary, "private_ranges=blocked") {
		t.Fatalf("effective policy should show private ranges blocked by default, got:\n%s", summary)
	}

	cfg.Network.AllowPrivateRanges = true
	summary = cfg.EffectivePolicy()
	if !strings.Contains(summary, "private_ranges=allowed") {
		t.Fatalf("effective policy should show private ranges allowed when configured, got:\n%s", summary)
	}
}

// hasError returns true if errs contains an error-severity entry for the given field.
func hasError(errs []ValidationError, field string) bool {
	for _, e := range errs {
		if e.Field == field && e.Severity == "error" {
			return true
		}
	}
	return false
}

func lookbackRule(name, on, within, then string) LookbackRule {
	return LookbackRule{Name: name, On: on, Within: within, Then: then}
}

// Test 7 (config half): a rule that cannot fire is a config error. Control: a
// valid rule loads.
func TestValidateLookback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.Lookback = []LookbackRule{
		lookbackRule("a", "file_blocked", "", "deny_egress"),
		lookbackRule("b", "file_blocked", "10m", "deny_egress"),
	}
	for _, e := range Validate(&cfg) {
		if e.Severity == "error" {
			t.Fatalf("valid look-back rules rejected: %s: %s", e.Field, e.Message)
		}
	}

	cases := []struct {
		name  string
		rules []LookbackRule
		field string
	}{
		{"unknown on", []LookbackRule{lookbackRule("a", "file_open", "", "deny_egress")}, "network.lookback[0].on"},
		{"on that is never blocked", []LookbackRule{lookbackRule("a", "file_passed", "", "deny_egress")}, "network.lookback[0].on"},
		{"dotted config.digest", []LookbackRule{lookbackRule("a", "config.digest", "", "deny_egress")}, "network.lookback[0].on"},
		{"underscored config_digest", []LookbackRule{lookbackRule("a", "config_digest", "", "deny_egress")}, "network.lookback[0].on"},
		{"blocked type slice 1 does not wire: secret_blocked", []LookbackRule{lookbackRule("a", "secret_blocked", "", "deny_egress")}, "network.lookback[0].on"},
		{"blocked type slice 1 does not wire: network_error", []LookbackRule{lookbackRule("a", "network_error", "", "deny_egress")}, "network.lookback[0].on"},
		{"empty on", []LookbackRule{lookbackRule("a", "", "", "deny_egress")}, "network.lookback[0].on"},
		{"unknown then", []LookbackRule{lookbackRule("a", "file_blocked", "", "allow_egress")}, "network.lookback[0].then"},
		{"empty then", []LookbackRule{lookbackRule("a", "file_blocked", "", "")}, "network.lookback[0].then"},
		{"unparseable within", []LookbackRule{lookbackRule("a", "file_blocked", "ten minutes", "deny_egress")}, "network.lookback[0].within"},
		{"zero within", []LookbackRule{lookbackRule("a", "file_blocked", "0s", "deny_egress")}, "network.lookback[0].within"},
		{"negative within", []LookbackRule{lookbackRule("a", "file_blocked", "-5m", "deny_egress")}, "network.lookback[0].within"},
		{"empty name", []LookbackRule{lookbackRule(" ", "file_blocked", "", "deny_egress")}, "network.lookback[0].name"},
		{"duplicate name", []LookbackRule{lookbackRule("a", "file_blocked", "", "deny_egress"), lookbackRule("a", "file_blocked", "", "deny_egress")}, "network.lookback[1].name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network.Lookback = tc.rules
			if !hasError(Validate(&cfg), tc.field) {
				t.Fatalf("Validate accepted %+v, want an error on %s", tc.rules, tc.field)
			}
		})
	}
}
