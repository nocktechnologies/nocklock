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
	if !strings.Contains(summary, "DENY") {
		t.Error("effective policy should mention default policy DENY")
	}
}

func TestEffectivePolicyAllowAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.AllowAll = true

	summary := cfg.EffectivePolicy()

	if !strings.Contains(summary, "allow_all") && !strings.Contains(summary, "ALLOW ALL") {
		t.Error("effective policy should indicate allow_all is set")
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
