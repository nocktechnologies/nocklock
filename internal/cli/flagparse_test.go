package cli

import (
	"testing"
)

func TestParseWrapFlagsNoFlags(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--", "echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.DryRun || flags.AllowPrivateRanges {
		t.Errorf("expected no flags set, got %+v", flags)
	}
	if len(childArgs) != 2 || childArgs[0] != "echo" || childArgs[1] != "hello" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsAllowPrivateRanges(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--allow-private-ranges", "--", "mycommand"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.AllowPrivateRanges {
		t.Error("expected AllowPrivateRanges to be true")
	}
	if len(childArgs) != 1 || childArgs[0] != "mycommand" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsDryRun(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--dry-run", "--", "cmd", "arg"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.DryRun {
		t.Error("expected DryRun to be true")
	}
	if len(childArgs) != 2 || childArgs[0] != "cmd" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsDryRunWithoutSeparator(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--dry-run"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.DryRun {
		t.Error("expected DryRun to be true")
	}
	if len(childArgs) != 0 {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsChildFlagsNotConsumed(t *testing.T) {
	// Flags after "--" belong to the child, not nocklock.
	flags, childArgs, err := parseWrapFlags([]string{"--", "cmd", "--dry-run"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.DryRun {
		t.Error("--dry-run after -- should not set DryRun")
	}
	if len(childArgs) != 2 || childArgs[1] != "--dry-run" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsNoSeparator(t *testing.T) {
	// No "--" separator: all args go to child, no nocklock flags parsed.
	flags, childArgs, err := parseWrapFlags([]string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.DryRun || flags.AllowPrivateRanges {
		t.Errorf("expected no flags, got %+v", flags)
	}
	if len(childArgs) != 2 || childArgs[0] != "echo" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsUnknownFlagBeforeSeparatorIsError(t *testing.T) {
	_, _, err := parseWrapFlags([]string{"--unknown-flag", "--", "cmd"})
	if err == nil {
		t.Error("expected error for unknown flag before --")
	}
}

func TestParseWrapFlagsAllowUnfencedIsRejected(t *testing.T) {
	_, _, err := parseWrapFlags([]string{"--allow-unfenced", "--", "cmd"})
	if err == nil {
		t.Error("expected error for removed --allow-unfenced flag")
	}
}

func TestParseWrapFlagsEmptyArgs(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.DryRun || flags.AllowPrivateRanges {
		t.Errorf("expected no flags, got %+v", flags)
	}
	if len(childArgs) != 0 {
		t.Errorf("expected empty child args, got %v", childArgs)
	}
}
