package cli

import (
	"testing"
)

func TestParseWrapFlagsNoFlags(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--", "echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.AllowUnfenced || flags.AllowPrivateRanges {
		t.Errorf("expected no flags set, got %+v", flags)
	}
	if len(childArgs) != 2 || childArgs[0] != "echo" || childArgs[1] != "hello" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsAllowUnfenced(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--allow-unfenced", "--", "echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.AllowUnfenced {
		t.Error("expected AllowUnfenced to be true")
	}
	if flags.AllowPrivateRanges {
		t.Error("expected AllowPrivateRanges to be false")
	}
	if len(childArgs) != 2 || childArgs[0] != "echo" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsAllowPrivateRanges(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--allow-private-ranges", "--", "mycommand"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.AllowUnfenced {
		t.Error("expected AllowUnfenced to be false")
	}
	if !flags.AllowPrivateRanges {
		t.Error("expected AllowPrivateRanges to be true")
	}
	if len(childArgs) != 1 || childArgs[0] != "mycommand" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsBothFlags(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--allow-unfenced", "--allow-private-ranges", "--", "cmd", "arg"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.AllowUnfenced {
		t.Error("expected AllowUnfenced to be true")
	}
	if !flags.AllowPrivateRanges {
		t.Error("expected AllowPrivateRanges to be true")
	}
	if len(childArgs) != 2 || childArgs[0] != "cmd" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsChildFlagsNotConsumed(t *testing.T) {
	// Flags after "--" belong to the child, not nocklock.
	flags, childArgs, err := parseWrapFlags([]string{"--", "cmd", "--allow-unfenced"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.AllowUnfenced {
		t.Error("--allow-unfenced after -- should not set AllowUnfenced")
	}
	if len(childArgs) != 2 || childArgs[1] != "--allow-unfenced" {
		t.Errorf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsNoSeparator(t *testing.T) {
	// No "--" separator: all args go to child, no nocklock flags parsed.
	flags, childArgs, err := parseWrapFlags([]string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.AllowUnfenced || flags.AllowPrivateRanges {
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

func TestParseWrapFlagsEmptyArgs(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.AllowUnfenced || flags.AllowPrivateRanges {
		t.Errorf("expected no flags, got %+v", flags)
	}
	if len(childArgs) != 0 {
		t.Errorf("expected empty child args, got %v", childArgs)
	}
}
