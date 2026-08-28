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

func TestParseWrapFlagsProfile(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--profile", "codex", "--", "cmd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.Profile != "codex" {
		t.Fatalf("Profile = %q, want codex", flags.Profile)
	}
	if len(childArgs) != 1 || childArgs[0] != "cmd" {
		t.Fatalf("unexpected child args: %v", childArgs)
	}
}

// TestParseWrapFlagsNetFence verifies both supported net-fence flag forms.
func TestParseWrapFlagsNetFence(t *testing.T) {
	// Both the space and =-joined forms select the netns floor.
	for _, args := range [][]string{
		{"--net-fence", "netns", "--", "cmd"},
		{"--net-fence=netns", "--", "cmd"},
	} {
		flags, childArgs, err := parseWrapFlags(args)
		if err != nil {
			t.Fatalf("args %v: unexpected error: %v", args, err)
		}
		if flags.NetFence != "netns" {
			t.Fatalf("args %v: NetFence = %q, want netns", args, flags.NetFence)
		}
		if len(childArgs) != 1 || childArgs[0] != "cmd" {
			t.Fatalf("args %v: unexpected child args: %v", args, childArgs)
		}
	}
}

// TestParseWrapFlagsNetFenceDefaultsEmpty verifies the default net-fence mode.
func TestParseWrapFlagsNetFenceDefaultsEmpty(t *testing.T) {
	// Negative control: without the flag, NetFence stays empty — default wrap
	// behavior is unchanged.
	flags, _, err := parseWrapFlags([]string{"--", "cmd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.NetFence != "" {
		t.Fatalf("NetFence = %q, want empty by default", flags.NetFence)
	}
}

// TestParseWrapFlagsNetFenceUnknownValueRejected verifies invalid net-fence values fail.
func TestParseWrapFlagsNetFenceUnknownValueRejected(t *testing.T) {
	// A typo must be rejected, never silently degraded to "no fence".
	if _, _, err := parseWrapFlags([]string{"--net-fence=bogus", "--", "cmd"}); err == nil {
		t.Fatal("expected an error for an unknown --net-fence value, got nil")
	}
	// An empty =-value must error, not select the default.
	if _, _, err := parseWrapFlags([]string{"--net-fence=", "--", "cmd"}); err == nil {
		t.Fatal("expected an error for an empty --net-fence value, got nil")
	}
	// --net-fence with no following value in the flag region must error.
	if _, _, err := parseWrapFlags([]string{"--net-fence", "--"}); err == nil {
		t.Fatal("expected an error for --net-fence with no value, got nil")
	}
}

func TestParseWrapFlagsProfileEquals(t *testing.T) {
	flags, childArgs, err := parseWrapFlags([]string{"--profile=claude-code", "--dry-run"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.Profile != "claude-code" || !flags.DryRun {
		t.Fatalf("unexpected flags: %+v", flags)
	}
	if len(childArgs) != 0 {
		t.Fatalf("unexpected child args: %v", childArgs)
	}
}

func TestParseWrapFlagsProfileRequiresValue(t *testing.T) {
	_, _, err := parseWrapFlags([]string{"--profile", "--", "cmd"})
	if err == nil {
		t.Fatal("expected --profile without value to fail")
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
