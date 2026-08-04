package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// These tests exercise the classification/verdict logic over SYNTHETIC
// capability inputs only. They never exec, read /proc, or require root, so the
// suite is green regardless of the host — including CI runners whose real
// capabilities (unprivileged userns permitted, passwordless sudo present) are
// the inverse of the hardened VPS the probe was modelled on.

func blocked(detail string) nsAttemptResult {
	return nsAttemptResult{Status: nsBlocked, Detail: detail}
}
func permitted(detail string) nsAttemptResult {
	return nsAttemptResult{Status: nsPermitted, Detail: detail}
}
func toolMissing() nsAttemptResult {
	return nsAttemptResult{Status: nsToolMissing, Detail: "unshare(1) not found"}
}

// baseCaps returns a fully-stubbed linux capability set matching the receipted
// VPS posture (root-mapping denied); individual tests override what they need.
func baseCaps() egressProbeCapabilities {
	return egressProbeCapabilities{
		goos:                 "linux",
		arch:                 "amd64",
		kernelRelease:        func() string { return "7.0.0-27-generic" },
		distro:               func() string { return "Ubuntu 26.04 LTS" },
		unprivUsernsClone:    func() (string, bool) { return "1", true },
		apparmorRestrict:     func() (string, bool) { return "1", true },
		tryUsernsMapped:      func() nsAttemptResult { return blocked("uid_map: Operation not permitted") },
		tryUserNetnsMapped:   func() nsAttemptResult { return blocked("uid_map: Operation not permitted") },
		tryUserNetnsUnmapped: func() nsAttemptResult { return permitted("succeeded") },
		nftVersion:           func() (string, bool) { return "nftables v1.1.6", true },
		nftTproxyModule:      func() bool { return true },
		sudoNonInteractive:   func() bool { return true },
	}
}

func findCheck(t *testing.T, report egressProbeReport, id string) egressProbeCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check with id %q in report; got %+v", id, report.Checks)
	return egressProbeCheck{}
}

func hasCheck(report egressProbeReport, id string) bool {
	for _, c := range report.Checks {
		if c.ID == id {
			return true
		}
	}
	return false
}

// The receipted VPS posture: root-mapped netns blocked, classic sysctl
// permissive, nft + passwordless sudo present. Expect the privileged-helper
// track, marked reachable-not-confirmed, plus the uid-map-write-gate cause
// (because the unmapped path succeeds).
func TestEgressProbeVPSPostureYieldsPrivilegedHelperTrack(t *testing.T) {
	report := runEgressProbe(baseCaps())

	if report.Track != trackPrivilegedHelper {
		t.Fatalf("track = %q, want %q", report.Track, trackPrivilegedHelper)
	}
	if report.Schema != egressProbeSchema {
		t.Fatalf("schema = %q, want %q", report.Schema, egressProbeSchema)
	}
	if report.Host.KernelRelease != "7.0.0-27-generic" || report.Host.Distro != "Ubuntu 26.04 LTS" {
		t.Fatalf("host identity not populated: %+v", report.Host)
	}

	track := findCheck(t, report, "track")
	if track.Status != trackPrivilegedHelper || track.Evidence != evidenceNotProbed {
		t.Fatalf("track check = %+v, want status=%s evidence=%s (reachable, not confirmed)",
			track, trackPrivilegedHelper, evidenceNotProbed)
	}

	cause := findCheck(t, report, "unprivileged-userns-cause")
	if cause.Status != "uid-map-write-gate" || cause.Evidence != evidenceIndicated {
		t.Fatalf("cause check = %+v, want uid-map-write-gate/indicated", cause)
	}
}

// The unmapped discriminator row must always be present so drift is visible on
// every run.
func TestEgressProbeRecordsUnmappedDiscriminator(t *testing.T) {
	report := runEgressProbe(baseCaps())
	disc := findCheck(t, report, "unprivileged-userns-netns-unmapped")
	if disc.Status != nsPermitted {
		t.Fatalf("unmapped discriminator = %+v, want permitted", disc)
	}
}

// Root-mapped netns succeeds → unprivileged-clean, observed. No helper needed,
// and no cause attribution (mapped userns wasn't blocked).
func TestEgressProbeUnprivilegedCleanWhenMappedNetnsPermitted(t *testing.T) {
	caps := baseCaps()
	caps.tryUsernsMapped = func() nsAttemptResult { return permitted("succeeded") }
	caps.tryUserNetnsMapped = func() nsAttemptResult { return permitted("succeeded") }
	caps.apparmorRestrict = func() (string, bool) { return "0", true }

	report := runEgressProbe(caps)

	if report.Track != trackUnprivilegedClean {
		t.Fatalf("track = %q, want %q", report.Track, trackUnprivilegedClean)
	}
	track := findCheck(t, report, "track")
	if track.Evidence != evidenceObserved {
		t.Fatalf("unprivileged-clean track should be observed, got %+v", track)
	}
	if hasCheck(report, "unprivileged-userns-cause") {
		t.Fatal("should not attribute a cause when mapped userns is permitted")
	}
}

// Mapped netns blocked and no privileged path (no sudo) → blocked track.
func TestEgressProbeBlockedWhenNoPrivilegedPath(t *testing.T) {
	caps := baseCaps()
	caps.sudoNonInteractive = func() bool { return false }

	report := runEgressProbe(caps)

	if report.Track != trackBlocked {
		t.Fatalf("track = %q, want %q", report.Track, trackBlocked)
	}
	track := findCheck(t, report, "track")
	if track.Status != trackBlocked || track.Evidence != evidenceObserved {
		t.Fatalf("blocked track check = %+v", track)
	}
}

// Mapped netns blocked, sudo present but nft absent → still blocked (no usable
// redirect mechanism), not a false privileged-helper claim.
func TestEgressProbeBlockedWhenNftAbsent(t *testing.T) {
	caps := baseCaps()
	caps.nftVersion = func() (string, bool) { return "", false }

	report := runEgressProbe(caps)

	if report.Track != trackBlocked {
		t.Fatalf("track = %q, want %q (sudo without nft is not a helper track)", report.Track, trackBlocked)
	}
}

// unshare missing → the attempt is not-probed, and the verdict must NOT read a
// missing tool as a hard block. With no privileged path either, the track is
// undetermined (not blocked).
func TestEgressProbeUndeterminedWhenUnshareMissing(t *testing.T) {
	caps := baseCaps()
	caps.tryUsernsMapped = toolMissing
	caps.tryUserNetnsMapped = toolMissing
	caps.tryUserNetnsUnmapped = toolMissing
	caps.sudoNonInteractive = func() bool { return false }

	report := runEgressProbe(caps)

	if report.Track != trackUndetermined {
		t.Fatalf("track = %q, want %q (missing tool is not a denied capability)", report.Track, trackUndetermined)
	}
	attempt := findCheck(t, report, "unprivileged-userns-netns")
	if attempt.Status != nsToolMissing || attempt.Evidence != evidenceNotProbed {
		t.Fatalf("missing-tool attempt = %+v, want unavailable/not-probed", attempt)
	}
	if hasCheck(report, "unprivileged-userns-cause") {
		t.Fatal("must not attribute a cause when the attempt was not probed")
	}
}

// unshare missing but a privileged path IS reachable → privileged-helper still
// applies (reachability is independent of the unprivileged probe).
func TestEgressProbePrivilegedHelperWhenUnshareMissingButSudoPresent(t *testing.T) {
	caps := baseCaps()
	caps.tryUsernsMapped = toolMissing
	caps.tryUserNetnsMapped = toolMissing
	caps.tryUserNetnsUnmapped = toolMissing

	report := runEgressProbe(caps)
	if report.Track != trackPrivilegedHelper {
		t.Fatalf("track = %q, want %q", report.Track, trackPrivilegedHelper)
	}
}

// Classic sysctl NOT permissive (=0): neither cause branch should fire, because
// the classic knob is not ruled out.
func TestEgressProbeNoCauseWhenClassicSysctlRestrictive(t *testing.T) {
	caps := baseCaps()
	caps.unprivUsernsClone = func() (string, bool) { return "0", true }

	report := runEgressProbe(caps)
	if hasCheck(report, "unprivileged-userns-cause") {
		t.Fatal("must not attribute a cause when the classic sysctl is restrictive")
	}
}

// Mapped userns blocked, classic sysctl permissive, unmapped ALSO blocked, and
// AppArmor =1 → apparmor-gate attribution (full userns denial, not just the map
// write).
func TestEgressProbeAppArmorGateWhenUnmappedAlsoBlocked(t *testing.T) {
	caps := baseCaps()
	caps.tryUserNetnsUnmapped = func() nsAttemptResult { return blocked("Operation not permitted") }

	report := runEgressProbe(caps)
	cause := findCheck(t, report, "unprivileged-userns-cause")
	if cause.Status != "apparmor-gate" || cause.Evidence != evidenceIndicated {
		t.Fatalf("cause = %+v, want apparmor-gate/indicated", cause)
	}
}

// Mapped userns blocked, classic sysctl permissive, unmapped blocked, AppArmor
// not =1 → unattributed/indicated (not falsely pinned on AppArmor).
func TestEgressProbeUnattributedCauseWhenAppArmorNotSet(t *testing.T) {
	caps := baseCaps()
	caps.tryUserNetnsUnmapped = func() nsAttemptResult { return blocked("Operation not permitted") }
	caps.apparmorRestrict = func() (string, bool) { return "", false }

	report := runEgressProbe(caps)
	cause := findCheck(t, report, "unprivileged-userns-cause")
	if cause.Status != "unattributed" || cause.Evidence != evidenceIndicated {
		t.Fatalf("cause = %+v, want unattributed/indicated", cause)
	}
}

// Absent sysctls report status "absent" with observed evidence, and the probe
// still completes with a verdict.
func TestEgressProbeHandlesAbsentSysctls(t *testing.T) {
	caps := baseCaps()
	caps.unprivUsernsClone = func() (string, bool) { return "", false }
	caps.apparmorRestrict = func() (string, bool) { return "", false }

	report := runEgressProbe(caps)
	sc := findCheck(t, report, "unprivileged-userns-clone")
	if sc.Status != "absent" || sc.Evidence != evidenceObserved {
		t.Fatalf("absent sysctl check = %+v", sc)
	}
}

// Non-Linux hosts short-circuit to unsupported without invoking any probe
// function field (all nil here — a panic would mean a field was called).
func TestEgressProbeUnsupportedOnNonLinux(t *testing.T) {
	report := runEgressProbe(egressProbeCapabilities{goos: "darwin", arch: "arm64"})
	if report.Track != trackUnsupported {
		t.Fatalf("track = %q, want %q", report.Track, trackUnsupported)
	}
	if len(report.Checks) != 1 || report.Checks[0].ID != "platform" {
		t.Fatalf("expected a single platform check, got %+v", report.Checks)
	}
}

// The --json path emits a parseable document with the versioned schema and exits 0.
func TestEgressProbeJSONShape(t *testing.T) {
	restore := stubEgressProbeCapabilities(baseCaps())
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := egressProbeCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("egress-probe --json should exit 0 on a completed probe: %v", err)
	}

	var got egressProbeReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if got.Schema != egressProbeSchema {
		t.Fatalf("schema = %q, want %q", got.Schema, egressProbeSchema)
	}
	if got.Track != trackPrivilegedHelper {
		t.Fatalf("track = %q, want %q", got.Track, trackPrivilegedHelper)
	}
	if len(got.Checks) == 0 {
		t.Fatal("expected structured checks")
	}
}

// The human path renders host identity, per-check lines, and the verdict.
func TestEgressProbeHumanRender(t *testing.T) {
	restore := stubEgressProbeCapabilities(baseCaps())
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := egressProbeCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("egress-probe should exit 0: %v", err)
	}
	s := out.String()
	for _, want := range []string{"7.0.0-27-generic", "Ubuntu 26.04 LTS", "TRACK: " + trackPrivilegedHelper} {
		if !strings.Contains(s, want) {
			t.Fatalf("human output missing %q:\n%s", want, s)
		}
	}
}

func stubEgressProbeCapabilities(c egressProbeCapabilities) func() {
	orig := currentEgressProbeCapabilities
	currentEgressProbeCapabilities = c
	return func() { currentEgressProbeCapabilities = orig }
}
