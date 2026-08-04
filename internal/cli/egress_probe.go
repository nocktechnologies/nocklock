package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

// egress_probe.go implements `nocklock egress-probe`: a repeatable, structured
// feasibility probe for the Linux network-egress-enforcement track (see
// docs/superpowers/specs/2026-07-30-linux-network-egress-enforcement.md). It
// codifies the Phase 0 VPS probe runs so that every fleet kernel — CI runners
// included — is measured the same way before Phase 1 locks the privileged-helper
// design.
//
// Fidelity to the receipt is the point. The spec's Phase 0 table rows are literal
// `unshare` invocations; "probed the same way" means the same command, not a
// Go-native reimplementation that could answer differently (an equivalent-looking
// clone with a parent-written uid_map takes a different privilege path and can
// report a more-permissive false green). So the namespace attempts here shell out
// to `unshare` with the receipted flags verbatim.
//
// Scope of THIS tool (Phase 0, deliverable 1): the non-mutating feasibility
// checks only —
//   - unprivileged userns / userns+netns creation via `unshare` (subprocess, so
//     a successful clone never alters the probe's own credentials);
//   - the two sysctls that decide the classic-vs-AppArmor cause
//     (unprivileged_userns_clone, apparmor_restrict_unprivileged_userns);
//   - nftables binary + nft_tproxy module presence;
//   - passwordless-sudo reachability for the privileged-helper track.
//
// It deliberately does NOT create a real, persistent network namespace, load
// modules, or run the acceptance tests. The Q6 post-drop mutation test, the
// protocol-matrix egress test, and the AppArmor toggle test all require root and
// live namespace setup; they are enumerated as integration-tagged follow-ups and
// would turn a bare CI `go test ./...` red, so they are intentionally out of this
// increment.
//
// Naming note: the hidden `__probe` command (probe.go) is the in-child fence
// self-test used by `verify`. It is a different concept, so everything here is
// prefixed `egressProbe*` to avoid colliding with that command's symbols.

// egressProbeSchema versions the machine-readable output so results collected
// from different fleet kernels over time remain comparable and parseable.
const egressProbeSchema = "nocklock.egress-probe/v1"

// Evidence qualifiers. The spec is deliberate that AppArmor is the *indicated*
// (documented-signature) cause rather than a toggle-proven one, and that the
// privileged-helper setup path is only "confirmed" once a live namespace is
// actually created — which this non-mutating probe does not do. The schema
// carries that distinction explicitly instead of overclaiming.
const (
	evidenceObserved  = "observed"   // directly measured on this host
	evidenceIndicated = "indicated"  // documented signature, not isolated/proven here
	evidenceNotProbed = "not-probed" // requires a mutating/root/tool step not exercised here
)

// Namespace-attempt outcomes. "unavailable" (the `unshare` tool is missing) is
// deliberately distinct from "blocked" (the kernel denied the capability): a
// missing tool is not a denied capability and must not read as a hard block.
const (
	nsPermitted   = "permitted"
	nsBlocked     = "blocked"
	nsToolMissing = "unavailable"
)

// Track verdicts — which Candidate B path this host supports.
const (
	trackUnprivilegedClean = "unprivileged-clean" // unprivileged userns+netns works; no helper needed
	trackPrivilegedHelper  = "privileged-helper"  // unprivileged blocked, but a privileged helper is reachable
	trackBlocked           = "blocked"            // unprivileged blocked and no privileged path detected
	trackUndetermined      = "undetermined"       // unprivileged path could not be probed (tool missing) and no privileged path
	trackUnsupported       = "unsupported"        // not a Linux host
)

// nsAttemptResult is the outcome of a single `unshare` feasibility attempt.
type nsAttemptResult struct {
	Status string // nsPermitted | nsBlocked | nsToolMissing
	Detail string
}

type egressProbeCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
}

type egressProbeHost struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelRelease string `json:"kernel_release,omitempty"`
	Distro        string `json:"distro,omitempty"`
}

type egressProbeReport struct {
	Schema string             `json:"schema"`
	Track  string             `json:"track"`
	Host   egressProbeHost    `json:"host"`
	Checks []egressProbeCheck `json:"checks"`
}

// egressProbeCapabilities holds the host-touching operations behind injectable
// function fields so runEgressProbe stays pure and unit-testable without root,
// exec, or /proc access — the same pattern doctor uses for its backend probes.
// The real implementations live in egress_probe_linux.go; egress_probe_other.go
// supplies no-op stubs for non-Linux builds.
type egressProbeCapabilities struct {
	goos string
	arch string

	kernelRelease func() string
	distro        func() string

	// Sysctls. Each returns the trimmed value and whether the knob exists.
	unprivUsernsClone func() (value string, found bool)
	apparmorRestrict  func() (value string, found bool)

	// Unprivileged namespace creation, attempted via `unshare` subprocesses with
	// the receipted flags.
	tryUsernsMapped      func() nsAttemptResult // unshare --user --map-root-user
	tryUserNetnsMapped   func() nsAttemptResult // unshare --user --net --map-root-user
	tryUserNetnsUnmapped func() nsAttemptResult // unshare --user --net (no uid_map write)

	// Mechanism + privileged-path detection (non-mutating).
	nftVersion         func() (version string, ok bool)
	nftTproxyModule    func() (ok bool)
	sudoNonInteractive func() (ok bool)
}

var currentEgressProbeCapabilities = defaultEgressProbeCapabilities()

var egressProbeCmd = &cobra.Command{
	Use:   "egress-probe",
	Short: "Probe Linux network-egress enforcement feasibility on this host",
	Long: "egress-probe measures whether this kernel can host NockLock's network-egress\n" +
		"fence (Candidate B: netns + transparent redirect) and, if not unprivileged-clean,\n" +
		"whether the privileged-helper track is reachable. It emits a structured, versioned\n" +
		"result so CI-runner kernels are probed identically to the dev VPS before Phase 1.\n\n" +
		"It is non-mutating: it attempts unprivileged namespace creation via throwaway\n" +
		"`unshare` subprocesses and detects tool/module presence, but never creates a\n" +
		"persistent namespace, loads modules, or runs the root-only acceptance tests\n" +
		"(those are integration follow-ups).",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		report := runEgressProbe(currentEgressProbeCapabilities)
		if asJSON {
			if err := renderEgressProbeJSON(cmd.OutOrStdout(), report); err != nil {
				return err
			}
		} else {
			renderEgressProbeHuman(cmd.OutOrStdout(), report)
		}
		// A probe that runs to completion always exits 0, whatever the verdict:
		// "unprivileged netns blocked" is the *expected, correct* finding on a
		// hardened host, and a CI wrapper must read a completed probe as success.
		return nil
	},
}

func init() {
	egressProbeCmd.Flags().Bool("json", false, "emit structured JSON output")
	rootCmd.AddCommand(egressProbeCmd)
}

func runEgressProbe(caps egressProbeCapabilities) egressProbeReport {
	report := egressProbeReport{
		Schema: egressProbeSchema,
		Host:   egressProbeHost{OS: caps.goos, Arch: caps.arch},
	}
	if caps.kernelRelease != nil {
		report.Host.KernelRelease = caps.kernelRelease()
	}
	if caps.distro != nil {
		report.Host.Distro = caps.distro()
	}

	if caps.goos != "linux" {
		report.Track = trackUnsupported
		report.Checks = append(report.Checks, egressProbeCheck{
			ID:       "platform",
			Category: "platform",
			Status:   "unsupported",
			Evidence: evidenceObserved,
			Detail: fmt.Sprintf(
				"Linux network-egress enforcement is only meaningful on Linux; host is %s. No probe performed.",
				caps.goos),
		})
		return report
	}

	var checks []egressProbeCheck

	// --- Sysctls that decide the classic-vs-AppArmor cause ------------------
	usernsClone, usernsCloneFound := caps.unprivUsernsClone()
	checks = append(checks, sysctlCheck(
		"unprivileged-userns-clone", "userns",
		"kernel.unprivileged_userns_clone", usernsClone, usernsCloneFound,
		"classic unprivileged-userns sysctl"))

	apparmorRestrict, apparmorFound := caps.apparmorRestrict()
	checks = append(checks, sysctlCheck(
		"apparmor-restrict-unprivileged-userns", "apparmor",
		"kernel.apparmor_restrict_unprivileged_userns", apparmorRestrict, apparmorFound,
		"Ubuntu 24.04+ AppArmor unprivileged-userns gate"))

	// --- Unprivileged namespace creation via `unshare` ---------------------
	usernsMapped := caps.tryUsernsMapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns", "userns", "unshare --user --map-root-user", usernsMapped))

	netnsMapped := caps.tryUserNetnsMapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns-netns", "netns", "unshare --user --net --map-root-user", netnsMapped))

	// The discriminator the one-off 2026-08-03 probe did not run: bare userns+netns
	// creation WITHOUT the root-mapping uid_map write. If this succeeds while the
	// mapped attempt is denied, the blocker is specifically the uid_map write, not
	// namespace creation — a materially narrower finding.
	netnsUnmapped := caps.tryUserNetnsUnmapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns-netns-unmapped", "netns", "unshare --user --net", netnsUnmapped))

	// --- Cause attribution --------------------------------------------------
	if cause, ok := attributeUsernsCause(usernsMapped, netnsUnmapped, usernsClone, usernsCloneFound, apparmorRestrict, apparmorFound); ok {
		checks = append(checks, cause)
	}

	// --- Mechanism + privileged-path detection -----------------------------
	nftVer, nftOK := caps.nftVersion()
	checks = append(checks, presenceCheck(
		"nftables-binary", "nftables", nftOK,
		fmt.Sprintf("nft present (%s) — tproxy mechanism candidate", nftVer),
		"nft binary not found — tproxy redirect mechanism unavailable"))

	tproxyOK := caps.nftTproxyModule()
	checks = append(checks, presenceCheck(
		"nftables-tproxy-module", "nftables", tproxyOK,
		"nft_tproxy module available (loaded or loadable) — Q2 tproxy is on this kernel",
		"nft_tproxy module not detected — transparent redirect (Q2) unproven on this kernel"))

	sudoOK := caps.sudoNonInteractive()
	checks = append(checks, presenceCheck(
		"sudo-nopasswd", "privileged-helper", sudoOK,
		"passwordless sudo available — a privileged helper is reachable on this host",
		"passwordless sudo unavailable — the sudo-based privileged-helper path is not reachable non-interactively here"))

	// --- Track verdict ------------------------------------------------------
	track, trackCheck := deriveEgressTrack(netnsMapped, sudoOK, nftOK)
	checks = append(checks, trackCheck)

	report.Track = track
	report.Checks = checks
	return report
}

// attributeUsernsCause reproduces the spec's careful reasoning about WHY an
// unprivileged userns is denied, and returns false when no attribution applies
// (mapped userns not blocked, or the classic sysctl not permissive).
func attributeUsernsCause(usernsMapped, netnsUnmapped nsAttemptResult, usernsClone string, usernsCloneFound bool, apparmorRestrict string, apparmorFound bool) (egressProbeCheck, bool) {
	if usernsMapped.Status != nsBlocked || !usernsCloneFound || usernsClone != "1" {
		return egressProbeCheck{}, false
	}
	switch {
	case netnsUnmapped.Status == nsPermitted:
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "uid-map-write-gate",
			Evidence: evidenceIndicated,
			Detail: "Bare unprivileged userns+netns creation succeeds, but the root-mapping uid_map write is denied — a NARROWER blocker than a full userns denial. " +
				"(The 2026-08-03 manual probe recorded the mapped failure but did not test the unmapped path.) " +
				"The classic sysctl is permissive (=1), so it is ruled out; apparmor_restrict_unprivileged_userns is the indicated cause of the map-write restriction — documented signature, not toggle-proven here.",
		}, true
	case apparmorFound && apparmorRestrict == "1":
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "apparmor-gate",
			Evidence: evidenceIndicated,
			Detail: "Unprivileged userns denied despite unprivileged_userns_clone=1, so the classic sysctl is ruled out. " +
				"apparmor_restrict_unprivileged_userns=1 (standard on Ubuntu 24.04+) is the indicated cause of this signature — " +
				"documented, not isolated here (toggling a live security control is out of scope; see the AppArmor-toggle follow-up).",
		}, true
	default:
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "unattributed",
			Evidence: evidenceIndicated,
			Detail: "Unprivileged userns denied despite unprivileged_userns_clone=1 (classic sysctl ruled out), " +
				"but apparmor_restrict_unprivileged_userns is not =1/present here — cause unattributed on this host; needs a targeted follow-up.",
		}, true
	}
}

// deriveEgressTrack decides which Candidate B path this host supports and
// returns a summary check. The privileged-helper verdict is marked "reachable,
// not confirmed": this probe never creates a live namespace, so it records
// reachability (sudo + nft observed) while leaving actual setup viability
// not-probed — that proof is the integration-tagged follow-up.
func deriveEgressTrack(netnsMapped nsAttemptResult, sudoOK, nftOK bool) (string, egressProbeCheck) {
	switch {
	case netnsMapped.Status == nsPermitted:
		return trackUnprivilegedClean, egressProbeCheck{
			ID:       "track",
			Category: "verdict",
			Status:   trackUnprivilegedClean,
			Evidence: evidenceObserved,
			Detail:   "Unprivileged userns+netns creation with root-mapping succeeded here: Candidate B can run unprivileged-clean, no privileged helper required on this host.",
		}
	case sudoOK && nftOK:
		return trackPrivilegedHelper, egressProbeCheck{
			ID:       "track",
			Category: "verdict",
			Status:   trackPrivilegedHelper,
			Evidence: evidenceNotProbed,
			Detail: "Unprivileged root-mapped netns is not available, but passwordless sudo and nft are present, so the privileged-helper track is REACHABLE. " +
				"Setup viability is NOT confirmed by this probe — it does not create a live namespace or nftables policy; " +
				"that proof (plus the Q6 post-drop mutation acceptance test) is the integration follow-up.",
		}
	case netnsMapped.Status == nsBlocked:
		return trackBlocked, egressProbeCheck{
			ID:       "track",
			Category: "verdict",
			Status:   trackBlocked,
			Evidence: evidenceObserved,
			Detail: "Unprivileged root-mapped netns is denied and no privileged-helper path was detected (missing passwordless sudo and/or nft). " +
				"Candidate B is not deployable on this host without further provisioning.",
		}
	default:
		return trackUndetermined, egressProbeCheck{
			ID:       "track",
			Category: "verdict",
			Status:   trackUndetermined,
			Evidence: evidenceNotProbed,
			Detail: "The unprivileged path could not be probed (the unshare tool is unavailable) and no privileged-helper path was detected. " +
				"Install util-linux (unshare) to determine the unprivileged-clean track on this host.",
		}
	}
}

func sysctlCheck(id, category, knob, value string, found bool, desc string) egressProbeCheck {
	if !found {
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "absent",
			Evidence: evidenceObserved,
			Detail:   fmt.Sprintf("%s (%s) not present on this kernel.", desc, knob),
		}
	}
	return egressProbeCheck{
		ID:       id,
		Category: category,
		Status:   "value=" + value,
		Evidence: evidenceObserved,
		Detail:   fmt.Sprintf("%s (%s) = %s.", desc, knob, value),
	}
}

func attemptCheck(id, category, method string, r nsAttemptResult) egressProbeCheck {
	evidence := evidenceObserved
	if r.Status == nsToolMissing {
		evidence = evidenceNotProbed
	}
	return egressProbeCheck{
		ID:       id,
		Category: category,
		Status:   r.Status,
		Evidence: evidence,
		Detail:   r.Detail,
	}
}

func presenceCheck(id, category string, ok bool, presentDetail, absentDetail string) egressProbeCheck {
	if ok {
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "available",
			Evidence: evidenceObserved,
			Detail:   presentDetail,
		}
	}
	return egressProbeCheck{
		ID:       id,
		Category: category,
		Status:   "unavailable",
		Evidence: evidenceObserved,
		Detail:   absentDetail,
	}
}

func renderEgressProbeJSON(w io.Writer, report egressProbeReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderEgressProbeHuman(w io.Writer, report egressProbeReport) {
	fmt.Fprintf(w, "NockLock egress-probe (%s)\n", report.Schema)
	host := report.Host
	fmt.Fprintf(w, "Host: %s/%s", host.OS, host.Arch)
	if host.KernelRelease != "" {
		fmt.Fprintf(w, " kernel %s", host.KernelRelease)
	}
	if host.Distro != "" {
		fmt.Fprintf(w, " (%s)", host.Distro)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	currentCategory := ""
	for _, check := range report.Checks {
		if check.Category != currentCategory {
			if currentCategory != "" {
				fmt.Fprintln(w)
			}
			currentCategory = check.Category
			fmt.Fprintf(w, "%s\n", check.Category)
		}
		fmt.Fprintf(w, "  %s [%s] (%s): %s\n", check.ID, check.Status, check.Evidence, check.Detail)
	}
	fmt.Fprintf(w, "\nTRACK: %s\n", report.Track)
}

// goarch is a tiny indirection so the platform default-caps builders share one
// arch source.
func goarch() string { return runtime.GOARCH }
