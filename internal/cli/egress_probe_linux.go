//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

func defaultEgressProbeCapabilities() egressProbeCapabilities {
	return egressProbeCapabilities{
		goos:              "linux",
		arch:              goarch(),
		kernelRelease:     linuxKernelRelease,
		distro:            linuxDistro,
		unprivUsernsClone: func() (string, bool) { return readSysctl("/proc/sys/kernel/unprivileged_userns_clone") },
		apparmorRestrict:  func() (string, bool) { return readSysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") },
		// The receipted Phase 0 commands, verbatim. `true` is the harmless payload
		// each namespace is created around.
		tryUsernsMapped:      func() nsAttemptResult { return attemptUnshare("--user", "--map-root-user", "true") },
		tryUserNetnsMapped:   func() nsAttemptResult { return attemptUnshare("--user", "--net", "--map-root-user", "true") },
		tryUserNetnsUnmapped: func() nsAttemptResult { return attemptUnshare("--user", "--net", "true") },
		nftVersion:           detectNftVersion,
		nftTproxyModule:      detectNftTproxyModule,
		sudoNonInteractive:   detectPasswordlessSudo,
	}
}

// attemptUnshare runs `unshare <args>` as a subprocess and classifies the
// outcome. The subprocess isolation means a successful namespace creation never
// touches the probe process's own credentials. A missing `unshare` binary is
// reported as nsToolMissing (a capability we could not probe), NOT nsBlocked (a
// capability the kernel denied) — the two must not be conflated.
func attemptUnshare(args ...string) nsAttemptResult {
	path, err := exec.LookPath("unshare")
	if err != nil {
		return nsAttemptResult{
			Status: nsToolMissing,
			Detail: "unshare(1) not found on PATH; unprivileged namespace feasibility could not be probed on this host",
		}
	}
	cmdline := "unshare " + strings.Join(args, " ")
	out, err := exec.Command(path, args...).CombinedOutput()
	if err == nil {
		return nsAttemptResult{Status: nsPermitted, Detail: "`" + cmdline + "` succeeded"}
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return nsAttemptResult{Status: nsBlocked, Detail: "`" + cmdline + "` denied: " + detail}
}

func readSysctl(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

func linuxKernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

func linuxDistro() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if v, ok := strings.CutPrefix(scanner.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func detectNftVersion() (string, bool) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return "", false
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		// Binary is present but the version query failed; still report presence.
		return "present", true
	}
	return strings.TrimSpace(firstLine(out)), true
}

// detectNftTproxyModule reports whether nft_tproxy is loaded or loadable,
// without loading it: /proc/modules (loaded) first, then modinfo (loadable) —
// both read-only.
func detectNftTproxyModule() bool {
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "nft_tproxy ") {
				return true
			}
		}
	}
	if path, err := exec.LookPath("modinfo"); err == nil {
		if err := exec.Command(path, "nft_tproxy").Run(); err == nil {
			return true
		}
	}
	return false
}

// detectPasswordlessSudo reports whether `sudo -n true` succeeds — i.e. a
// privileged helper is reachable non-interactively. It runs the harmless `true`
// and mutates nothing.
func detectPasswordlessSudo() bool {
	path, err := exec.LookPath("sudo")
	if err != nil {
		return false
	}
	return exec.Command(path, "-n", "true").Run() == nil
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
