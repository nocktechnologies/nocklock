//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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
		unprivUsernsClone: func() (string, string) { return readSysctl("/proc/sys/kernel/unprivileged_userns_clone") },
		apparmorRestrict:  func() (string, string) { return readSysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") },
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
// capability the kernel denied) — the two must not be conflated. A tool that
// runs but rejects a flag it doesn't know (e.g. util-linux too old for
// --map-root-user) is also nsToolMissing, not nsBlocked: that is a tooling
// incompatibility, not a kernel capability denial.
func attemptUnshare(args ...string) nsAttemptResult {
	path, err := exec.LookPath("unshare")
	if err != nil {
		return nsAttemptResult{
			Status: nsToolMissing,
			Detail: "unshare(1) not found on PATH; unprivileged namespace feasibility could not be probed on this host",
		}
	}
	cmdline := "unshare " + strings.Join(args, " ")
	cmd := exec.Command(path, args...)
	// looksLikeUnshareUsageError below classifies unshare's stderr text against
	// English markers; pin the locale so a localized diagnostic can't silently
	// fall through to the kernel-denial branch.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nsAttemptResult{Status: nsPermitted, Detail: fmt.Sprintf("`%s` succeeded", cmdline)}
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		// The command couldn't even run (e.g. exec form error) — not a kernel
		// capability decision.
		return nsAttemptResult{
			Status: nsToolMissing,
			Detail: fmt.Sprintf("`%s` could not be run: %s", cmdline, detail),
		}
	}
	if looksLikeUnshareUsageError(detail) {
		return nsAttemptResult{
			Status: nsToolMissing,
			Detail: fmt.Sprintf("`%s` rejected by this unshare build (flag not supported — likely an older util-linux), not a kernel denial: %s", cmdline, detail),
		}
	}
	return nsAttemptResult{Status: nsBlocked, Detail: fmt.Sprintf("`%s` denied: %s", cmdline, detail)}
}

func readSysctl(path string) (string, string) {
	data, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(data)), sysctlFound
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", sysctlAbsent
	}
	return "", sysctlUnreadable
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

// detectNftTproxyModule reports whether nft_tproxy is available, without
// loading it: /proc/modules (loaded) first, then modinfo (loadable module),
// then the running kernel's own config (compiled-in, CONFIG_NFT_TPROXY=y) —
// all read-only. Neither of the first two sources sees a built-in symbol, so
// skipping the config check would report a false "unavailable" for a kernel
// that compiled nft_tproxy in. If no source can confirm presence OR absence
// (e.g. no config source is readable), the result is tproxyUnproven rather
// than a false negative.
func detectNftTproxyModule() string {
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "nft_tproxy ") {
				return tproxyAvailable
			}
		}
	}
	if path, err := exec.LookPath("modinfo"); err == nil {
		if err := exec.Command(path, "nft_tproxy").Run(); err == nil {
			return tproxyAvailable
		}
	}
	if enabled, found := kernelConfigHasSymbol("CONFIG_NFT_TPROXY"); found {
		if enabled {
			return tproxyAvailable
		}
		return tproxyUnavailable
	}
	return tproxyUnproven
}

// kernelConfigHasSymbol looks up a CONFIG_* symbol in the running kernel's own
// config, trying /proc/config.gz (gzip, requires CONFIG_IKCONFIG_PROC) then
// /boot/config-<uname -r> (plain text) — both read-only.
func kernelConfigHasSymbol(symbol string) (enabled, found bool) {
	if enabled, found := scanKernelConfigFile("/proc/config.gz", symbol); found {
		return enabled, true
	}
	if release := linuxKernelRelease(); release != "" {
		if enabled, found := scanKernelConfigFile("/boot/config-"+release, symbol); found {
			return enabled, true
		}
	}
	return false, false
}

// scanKernelConfigFile opens path — gzip-decoding it first if the name ends
// in .gz — and scans it for symbol via scanKernelConfigForSymbol. found=false
// covers a missing/unreadable file exactly like an unaddressed symbol: the
// caller already treats both as "try the next source".
func scanKernelConfigFile(path, symbol string) (enabled, found bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return false, false
		}
		defer gz.Close()
		r = gz
	}
	return scanKernelConfigForSymbol(r, symbol)
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
