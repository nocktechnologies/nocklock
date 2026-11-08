package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The contract tests pin the public CLI surface recorded in
// docs/reference/cli.md: commands and flags, wrap's own flags, config keys,
// egress levels, verify --audit run states and doctor exit codes. Each fails
// when the code changes the surface, and when the reference stops naming a
// part of it. A deliberate change regenerates the golden files with
// -update-contract-golden and updates the reference in the same change.

var updateContractGolden = flag.Bool("update-contract-golden", false, "rewrite testdata/contract/*.golden")

const cliReferencePath = "../../docs/reference/cli.md"

func readCLIReference(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(cliReferencePath)
	if err != nil {
		t.Fatalf("read %s: %v", cliReferencePath, err)
	}
	return string(data)
}

func checkContractGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "contract", name)
	if *updateContractGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update-contract-golden to create it): %v", err)
	}
	if got != string(want) {
		t.Fatalf("CLI contract changed: %s differs (update docs/reference/cli.md, then run with -update-contract-golden and review the diff):\n--- got\n%s--- want\n%s", path, got, want)
	}
}

// sourceStrings returns every first submatch of re in a package source file.
// It pins value sets that the code declares only as constants or switch cases.
func sourceStrings(t *testing.T, path string, re *regexp.Regexp) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		out = append(out, m[1])
	}
	return out
}

// contractCommands returns every command under the root, cobra's help and
// completion built-ins included, as Execute registers them.
func contractCommands() []*cobra.Command {
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	var out []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		out = append(out, c)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	return out
}

func isCobraBuiltin(c *cobra.Command) bool {
	for p := c; p != nil; p = p.Parent() {
		if p.Name() == "help" || p.Name() == "completion" {
			return p.Parent() == rootCmd
		}
	}
	return false
}

// commandFlags lists a command's own flags, skipping cobra's help flag, which
// only some commands carry depending on which ones a test has executed.
func commandFlags(c *cobra.Command) []*pflag.Flag {
	var out []*pflag.Flag
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" {
			out = append(out, f)
		}
	})
	return out
}

func TestCLIContractCommandsAndFlags(t *testing.T) {
	var b strings.Builder
	for _, c := range contractCommands() {
		fmt.Fprintf(&b, "%s hidden=%t\n", c.CommandPath(), c.Hidden)
		for _, f := range commandFlags(c) {
			fmt.Fprintf(&b, "  --%s %s default=%q\n", f.Name, f.Value.Type(), f.DefValue)
		}
	}
	checkContractGolden(t, "commands.golden", b.String())

	ref := readCLIReference(t)
	for _, c := range contractCommands() {
		if c == rootCmd || isCobraBuiltin(c) {
			continue
		}
		name := strings.TrimPrefix(c.CommandPath(), "nocklock ")
		if !strings.Contains(ref, "`"+name) {
			t.Errorf("%s does not name command %q", cliReferencePath, name)
		}
		if c.Hidden {
			continue
		}
		for _, f := range commandFlags(c) {
			if !strings.Contains(ref, "--"+f.Name) {
				t.Errorf("%s does not name flag --%s of %q", cliReferencePath, f.Name, name)
			}
		}
	}
}

// wrap disables cobra flag parsing (wrap.go), so its flags live in
// parseWrapFlags; flagparse_test.go covers each one's behavior.
func TestCLIContractWrapFlags(t *testing.T) {
	want := []string{
		"--allow-private-ranges",
		"--allow-unfenced",
		"--dry-run",
		"--net-fence",
		"--net-fence=",
		"--profile",
		"--profile=",
		"--require-enforced-egress",
	}
	got := sourceStrings(t, "flagparse.go", regexp.MustCompile(`"(--[a-z-]+=?)"`))
	slices.Sort(got)
	got = slices.Compact(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrap flag tokens in flagparse.go = %q, want %q (update docs/reference/cli.md and this list together)", got, want)
	}

	// Every accepted token parses; the removed one is refused, not ignored.
	for _, args := range [][]string{
		{"--allow-private-ranges", "--", "true"},
		{"--dry-run", "--", "true"},
		{"--require-enforced-egress", "--", "true"},
		{"--profile", "claude-code", "--", "true"},
		{"--profile=claude-code", "--", "true"},
		{"--net-fence", "netns", "--", "true"},
		{"--net-fence=netns", "--", "true"},
	} {
		if _, _, err := parseWrapFlags(args); err != nil {
			t.Errorf("parseWrapFlags(%q) = %v, want accepted", args, err)
		}
	}
	for _, args := range [][]string{
		{"--allow-unfenced", "--", "true"},
		{"--net-fence=proxy", "--", "true"},
		{"--unknown", "--", "true"},
	} {
		if _, _, err := parseWrapFlags(args); err == nil {
			t.Errorf("parseWrapFlags(%q) accepted, want refused", args)
		}
	}

	ref := readCLIReference(t)
	for _, tok := range want {
		if !strings.Contains(ref, strings.TrimSuffix(tok, "=")) {
			t.Errorf("%s does not name wrap flag %s", cliReferencePath, tok)
		}
	}
}

// configKeys lists every TOML key reachable from t as dotted paths with their
// Go types, in declaration order.
func configKeys(prefix string, t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		ft := f.Type
		if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
			out = append(out, configKeys(key, ft.Elem())...)
			continue
		}
		if ft.Kind() == reflect.Struct {
			out = append(out, configKeys(key, ft)...)
			continue
		}
		out = append(out, key+" "+ft.String())
	}
	return out
}

func TestCLIContractConfigSchema(t *testing.T) {
	keys := configKeys("", reflect.TypeOf(config.Config{}))
	checkContractGolden(t, "config-schema.golden", strings.Join(keys, "\n")+"\n")

	// Each key is named in the schema row of its closest documented table:
	// | `[audit.forward]` | ... for audit.forward.url, | `[network]` | ...
	// for network.lookback.name.
	rowRE := regexp.MustCompile("^\\| `\\[([a-z_.]+)\\]` \\|")
	rows := map[string]string{}
	for _, line := range strings.Split(readCLIReference(t), "\n") {
		if m := rowRE.FindStringSubmatch(line); m != nil {
			rows[m[1]] = line
		}
	}
	for _, k := range keys {
		path := strings.Fields(k)[0]
		parts := strings.Split(path, ".")
		leaf := parts[len(parts)-1]
		row := ""
		for n := len(parts) - 1; n > 0 && row == ""; n-- {
			row = rows[strings.Join(parts[:n], ".")]
		}
		if !strings.Contains(row, "`"+leaf+"`") {
			t.Errorf("%s config schema does not name %s in its table row", cliReferencePath, path)
		}
	}
}

func TestCLIContractEgressLevels(t *testing.T) {
	want := []string{"KERNEL", "CONFINED", "SEATBELT", "ADVISORY", "OFF", "UNREACHABLE"}
	got := sourceStrings(t, "egress_level.go", regexp.MustCompile(`egressLevel = "([A-Z]+)"`))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("egress levels = %q, want %q", got, want)
	}
	// Only the kernel-backed levels satisfy require_enforced; the full
	// derivation is TestEffectiveEgressLevelTruthTable.
	for _, level := range want {
		meets := level == "KERNEL" || level == "CONFINED" || level == "SEATBELT"
		if got := egressLevelMeetsRequirement(egressLevel(level)); got != meets {
			t.Errorf("egressLevelMeetsRequirement(%s) = %t, want %t", level, got, meets)
		}
	}
	ref := readCLIReference(t)
	for _, level := range want {
		if !strings.Contains(ref, "| `"+level+"` |") {
			t.Errorf("%s egress level table has no row for %s", cliReferencePath, level)
		}
	}
}

func TestCLIContractVerifyAuditRunStates(t *testing.T) {
	want := map[logging.RunLifecycleStatus]bool{
		logging.RunClosed:         false,
		logging.RunUnclosed:       false,
		logging.RunPruned:         false,
		logging.RunCloseMismatch:  true,
		logging.RunRowsAfterClose: true,
		logging.RunLegacy:         false,
	}
	declared := sourceStrings(t, "../logging/run_close.go", regexp.MustCompile(`RunLifecycleStatus = "([a-z_]+)"`))
	if len(declared) != len(want) {
		t.Fatalf("run states declared in run_close.go = %q, want the %d pinned here", declared, len(want))
	}
	ref := readCLIReference(t)
	for _, s := range declared {
		failure, ok := want[logging.RunLifecycleStatus(s)]
		if !ok {
			t.Errorf("run state %q is not pinned", s)
			continue
		}
		if got := logging.RunLifecycleStatus(s).Failure(); got != failure {
			t.Errorf("%s.Failure() = %t, want %t", s, got, failure)
		}
		if !strings.Contains(ref, "| `"+s+"` |") {
			t.Errorf("%s run-state table has no row for %s", cliReferencePath, s)
		}
	}
}

func TestCLIContractDoctorExitCodes(t *testing.T) {
	want := map[doctorVerdict]int{
		doctorVerdictProtected:   0,
		doctorVerdictGapsFound:   2,
		doctorVerdictPartial:     3,
		doctorVerdictUnprotected: 4,
	}
	declared := sourceStrings(t, "doctor.go", regexp.MustCompile(`doctorVerdict = "([A-Z ]+)"`))
	if len(declared) != len(want) {
		t.Fatalf("doctor verdicts declared in doctor.go = %q, want the %d pinned here", declared, len(want))
	}
	ref := readCLIReference(t)
	for _, v := range declared {
		code, ok := want[doctorVerdict(v)]
		if !ok {
			t.Errorf("doctor verdict %q is not pinned", v)
			continue
		}
		if got := doctorExitCode(doctorVerdict(v)); got != code {
			t.Errorf("doctorExitCode(%s) = %d, want %d", v, got, code)
		}
		if !strings.Contains(ref, "`"+v+"`") {
			t.Errorf("%s does not name doctor verdict %s", cliReferencePath, v)
		}
	}
	// An unrecognized verdict fails closed to GAPS FOUND.
	if got := doctorExitCode("UNKNOWN"); got != 2 {
		t.Errorf("doctorExitCode(UNKNOWN) = %d, want 2", got)
	}
}
