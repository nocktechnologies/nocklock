package cli

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
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

// sourceStrings returns every first submatch of re in a source file. wrap's
// flag tokens exist only as switch cases and prefixes in flagparse.go.
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

// declaredConsts returns the values of every string constant of type
// typeName declared in the non-test files of the package in dir, so a value
// added in any file of that package is seen.
func declaredConsts(t *testing.T, dir, typeName string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			if id, ok := spec.Type.(*ast.Ident); !ok || id.Name != typeName {
				return true
			}
			for _, v := range spec.Values {
				if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, value)
				}
			}
			return true
		})
	}
	return out
}

// checkDeclaredSet requires the constants of typeName declared in dir to be
// exactly the keys of want, eval to map each to its pinned value, and the
// reference to contain docNeedle(value) for each.
func checkDeclaredSet[K ~string, V comparable](t *testing.T, dir, typeName string, want map[K]V, eval func(K) V, docNeedle func(string) string) {
	t.Helper()
	declared := declaredConsts(t, dir, typeName)
	slices.Sort(declared)
	var pinned []string
	for k := range maps.Keys(want) {
		pinned = append(pinned, string(k))
	}
	slices.Sort(pinned)
	if !slices.Equal(declared, pinned) {
		t.Fatalf("%s constants declared in %s = %q, pinned %q (update docs/reference/cli.md and this test together)", typeName, dir, declared, pinned)
	}
	ref := readCLIReference(t)
	for k, v := range want {
		if got := eval(k); got != v {
			t.Errorf("%s %q maps to %v, want %v", typeName, k, got, v)
		}
		if !strings.Contains(ref, docNeedle(string(k))) {
			t.Errorf("%s does not contain %q", cliReferencePath, docNeedle(string(k)))
		}
	}
}

func tableRow(v string) string { return "| `" + v + "` |" }

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
	cmds := contractCommands()
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "%s hidden=%t\n", c.CommandPath(), c.Hidden)
		for _, f := range commandFlags(c) {
			fmt.Fprintf(&b, "  --%s %s default=%q\n", f.Name, f.Value.Type(), f.DefValue)
		}
	}
	checkContractGolden(t, "commands.golden", b.String())

	ref := readCLIReference(t)
	for _, c := range cmds {
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
		if strings.HasSuffix(tok, "=") {
			continue
		}
		if !strings.Contains(ref, tok) {
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
			ft = ft.Elem()
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

// The full derivation of each level is TestEffectiveEgressLevelTruthTable.
func TestCLIContractEgressLevels(t *testing.T) {
	checkDeclaredSet(t, ".", "egressLevel", map[egressLevel]bool{
		egressLevelKernel:      true,
		egressLevelConfined:    true,
		egressLevelSeatbelt:    true,
		egressLevelAdvisory:    false,
		egressLevelOff:         false,
		egressLevelUnreachable: false,
	}, egressLevelMeetsRequirement, tableRow)
}

func TestCLIContractVerifyAuditRunStates(t *testing.T) {
	checkDeclaredSet(t, "../logging", "RunLifecycleStatus", map[logging.RunLifecycleStatus]bool{
		logging.RunClosed:         false,
		logging.RunUnclosed:       false,
		logging.RunPruned:         false,
		logging.RunCloseMismatch:  true,
		logging.RunRowsAfterClose: true,
		logging.RunLegacy:         false,
	}, logging.RunLifecycleStatus.Failure, tableRow)
}

func TestCLIContractDoctorExitCodes(t *testing.T) {
	want := map[doctorVerdict]int{
		doctorVerdictProtected:   0,
		doctorVerdictGapsFound:   2,
		doctorVerdictPartial:     3,
		doctorVerdictUnprotected: 4,
	}
	checkDeclaredSet(t, ".", "doctorVerdict", want, doctorExitCode, func(v string) string { return "`" + v + "`" })
	// An unrecognized verdict fails closed to GAPS FOUND.
	if got := doctorExitCode("UNKNOWN"); got != want[doctorVerdictGapsFound] {
		t.Errorf("doctorExitCode(UNKNOWN) = %d, want %d", got, want[doctorVerdictGapsFound])
	}
}
