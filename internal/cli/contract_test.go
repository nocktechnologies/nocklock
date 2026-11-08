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
// added in any file of that package is seen. A constant is matched by its
// declared type (x T = "v") or a conversion (x = T("v")); one whose value is
// not a string literal is an error, not a silent skip, so a new value cannot
// slip past the pinned set.
func declaredConsts(dir, typeName string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var out []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		var scanErr error
		ast.Inspect(f, func(n ast.Node) bool {
			decl, ok := n.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST || scanErr != nil {
				return scanErr == nil
			}
			for _, s := range decl.Specs {
				spec := s.(*ast.ValueSpec)
				typed := isIdent(spec.Type, typeName)
				for _, v := range spec.Values {
					if call, ok := v.(*ast.CallExpr); ok && isIdent(call.Fun, typeName) && len(call.Args) == 1 {
						v = call.Args[0]
					} else if !typed {
						continue
					}
					lit, ok := ast.Unparen(v).(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						scanErr = fmt.Errorf("%s: a %s constant's value is not a string literal; declare it as one or teach declaredConsts the form", fset.Position(v.Pos()), typeName)
						return false
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						scanErr = err
						return false
					}
					out = append(out, value)
				}
			}
			return true
		})
		if scanErr != nil {
			return nil, scanErr
		}
	}
	return out, nil
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && id.Name == name
}

func writeConstFixture(t *testing.T, consts string) string {
	t.Helper()
	dir := t.TempDir()
	src := "package p\n\ntype Level string\ntype Other string\n\nconst name = \"n\"\n\n" + consts
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDeclaredConstsFindsTypedAndConvertedConstants(t *testing.T) {
	dir := writeConstFixture(t, `const (
	typed     Level = "typed"
	converted       = Level("converted")
	paren           = (Level)("paren")
	other     Other = "other"
	otherConv       = Other("other-conv")
	untyped         = "untyped"
)

var typedVar Level = "typed-var"
var _ = Level("var-converted")
`)
	got, err := declaredConsts(dir, "Level")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"converted", "paren", "typed"}; !slices.Equal(got, want) {
		t.Fatalf("declaredConsts(Level) = %q, want %q", got, want)
	}
}

// A Level constant whose value the scan cannot read fails instead of being
// left out of the pinned set.
func TestDeclaredConstsRefusesUnreadableValues(t *testing.T) {
	for _, decl := range []string{
		`const bad Level = "a" + "b"`,
		`const bad Level = name`,
		`const bad = Level(name)`,
	} {
		if got, err := declaredConsts(writeConstFixture(t, decl), "Level"); err == nil {
			t.Errorf("declaredConsts(%s) = %q, want an error", decl, got)
		}
	}
}

// checkDeclaredSet requires the constants of typeName declared in dir to be
// exactly the keys of want, eval to map each to its pinned value, and the
// reference to contain docNeedle(value) for each.
func checkDeclaredSet[K ~string, V comparable](t *testing.T, dir, typeName string, want map[K]V, eval func(K) V, docNeedle func(string) string) {
	t.Helper()
	declared, err := declaredConsts(dir, typeName)
	if err != nil {
		t.Fatal(err)
	}
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
// Go types, in declaration order. Each table is listed before its keys as
// "<path> [table]" or "<path> [[table]]", so a change between a table and an
// array of tables changes the list.
func configKeys(prefix string, t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		// BurntSushi/toml decodes an untagged exported field by its name and
		// ignores tag options after the comma.
		name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if name == "-" || (name == "" && !f.IsExported()) {
			continue
		}
		if name == "" {
			name = f.Name
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		ft, kind := derefType(f.Type), "[table]"
		if ft.Kind() == reflect.Slice && derefType(ft.Elem()).Kind() == reflect.Struct {
			ft, kind = derefType(ft.Elem()), "[[table]]"
		}
		if ft.Kind() == reflect.Struct {
			out = append(out, key+" "+kind)
			out = append(out, configKeys(key, ft)...)
			continue
		}
		out = append(out, key+" "+ft.String())
	}
	return out
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func TestCLIContractConfigSchema(t *testing.T) {
	keys := configKeys("", reflect.TypeOf(config.Config{}))
	checkContractGolden(t, "config-schema.golden", strings.Join(keys, "\n")+"\n")

	// Each key is named in the schema row of its closest documented table:
	// | `[audit.forward]` | ... for audit.forward.url, | `[network]` | ...
	// for network.lookback.name.
	rowRE := regexp.MustCompile("^\\| `\\[([a-z_.]+)\\]` \\|")
	rows := map[string]string{}
	ref := readCLIReference(t)
	for _, line := range strings.Split(ref, "\n") {
		if m := rowRE.FindStringSubmatch(line); m != nil {
			rows[m[1]] = line
		}
	}
	for _, k := range keys {
		path, kind, _ := strings.Cut(k, " ")
		// The reference writes an array of tables as `[[path]]`, and only those.
		if kind == "[table]" || kind == "[[table]]" {
			if documented := strings.Contains(ref, "`[["+path+"]]`"); documented != (kind == "[[table]]") {
				t.Errorf("%s writes %s as an array of tables = %t, schema says %s", cliReferencePath, path, documented, kind)
			}
			continue
		}
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

func TestConfigKeysKeepsTableArrayCardinality(t *testing.T) {
	type entry struct {
		Name    string `toml:"name,omitempty"`
		Timeout string
		hidden  string
	}
	leaves := []string{"rule.name string", "rule.Timeout string"}
	for _, tc := range []struct {
		typ  reflect.Type
		kind string
	}{
		{reflect.TypeOf(struct {
			Rule entry `toml:"rule"`
		}{}), "[table]"},
		{reflect.TypeOf(struct {
			Rule *entry `toml:"rule"`
		}{}), "[table]"},
		{reflect.TypeOf(struct {
			Rule []entry `toml:"rule"`
		}{}), "[[table]]"},
		{reflect.TypeOf(struct {
			Rule []*entry `toml:"rule"`
		}{}), "[[table]]"},
	} {
		got := configKeys("", tc.typ)
		if want := append([]string{"rule " + tc.kind}, leaves...); !slices.Equal(got, want) {
			t.Errorf("configKeys(%v) = %q, want %q", tc.typ, got, want)
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
