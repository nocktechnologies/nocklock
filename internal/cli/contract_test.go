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
// typeName declared at package level in the non-test files of the package in
// dir, so a value added in any file of that package is seen. A constant's type
// is its declared type (x T = "v") or, without one, the type of its value: a
// conversion (x = T("v")), another constant of the package (x = y), or the
// previous spec's in a const block (implicit repetition); a type alias of
// typeName counts as typeName. One of typeName
// whose value is not a string literal, a conversion of one, or such a
// constant is an error, not a silent skip, so a new value cannot slip past
// the pinned set.
func declaredConsts(dir, typeName string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var specs []*constSpec
	r := constResolver{typeName: typeName, named: map[string][]*constSpec{}, aliases: map[string]string{}, visiting: map[*constSpec]bool{}}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			decl, ok := d.(*ast.GenDecl)
			if ok && decl.Tok == token.TYPE {
				for _, s := range decl.Specs {
					if spec := s.(*ast.TypeSpec); spec.Assign.IsValid() {
						r.aliases[spec.Name.Name] = identName(spec.Type)
					}
				}
			}
			if !ok || decl.Tok != token.CONST {
				continue
			}
			var typ ast.Expr
			var values []ast.Expr
			for _, s := range decl.Specs {
				spec := s.(*ast.ValueSpec)
				if len(spec.Values) > 0 {
					typ, values = spec.Type, spec.Values
				}
				for i, n := range spec.Names {
					if i >= len(values) {
						return nil, fmt.Errorf("%s: constant %s has no value", fset.Position(n.Pos()), n.Name)
					}
					c := &constSpec{typ: typ, value: values[i], pos: n.Pos()}
					specs = append(specs, c)
					if n.Name != "_" {
						r.named[n.Name] = append(r.named[n.Name], c)
					}
				}
			}
		}
	}
	var out []string
	for _, c := range specs {
		if r.typeOf(c) != typeName {
			continue
		}
		value, ok := r.value(c.value)
		if !ok {
			return nil, fmt.Errorf("%s: a %s constant's value is not a string literal; declare it as one or teach declaredConsts the form", fset.Position(c.pos), typeName)
		}
		out = append(out, value)
	}
	return out, nil
}

type constSpec struct {
	typ, value ast.Expr
	pos        token.Pos
}

// constResolver resolves package-level constants by name, enough to classify
// string constants by type; it is no substitute for go/types. A name declared
// in more than one file (a build-tagged pair) has every declaration's type
// considered and no readable value, so a pinned constant defined through one
// is an error rather than whichever file sorts last. A reference cycle, which
// Go rejects, resolves to no type and no value instead of overflowing the
// stack.
type constResolver struct {
	typeName string
	named    map[string][]*constSpec
	aliases  map[string]string
	visiting map[*constSpec]bool
}

// typeOf returns the name of c's type, "" for an untyped constant or a type
// declaredConsts never pins, such as one from another package.
func (r constResolver) typeOf(c *constSpec) string {
	if r.visiting[c] {
		return ""
	}
	r.visiting[c] = true
	defer delete(r.visiting, c)
	if c.typ != nil {
		return r.canonical(identName(c.typ))
	}
	return r.exprType(c.value)
}

// canonical follows type aliases declared in the package to the named type.
func (r constResolver) canonical(name string) string {
	for range len(r.aliases) {
		target, ok := r.aliases[name]
		if !ok {
			break
		}
		name = target
	}
	return name
}

func (r constResolver) exprType(e ast.Expr) string {
	switch e := ast.Unparen(e).(type) {
	case *ast.Ident:
		typ := ""
		for _, c := range r.named[e.Name] {
			if t := r.typeOf(c); t != "" && typ != r.typeName {
				typ = t
			}
		}
		return typ
	case *ast.CallExpr:
		return r.canonical(identName(e.Fun))
	case *ast.BinaryExpr:
		switch e.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			return "bool"
		}
		if x := r.exprType(e.X); x != "" {
			return x
		}
		return r.exprType(e.Y)
	}
	return ""
}

func (r constResolver) value(e ast.Expr) (string, bool) {
	switch e := ast.Unparen(e).(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		return v, err == nil
	case *ast.Ident:
		if cs := r.named[e.Name]; len(cs) == 1 && !r.visiting[cs[0]] {
			r.visiting[cs[0]] = true
			defer delete(r.visiting, cs[0])
			return r.value(cs[0].value)
		}
	case *ast.CallExpr:
		if r.canonical(identName(e.Fun)) == r.typeName && len(e.Args) == 1 {
			return r.value(e.Args[0])
		}
	}
	return "", false
}

// identName returns the name e spells, "" when it is not an identifier.
func identName(e ast.Expr) string {
	if id, ok := ast.Unparen(e).(*ast.Ident); ok {
		return id.Name
	}
	return ""
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

// A Level constant typed only by inference is found, so adding one changes
// the declared set and fails the pinned-set check in checkDeclaredSet.
func TestDeclaredConstsFindsInferredConstants(t *testing.T) {
	for _, tc := range []struct {
		decl string
		want []string
	}{
		{"const a Level = \"a\"\nconst b = a", []string{"a", "a"}},
		{"const b = a\nconst a Level = \"a\"", []string{"a", "a"}},
		{"const a = Level(\"a\")\nconst b = (a)", []string{"a", "a"}},
		{"const (\n\ta Level = \"a\"\n\tb\n)", []string{"a", "a"}},
		{"const b Level = name", []string{"n"}},
		{"const b = Level(name)", []string{"n"}},
		{"const o Other = \"o\"\nconst b = o", nil},
		{"const a Level = \"a\"\nconst b = a == \"x\"", []string{"a"}},
		{"type alias = Level\nconst a alias = \"a\"\nconst b = alias(\"b\")", []string{"a", "b"}},
		{"const b = name", nil},
	} {
		got, err := declaredConsts(writeConstFixture(t, tc.decl), "Level")
		if err != nil {
			t.Errorf("declaredConsts(%s): %v", tc.decl, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("declaredConsts(%s) = %q, want %q", tc.decl, got, tc.want)
		}
	}
}

// A conversion is found however it is parenthesized.
func TestDeclaredConstsFindsParenthesizedConversions(t *testing.T) {
	for _, decl := range []string{
		`const x = (Level("x"))`,
		`const x = Level(("x"))`,
		`const x = ((Level)(("x")))`,
	} {
		got, err := declaredConsts(writeConstFixture(t, decl), "Level")
		if err != nil || !slices.Equal(got, []string{"x"}) {
			t.Errorf("declaredConsts(%s) = %q, %v, want [\"x\"]", decl, got, err)
		}
	}
}

// A Level constant whose value the scan cannot read fails instead of being
// left out of the pinned set.
func TestDeclaredConstsRefusesUnreadableValues(t *testing.T) {
	for _, decl := range []string{
		`const bad Level = "a" + "b"`,
		`const bad Level = name + "b"`,
		`const bad = Level(name + "b")`,
		"const a Level = \"a\"\nconst bad = a + \"b\"",
		`const bad Level = undeclared`,
		"const bad Level = a\nconst a = bad",
	} {
		if got, err := declaredConsts(writeConstFixture(t, decl), "Level"); err == nil {
			t.Errorf("declaredConsts(%s) = %q, want an error", decl, got)
		}
	}
}

// A Level constant defined through a name a build-tagged pair of files both
// declare fails instead of taking whichever file sorts last.
func TestDeclaredConstsRefusesPlatformDuplicates(t *testing.T) {
	dir := writeConstFixture(t, "const v Level = shared\n")
	for file, value := range map[string]string{"shared_unix.go": "a", "shared_other.go": "b"} {
		src := "package p\n\nconst shared = \"" + value + "\"\n"
		if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := declaredConsts(dir, "Level"); err == nil {
		t.Errorf("declaredConsts = %q, want an error", got)
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

// commandsGolden renders every command path with its own flags, each with
// its shorthand, type and default.
func commandsGolden(cmds []*cobra.Command) string {
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "%s hidden=%t\n", c.CommandPath(), c.Hidden)
		for _, f := range commandFlags(c) {
			fmt.Fprintf(&b, "  --%s shorthand=%q %s default=%q\n", f.Name, f.Shorthand, f.Value.Type(), f.DefValue)
		}
	}
	return b.String()
}

var backtickSpanRE = regexp.MustCompile("`([^`]+)`")

// commandRows maps each command named in the first cell of a row of ref's
// Commands table to that row. The cell writes commands as backticked
// synopses ("`anchor emit [--out <file>]`"): the name is the words before the
// first flag, argument or placeholder, and a word written a\|b names each
// alternative. A command named in several rows maps to all of them.
func commandRows(ref string) map[string]string {
	rows := map[string]string{}
	_, section, _ := strings.Cut(ref, "\n## Commands\n")
	section, _, _ = strings.Cut(section, "\n## ")
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		first, _, _ := strings.Cut(line, " | ")
		for _, m := range backtickSpanRE.FindAllStringSubmatch(first, -1) {
			names := []string{""}
			for _, w := range strings.Fields(m[1]) {
				if strings.ContainsAny(w[:1], "[<-") {
					break
				}
				var next []string
				for _, n := range names {
					for _, alt := range strings.Split(w, `\|`) {
						next = append(next, strings.TrimSpace(n+" "+alt))
					}
				}
				names = next
			}
			for _, n := range names {
				rows[n] += line + "\n"
			}
		}
	}
	return rows
}

// namesToken reports whether text contains tok as a whole token, so --out
// does not match --output and -j does not match --json.
func namesToken(text, tok string) bool {
	return regexp.MustCompile(`(^|[^\w-])` + regexp.QuoteMeta(tok) + `($|[^\w-])`).MatchString(text)
}

// checkCommandReference returns every command of cmds, cobra's built-ins
// included, that ref's Commands table does not name exactly, and every flag
// or shorthand of a visible command that the command's own row does not name.
// A group command without flags may go unnamed: its subcommands' rows name it.
// The root has no row; its flags, global to every command, must be named
// somewhere on the page.
func checkCommandReference(ref string, cmds []*cobra.Command) []string {
	rows := commandRows(ref)
	var problems []string
	for _, c := range cmds {
		if !c.HasParent() {
			for _, f := range commandFlags(c) {
				if !namesToken(ref, "--"+f.Name) {
					problems = append(problems, fmt.Sprintf("%s does not name global flag --%s", cliReferencePath, f.Name))
				}
			}
			continue
		}
		name := strings.TrimPrefix(c.CommandPath(), c.Root().Name()+" ")
		row, ok := rows[name]
		if !ok {
			if !c.HasSubCommands() || len(commandFlags(c)) > 0 {
				problems = append(problems, fmt.Sprintf("%s Commands table does not name command %q", cliReferencePath, name))
			}
			continue
		}
		if c.Hidden {
			continue
		}
		for _, f := range commandFlags(c) {
			toks := []string{"--" + f.Name}
			if f.Shorthand != "" {
				toks = append(toks, "-"+f.Shorthand)
			}
			for _, tok := range toks {
				if !namesToken(row, tok) {
					problems = append(problems, fmt.Sprintf("%s row for %q does not name its flag %s", cliReferencePath, name, tok))
				}
			}
		}
	}
	return problems
}

func TestCLIContractCommandsAndFlags(t *testing.T) {
	cmds := contractCommands()
	checkContractGolden(t, "commands.golden", commandsGolden(cmds))
	for _, p := range checkCommandReference(readCLIReference(t), cmds) {
		t.Error(p)
	}
}

// mutateReference returns ref with old replaced by new, failing when old is
// absent so a control cannot go stale and pass vacuously.
func mutateReference(t *testing.T, ref, old, new string) string {
	t.Helper()
	if !strings.Contains(ref, old) {
		t.Fatalf("%s no longer contains %q; update this control", cliReferencePath, old)
	}
	return strings.Replace(ref, old, new, 1)
}

func requireProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Errorf("reference check problems %q, want one containing %q", problems, want)
}

// Each mutation of the real reference is caught by the check that passes on
// the unmutated page.
func TestCheckCommandReferenceCatchesMutations(t *testing.T) {
	ref, cmds := readCLIReference(t), contractCommands()
	if p := checkCommandReference(ref, cmds); len(p) > 0 {
		t.Fatalf("unmutated reference: %q", p)
	}
	t.Run("built-ins", func(t *testing.T) {
		mutated := mutateReference(t, ref, "| `help [command]`, `completion bash\\|zsh\\|fish\\|powershell` |", "| |")
		p := checkCommandReference(mutated, cmds)
		requireProblem(t, p, `command "help"`)
		requireProblem(t, p, `command "completion zsh"`)
	})
	t.Run("exact name", func(t *testing.T) {
		// The old prefix match accepted `logging` as naming `log`.
		mutated := mutateReference(t, ref, "| `log` |", "| `logging` |")
		requireProblem(t, checkCommandReference(mutated, cmds), `command "log"`)
	})
	t.Run("own row", func(t *testing.T) {
		// --json stays on the page in the doctor, verify and scan rows.
		mutated := mutateReference(t, ref, "`--since`, `--json`, `--stats`", "`--since`, `--stats`")
		if !strings.Contains(mutated, "--json") {
			t.Fatal("control needs --json elsewhere on the page")
		}
		requireProblem(t, checkCommandReference(mutated, cmds), `row for "log" does not name its flag --json`)
	})
}

// A flag's shorthand is pinned by the golden and must be named in its row.
func TestCommandContractPinsShorthands(t *testing.T) {
	tree := func(shorthand string) []*cobra.Command {
		root := &cobra.Command{Use: "nocklock"}
		sub := &cobra.Command{Use: "scan", Run: func(*cobra.Command, []string) {}}
		sub.Flags().BoolP("json", shorthand, false, "")
		root.AddCommand(sub)
		return []*cobra.Command{root, sub}
	}
	with, changed, removed := commandsGolden(tree("j")), commandsGolden(tree("J")), commandsGolden(tree(""))
	if with == changed || with == removed {
		t.Fatalf("golden does not pin the shorthand:\n%s", with)
	}
	ref := "\n## Commands\n| `scan` | `--json` | |\n"
	requireProblem(t, checkCommandReference(ref, tree("j")), `row for "scan" does not name its flag -j`)
	global := tree("j")
	global[0].Flags().Bool("verbose", false, "")
	requireProblem(t, checkCommandReference(ref, global), "global flag --verbose")
	if p := checkCommandReference(strings.Replace(ref, "`--json`", "`-j`, `--json`", 1), tree("j")); len(p) > 0 {
		t.Errorf("shorthand named in its row: %q", p)
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

	row := commandRows(readCLIReference(t))["wrap"]
	for _, tok := range want {
		if strings.HasSuffix(tok, "=") {
			continue
		}
		if !namesToken(row, tok) {
			t.Errorf("%s row for \"wrap\" does not name its flag %s", cliReferencePath, tok)
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
		if ft.Kind() == reflect.Slice {
			if elem := derefType(ft.Elem()); elem.Kind() == reflect.Struct {
				ft, kind = elem, "[[table]]"
			}
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
		parts := strings.Split(path, ".")
		// A table is looked up from its own row, a key from its table's.
		n := len(parts)
		if !strings.HasSuffix(kind, "table]") {
			n--
		}
		row := ""
		for ; n > 0 && row == ""; n-- {
			row = rows[strings.Join(parts[:n], ".")]
		}
		switch kind {
		case "[table]":
			// Its keys carry its row; that row must not call it an array.
			if strings.Contains(row, "`[["+path+"]]`") {
				t.Errorf("%s writes %s as an array of tables, schema says %s", cliReferencePath, path, kind)
			}
		case "[[table]]":
			if !strings.Contains(row, "`[["+path+"]]`") {
				t.Errorf("%s config schema does not name %s as `[[%s]]` in its table row", cliReferencePath, path, path)
			}
		default:
			if !strings.Contains(row, "`"+parts[len(parts)-1]+"`") {
				t.Errorf("%s config schema does not name %s in its table row", cliReferencePath, path)
			}
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
