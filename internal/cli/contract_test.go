package cli

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The contract tests pin the public CLI surface recorded in
// docs/reference/cli.md: commands with their aliases and flags, wrap's own
// flags, config keys, egress levels, verify --audit run states and the exit
// codes of doctor, Execute and wrap. Each fails
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
		// The built-in min and max take their arguments' type, so a constant
		// built with one is classified, and refused when value cannot read it.
		// A package type or alias of that name is a conversion instead.
		if fn := r.canonical(identName(e.Fun)); (fn == "min" || fn == "max") && fn != r.typeName {
			for _, a := range e.Args {
				if t := r.exprType(a); t != "" {
					return t
				}
			}
			return ""
		}
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
		{"const b = min(\"x\", name)", nil},
		{"type max = Level\nconst b = max(\"b\")", []string{"b"}},
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
		`const bad = min(Level("a"), Level("b"))`,
		"const a Level = \"a\"\nconst bad = max(\"b\", a)",
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

// hostDir is a host- or platform-dependent directory and the placeholder the
// command golden writes in its place.
type hostDir struct{ dir, placeholder string }

// contractHostDirs lists the directories a flag default could embed, longest
// first so a directory under the home directory keeps its own placeholder; a
// directory two sources resolve to keeps the first source's placeholder. The
// state, config and cache directories differ by GOOS or by the XDG variables
// as well as by user. /tmp is listed on every platform so a fixed /tmp
// default renders as <tmp> on Linux and macOS alike. It is computed during
// package initialization, before TestMain changes the environment, from the
// environment the flag defaults were registered under.
var contractHostDirs = func() []hostDir {
	var dirs []hostDir
	for _, d := range []struct {
		placeholder string
		dir         func() (string, error)
	}{
		// The audit state root, as config.auditStateLayout resolves it.
		{"<state>", func() (string, error) { return os.Getenv("XDG_STATE_HOME"), nil }},
		{"<config>", os.UserConfigDir},
		{"<cache>", os.UserCacheDir},
		{"<home>", os.UserHomeDir},
		{"<tmp>", func() (string, error) { return os.TempDir(), nil }},
		{"<tmp>", func() (string, error) { return "/tmp", nil }},
	} {
		dir, err := d.dir()
		if err != nil || !filepath.IsAbs(dir) || dir == string(filepath.Separator) {
			continue
		}
		dir = filepath.Clean(dir)
		if !slices.ContainsFunc(dirs, func(h hostDir) bool { return h.dir == dir }) {
			dirs = append(dirs, hostDir{dir, d.placeholder})
		}
	}
	slices.SortStableFunc(dirs, func(a, b hostDir) int { return len(b.dir) - len(a.dir) })
	return dirs
}()

// contractDefault returns a flag default with each host directory that starts
// a path replaced by its placeholder, so the golden passes unchanged on every
// host and GOOS. A path starts the value or follows one of "[, =", which
// covers slice and map defaults ("[a,b]", "[k=v]"); only whole path elements
// match, so /tmpfs stays /tmpfs.
func contractDefault(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		if i == 0 || strings.IndexByte("[, =", v[i-1]) >= 0 {
			if d, ok := leadingHostDir(v[i:]); ok {
				b.WriteString(d.placeholder)
				i += len(d.dir)
				continue
			}
		}
		b.WriteByte(v[i])
		i++
	}
	return b.String()
}

// leadingHostDir returns the longest host directory that is a whole leading
// path of v.
func leadingHostDir(v string) (hostDir, bool) {
	for _, d := range contractHostDirs {
		if rest, ok := strings.CutPrefix(v, d.dir); ok && (rest == "" || strings.IndexByte("/,] ", rest[0]) >= 0) {
			return d, true
		}
	}
	return hostDir{}, false
}

// commandsGolden renders every command path with its aliases and its own
// flags, each with its shorthand, type and host-independent default.
func commandsGolden(cmds []*cobra.Command) string {
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "%s hidden=%t aliases=%q\n", c.CommandPath(), c.Hidden, c.Aliases)
		for _, f := range commandFlags(c) {
			fmt.Fprintf(&b, "  --%s shorthand=%q %s default=%q\n", f.Name, f.Shorthand, f.Value.Type(), contractDefault(f.DefValue))
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

// A default under a host directory renders as a placeholder, not the host's
// path, also inside a slice default; any other default, including one that
// merely starts with a host directory's name, renders unchanged.
func TestCommandContractNormalizesHostDefaults(t *testing.T) {
	root := &cobra.Command{Use: "nocklock"}
	var dirs []string
	for i, d := range contractHostDirs {
		dirs = append(dirs, filepath.Join(d.dir, "nocklock"))
		root.Flags().String(fmt.Sprintf("dir%d", i), filepath.Join(d.dir, "nocklock"), "")
	}
	root.Flags().StringSlice("dirs", dirs, "")
	root.Flags().String("plain", "/etc/nocklock", "")
	root.Flags().String("prefix", "/tmpfs/nocklock", "")
	got := commandsGolden([]*cobra.Command{root})
	var placeholders []string
	for _, d := range contractHostDirs {
		if strings.Contains(got, d.dir+"/") {
			t.Errorf("golden pins host path %s:\n%s", d.dir, got)
		}
		if !strings.Contains(got, `default="`+d.placeholder+`/nocklock"`) {
			t.Errorf("golden does not render %s as %s:\n%s", d.dir, d.placeholder, got)
		}
		placeholders = append(placeholders, d.placeholder+"/nocklock")
	}
	for _, want := range []string{
		`default="[` + strings.Join(placeholders, ",") + `]"`,
		`default="/etc/nocklock"`,
		`default="/tmpfs/nocklock"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("golden does not contain %s:\n%s", want, got)
		}
	}
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

// A command's aliases are pinned by the golden: adding, changing or removing
// one changes it.
func TestCommandContractPinsAliases(t *testing.T) {
	golden := func(aliases ...string) string {
		root := &cobra.Command{Use: "nocklock"}
		root.AddCommand(&cobra.Command{Use: "status", Aliases: aliases, Run: func(*cobra.Command, []string) {}})
		return commandsGolden(contractTree(root))
	}
	with := golden("st")
	if !strings.Contains(with, `nocklock status hidden=false aliases=["st"]`) {
		t.Fatalf("golden does not render the alias:\n%s", with)
	}
	for _, other := range []string{golden(), golden("stat"), golden("st", "stat")} {
		if other == with {
			t.Errorf("golden does not pin the aliases:\n%s", with)
		}
	}
}

// contractTree lists root and its direct subcommands.
func contractTree(root *cobra.Command) []*cobra.Command {
	return append([]*cobra.Command{root}, root.Commands()...)
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

// Markers that make the test binary run as nocklock or as a wrapped child for
// the exit-code contract tests. TestMain checks them before it creates any
// state, since both exit without returning to it.
const (
	contractExecuteArg   = "nocklock-contract-execute"
	contractNoLeaseArg   = "nocklock-contract-no-lease"
	contractChildExitArg = "nocklock-contract-child-exit="
)

// runContractProcess returns unless the test binary's first argument is a
// contract marker. contractChildExitArg<n> exits n, or kills the process
// with SIGKILL for "signal". contractExecuteArg runs Execute with the
// remaining arguments, after contractNoLeaseArg makes the installation lease
// unavailable.
func runContractProcess() {
	if len(os.Args) < 2 {
		return
	}
	args := os.Args[2:]
	if v, ok := strings.CutPrefix(os.Args[1], contractChildExitArg); ok {
		if v == "signal" {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		code, err := strconv.Atoi(v)
		if err != nil {
			code = 125
		}
		os.Exit(code)
	}
	if os.Args[1] != contractExecuteArg {
		return
	}
	if len(args) > 0 && args[0] == contractNoLeaseArg {
		installLease = func() (*os.File, error) { return nil, errors.New("simulated inactive release") }
		args = args[1:]
	}
	rootCmd.SetArgs(args)
	Execute()
	os.Exit(0)
}

// Execute exits 2 when the installation lease is unavailable, whatever the
// command, and otherwise with exitCode of the command's error. It runs in a
// subprocess: it calls os.Exit and mutates the shared command tree.
func TestCLIContractExecuteExitCodes(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"help", []string{"--help"}, 0, ""},
		{"installation unavailable", []string{contractNoLeaseArg, "--help"}, 2, "NockLock: installation unavailable: simulated inactive release"},
		{"unknown command", []string{"no-such-command"}, 1, `unknown command "no-such-command"`},
		{"unknown flag", []string{"status", "--no-such-flag"}, 1, "unknown flag: --no-such-flag"},
		// A missing .nock/config.toml is GAPS FOUND: an exitCodeError other
		// than 1 reaches the process unchanged.
		{"exitCodeError code", []string{"doctor"}, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(exe, append([]string{contractExecuteArg}, tc.args...)...)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+t.TempDir())
			var stderr strings.Builder
			cmd.Stderr = &stderr
			err := cmd.Run()
			got := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				got = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if got != tc.code {
				t.Errorf("nocklock %q exited %d, want %d; stderr:\n%s", tc.args, got, tc.code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Errorf("nocklock %q stderr does not contain %q:\n%s", tc.args, tc.stderr, stderr.String())
			}
		})
	}
}

func TestExitCodeMapsCommandErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{nil, 0},
		{errors.New("usage"), 1},
		{&exitCodeError{code: 1}, 1},
		{&exitCodeError{code: 2}, 2},
		{&exitCodeError{code: 7}, 7},
		{errors.Join(errors.New("refusing"), &exitCodeError{code: 2}), 2},
	} {
		if got := exitCode(tc.err); got != tc.code {
			t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.code)
		}
	}
}

// wrap's exit codes as Execute maps them: a startup refusal, a child that
// cannot be launched, a failed audit write, and the child's own code passed
// through. Each exit-2 row differs from "child exits 0" only in its cause.
// TestWrapFailsWhenAuditWritesFail and TestWrapDurableAudit cover the other
// audit-failure paths.
func TestCLIContractWrapExitCodes(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(code string) []string { return []string{"--", exe, contractChildExitArg + code} }
	for _, tc := range []struct {
		name        string
		args        []string
		failAuditOf logging.EventType
		code        int
	}{
		{name: "no command", args: []string{"--"}, code: 1},
		{name: "unknown flag", args: []string{"--no-such-flag", "--", exe}, code: 1},
		{name: "require enforced egress unmet", args: append([]string{"--require-enforced-egress"}, child("0")...), code: 2},
		{name: "command not found", args: []string{"--", "nocklock-contract-no-such-command"}, code: 1},
		{name: "session_end write fails", args: child("0"), failAuditOf: logging.EventSessionEnd, code: 2},
		{name: "child exits 0", args: child("0"), code: 0},
		{name: "child exits 1", args: child("1"), code: 1},
		{name: "child exits 2", args: child("2"), code: 2},
		{name: "child exits 3", args: child("3"), code: 3},
		{name: "child exits 125", args: child("125"), code: 125},
		{name: "child killed by a signal", args: child("signal"), code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
			projectRoot := resolvedTempDir(t)
			db := filepath.Join(projectRoot, "fresh", config.Dir, "events.db")
			if tc.failAuditOf != "" {
				installAuditWriteFailure(t, projectRoot, db, tc.failAuditOf)
			}
			err := runWrapCommand(t, projectRoot, db, tc.args...)
			if got := exitCode(err); got != tc.code {
				t.Errorf("wrap %q exits %d (error %v), want %d", tc.args, got, err, tc.code)
			}
		})
	}
}
