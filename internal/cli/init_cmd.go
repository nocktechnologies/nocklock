package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var (
	initRuntime string
	initDiff    bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize NockLock config in current directory",
	Long:  "Initialize NockLock config in current directory. Use --runtime to scaffold from an embedded runtime preset.",
	RunE: func(cmd *cobra.Command, args []string) error {
		nockDir := config.Dir
		configPath := filepath.Join(nockDir, config.File)
		configBody, runtimeName, err := initConfigBody(initRuntime)
		if err != nil {
			return err
		}

		if initDiff {
			if runtimeName == "" {
				return fmt.Errorf("--diff needs --runtime <name>: it compares that preset with the existing %s", configPath)
			}
			return runInitDiff(cmd.OutOrStdout(), configPath, runtimeName)
		}

		if err := os.MkdirAll(nockDir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", nockDir, err)
		}

		// Use O_CREATE|O_EXCL for atomic create-or-fail, avoiding TOCTOU race.
		f, err := os.OpenFile(configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				cmd.SilenceUsage = true
				hint := ""
				if runtimeName != "" {
					hint = fmt.Sprintf("; run 'nocklock init --runtime %s --diff' to see what the preset would change, then edit the file", runtimeName)
				}
				return fmt.Errorf("config already exists at %s and was left unchanged%s", configPath, hint)
			}
			return fmt.Errorf("failed to create config at %s: %w", configPath, err)
		}
		if _, err := f.WriteString(configBody); err != nil {
			f.Close()
			os.Remove(configPath) // best-effort cleanup of partial file
			return fmt.Errorf("failed to write config at %s: %w", configPath, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to finalize config at %s: %w", configPath, err)
		}

		if runtimeName != "" {
			fmt.Fprintf(os.Stderr, "NockLock initialized for runtime %q. Config at %s\n", runtimeName, configPath)
		} else {
			fmt.Fprintf(os.Stderr, "NockLock initialized. Config at %s\n", configPath)
		}
		return nil
	},
}

// runInitDiff prints the policy lines the runtime preset would add (+) to or
// remove (-) from the existing config at configPath. It never writes.
func runInitDiff(w io.Writer, configPath, runtimeName string) error {
	existing, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("no config at %s to compare against; run 'nocklock init --runtime %s' to create one", configPath, runtimeName)
		}
		return fmt.Errorf("failed to load %s: %w", configPath, err)
	}
	preset, err := config.LoadProfile(runtimeName)
	if err != nil {
		return err
	}
	preset.ProfileName = ""
	have, err := configTree(existing)
	if err != nil {
		return err
	}
	want, err := configTree(preset)
	if err != nil {
		return err
	}
	var removed, added []string
	diffValue("", have, want, &removed, &added)
	for _, l := range removed {
		fmt.Fprintf(w, "- %s\n", l)
	}
	for _, l := range added {
		fmt.Fprintf(w, "+ %s\n", l)
	}
	if len(removed)+len(added) == 0 {
		fmt.Fprintf(w, "%s already matches the %s preset.\n", configPath, runtimeName)
	} else {
		fmt.Fprintf(w, "\n'-' lines are in %s only; '+' lines are in the %s preset only. Nothing was written.\n", configPath, runtimeName)
	}
	return nil
}

// configTree renders cfg as TOML and decodes it back into generic tables, so
// two configs can be compared key by key.
func configTree(cfg *config.Config) (map[string]any, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return nil, fmt.Errorf("failed to render config: %w", err)
	}
	var tree map[string]any
	if _, err := toml.Decode(buf.String(), &tree); err != nil {
		return nil, fmt.Errorf("failed to parse rendered config: %w", err)
	}
	return tree, nil
}

// diffValue compares have and want at path (nil means absent) and appends one
// "path = value" line to removed or added per difference (array elements use
// "path -= value" and "path += value" so they do not read as assignments). Tables recurse key
// by key, arrays of tables compare entry by entry in order (a missing entry is
// reported whole as path[i]), and arrays of scalars compare element by element.
func diffValue(path string, have, want any, removed, added *[]string) {
	switch h := have.(type) {
	case map[string]any:
		if w, ok := want.(map[string]any); ok {
			for _, k := range sortedUnionKeys(h, w) {
				diffValue(joinKey(path, k), h[k], w[k], removed, added)
			}
			return
		}
	case []map[string]any:
		if w, ok := want.([]map[string]any); ok {
			for i := 0; i < max(len(h), len(w)); i++ {
				var he, we any
				if i < len(h) {
					he = h[i]
				}
				if i < len(w) {
					we = w[i]
				}
				diffValue(fmt.Sprintf("%s[%d]", path, i), he, we, removed, added)
			}
			return
		}
	case []any:
		if w, ok := want.([]any); ok {
			for _, e := range h {
				if !slices.ContainsFunc(w, func(o any) bool { return reflect.DeepEqual(e, o) }) {
					*removed = append(*removed, path+" -= "+renderValue(e))
				}
			}
			for _, e := range w {
				if !slices.ContainsFunc(h, func(o any) bool { return reflect.DeepEqual(e, o) }) {
					*added = append(*added, path+" += "+renderValue(e))
				}
			}
			return
		}
	}
	if reflect.DeepEqual(have, want) {
		return
	}
	if have != nil {
		*removed = append(*removed, path+" = "+renderValue(have))
	}
	if want != nil {
		*added = append(*added, path+" = "+renderValue(want))
	}
}

func joinKey(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func sortedUnionKeys(a, b map[string]any) []string {
	keys := slices.Collect(maps.Keys(a))
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// renderValue prints v compactly; json.Marshal sorts map keys, so output is stable.
func renderValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func initConfigBody(runtimeName string) (body string, resolvedRuntime string, err error) {
	runtimeName = strings.TrimSpace(runtimeName)
	if runtimeName == "" {
		return config.DefaultTOML(), "", nil
	}
	if _, err = config.LoadProfile(runtimeName); err != nil {
		return "", "", err
	}
	body, err = config.ProfileTOML(runtimeName)
	if err != nil {
		return "", "", err
	}
	return body, runtimeName, nil
}

func init() {
	initCmd.Flags().StringVar(&initRuntime, "runtime", "", "scaffold config from an embedded runtime preset")
	initCmd.Flags().BoolVar(&initDiff, "diff", false, "with --runtime, print the policy changes the preset would make to the existing config (no write)")
	rootCmd.AddCommand(initCmd)
}
