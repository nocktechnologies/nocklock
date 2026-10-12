package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		if os.IsNotExist(err) {
			return fmt.Errorf("no config at %s to compare against; run 'nocklock init --runtime %s' to create one", configPath, runtimeName)
		}
		return fmt.Errorf("failed to load %s: %w", configPath, err)
	}
	preset, err := config.LoadProfile(runtimeName)
	if err != nil {
		return err
	}
	preset.ProfileName = ""
	have, err := policyLines(existing)
	if err != nil {
		return err
	}
	want, err := policyLines(preset)
	if err != nil {
		return err
	}
	n := 0
	for _, l := range have {
		if !slices.Contains(want, l) {
			fmt.Fprintf(w, "- %s\n", l)
			n++
		}
	}
	for _, l := range want {
		if !slices.Contains(have, l) {
			fmt.Fprintf(w, "+ %s\n", l)
			n++
		}
	}
	if n == 0 {
		fmt.Fprintf(w, "%s already matches the %s preset.\n", configPath, runtimeName)
	} else {
		fmt.Fprintf(w, "\n'-' lines are in %s only; '+' lines are in the %s preset only. Nothing was written.\n", configPath, runtimeName)
	}
	return nil
}

// policyLines renders cfg as TOML and returns each setting prefixed with its
// [section], so two configs can be compared line by line.
func policyLines(cfg *config.Config) ([]string, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return nil, fmt.Errorf("failed to render config: %w", err)
	}
	var out []string
	section := ""
	for _, l := range strings.Split(buf.String(), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "["):
			section = l
		default:
			out = append(out, section+" "+l)
		}
	}
	return out, nil
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
