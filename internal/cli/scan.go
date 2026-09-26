package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	var includeEnv, jsonOutput bool
	cmd := &cobra.Command{
		Use:          "scan [path ...]",
		Short:        "Scan local files for recognized secret formats before launching an agent",
		Long:         "Scans explicit paths relative to the current directory (default: .). No implicit exclusions. Findings and incomplete scans exit nonzero. This is a preflight check, not read-time protection.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("resolve scan directory: %w", err)
			}
			if len(args) == 0 {
				args = []string{"."}
			}
			var env []string
			if includeEnv {
				env = os.Environ()
			}
			report := secrets.Scan(cmd.Context(), root, args, env)
			if err := writeScanReport(cmd.OutOrStdout(), report, jsonOutput); err != nil {
				return fmt.Errorf("write scan report: %w", err)
			}
			if !report.Safe() {
				return &exitCodeError{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&includeEnv, "env", false, "Also scan the invoking environment (without config filtering)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print a metadata-only JSON report")
	return cmd
}

func writeScanReport(w io.Writer, report secrets.ScanReport, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(w).Encode(report)
	}
	var out strings.Builder
	status := "complete"
	if !report.Complete {
		status = "incomplete"
	}
	fmt.Fprintf(&out, "NockLock secret preflight: %s — %d finding(s), %d issue(s), %d file(s), %d environment value(s)\n", status, len(report.Findings), len(report.Issues), report.FilesScanned, report.EnvScanned)
	for _, f := range report.Findings {
		fmt.Fprintf(&out, "  %s %q", f.Source, f.Location)
		if f.Line > 0 {
			fmt.Fprintf(&out, ":%d", f.Line)
		}
		fmt.Fprintf(&out, " — %s\n", f.Rule)
	}
	for _, issue := range report.Issues {
		fmt.Fprintf(&out, "  incomplete %q — %s\n", issue.Location, issue.Reason)
	}
	_, err := io.WriteString(w, out.String())
	return err
}

func runSecretPreflight(ctx context.Context, cfg *config.Config, configPath string, childEnv []string, sessionID string, record func([]logging.Event) error, out io.Writer) error {
	if !cfg.Secrets.ScanEnv && len(cfg.Secrets.ScanPaths) == 0 {
		return nil
	}
	root := filepath.Dir(filepath.Dir(configPath))
	if cfg.ProfileName != "" && strings.HasPrefix(configPath, "embedded profile ") {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve secret scan root: %w", err)
		}
	}
	var env []string
	if cfg.Secrets.ScanEnv {
		for _, entry := range childEnv {
			name, _, _ := strings.Cut(entry, "=")
			if !slices.Contains(cfg.Secrets.ScanEnvAllow, name) {
				env = append(env, entry)
			}
		}
	}
	report := secrets.Scan(ctx, root, cfg.Secrets.ScanPaths, env)
	detail, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode secret preflight audit: %w", err)
	}
	eventType := logging.EventSecretPassed
	if !report.Safe() {
		eventType = logging.EventSecretBlocked
	}
	events := []logging.Event{{Timestamp: time.Now(), EventType: eventType, Category: "secret", Detail: "preflight " + string(detail), Blocked: !report.Safe(), SessionID: sessionID}}
	if !report.Safe() {
		events = append(events, logging.Event{Timestamp: time.Now(), EventType: logging.EventSessionEnd, Category: "session", Detail: "exit_code=1 secret_preflight=refused", Blocked: true, SessionID: sessionID})
	}
	if err := record(events); err != nil {
		return fmt.Errorf("record secret preflight: %w; refusing to start without its audit record", err)
	}
	if err := writeScanReport(out, report, false); err != nil {
		return fmt.Errorf("write secret preflight report: %w; refusing to start", err)
	}
	if !report.Safe() {
		return fmt.Errorf("secret preflight refused launch; resolve the reported findings or incomplete inputs, then rerun the scan")
	}
	return nil
}

func init() { rootCmd.AddCommand(newScanCommand()) }
