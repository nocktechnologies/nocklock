package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View fence event log",
	Long:  "Query and display fence events from the local SQLite event log.",
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionFilter, _ := cmd.Flags().GetString("session")
		blockedOnly, _ := cmd.Flags().GetBool("blocked")
		sinceStr, _ := cmd.Flags().GetString("since")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showStats, _ := cmd.Flags().GetBool("stats")
		pruneStr, _ := cmd.Flags().GetString("prune")

		// Load config and resolve DB path.
		configPath, err := config.FindConfig()
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("no NockLock config found. Run 'nocklock init' first")
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to load config: %w", err)
		}

		dbPath, projectRoot := config.ResolveDBPath(cfg, configPath)

		// Don't create the DB file for a read-only operation.
		if _, statErr := os.Stat(dbPath); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				fmt.Println("No fence events recorded. Events will appear here once fences are active.")
				return nil
			}
			cmd.SilenceUsage = true
			return fmt.Errorf("cannot access event log: %w", statErr)
		}

		logger, err := logging.NewLogger(dbPath, projectRoot)
		if err != nil {
			cmd.SilenceUsage = true
			return fmt.Errorf("failed to open event log: %w", err)
		}
		defer logger.Close()

		// Handle --prune: delete old events and exit.
		if pruneStr != "" {
			dur, err := parseDuration(pruneStr)
			if err != nil {
				return fmt.Errorf("invalid prune duration %q: %w", pruneStr, err)
			}
			n, err := logger.Prune(dur)
			if err != nil {
				return fmt.Errorf("failed to prune events: %w", err)
			}
			fmt.Printf("Pruned %d event(s) older than %s\n", n, pruneStr)
			return nil
		}

		// Handle --stats: show aggregate statistics and exit.
		if showStats {
			s, err := logger.Stats(sessionFilter)
			if err != nil {
				return fmt.Errorf("failed to get stats: %w", err)
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			fmt.Printf("Total events: %d\n", s.TotalEvents)
			fmt.Printf("Sessions:     %d\n", s.SessionCount)
			fmt.Printf("Blocked:      %d\n", s.BlockedCount)
			fmt.Printf("Passed:       %d\n", s.PassedCount)
			if s.FirstEvent != nil {
				fmt.Printf("First event:  %s\n", s.FirstEvent.Local().Format("2006-01-02 15:04:05"))
			}
			if s.LastEvent != nil {
				fmt.Printf("Last event:   %s\n", s.LastEvent.Local().Format("2006-01-02 15:04:05"))
			}
			for cat, count := range s.ByCategory {
				fmt.Printf("  %s: %d\n", cat, count)
			}
			return nil
		}

		// Build query options.
		opts := logging.QueryOptions{
			Limit:      1000, // generous default for display
			Descending: true, // newest first so we always see recent events
		}
		if sessionFilter != "" {
			opts.SessionID = &sessionFilter
		}
		if blockedOnly {
			b := true
			opts.Blocked = &b
		}
		if sinceStr != "" {
			dur, err := parseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("invalid since duration %q: %w", sinceStr, err)
			}
			since := time.Now().Add(-dur)
			opts.Since = &since
		}

		events, err := logger.Query(opts)
		if err != nil {
			return fmt.Errorf("failed to query events: %w", err)
		}

		if len(events) == 0 {
			fmt.Println("No fence events recorded. Events will appear here once fences are active.")
			return nil
		}

		// JSON output mode.
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(events)
		}

		// Group events by session, most recent session first.
		type sessionGroup struct {
			events []logging.Event
		}
		sessionOrder := []string{}
		sessionMap := map[string]*sessionGroup{}
		for _, e := range events {
			sg, exists := sessionMap[e.SessionID]
			if !exists {
				sg = &sessionGroup{}
				sessionMap[e.SessionID] = sg
				sessionOrder = append(sessionOrder, e.SessionID)
			}
			sg.events = append(sg.events, e)
		}

		totalBlocked := 0
		totalPassed := 0

		for _, sid := range sessionOrder {
			sg := sessionMap[sid]
			shortID := sid
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			// Find start and end times.
			var startTime, endTime *time.Time
			for i := range sg.events {
				e := &sg.events[i]
				if e.EventType == logging.EventSessionStart && startTime == nil {
					t := e.Timestamp
					startTime = &t
				}
				if e.EventType == logging.EventSessionEnd {
					t := e.Timestamp
					endTime = &t
				}
			}

			// Session header.
			fmt.Printf("Session %s", shortID)
			if startTime != nil {
				fmt.Printf("  started %s", startTime.Local().Format("2006-01-02 15:04:05"))
			}
			if endTime != nil {
				fmt.Printf("  ended %s", endTime.Local().Format("2006-01-02 15:04:05"))
			}
			if startTime != nil && endTime != nil {
				dur := endTime.Sub(*startTime)
				fmt.Printf("  (%s)", formatDuration(dur))
			}
			fmt.Println()

			// Display events.
			for _, e := range sg.events {
				fmt.Printf("  %s: %s\n", e.EventType, sanitizeDetail(e.Detail))
				if e.Blocked {
					totalBlocked++
				} else if e.EventType == logging.EventSecretPassed ||
					e.EventType == logging.EventFilePassed ||
					e.EventType == logging.EventNetworkPassed {
					totalPassed++
				}
			}
			fmt.Println()
		}

		// Footer with totals.
		fmt.Printf("Total: %d event(s) across %d session(s), %d blocked, %d passed\n",
			len(events), len(sessionOrder), totalBlocked, totalPassed)

		return nil
	},
}

func init() {
	logCmd.Flags().String("session", "", "filter by session ID")
	logCmd.Flags().Bool("blocked", false, "show only blocked events")
	logCmd.Flags().String("since", "", "show events since duration (e.g., 24h, 7d)")
	logCmd.Flags().Bool("json", false, "output as JSON")
	logCmd.Flags().Bool("stats", false, "show aggregate statistics only")
	logCmd.Flags().String("prune", "", "delete events older than duration (e.g., 30d)")
	rootCmd.AddCommand(logCmd)
}

// parseDuration parses a Go duration string with additional support for "d" suffix (days).
func parseDuration(s string) (time.Duration, error) {
	// Check for day suffix.
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration %q", s)
		}
		if days <= 0 || days > 3650 {
			return 0, fmt.Errorf("day duration must be between 1 and 3650, got %d", days)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// sanitizeDetail removes control characters that could spoof terminal output.
func sanitizeDetail(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\x1b' {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatDuration produces a human-readable duration string like "1h 23m 45s".
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
