package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	verifySecretName     = "NOCKLOCK_VERIFY_SECRET"
	verifyCanaryPathEnv  = "NOCKLOCK_VERIFY_CANARY_PATH"
	verifyNetworkTimeout = 2 * time.Second
	verifyInvalidHostURL = "http://verify.nocklock.invalid"
	verifyExampleHostURL = "http://example.com"
)

type probeResult struct {
	Fence     string `json:"fence"`
	Attempted bool   `json:"attempted"`
	Blocked   bool   `json:"blocked"`
	Detail    string `json:"detail"`
}

var probeCmd = &cobra.Command{
	Use:    "__probe <fence>",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result := runProbe(args[0])
		if err := renderProbeJSON(cmd.OutOrStdout(), result); err != nil {
			return err
		}
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if !result.Attempted || result.Blocked {
			return nil
		}
		return &exitCodeError{code: 1}
	},
}

func init() {
	rootCmd.AddCommand(probeCmd)
}

func runProbe(fence string) probeResult {
	switch fence {
	case "filesystem":
		return probeFilesystem()
	case "network":
		return probeNetwork()
	case "secret", "secrets":
		return probeSecret()
	case "syscall":
		return probeSyscall()
	default:
		return probeResult{Fence: fence, Attempted: false, Blocked: false, Detail: "unknown fence"}
	}
}

func probeFilesystem() probeResult {
	path := os.Getenv(verifyCanaryPathEnv)
	if path == "" {
		return probeResult{Fence: "filesystem", Attempted: false, Blocked: false, Detail: "canary path not provided"}
	}
	if _, err := os.ReadFile(path); err == nil {
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: false, Detail: "read outside-root canary"}
	} else if isBlockedReadError(err) {
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: true, Detail: fmt.Sprintf("outside-root canary blocked: %v", err)}
	} else {
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: true, Detail: fmt.Sprintf("outside-root canary unavailable: %v", err)}
	}
}

func isBlockedReadError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)
}

func probeNetwork() probeResult {
	client := &http.Client{Timeout: verifyNetworkTimeout}
	for _, target := range []string{verifyInvalidHostURL, verifyExampleHostURL} {
		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "NockLock") {
			continue
		}
		return probeResult{Fence: "network", Attempted: true, Blocked: false, Detail: fmt.Sprintf("reached off-allowlist host %s with status %d", target, resp.StatusCode)}
	}
	return probeResult{Fence: "network", Attempted: true, Blocked: true, Detail: "off-allowlist HTTP probes were blocked"}
}

func probeSecret() probeResult {
	if _, ok := os.LookupEnv(verifySecretName); ok {
		return probeResult{Fence: "secret", Attempted: true, Blocked: false, Detail: verifySecretName + " remained in child environment"}
	}
	return probeResult{Fence: "secret", Attempted: true, Blocked: true, Detail: verifySecretName + " absent from child environment"}
}

func renderProbeJSON(w io.Writer, result probeResult) error {
	enc := json.NewEncoder(w)
	return enc.Encode(result)
}
