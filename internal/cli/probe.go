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
	verifySecretName        = "NOCKLOCK_VERIFY_SECRET"
	verifySecretControlName = "NOCKLOCK_VERIFY_CONTROL"
	verifyCanaryPathEnv     = "NOCKLOCK_VERIFY_CANARY_PATH"
	verifyCanaryTokenEnv    = "NOCKLOCK_VERIFY_CANARY_TOKEN"
	verifyCanaryKnownEnv    = "NOCKLOCK_VERIFY_CANARY_KNOWN"
	verifyNetworkURLEnv     = "NOCKLOCK_VERIFY_NETWORK_URL"
	verifyNetworkTimeout    = 2 * time.Second
)

type probeResult struct {
	Fence     string `json:"fence"`
	Attempted bool   `json:"attempted"`
	Blocked   bool   `json:"blocked"`
	Detail    string `json:"detail"`
}

var verifyProxyFromEnvironment = http.ProxyFromEnvironment

var probeCmd = &cobra.Command{
	Use:    "__probe <fence>",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		result := runProbe(args[0], cmd)
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
	probeCmd.Flags().String("canary-path", "", "private filesystem canary path")
	probeCmd.Flags().String("canary-token", "", "non-secret canary content")
	probeCmd.Flags().Bool("canary-known", false, "canary passed its unfenced control")
	probeCmd.Flags().Bool("write-canary", false, "probe write access instead of read access")
	probeCmd.Flags().String("network-url", "", "off-allowlist probe URL")
	rootCmd.AddCommand(probeCmd)
}

func runProbe(fence string, cmd *cobra.Command) probeResult {
	switch fence {
	case "filesystem":
		path, _ := cmd.Flags().GetString("canary-path")
		token, _ := cmd.Flags().GetString("canary-token")
		known, _ := cmd.Flags().GetBool("canary-known")
		write, _ := cmd.Flags().GetBool("write-canary")
		return probeFilesystem(path, token, known, write)
	case "network":
		target, _ := cmd.Flags().GetString("network-url")
		return probeNetwork(target)
	case "secret", "secrets":
		return probeSecret()
	case "syscall":
		return probeSyscall()
	default:
		return probeResult{Fence: fence, Attempted: false, Blocked: false, Detail: "unknown fence"}
	}
}

func probeFilesystem(path, wantToken string, known, write bool) probeResult {
	if path == "" {
		return probeResult{Fence: "filesystem", Attempted: false, Blocked: false, Detail: "canary path not provided"}
	}
	if wantToken == "" {
		return probeResult{Fence: "filesystem", Attempted: false, Blocked: false, Detail: "canary token not provided"}
	}
	// Seatbelt promises outside-root write confinement, not general read
	// confinement. Opening the private canary O_WRONLY tests that boundary
	// without creating, truncating or changing any file.
	if write {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_ = f.Close()
			return probeResult{Fence: "filesystem", Attempted: true, Detail: "opened outside-root canary for writing"}
		}
		if errors.Is(err, os.ErrPermission) {
			return probeResult{Fence: "filesystem", Attempted: true, Blocked: true, Detail: fmt.Sprintf("outside-root canary write blocked: %v", err)}
		}
		return probeResult{Fence: "filesystem", Detail: fmt.Sprintf("outside-root write canary unavailable: %v", err)}
	}
	if data, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(data)) != wantToken {
			return probeResult{Fence: "filesystem", Attempted: true, Blocked: false, Detail: "read outside-root canary with unexpected token"}
		}
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: false, Detail: "read outside-root canary"}
	} else if isBlockedReadError(err) {
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: true, Detail: fmt.Sprintf("outside-root canary blocked: %v", err)}
	} else if errors.Is(err, os.ErrNotExist) && known {
		return probeResult{Fence: "filesystem", Attempted: true, Blocked: true, Detail: fmt.Sprintf("outside-root canary hidden by fence: %v", err)}
	} else if errors.Is(err, os.ErrNotExist) {
		return probeResult{Fence: "filesystem", Attempted: false, Blocked: false, Detail: fmt.Sprintf("outside-root canary missing: %v", err)}
	} else {
		return probeResult{Fence: "filesystem", Attempted: false, Blocked: false, Detail: fmt.Sprintf("outside-root canary unavailable: %v", err)}
	}
}

func isBlockedReadError(err error) bool {
	return errors.Is(err, os.ErrPermission)
}

func probeNetwork(target string) probeResult {
	if target == "" {
		return probeResult{Fence: "network", Attempted: false, Blocked: false, Detail: "off-allowlist target not provided"}
	}
	client := &http.Client{
		Timeout:   verifyNetworkTimeout,
		Transport: &http.Transport{Proxy: verifyProxyFromEnvironment},
	}
	resp, err := client.Get(target)
	if err != nil {
		return probeResult{Fence: "network", Attempted: false, Blocked: false, Detail: fmt.Sprintf("off-allowlist HTTP probe inconclusive: %v", err)}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "NockLock") {
		return probeResult{Fence: "network", Attempted: true, Blocked: true, Detail: fmt.Sprintf("off-allowlist host %s blocked by NockLock proxy", target)}
	}
	return probeResult{Fence: "network", Attempted: true, Blocked: false, Detail: fmt.Sprintf("reached off-allowlist host %s with status %d", target, resp.StatusCode)}
}

func probeSecret() probeResult {
	if _, ok := os.LookupEnv(verifySecretControlName); !ok {
		return probeResult{Fence: "secret", Attempted: false, Blocked: false, Detail: verifySecretControlName + " absent from child environment"}
	}
	if _, ok := os.LookupEnv(verifySecretName); ok {
		return probeResult{Fence: "secret", Attempted: true, Blocked: false, Detail: verifySecretName + " remained in child environment"}
	}
	return probeResult{Fence: "secret", Attempted: true, Blocked: true, Detail: verifySecretName + " absent from child environment"}
}

func renderProbeJSON(w io.Writer, result probeResult) error {
	enc := json.NewEncoder(w)
	return enc.Encode(result)
}
