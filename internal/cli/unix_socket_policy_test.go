package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestConfinedUnixSocketPolicy(t *testing.T) {
	tests := []struct {
		name          string
		abi           int
		detectErr     error
		allow         bool
		wantIsolated  bool
		wantWarning   bool
		wantErrorText string
	}{
		{name: "supported ABI isolates", abi: 9, wantIsolated: true},
		{name: "older ABI refuses by default", abi: 5, wantErrorText: "upgrade to Landlock ABI v9"},
		{name: "older ABI requires explicit opt in", abi: 5, allow: true, wantWarning: true},
		{name: "unknown capability refuses by default", detectErr: errors.New("probe failed"), wantErrorText: "probe failed"},
		{name: "unknown capability can be explicitly allowed", detectErr: errors.New("probe failed"), allow: true, wantWarning: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolated, warning, err := confinedUnixSocketPolicy(tt.abi, tt.detectErr, tt.allow)
			if isolated != tt.wantIsolated {
				t.Fatalf("isolated = %t, want %t", isolated, tt.wantIsolated)
			}
			if (warning != "") != tt.wantWarning {
				t.Fatalf("warning = %q, want warning=%t", warning, tt.wantWarning)
			}
			if tt.wantErrorText == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrorText) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErrorText)
			}
		})
	}
}
