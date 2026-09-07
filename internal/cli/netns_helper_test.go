package cli

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/fence/network/netns"
)

func TestBuildNetnsChildCarriesAuthenticatedProxyConfig(t *testing.T) {
	proxy := netns.ProxyConfig{
		Allow:              []string{"api.example.test"},
		AllowPrivateRanges: true,
		BrokerPath:         "/tmp/nocklock-broker.sock",
		BrokerToken:        "test-broker-token",
	}
	cmd, err := buildNetnsChild(t.Context(), []string{"echo", "ok"}, []string{"PATH=/usr/bin"}, proxy)
	if err != nil {
		t.Fatalf("buildNetnsChild() error = %v", err)
	}
	if !reflect.DeepEqual(cmd.Args, []string{"sudo", "-n", netnsHelperPath, "setup"}) {
		t.Fatalf("helper argv = %q, want fixed sudo setup vector", cmd.Args)
	}
	body, err := io.ReadAll(cmd.Stdin)
	if err != nil {
		t.Fatalf("read setup request: %v", err)
	}
	var request netns.Request
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode setup request: %v", err)
	}
	if !reflect.DeepEqual(request.Proxy, proxy) {
		t.Fatalf("request proxy = %#v, want %#v", request.Proxy, proxy)
	}
	if request.Argv[0] == "echo" {
		t.Fatalf("child command was not resolved to an absolute path: %#v", request.Argv)
	}
}

func TestBuildNetnsChildRequiresUsableCommand(t *testing.T) {
	_, err := buildNetnsChild(context.Background(), []string{"nocklock-command-that-does-not-exist"}, nil, netns.ProxyConfig{})
	if err == nil {
		t.Fatal("buildNetnsChild() accepted an unresolved child command")
	}
}
