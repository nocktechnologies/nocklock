//go:build linux

package fs

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInterposerProxyBridgeExecutable(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "nlbridge-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	soPath := filepath.Join(dir, "libfence_fs.so")
	build := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", soPath, "interposer/libfence_fs.c", "-ldl", "-lpthread")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build interposer: %v\n%s", err, out)
	}

	eventSock := filepath.Join(dir, "events.sock")
	eventLn, err := net.Listen("unix", eventSock)
	if err != nil {
		t.Fatalf("listen event socket: %v", err)
	}
	defer eventLn.Close()
	events := make(chan string, 1)
	go func() {
		conn, err := eventLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		events <- string(data)
	}()

	proxySock := filepath.Join(dir, "proxy.sock")
	proxyLn, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatalf("listen proxy socket: %v", err)
	}
	defer proxyLn.Close()
	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("ok"))
	}()

	helperSrc := filepath.Join(dir, "bridge_child.c")
	helperBin := filepath.Join(dir, "bridge_child")
	if err := os.WriteFile(helperSrc, []byte(proxyBridgeChildSource), 0o600); err != nil {
		t.Fatalf("write helper source: %v", err)
	}
	helperBuild := exec.Command("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", helperBin, helperSrc)
	if out, err := helperBuild.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	cmd := exec.Command(helperBin)
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+soPath,
		"NOCKLOCK_FS_ALLOWED=/\x1frw\x1f"+eventSock,
		"NOCKLOCK_PROXY_TCP_ADDR=127.0.0.1:32123",
		"NOCKLOCK_PROXY_UNIX_SOCKET="+proxySock,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bridge child failed: %v\n%s", err, out)
	}

	select {
	case got := <-events:
		if !strings.Contains(got, `"operation":"connect"`) ||
			!strings.Contains(got, "unexpected AF_INET/AF_INET6 proxy bridge target") {
			t.Fatalf("blocked event = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for blocked connect event")
	}
}

const proxyBridgeChildSource = `
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_v4(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) return -2;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) return -3;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -4;
    }
    return fd;
}

int main(void) {
    int fd = connect_v4(32123);
    if (fd < 0) {
        fprintf(stderr, "proxy connect failed rc=%d errno=%d\n", fd, errno);
        return 10;
    }
    if (write(fd, "ping", 4) != 4) return 11;
    char buf[2];
    if (read(fd, buf, sizeof(buf)) != 2) return 12;
    if (memcmp(buf, "ok", 2) != 0) return 13;
    close(fd);

    fd = connect_v4(32124);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "unexpected direct connect success\n");
        return 20;
    }
    if (errno != EPERM) {
        fprintf(stderr, "direct connect errno=%d want EPERM=%d\n", errno, EPERM);
        return 21;
    }
    return 0;
}
`
