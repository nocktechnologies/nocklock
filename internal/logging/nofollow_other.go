//go:build !unix

package logging

// oNoFollow is a no-op on platforms without O_NOFOLLOW (e.g. Windows). The
// pre-open lstat symlink check in NewLogger still applies on every platform;
// only the extra kernel-level TOCTOU guard is unavailable here. NockLock ships
// for Linux and macOS, so this branch exists purely so the module still builds
// under `go vet`/`go build` on any GOOS.
const oNoFollow = 0
