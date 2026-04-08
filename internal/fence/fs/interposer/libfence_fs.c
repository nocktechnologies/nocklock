/*
 * libfence_fs.c — NockLock filesystem fence via LD_PRELOAD
 *
 * This shared library intercepts libc file operations and blocks access
 * to paths outside the allowed directory tree. It is loaded into child
 * processes via LD_PRELOAD by the NockLock Go parent process.
 *
 * Configuration is read from the NOCKLOCK_FS_ALLOWED environment variable
 * on the first intercepted call (lazy init, thread-safe via pthread_once).
 *
 * Blocked calls set errno = EACCES and return -1 (or NULL for fopen/realpath).
 * Events are reported as newline-delimited JSON over a Unix domain socket.
 *
 * Future enhancement: stat/lstat interception. On modern glibc, stat() is
 * implemented via __xstat(). The primary attack surface (open/fopen/access)
 * is covered by this implementation. stat interception can be added later
 * by hooking __xstat/__lxstat with fallback to stat/lstat via dlsym.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#define MAX_PATHS 256
#define FIELD_SEP '\x1f'

typedef struct {
    char root[PATH_MAX];
    int  mode_rw;          /* 1=read-write, 0=read-only */
    char socket_path[PATH_MAX];
    char allow[MAX_PATHS][PATH_MAX];
    int  allow_count;
    char deny[MAX_PATHS][PATH_MAX];
    int  deny_count;
    int  initialized;
} fence_config_t;

static fence_config_t g_config;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

/* ------------------------------------------------------------------ */
/* Real function pointers                                              */
/* ------------------------------------------------------------------ */

typedef int    (*real_open_t)(const char *, int, ...);
typedef int    (*real_openat_t)(int, const char *, int, ...);
typedef FILE * (*real_fopen_t)(const char *, const char *);
typedef int    (*real_access_t)(const char *, int);
typedef int    (*real_unlink_t)(const char *);
typedef int    (*real_rename_t)(const char *, const char *);
typedef int    (*real_mkdir_t)(const char *, mode_t);
typedef int    (*real_rmdir_t)(const char *);
typedef ssize_t (*real_readlink_t)(const char *, char *, size_t);
typedef char * (*real_realpath_t)(const char *, char *);

/* 64-bit variants */
typedef int    (*real_open64_t)(const char *, int, ...);
typedef int    (*real_openat64_t)(int, const char *, int, ...);
typedef FILE * (*real_fopen64_t)(const char *, const char *);

/* *at family */
typedef int    (*real_unlinkat_t)(int, const char *, int);
typedef int    (*real_renameat_t)(int, const char *, int, const char *);
typedef int    (*real_renameat2_t)(int, const char *, int, const char *, unsigned int);
typedef int    (*real_mkdirat_t)(int, const char *, mode_t);
typedef int    (*real_symlinkat_t)(const char *, int, const char *);
typedef int    (*real_linkat_t)(int, const char *, int, const char *, int);

/* Other important functions */
typedef int    (*real_creat_t)(const char *, mode_t);
typedef int    (*real_symlink_t)(const char *, const char *);
typedef int    (*real_link_t)(const char *, const char *);
typedef int    (*real_chmod_t)(const char *, mode_t);
typedef int    (*real_chown_t)(const char *, uid_t, gid_t);
typedef int    (*real_truncate_t)(const char *, off_t);

/* chdir family */
typedef int    (*real_chdir_t)(const char *);
typedef int    (*real_fchdir_t)(int);

static real_open_t     real_open;
static real_openat_t   real_openat;
static real_fopen_t    real_fopen;
static real_access_t   real_access;
static real_unlink_t   real_unlink;
static real_rename_t   real_rename;
static real_mkdir_t    real_mkdir;
static real_rmdir_t    real_rmdir;
static real_readlink_t real_readlink;
static real_realpath_t real_realpath;

/* 64-bit variants */
static real_open64_t   real_open64;
static real_openat64_t real_openat64;
static real_fopen64_t  real_fopen64;

/* *at family */
static real_unlinkat_t   real_unlinkat;
static real_renameat_t   real_renameat;
static real_renameat2_t  real_renameat2;
static real_mkdirat_t    real_mkdirat;
static real_symlinkat_t  real_symlinkat;
static real_linkat_t     real_linkat;

/* Other important functions */
static real_creat_t    real_creat;
static real_symlink_t  real_symlink;
static real_link_t     real_link;
static real_chmod_t    real_chmod;
static real_chown_t    real_chown;
static real_truncate_t real_truncate;

/* chdir family */
static real_chdir_t    real_chdir;
static real_fchdir_t   real_fchdir;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * path_starts_with checks that `path` starts with `prefix` and the character
 * immediately after the prefix is either '\0' or '/'. This prevents
 * "/tmp" from matching "/tmpfoo".
 */
static int path_starts_with(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);

    /* Root "/" matches all absolute paths. */
    if (plen == 1 && prefix[0] == '/')
        return 1;

    if (strncmp(path, prefix, plen) != 0)
        return 0;
    /* After matching the prefix, the next char must be end-of-string or '/'. */
    char next = path[plen];
    return (next == '\0' || next == '/');
}

/*
 * resolve_path resolves `path` to an absolute path. For existing paths we use
 * realpath(). For non-existing paths (e.g. O_CREAT targets) we resolve the
 * parent directory and append the basename.
 *
 * Returns 0 on success, -1 on failure (resolved is left unchanged).
 */
static int resolve_path(const char *path, char *resolved)
{
    /* Try realpath first (works for existing paths). */
    if (real_realpath(path, resolved) != NULL)
        return 0;

    /* Path does not exist — resolve parent + basename. */
    char tmp[PATH_MAX];

    /* Handle relative paths with no slash: prepend cwd. */
    if (path[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL)
            return -1;
        if (strchr(path, '/') == NULL) {
            /* Simple filename, parent is cwd. */
            if (real_realpath(cwd, tmp) == NULL)
                return -1;
            size_t cwdlen = strlen(tmp);
            size_t pathlen = strlen(path);
            if (cwdlen + 1 + pathlen >= PATH_MAX)
                return -1;
            memcpy(resolved, tmp, cwdlen);
            resolved[cwdlen] = '/';
            memcpy(resolved + cwdlen + 1, path, pathlen + 1);
            return 0;
        }
        /* Has slashes but is relative. Build absolute from cwd. */
        size_t cwdlen = strlen(cwd);
        size_t pathlen = strlen(path);
        if (cwdlen + 1 + pathlen >= PATH_MAX)
            return -1;
        memcpy(tmp, cwd, cwdlen);
        tmp[cwdlen] = '/';
        memcpy(tmp + cwdlen + 1, path, pathlen + 1);
    } else {
        if (strlen(path) >= PATH_MAX)
            return -1;
        strncpy(tmp, path, PATH_MAX);
        tmp[PATH_MAX - 1] = '\0';
    }

    /* Find last slash to split parent/basename. */
    char *last_slash = strrchr(tmp, '/');
    if (last_slash == NULL)
        return -1;

    /* Extract basename. */
    const char *basename = last_slash + 1;
    size_t blen = strlen(basename);

    /* Temporarily null-terminate to get parent path. */
    if (last_slash == tmp) {
        /* Parent is root "/". */
        resolved[0] = '/';
        memcpy(resolved + 1, basename, blen + 1);
        return 0;
    }

    *last_slash = '\0';
    char parent_resolved[PATH_MAX];
    if (real_realpath(tmp, parent_resolved) == NULL) {
        *last_slash = '/'; /* Restore. */
        return -1;
    }
    *last_slash = '/'; /* Restore. */

    size_t plen = strlen(parent_resolved);
    if (plen + 1 + blen >= PATH_MAX)
        return -1;
    memcpy(resolved, parent_resolved, plen);
    resolved[plen] = '/';
    memcpy(resolved + plen + 1, basename, blen + 1);
    return 0;
}

/*
 * resolve_openat_path resolves a pathname relative to a directory file
 * descriptor. If pathname is absolute or dirfd is AT_FDCWD, falls through
 * to resolve_path directly. Otherwise reads /proc/self/fd/<dirfd> to
 * determine the directory and builds the full path before resolving.
 *
 * Returns 0 on success, -1 on failure.
 */
static int resolve_openat_path(int dirfd, const char *pathname, char *resolved)
{
    if (pathname[0] == '/' || dirfd == AT_FDCWD)
        return resolve_path(pathname, resolved);

    char fdpath[64];
    char dirpath[PATH_MAX];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", dirfd);
    ssize_t n = real_readlink(fdpath, dirpath, sizeof(dirpath) - 1);
    if (n <= 0)
        return -1;
    dirpath[n] = '\0';

    char fullpath[PATH_MAX];
    size_t dlen = (size_t)n;
    size_t plen = strlen(pathname);
    if (dlen + 1 + plen >= PATH_MAX)
        return -1;
    memcpy(fullpath, dirpath, dlen);
    fullpath[dlen] = '/';
    memcpy(fullpath + dlen + 1, pathname, plen + 1);

    return resolve_path(fullpath, resolved);
}

/*
 * is_write_open returns 1 if the open flags indicate a write operation.
 */
static int is_write_open(int flags)
{
    if ((flags & O_WRONLY) || (flags & O_RDWR))
        return 1;
    if ((flags & O_CREAT) || (flags & O_TRUNC) || (flags & O_APPEND))
        return 1;
#ifdef O_TMPFILE
    if (flags & O_TMPFILE)
        return 1;
#endif
    return 0;
}

/*
 * is_write_fopen returns 1 if the fopen mode string indicates a write.
 */
static int is_write_fopen(const char *mode)
{
    if (mode == NULL)
        return 0;
    if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'))
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Event reporting                                                     */
/* ------------------------------------------------------------------ */

/*
 * json_escape writes a JSON-safe version of `src` into `dst` (max `dstlen`).
 * Escapes backslash and double-quote characters.
 */
static void json_escape(const char *src, char *dst, size_t dstlen)
{
    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 6 < dstlen; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"' || c == '\\') {
            dst[di++] = '\\';
            dst[di++] = (char)c;
        } else if (c == '\n') {
            dst[di++] = '\\';
            dst[di++] = 'n';
        } else if (c == '\r') {
            dst[di++] = '\\';
            dst[di++] = 'r';
        } else if (c == '\t') {
            dst[di++] = '\\';
            dst[di++] = 't';
        } else if (c < 0x20) {
            /* Other control characters: emit \uXXXX. */
            int written = snprintf(dst + di, dstlen - di, "\\u%04x", c);
            if (written < 0 || (size_t)written >= dstlen - di)
                break;
            di += (size_t)written;
        } else {
            dst[di++] = (char)c;
        }
    }
    dst[di] = '\0';
}

/*
 * report_blocked sends a blocked-event JSON message to the Unix domain socket.
 * Best-effort: if the socket connection fails, we silently continue.
 */
static void report_blocked(const char *path, const char *operation,
                           const char *reason)
{
    if (g_config.socket_path[0] == '\0')
        return;

    /* Build timestamp in ISO 8601 UTC. */
    char timestamp[64];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm);

    /* Escape path and reason for JSON. */
    char escaped_path[PATH_MAX * 2];
    char escaped_reason[512];
    json_escape(path, escaped_path, sizeof(escaped_path));
    json_escape(reason, escaped_reason, sizeof(escaped_reason));

    /* operation is always a compile-time literal — no escaping needed */

    /* Build JSON line. */
    char buf[PATH_MAX * 3];
    int len = snprintf(buf, sizeof(buf),
        "{\"type\":\"fs\",\"action\":\"blocked\",\"path\":\"%s\","
        "\"operation\":\"%s\",\"reason\":\"%s\",\"timestamp\":\"%s\"}\n",
        escaped_path, operation, escaped_reason, timestamp);
    if (len < 0 || (size_t)len >= sizeof(buf))
        return;

    /* Connect to Unix domain socket and send. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        /* Write the full buffer; best-effort, ignore partial writes. */
        (void)write(fd, buf, (size_t)len);
    }
    close(fd);
}

/* ------------------------------------------------------------------ */
/* Access control                                                      */
/* ------------------------------------------------------------------ */

/*
 * check_path determines whether access to `resolved` is allowed.
 *
 * Returns:
 *   0  = allowed
 *  -1  = blocked (reason is written to `reason_out`, max `reason_len`)
 */
static int check_path(const char *resolved, int is_write,
                      char *reason_out, size_t reason_len)
{
    /* 1. Check deny list — if path starts with any deny entry, BLOCK. */
    for (int i = 0; i < g_config.deny_count; i++) {
        if (path_starts_with(resolved, g_config.deny[i])) {
            snprintf(reason_out, reason_len, "denied path %s",
                     g_config.deny[i]);
            return -1;
        }
    }

    /* 2. Check root — if path starts with root, ALLOW (respect mode). */
    if (path_starts_with(resolved, g_config.root)) {
        if (is_write && !g_config.mode_rw) {
            snprintf(reason_out, reason_len,
                     "read-only root, write denied");
            return -1;
        }
        return 0; /* Allowed. */
    }

    /* 3. Check allow list — if path starts with any allow entry, reads only. */
    for (int i = 0; i < g_config.allow_count; i++) {
        if (path_starts_with(resolved, g_config.allow[i])) {
            if (is_write) {
                snprintf(reason_out, reason_len,
                         "write denied on allow-list path %s",
                         g_config.allow[i]);
                return -1;
            }
            return 0; /* Read allowed. */
        }
    }

    /* 4. Default: BLOCK. */
    snprintf(reason_out, reason_len, "outside allowed directory");
    return -1;
}

/* ------------------------------------------------------------------ */
/* Initialization                                                      */
/* ------------------------------------------------------------------ */

static void fence_init(void)
{
    memset(&g_config, 0, sizeof(g_config));

    /* Load real function pointers. */
    real_open     = (real_open_t)dlsym(RTLD_NEXT, "open");
    real_openat   = (real_openat_t)dlsym(RTLD_NEXT, "openat");
    real_fopen    = (real_fopen_t)dlsym(RTLD_NEXT, "fopen");
    real_access   = (real_access_t)dlsym(RTLD_NEXT, "access");
    real_unlink   = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    real_rename   = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    real_mkdir    = (real_mkdir_t)dlsym(RTLD_NEXT, "mkdir");
    real_rmdir    = (real_rmdir_t)dlsym(RTLD_NEXT, "rmdir");
    real_readlink = (real_readlink_t)dlsym(RTLD_NEXT, "readlink");
    real_realpath = (real_realpath_t)dlsym(RTLD_NEXT, "realpath");

    /* 64-bit variants (may be NULL on platforms that don't have them). */
    real_open64    = (real_open64_t)dlsym(RTLD_NEXT, "open64");
    real_openat64  = (real_openat64_t)dlsym(RTLD_NEXT, "openat64");
    real_fopen64   = (real_fopen64_t)dlsym(RTLD_NEXT, "fopen64");

    /* *at family */
    real_unlinkat  = (real_unlinkat_t)dlsym(RTLD_NEXT, "unlinkat");
    real_renameat  = (real_renameat_t)dlsym(RTLD_NEXT, "renameat");
    real_renameat2 = (real_renameat2_t)dlsym(RTLD_NEXT, "renameat2");
    real_mkdirat   = (real_mkdirat_t)dlsym(RTLD_NEXT, "mkdirat");
    real_symlinkat = (real_symlinkat_t)dlsym(RTLD_NEXT, "symlinkat");
    real_linkat    = (real_linkat_t)dlsym(RTLD_NEXT, "linkat");

    /* Other important functions */
    real_creat     = (real_creat_t)dlsym(RTLD_NEXT, "creat");
    real_symlink   = (real_symlink_t)dlsym(RTLD_NEXT, "symlink");
    real_link      = (real_link_t)dlsym(RTLD_NEXT, "link");
    real_chmod     = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    real_chown     = (real_chown_t)dlsym(RTLD_NEXT, "chown");
    real_truncate  = (real_truncate_t)dlsym(RTLD_NEXT, "truncate");

    /* chdir family */
    real_chdir     = (real_chdir_t)dlsym(RTLD_NEXT, "chdir");
    real_fchdir    = (real_fchdir_t)dlsym(RTLD_NEXT, "fchdir");

    /* Parse NOCKLOCK_FS_ALLOWED environment variable. */
    const char *env = getenv("NOCKLOCK_FS_ALLOWED");
    if (env == NULL || env[0] == '\0') {
        /* No config: fence is disabled, all calls pass through. */
        g_config.initialized = 0;
        return;
    }

    /* Copy env value so we can tokenize it. */
    char envbuf[PATH_MAX * (MAX_PATHS + 4)];
    size_t envlen = strlen(env);
    if (envlen >= sizeof(envbuf)) {
        /* Config too large, fail closed. */
        g_config.initialized = 1;
        g_config.root[0] = '\0'; /* Empty root blocks everything. */
        return;
    }
    memcpy(envbuf, env, envlen + 1);

    /* Split on FIELD_SEP. */
    char *fields[MAX_PATHS + 4];
    int field_count = 0;
    char *p = envbuf;
    fields[field_count++] = p;
    while (*p != '\0' && field_count < (int)(sizeof(fields) / sizeof(fields[0]))) {
        if (*p == FIELD_SEP) {
            *p = '\0';
            fields[field_count++] = p + 1;
        }
        p++;
    }

    if (field_count < 3) {
        /* Malformed config, fail closed. */
        g_config.initialized = 1;
        g_config.root[0] = '\0';
        return;
    }

    /* Field 0: root path. */
    strncpy(g_config.root, fields[0], PATH_MAX - 1);
    g_config.root[PATH_MAX - 1] = '\0';

    /* Field 1: mode. */
    g_config.mode_rw = (strcmp(fields[1], "rw") == 0) ? 1 : 0;

    /* Field 2: socket path. */
    strncpy(g_config.socket_path, fields[2], PATH_MAX - 1);
    g_config.socket_path[PATH_MAX - 1] = '\0';

    /* Fields 3+: +allow / -deny paths. */
    g_config.allow_count = 0;
    g_config.deny_count = 0;
    for (int i = 3; i < field_count; i++) {
        char *f = fields[i];
        if (f[0] == '+' && g_config.allow_count < MAX_PATHS) {
            strncpy(g_config.allow[g_config.allow_count], f + 1, PATH_MAX - 1);
            g_config.allow[g_config.allow_count][PATH_MAX - 1] = '\0';
            g_config.allow_count++;
        } else if (f[0] == '-' && g_config.deny_count < MAX_PATHS) {
            strncpy(g_config.deny[g_config.deny_count], f + 1, PATH_MAX - 1);
            g_config.deny[g_config.deny_count][PATH_MAX - 1] = '\0';
            g_config.deny_count++;
        }
    }

    g_config.initialized = 1;
}

/*
 * ensure_init triggers lazy initialization via pthread_once.
 * Returns 1 if the fence is active (should check paths), 0 if disabled.
 */
static int ensure_init(void)
{
    pthread_once(&g_init_once, fence_init);
    return g_config.initialized;
}

/* ------------------------------------------------------------------ */
/* Intercepted functions                                               */
/* ------------------------------------------------------------------ */

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    int need_mode = (flags & O_CREAT);
#ifdef O_TMPFILE
    need_mode = need_mode || (flags & O_TMPFILE);
#endif
    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_init())
        return real_open(pathname, flags, mode);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "open", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, is_write_open(flags), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "open", reason);
        errno = EACCES;
        return -1;
    }

    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    int need_mode = (flags & O_CREAT);
#ifdef O_TMPFILE
    need_mode = need_mode || (flags & O_TMPFILE);
#endif
    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_init())
        return real_openat(dirfd, pathname, flags, mode);

    char resolved[PATH_MAX];
    if (resolve_openat_path(dirfd, pathname, resolved) != 0) {
        report_blocked(pathname, "openat", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, is_write_open(flags), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "openat", reason);
        errno = EACCES;
        return -1;
    }

    return real_openat(dirfd, pathname, flags, mode);
}

FILE *fopen(const char *pathname, const char *mode)
{
    if (!ensure_init())
        return real_fopen(pathname, mode);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "fopen", "path resolution failed");
        errno = EACCES;
        return NULL;
    }

    char reason[512];
    if (check_path(resolved, is_write_fopen(mode), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "fopen", reason);
        errno = EACCES;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

int access(const char *pathname, int amode)
{
    if (!ensure_init())
        return real_access(pathname, amode);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "access", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    int is_write = (amode & W_OK) ? 1 : 0;
    char reason[512];
    if (check_path(resolved, is_write, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "access", reason);
        errno = EACCES;
        return -1;
    }

    return real_access(pathname, amode);
}

int unlink(const char *pathname)
{
    if (!ensure_init())
        return real_unlink(pathname);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "unlink", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "unlink", reason);
        errno = EACCES;
        return -1;
    }

    return real_unlink(pathname);
}

int rename(const char *oldpath, const char *newpath)
{
    if (!ensure_init())
        return real_rename(oldpath, newpath);

    /* Both paths must be allowed for write. */
    char resolved_old[PATH_MAX];
    char resolved_new[PATH_MAX];
    char reason[512];

    if (resolve_path(oldpath, resolved_old) != 0) {
        report_blocked(oldpath, "rename", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_old, 1, reason, sizeof(reason)) != 0) {
        report_blocked(oldpath, "rename", reason);
        errno = EACCES;
        return -1;
    }

    if (resolve_path(newpath, resolved_new) != 0) {
        report_blocked(newpath, "rename", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_new, 1, reason, sizeof(reason)) != 0) {
        report_blocked(newpath, "rename", reason);
        errno = EACCES;
        return -1;
    }

    return real_rename(oldpath, newpath);
}

int mkdir(const char *pathname, mode_t mode)
{
    if (!ensure_init())
        return real_mkdir(pathname, mode);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "mkdir", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "mkdir", reason);
        errno = EACCES;
        return -1;
    }

    return real_mkdir(pathname, mode);
}

int rmdir(const char *pathname)
{
    if (!ensure_init())
        return real_rmdir(pathname);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "rmdir", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "rmdir", reason);
        errno = EACCES;
        return -1;
    }

    return real_rmdir(pathname);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    if (!ensure_init())
        return real_readlink(pathname, buf, bufsiz);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "readlink", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 0 /* read */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "readlink", reason);
        errno = EACCES;
        return -1;
    }

    return real_readlink(pathname, buf, bufsiz);
}

char *realpath(const char *path, char *resolved_path)
{
    if (!ensure_init())
        return real_realpath(path, resolved_path);

    /* Call real realpath first, then check the result. */
    char *result = real_realpath(path, resolved_path);
    if (result == NULL)
        return NULL;

    char reason[512];
    if (check_path(result, 0 /* read */, reason, sizeof(reason)) != 0) {
        report_blocked(path, "realpath", reason);
        /*
         * If resolved_path was NULL, real_realpath allocated memory.
         * We must free it before returning NULL.
         */
        if (resolved_path == NULL)
            free(result);
        errno = EACCES;
        return NULL;
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* 64-bit variants                                                     */
/* ------------------------------------------------------------------ */

int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    int need_mode = (flags & O_CREAT);
#ifdef O_TMPFILE
    need_mode = need_mode || (flags & O_TMPFILE);
#endif
    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_init()) {
        if (real_open64)
            return real_open64(pathname, flags, mode);
        return real_open(pathname, flags, mode);
    }

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "open64", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, is_write_open(flags), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "open64", reason);
        errno = EACCES;
        return -1;
    }

    if (real_open64)
        return real_open64(pathname, flags, mode);
    return real_open(pathname, flags, mode);
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    int need_mode = (flags & O_CREAT);
#ifdef O_TMPFILE
    need_mode = need_mode || (flags & O_TMPFILE);
#endif
    if (need_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!ensure_init()) {
        if (real_openat64)
            return real_openat64(dirfd, pathname, flags, mode);
        return real_openat(dirfd, pathname, flags, mode);
    }

    char resolved[PATH_MAX];
    if (resolve_openat_path(dirfd, pathname, resolved) != 0) {
        report_blocked(pathname, "openat64", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, is_write_open(flags), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "openat64", reason);
        errno = EACCES;
        return -1;
    }

    if (real_openat64)
        return real_openat64(dirfd, pathname, flags, mode);
    return real_openat(dirfd, pathname, flags, mode);
}

FILE *fopen64(const char *pathname, const char *mode)
{
    if (!ensure_init()) {
        if (real_fopen64)
            return real_fopen64(pathname, mode);
        return real_fopen(pathname, mode);
    }

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "fopen64", "path resolution failed");
        errno = EACCES;
        return NULL;
    }

    char reason[512];
    if (check_path(resolved, is_write_fopen(mode), reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "fopen64", reason);
        errno = EACCES;
        return NULL;
    }

    if (real_fopen64)
        return real_fopen64(pathname, mode);
    return real_fopen(pathname, mode);
}

/* ------------------------------------------------------------------ */
/* *at family variants                                                 */
/* ------------------------------------------------------------------ */

int unlinkat(int dirfd, const char *pathname, int flags)
{
    if (!ensure_init()) {
        if (real_unlinkat)
            return real_unlinkat(dirfd, pathname, flags);
        errno = ENOSYS;
        return -1;
    }

    char resolved[PATH_MAX];
    if (resolve_openat_path(dirfd, pathname, resolved) != 0) {
        report_blocked(pathname, "unlinkat", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "unlinkat", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_unlinkat) { errno = ENOSYS; return -1; }
    return real_unlinkat(dirfd, pathname, flags);
}

int renameat(int olddirfd, const char *oldpath,
             int newdirfd, const char *newpath)
{
    if (!ensure_init()) {
        if (real_renameat)
            return real_renameat(olddirfd, oldpath, newdirfd, newpath);
        errno = ENOSYS;
        return -1;
    }

    char resolved_old[PATH_MAX];
    char resolved_new[PATH_MAX];
    char reason[512];

    if (resolve_openat_path(olddirfd, oldpath, resolved_old) != 0) {
        report_blocked(oldpath, "renameat", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_old, 1, reason, sizeof(reason)) != 0) {
        report_blocked(oldpath, "renameat", reason);
        errno = EACCES;
        return -1;
    }

    if (resolve_openat_path(newdirfd, newpath, resolved_new) != 0) {
        report_blocked(newpath, "renameat", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_new, 1, reason, sizeof(reason)) != 0) {
        report_blocked(newpath, "renameat", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_renameat) { errno = ENOSYS; return -1; }
    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

int renameat2(int olddirfd, const char *oldpath,
              int newdirfd, const char *newpath, unsigned int flags)
{
    if (!ensure_init()) {
        if (real_renameat2)
            return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
        errno = ENOSYS;
        return -1;
    }

    char resolved_old[PATH_MAX];
    char resolved_new[PATH_MAX];
    char reason[512];

    if (resolve_openat_path(olddirfd, oldpath, resolved_old) != 0) {
        report_blocked(oldpath, "renameat2", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_old, 1, reason, sizeof(reason)) != 0) {
        report_blocked(oldpath, "renameat2", reason);
        errno = EACCES;
        return -1;
    }

    if (resolve_openat_path(newdirfd, newpath, resolved_new) != 0) {
        report_blocked(newpath, "renameat2", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_new, 1, reason, sizeof(reason)) != 0) {
        report_blocked(newpath, "renameat2", reason);
        errno = EACCES;
        return -1;
    }

    if (real_renameat2)
        return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    errno = ENOSYS;
    return -1;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    if (!ensure_init()) {
        if (real_mkdirat)
            return real_mkdirat(dirfd, pathname, mode);
        errno = ENOSYS;
        return -1;
    }

    char resolved[PATH_MAX];
    if (resolve_openat_path(dirfd, pathname, resolved) != 0) {
        report_blocked(pathname, "mkdirat", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "mkdirat", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_mkdirat) { errno = ENOSYS; return -1; }
    return real_mkdirat(dirfd, pathname, mode);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    if (!ensure_init()) {
        if (real_symlinkat)
            return real_symlinkat(target, newdirfd, linkpath);
        errno = ENOSYS;
        return -1;
    }

    /* Resolve the linkpath (where the symlink is created), always write. */
    char resolved[PATH_MAX];
    if (resolve_openat_path(newdirfd, linkpath, resolved) != 0) {
        report_blocked(linkpath, "symlinkat", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(linkpath, "symlinkat", reason);
        errno = EACCES;
        return -1;
    }

    /* Check target — resolve relative targets against linkpath's parent directory. */
    char resolved_target[PATH_MAX];
    if (target[0] == '/') {
        /* Absolute target — resolve directly. */
        if (resolve_path(target, resolved_target) != 0) {
            report_blocked(target, "symlinkat", "target path resolution failed");
            errno = EACCES;
            return -1;
        }
    } else {
        /* Relative target — resolve against linkpath's parent. */
        char link_parent[PATH_MAX];
        strncpy(link_parent, resolved, PATH_MAX - 1);
        link_parent[PATH_MAX - 1] = '\0';
        char *slash = strrchr(link_parent, '/');
        if (slash) *slash = '\0';
        char full_target[PATH_MAX];
        snprintf(full_target, PATH_MAX, "%s/%s", link_parent, target);
        if (resolve_path(full_target, resolved_target) != 0) {
            report_blocked(target, "symlinkat", "target path resolution failed");
            errno = EACCES;
            return -1;
        }
    }
    char target_reason[512];
    if (check_path(resolved_target, 0 /* read */, target_reason, sizeof(target_reason)) != 0) {
        report_blocked(target, "symlinkat", target_reason);
        errno = EACCES;
        return -1;
    }

    if (!real_symlinkat) { errno = ENOSYS; return -1; }
    return real_symlinkat(target, newdirfd, linkpath);
}

int linkat(int olddirfd, const char *oldpath,
           int newdirfd, const char *newpath, int flags)
{
    if (!ensure_init()) {
        if (real_linkat)
            return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
        errno = ENOSYS;
        return -1;
    }

    char resolved_old[PATH_MAX];
    char resolved_new[PATH_MAX];
    char reason[512];

    if (resolve_openat_path(olddirfd, oldpath, resolved_old) != 0) {
        report_blocked(oldpath, "linkat", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_old, 1, reason, sizeof(reason)) != 0) {
        report_blocked(oldpath, "linkat", reason);
        errno = EACCES;
        return -1;
    }

    if (resolve_openat_path(newdirfd, newpath, resolved_new) != 0) {
        report_blocked(newpath, "linkat", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_new, 1, reason, sizeof(reason)) != 0) {
        report_blocked(newpath, "linkat", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_linkat) { errno = ENOSYS; return -1; }
    return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

/* ------------------------------------------------------------------ */
/* Other important functions                                           */
/* ------------------------------------------------------------------ */

int creat(const char *pathname, mode_t mode)
{
    if (!ensure_init()) {
        if (real_creat)
            return real_creat(pathname, mode);
        return real_open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
    }

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "creat", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "creat", reason);
        errno = EACCES;
        return -1;
    }

    if (real_creat)
        return real_creat(pathname, mode);
    return real_open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int symlink(const char *target, const char *linkpath)
{
    if (!ensure_init()) {
        if (real_symlink)
            return real_symlink(target, linkpath);
        errno = ENOSYS;
        return -1;
    }

    /* Resolve the linkpath (where the symlink is created), always write. */
    char resolved[PATH_MAX];
    if (resolve_path(linkpath, resolved) != 0) {
        report_blocked(linkpath, "symlink", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(linkpath, "symlink", reason);
        errno = EACCES;
        return -1;
    }

    /* Check target — resolve relative targets against linkpath's parent directory. */
    char resolved_target[PATH_MAX];
    if (target[0] == '/') {
        /* Absolute target — resolve directly. */
        if (resolve_path(target, resolved_target) != 0) {
            report_blocked(target, "symlink", "target path resolution failed");
            errno = EACCES;
            return -1;
        }
    } else {
        /* Relative target — resolve against linkpath's parent. */
        char link_parent[PATH_MAX];
        strncpy(link_parent, resolved, PATH_MAX - 1);
        link_parent[PATH_MAX - 1] = '\0';
        char *slash = strrchr(link_parent, '/');
        if (slash) *slash = '\0';
        char full_target[PATH_MAX];
        snprintf(full_target, PATH_MAX, "%s/%s", link_parent, target);
        if (resolve_path(full_target, resolved_target) != 0) {
            report_blocked(target, "symlink", "target path resolution failed");
            errno = EACCES;
            return -1;
        }
    }
    char target_reason[512];
    if (check_path(resolved_target, 0 /* read */, target_reason, sizeof(target_reason)) != 0) {
        report_blocked(target, "symlink", target_reason);
        errno = EACCES;
        return -1;
    }

    if (!real_symlink) { errno = ENOSYS; return -1; }
    return real_symlink(target, linkpath);
}

int link(const char *oldpath, const char *newpath)
{
    if (!ensure_init())
        return real_link(oldpath, newpath);

    char resolved_old[PATH_MAX];
    char resolved_new[PATH_MAX];
    char reason[512];

    if (resolve_path(oldpath, resolved_old) != 0) {
        report_blocked(oldpath, "link", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_old, 1, reason, sizeof(reason)) != 0) {
        report_blocked(oldpath, "link", reason);
        errno = EACCES;
        return -1;
    }

    if (resolve_path(newpath, resolved_new) != 0) {
        report_blocked(newpath, "link", "path resolution failed");
        errno = EACCES;
        return -1;
    }
    if (check_path(resolved_new, 1, reason, sizeof(reason)) != 0) {
        report_blocked(newpath, "link", reason);
        errno = EACCES;
        return -1;
    }

    return real_link(oldpath, newpath);
}

int chmod(const char *pathname, mode_t mode)
{
    if (!ensure_init())
        return real_chmod(pathname, mode);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "chmod", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "chmod", reason);
        errno = EACCES;
        return -1;
    }

    return real_chmod(pathname, mode);
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    if (!ensure_init())
        return real_chown(pathname, owner, group);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "chown", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "chown", reason);
        errno = EACCES;
        return -1;
    }

    return real_chown(pathname, owner, group);
}

int truncate(const char *pathname, off_t length)
{
    if (!ensure_init())
        return real_truncate(pathname, length);

    char resolved[PATH_MAX];
    if (resolve_path(pathname, resolved) != 0) {
        report_blocked(pathname, "truncate", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 1 /* always write */, reason, sizeof(reason)) != 0) {
        report_blocked(pathname, "truncate", reason);
        errno = EACCES;
        return -1;
    }

    return real_truncate(pathname, length);
}

/* ------------------------------------------------------------------ */
/* chdir family                                                        */
/* ------------------------------------------------------------------ */

int chdir(const char *path)
{
    if (!ensure_init()) {
        if (real_chdir) return real_chdir(path);
        errno = ENOSYS;
        return -1;
    }

    char resolved[PATH_MAX];
    if (resolve_path(path, resolved) != 0) {
        report_blocked(path, "chdir", "path resolution failed");
        errno = EACCES;
        return -1;
    }

    char reason[512];
    if (check_path(resolved, 0 /* read */, reason, sizeof(reason)) != 0) {
        report_blocked(path, "chdir", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_chdir) { errno = ENOSYS; return -1; }
    return real_chdir(path);
}

int fchdir(int fd)
{
    if (!ensure_init()) {
        if (real_fchdir) return real_fchdir(fd);
        errno = ENOSYS;
        return -1;
    }

    /* Resolve fd to path via /proc/self/fd/ */
    char fd_link[64], resolved[PATH_MAX];
    snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", fd);
    ssize_t len = real_readlink(fd_link, resolved, sizeof(resolved) - 1);
    if (len < 0) {
        report_blocked("(unknown fd)", "fchdir", "fd resolution failed");
        errno = EACCES;
        return -1;
    }
    resolved[len] = '\0';

    char reason[512];
    if (check_path(resolved, 0 /* read */, reason, sizeof(reason)) != 0) {
        report_blocked(resolved, "fchdir", reason);
        errno = EACCES;
        return -1;
    }

    if (!real_fchdir) { errno = ENOSYS; return -1; }
    return real_fchdir(fd);
}
