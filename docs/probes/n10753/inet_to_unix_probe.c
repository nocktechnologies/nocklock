#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

#define MAX_TRACKED_FD 65536

static unsigned char swapped[MAX_TRACKED_FD];

static int (*real_socket_fn)(int, int, int);
static int (*real_connect_fn)(int, const struct sockaddr *, socklen_t);
static int (*real_setsockopt_fn)(int, int, int, const void *, socklen_t);
static int (*real_getsockopt_fn)(int, int, int, void *, socklen_t *);
static int (*real_getsockname_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_getpeername_fn)(int, struct sockaddr *, socklen_t *);
static int (*real_close_fn)(int);

static void load_real(void)
{
    if (!real_socket_fn) real_socket_fn = dlsym(RTLD_NEXT, "socket");
    if (!real_connect_fn) real_connect_fn = dlsym(RTLD_NEXT, "connect");
    if (!real_setsockopt_fn) real_setsockopt_fn = dlsym(RTLD_NEXT, "setsockopt");
    if (!real_getsockopt_fn) real_getsockopt_fn = dlsym(RTLD_NEXT, "getsockopt");
    if (!real_getsockname_fn) real_getsockname_fn = dlsym(RTLD_NEXT, "getsockname");
    if (!real_getpeername_fn) real_getpeername_fn = dlsym(RTLD_NEXT, "getpeername");
    if (!real_close_fn) real_close_fn = dlsym(RTLD_NEXT, "close");
}

static int env_truthy(const char *name)
{
    const char *v = getenv(name);
    return v && v[0] && strcmp(v, "0") != 0 && strcmp(v, "false") != 0;
}

static int tracked(int fd)
{
    return fd >= 0 && fd < MAX_TRACKED_FD && swapped[fd];
}

static int expected_proxy_v4(struct in_addr addr, unsigned short port)
{
    const char *host = getenv("NOCKLOCK_PROBE_PROXY_HOST");
    const char *port_env = getenv("NOCKLOCK_PROBE_PROXY_PORT");
    struct in_addr expected;
    unsigned long expected_port;

    if (!host || !host[0]) host = "127.0.0.1";
    if (!port_env || !port_env[0]) return 0;
    if (inet_pton(AF_INET, host, &expected) != 1) return 0;
    expected_port = strtoul(port_env, NULL, 10);
    return addr.s_addr == expected.s_addr && port == (unsigned short)expected_port;
}

static int connect_unix(int fd)
{
    const char *path = getenv("NOCKLOCK_PROBE_UNIX_SOCKET");
    struct sockaddr_un un;

    if (!path || !path[0]) {
        errno = EACCES;
        return -1;
    }
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(un.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(un.sun_path, path, sizeof(un.sun_path) - 1);
    fprintf(stderr, "shim: connect(fd=%d) -> AF_UNIX %s\n", fd, path);
    return real_connect_fn(fd, (const struct sockaddr *)&un, sizeof(un));
}

int socket(int domain, int type, int protocol)
{
    int fd;
    load_real();
    if ((domain == AF_INET || domain == AF_INET6) && ((type & SOCK_TYPE_MASK) == SOCK_STREAM)) {
        fd = real_socket_fn(AF_UNIX, type, 0);
        if (fd >= 0 && fd < MAX_TRACKED_FD) swapped[fd] = 1;
        fprintf(stderr, "shim: socket(domain=%s,type=%d,protocol=%d) -> unix fd=%d\n",
                domain == AF_INET ? "AF_INET" : "AF_INET6", type, protocol, fd);
        return fd;
    }
    return real_socket_fn(domain, type, protocol);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    load_real();
    if (tracked(fd)) {
        if (addr && len >= (socklen_t)sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
            const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
            unsigned short port = ntohs(in->sin_port);
            char ip[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
            fprintf(stderr, "shim: connect(fd=%d) requested %s:%u\n", fd, ip, port);
            if (expected_proxy_v4(in->sin_addr, port)) return connect_unix(fd);
        } else if (addr && addr->sa_family == AF_INET6) {
            fprintf(stderr, "shim: connect(fd=%d) denied unexpected AF_INET6 target\n", fd);
        } else {
            fprintf(stderr, "shim: connect(fd=%d) denied unexpected sockaddr family\n", fd);
        }
        errno = EPERM;
        return -1;
    }
    return real_connect_fn(fd, addr, len);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    int rc;
    load_real();
    if (tracked(fd) && level == IPPROTO_TCP) {
        if (env_truthy("NOCKLOCK_PROBE_FAKE_TCP")) {
            fprintf(stderr, "shim: setsockopt(fd=%d,level=IPPROTO_TCP,opt=%d) -> fake success\n", fd, optname);
            return 0;
        }
        rc = real_setsockopt_fn(fd, level, optname, optval, optlen);
        fprintf(stderr, "shim: setsockopt(fd=%d,level=IPPROTO_TCP,opt=%d) -> rc=%d errno=%d\n",
                fd, optname, rc, rc == -1 ? errno : 0);
        return rc;
    }
    return real_setsockopt_fn(fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    int rc;
    load_real();
    if (tracked(fd) && level == IPPROTO_TCP) {
        if (env_truthy("NOCKLOCK_PROBE_FAKE_TCP")) {
            if (optval && optlen && *optlen >= (socklen_t)sizeof(int)) {
                *(int *)optval = 1;
                *optlen = sizeof(int);
            }
            fprintf(stderr, "shim: getsockopt(fd=%d,level=IPPROTO_TCP,opt=%d) -> fake success\n", fd, optname);
            return 0;
        }
        rc = real_getsockopt_fn(fd, level, optname, optval, optlen);
        fprintf(stderr, "shim: getsockopt(fd=%d,level=IPPROTO_TCP,opt=%d) -> rc=%d errno=%d\n",
                fd, optname, rc, rc == -1 ? errno : 0);
        return rc;
    }
    return real_getsockopt_fn(fd, level, optname, optval, optlen);
}

static int fake_name(int fd, struct sockaddr *addr, socklen_t *len, const char *which)
{
    struct sockaddr_in in;
    const char *port_env = getenv("NOCKLOCK_PROBE_PROXY_PORT");
    unsigned short port = port_env && port_env[0] ? (unsigned short)strtoul(port_env, NULL, 10) : 0;

    if (!addr || !len || *len < (socklen_t)sizeof(in)) {
        errno = EINVAL;
        return -1;
    }
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &in.sin_addr);
    memcpy(addr, &in, sizeof(in));
    *len = sizeof(in);
    fprintf(stderr, "shim: %s(fd=%d) -> fake 127.0.0.1:%u\n", which, fd, port);
    return 0;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
    load_real();
    if (tracked(fd) && env_truthy("NOCKLOCK_PROBE_FAKE_NAMES")) return fake_name(fd, addr, len, "getsockname");
    return real_getsockname_fn(fd, addr, len);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len)
{
    load_real();
    if (tracked(fd) && env_truthy("NOCKLOCK_PROBE_FAKE_NAMES")) return fake_name(fd, addr, len, "getpeername");
    return real_getpeername_fn(fd, addr, len);
}

int close(int fd)
{
    load_real();
    if (fd >= 0 && fd < MAX_TRACKED_FD) swapped[fd] = 0;
    return real_close_fn(fd);
}
