#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Stable UAPI opcodes let this probe build with headers predating io_uring SOCKET. */
enum {
    PROBE_IORING_OP_CONNECT = 16,
    PROBE_IORING_OP_SOCKET = 45,
};

struct ring_state {
    int fd;
    struct io_uring_params params;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
    unsigned *sq_tail;
    unsigned *sq_mask;
    unsigned *sq_array;
    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_mask;
    struct io_uring_cqe *cqes;
};

static int ring_open(struct ring_state *ring) {
    memset(ring, 0, sizeof(*ring));
    ring->fd = syscall(__NR_io_uring_setup, 8, &ring->params);
    if (ring->fd < 0) {
        int saved_errno = errno;
        printf("io_uring_setup=-1 errno=%d (%s)\n", saved_errno, strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
    printf("io_uring_setup=%d errno=0\n", ring->fd);

    size_t sq_size = ring->params.sq_off.array + ring->params.sq_entries * sizeof(unsigned);
    size_t cq_size = ring->params.cq_off.cqes + ring->params.cq_entries * sizeof(struct io_uring_cqe);
    if (ring->params.features & IORING_FEAT_SINGLE_MMAP) {
        if (cq_size > sq_size) sq_size = cq_size;
        ring->sq_ring = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQ_RING);
        ring->cq_ring = ring->sq_ring;
    } else {
        ring->sq_ring = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQ_RING);
        ring->cq_ring = mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_CQ_RING);
    }
    if (ring->sq_ring == MAP_FAILED || ring->cq_ring == MAP_FAILED) {
        printf("ring_mmap=-1 errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    size_t sqes_size = ring->params.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) {
        printf("sqes_mmap=-1 errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    ring->sq_tail = (unsigned *)((char *)ring->sq_ring + ring->params.sq_off.tail);
    ring->sq_mask = (unsigned *)((char *)ring->sq_ring + ring->params.sq_off.ring_mask);
    ring->sq_array = (unsigned *)((char *)ring->sq_ring + ring->params.sq_off.array);
    ring->cq_head = (unsigned *)((char *)ring->cq_ring + ring->params.cq_off.head);
    ring->cq_tail = (unsigned *)((char *)ring->cq_ring + ring->params.cq_off.tail);
    ring->cq_mask = (unsigned *)((char *)ring->cq_ring + ring->params.cq_off.ring_mask);
    ring->cqes = (struct io_uring_cqe *)((char *)ring->cq_ring + ring->params.cq_off.cqes);
    return 0;
}

static int submit_one(struct ring_state *ring, struct io_uring_sqe *sqe) {
    unsigned tail = __atomic_load_n(ring->sq_tail, __ATOMIC_RELAXED);
    unsigned index = tail & *ring->sq_mask;
    ring->sqes[index] = *sqe;
    ring->sq_array[index] = index;
    __atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);
    int entered = syscall(__NR_io_uring_enter, ring->fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
    if (entered < 0) {
        printf("io_uring_enter=-1 errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    unsigned head = __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
    if (head == __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE)) {
        printf("completion=missing\n");
        return -1;
    }
    int result = ring->cqes[head & *ring->cq_mask].res;
    __atomic_store_n(ring->cq_head, head + 1, __ATOMIC_RELEASE);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <local-listener-port>\n", argv[0]);
        return 2;
    }
    unsigned long port = strtoul(argv[1], NULL, 10);
    if (port == 0 || port > 65535) return 2;
    struct ring_state ring;
    if (ring_open(&ring) < 0) {
        if (errno == EPERM) return 10;
        if (errno == ENOSYS) return 11;
        return 13;
    }

    struct io_uring_sqe sqe = {0};
    sqe.opcode = PROBE_IORING_OP_SOCKET;
    sqe.fd = AF_INET;
    sqe.off = SOCK_STREAM | SOCK_CLOEXEC;
    sqe.len = 0;
    sqe.user_data = 1;
    int socket_result = submit_one(&ring, &sqe);
    if (socket_result < 0) {
        printf("socket=-1 errno=%d (%s)\n", -socket_result, strerror(-socket_result));
        return 14; /* Distinct from setup ENOSYS (11). */
    }
    printf("socket=%d errno=0\n", socket_result);

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sqe = (struct io_uring_sqe){0};
    sqe.opcode = PROBE_IORING_OP_CONNECT;
    sqe.fd = socket_result;
    sqe.off = sizeof(address);
    sqe.addr = (uintptr_t)&address;
    sqe.user_data = 2;
    int connect_result = submit_one(&ring, &sqe);
    if (connect_result < 0) {
        printf("connect=-1 errno=%d (%s)\n", -connect_result, strerror(-connect_result));
        return 12;
    }
    printf("connect=%d errno=0\n", connect_result);
    close(socket_result);
    close(ring.fd);
    return connect_result == 0 ? 0 : 13;
}
