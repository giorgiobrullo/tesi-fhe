#ifndef A181_IPC_H
#define A181_IPC_H
#include "arm_clock.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define A181_IPC_MAGIC UINT64_C(0x4131383149504331)
enum { IPC_READY = 1, IPC_PAUSE = 2, IPC_PAUSED = 3, IPC_CAPTURE = 4,
       IPC_TERMINAL = 5, IPC_GO = 10, IPC_EXIT = 11 };
struct ipc_message {
    uint64_t magic, version, kind, sequence, parent_pid, worker_pid;
    uint64_t collector_pid, birth_abs, related_seq, sent_abs, status;
};
_Static_assert(sizeof(struct ipc_message) == 88, "fixed local IPC ABI");

static inline bool ipc_pipe_end(int fd, bool writer) {
    struct stat info;
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && (flags & O_NONBLOCK) &&
        (flags & O_ACCMODE) == (writer ? O_WRONLY : O_RDONLY) &&
        fstat(fd, &info) == 0 && S_ISFIFO(info.st_mode);
}

static inline uint64_t ipc_deadline(mach_timebase_info_data_t tb, uint64_t ms) {
    return a170_arm_clock() + (uint64_t)(((__uint128_t)ms * 1000000 * tb.denom + tb.numer - 1) / tb.numer);
}
static inline bool ipc_pipe(int fds[2]) {
    if (pipe(fds)) return false;
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(fds[i], F_GETFL);
        if (flags < 0 || fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fds[0]); close(fds[1]); return false;
        }
    }
    if (fcntl(fds[1], F_SETNOSIGPIPE, 1) < 0) {
        close(fds[0]); close(fds[1]); return false;
    }
    return true;
}
static inline int ipc_available(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    int rc = poll(&p, 1, 0);
    if (rc < 0 || (p.revents & (POLLERR | POLLNVAL))) return -1;
    return rc > 0 ? 1 : 0; /* POLLHUP is observed by a zero-byte read, never ignored. */
}
static inline bool ipc_receive(int fd, struct ipc_message *m, mach_timebase_info_data_t tb,
                               uint64_t *begin, uint64_t *end, bool *eof) {
    *begin = a170_arm_clock(); *eof = false;
    uint64_t deadline = *begin + (uint64_t)(((__uint128_t)15000000000ULL * tb.denom + tb.numer - 1) / tb.numer);
    size_t used = 0;
    memset(m, 0, sizeof(*m));
    while (used < sizeof(*m) && a170_arm_clock() < deadline) {
        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, 100);
        if (rc < 0 || (p.revents & (POLLERR | POLLNVAL))) break;
        if (!rc) continue;
        ssize_t n = read(fd, (char *)m + used, sizeof(*m) - used);
        if (n == 0) { *eof = true; break; }
        if (n < 0) { if (errno == EAGAIN) continue; break; }
        used += (size_t)n;
    }
    *end = a170_arm_clock();
    return used == sizeof(*m) && *end <= deadline &&
        m->magic == A181_IPC_MAGIC && m->version == 1;
}
static inline bool ipc_send(int fd, struct ipc_message *m, mach_timebase_info_data_t tb,
                            uint64_t *end) {
    uint64_t deadline = ipc_deadline(tb, 15000);
    m->magic = A181_IPC_MAGIC; m->version = 1; m->sent_abs = a170_arm_clock();
    while (a170_arm_clock() < deadline) {
        struct pollfd p = {fd, POLLOUT, 0};
        int rc = poll(&p, 1, 100);
        if (rc < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) break;
        if (!rc) continue;
        ssize_t n = write(fd, m, sizeof(*m)); /* One <= PIPE_BUF frame; no partial-frame repair. */
        if (n < 0 && errno == EAGAIN) continue;
        *end = a170_arm_clock();
        return n == (ssize_t)sizeof(*m) && *end <= deadline;
    }
    *end = a170_arm_clock(); return false;
}
static inline bool ipc_matches(const struct ipc_message *m, uint64_t kind, uint64_t sequence,
                               uint64_t parent, uint64_t worker, uint64_t collector,
                               uint64_t birth, uint64_t related) {
    return m->kind == kind && m->sequence == sequence && m->parent_pid == parent &&
        m->worker_pid == worker && m->collector_pid == collector &&
        m->birth_abs == birth && m->related_seq == related;
}
static inline void ipc_fields(FILE *f, const char *direction, const struct ipc_message *m,
                               uint64_t begin, uint64_t end) {
    fprintf(f, "\"direction\":\"%s\",\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64
               ",\"message\":{\"magic\":%" PRIu64 ",\"version\":%" PRIu64
               ",\"kind\":%" PRIu64 ",\"sequence\":%" PRIu64
               ",\"parent_pid\":%" PRIu64 ",\"worker_pid\":%" PRIu64
               ",\"collector_pid\":%" PRIu64 ",\"birth_abs\":%" PRIu64
               ",\"related_seq\":%" PRIu64 ",\"sent_abs\":%" PRIu64
               ",\"status\":%" PRIu64 "}}\n", direction, begin, end,
            m->magic, m->version, m->kind, m->sequence, m->parent_pid, m->worker_pid,
            m->collector_pid, m->birth_abs, m->related_seq, m->sent_abs, m->status);
}
#endif
