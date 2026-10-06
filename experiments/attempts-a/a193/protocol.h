#ifndef A193_PROTOCOL_H
#define A193_PROTOCOL_H
#include "arm_clock.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define A193_MAGIC UINT64_C(0x4131393343505531)
enum { READY=1, REQUEST=2, REPLY=3, RECEIPT=4, RELEASE=5, STAGE=6, WORKER_FAILURE=90 };
struct clock_obs {
    uint64_t begin_abs, end_abs;
    int64_t seconds, nanoseconds;
    uint64_t caller_tid;
    int32_t caller_pid, clock_id, status, error;
};
struct usage_obs {
    uint64_t begin_abs, end_abs, user_raw, system_raw, birth_abs, exit_abs;
    int32_t pid, status, error, reserved;
};
struct boundary_data { struct clock_obs before, after; struct usage_obs reads[2]; };
struct ready_data { struct usage_obs identity; struct clock_obs resolutions[2]; };
struct stage_data {
    struct clock_obs process[2], thread[2][2];
    uint64_t begin_abs, end_abs, deadline_abs, iterations[2], checksum[2];
    int32_t thread_id_status[2], threads, sleep_calls;
};
struct frame {
    uint64_t magic, version, bytes, kind, sequence, step, parent_pid, worker_pid, birth_abs, sent_abs;
    uint64_t process_clock_calls, thread_clock_calls;
    union { struct boundary_data boundary; struct ready_data ready; struct stage_data stage; int64_t failure[4]; } data;
};
_Static_assert(sizeof(struct clock_obs)==56, "fixed local clock record ABI");
_Static_assert(sizeof(struct usage_obs)==64, "fixed local usage record ABI");
_Static_assert(sizeof(struct frame)<=512, "atomic local PIPE_BUF-sized frame");
struct io_obs { uint64_t begin_abs, end_abs, deadline_abs, bytes; int32_t error; bool eof; };

static bool deadline_from(mach_timebase_info_data_t tb, uint64_t now, uint64_t ns, uint64_t *out) {
    if (!tb.numer || !tb.denom) return false;
    __uint128_t ticks=((__uint128_t)ns*tb.denom+tb.numer-1)/tb.numer;
    if (ticks>UINT64_MAX-now) return false;
    *out=now+(uint64_t)ticks;
    return true;
}
static bool deadline(mach_timebase_info_data_t tb, uint64_t ns, uint64_t *out) {
    return deadline_from(tb,a170_arm_clock(),ns,out);
}
static bool pipe_pair(int fd[2]) {
    if (pipe(fd)) return false;
    for (int i=0;i<2;i++) {
        int flags=fcntl(fd[i],F_GETFL);
        if (flags<0 || fcntl(fd[i],F_SETFL,flags|O_NONBLOCK)<0) {
            close(fd[0]);close(fd[1]);return false;
        }
    }
    if (fcntl(fd[1],F_SETNOSIGPIPE,1)<0) {close(fd[0]);close(fd[1]);return false;}
    return true;
}
static struct frame message(uint64_t kind,uint64_t sequence,uint64_t step,pid_t parent,pid_t worker,uint64_t birth) {
    struct frame f;memset(&f,0,sizeof(f));
    f.magic=A193_MAGIC;f.version=1;f.bytes=sizeof(f);f.kind=kind;f.sequence=sequence;f.step=step;
    f.parent_pid=(uint64_t)parent;f.worker_pid=(uint64_t)worker;f.birth_abs=birth;
    return f;
}
static bool matches(const struct frame *f,uint64_t kind,uint64_t sequence,uint64_t step,pid_t parent,pid_t worker,uint64_t birth) {
    return f->magic==A193_MAGIC && f->version==1 && f->bytes==sizeof(*f) && f->kind==kind &&
        f->sequence==sequence && f->step==step && f->parent_pid==(uint64_t)parent &&
        f->worker_pid==(uint64_t)worker && f->birth_abs==birth;
}
static bool transfer(int fd,struct frame *f,bool write_frame,mach_timebase_info_data_t tb,struct io_obs *io) {
    memset(io,0,sizeof(*io));io->begin_abs=a170_arm_clock();
    if (!deadline_from(tb,io->begin_abs,UINT64_C(15000000000),&io->deadline_abs)) {io->error=EOVERFLOW;io->end_abs=a170_arm_clock();return false;}
    if (write_frame) f->sent_abs=a170_arm_clock(); else memset(f,0,sizeof(*f));
    while (io->bytes<sizeof(*f) && a170_arm_clock()<io->deadline_abs) {
        struct pollfd pollfd={fd,write_frame?POLLOUT:POLLIN,0};
        int rc=poll(&pollfd,1,100);
        if (rc<0) {io->error=errno;break;}
        if (!rc) continue;
        if (pollfd.revents&(POLLERR|POLLNVAL)) {io->error=EIO;break;}
        if (write_frame && (pollfd.revents&POLLHUP)) {io->error=EPIPE;break;}
        ssize_t n=write_frame?write(fd,f,sizeof(*f)):read(fd,(char*)f+io->bytes,sizeof(*f)-io->bytes);
        if (n<0) {if (errno==EAGAIN) continue;io->error=errno;break;}
        if (n==0) {io->eof=true;break;}
        io->bytes+=(uint64_t)n;
        /* A partial <=PIPE_BUF write is a failure, never repaired/retried. Reads
         * accumulate a complete frame only within this original fixed deadline. */
        if (write_frame && n!=(ssize_t)sizeof(*f)) {io->error=EIO;break;}
    }
    io->end_abs=a170_arm_clock();
    return io->bytes==sizeof(*f) && io->error==0 && !io->eof && io->end_abs<=io->deadline_abs;
}
#endif
