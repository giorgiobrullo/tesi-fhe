/* A181 raw observer, not a qualified CPU-attribution monitor. No process launch,
 * signal, reap, tree discovery or tick-to-CPU-nanosecond conversion. */
#define _DARWIN_C_SOURCE 1
#include "arm_clock.h"
#include "source_identity.h"
#include "ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(natural_t) == 4, "host ticks must be recorded as u32");
_Static_assert(HOST_BASIC_INFO_COUNT == 12, "pinned public host ABI changed");
_Static_assert(HOST_CPU_LOAD_INFO_COUNT == 4, "pinned CPU ABI changed");
_Static_assert(sizeof(struct proc_bsdinfo) == 136, "pinned BSD ABI changed");

static bool decimal(const char *s, uint64_t *n) {
    if (!s || !*s) return false;
    uint64_t v = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || v > (UINT64_MAX - (*s - '0')) / 10)
            return false;
        v = v * 10 + (*s - '0');
    }
    *n = v;
    return true;
}

static bool sync_row(FILE *f) {
    return !ferror(f) && fflush(f) == 0 && fsync(fileno(f)) == 0;
}

static void usage(FILE *f, const struct rusage_info_v0 *r) {
    fprintf(f, "{\"user_raw\":%" PRIu64 ",\"system_raw\":%" PRIu64
               ",\"birth_abs\":%" PRIu64 ",\"exit_abs\":%" PRIu64 "}",
            r->ri_user_time, r->ri_system_time, r->ri_proc_start_abstime,
            r->ri_proc_exit_abstime);
}

static bool same_usage(const struct rusage_info_v0 *a, const struct rusage_info_v0 *b) {
    return a->ri_user_time == b->ri_user_time &&
        a->ri_system_time == b->ri_system_time &&
        a->ri_proc_start_abstime == b->ri_proc_start_abstime &&
        a->ri_proc_exit_abstime == b->ri_proc_exit_abstime;
}

static bool same_bsd_identity(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b) {
    return a->pbi_pid == b->pbi_pid && a->pbi_ppid == b->pbi_ppid &&
        a->pbi_start_tvsec == b->pbi_start_tvsec &&
        a->pbi_start_tvusec == b->pbi_start_tvusec;
}

static FILE *f;
static mach_timebase_info_data_t tb;
static mach_port_t host;
static uint64_t pid, birth, parent, written, protocol_seq;
static bool have_final, have_live_identity;
static struct rusage_info_v0 retained;
static struct proc_bsdinfo live_identity;

static bool sample(const char *stage) {
    uint64_t seq = written;
    host_basic_info_data_t c0 = {0}, c1 = {0};
    host_cpu_load_info_data_t cpu = {0};
    struct rusage_info_v0 r0 = {0}, r1 = {0};
    struct proc_bsdinfo bsd = {0};
    mach_msg_type_number_t nc0 = HOST_BASIC_INFO_COUNT;
    mach_msg_type_number_t nc1 = HOST_BASIC_INFO_COUNT;
    mach_msg_type_number_t nh = HOST_CPU_LOAD_INFO_COUNT;
    int rrc0 = 0, rrc1 = 0, re0 = 0, re1 = 0, brc = 0, be = 0;
    uint64_t begin = a170_arm_clock();
    uint64_t continuous = mach_continuous_time();
    uint64_t uptime_ns = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    kern_return_t crc0 = host_info(host, HOST_BASIC_INFO, (host_info_t)&c0, &nc0);
    kern_return_t hrc = host_statistics(host, HOST_CPU_LOAD_INFO,
                                        (host_info_t)&cpu, &nh);
    bool carried = have_final;
    if (carried) { r0 = retained; r1 = retained; }
    else {
        errno = 0;
        rrc0 = proc_pid_rusage((int)pid, RUSAGE_INFO_V0, (rusage_info_t *)&r0);
        re0 = errno;
        errno = 0;
        brc = proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd));
        be = errno;
        errno = 0;
        rrc1 = proc_pid_rusage((int)pid, RUSAGE_INFO_V0, (rusage_info_t *)&r1);
        re1 = errno;
    }
    kern_return_t crc1 = host_info(host, HOST_BASIC_INFO, (host_info_t)&c1, &nc1);
    uint64_t end = a170_arm_clock();
    bool prior_live = have_live_identity;
    bool bsd_available = brc == (int)sizeof(bsd) && bsd.pbi_pid == pid;
    bool bsd_conflict = brc > 0 && (!bsd_available ||
        (prior_live && !same_bsd_identity(&bsd, &live_identity)));
    bool live_pair = r0.ri_proc_exit_abstime == 0 && r1.ri_proc_exit_abstime == 0;
    bool stable_terminal_pair = r0.ri_proc_exit_abstime != 0 && same_usage(&r0, &r1);
    bool live_identity_ok = !carried && live_pair && bsd_available && !bsd_conflict;
    bool terminal_identity_ok = !carried && prior_live && stable_terminal_pair && !bsd_conflict;
    bool identity_ok = !strcmp(stage, "live") ? live_identity_ok :
        !strcmp(stage, "terminal") ? terminal_identity_ok : carried;
    bool raw_ok = crc0 == KERN_SUCCESS && crc1 == KERN_SUCCESS &&
        hrc == KERN_SUCCESS && nc0 == HOST_BASIC_INFO_COUNT &&
        nc1 == HOST_BASIC_INFO_COUNT && nh == HOST_CPU_LOAD_INFO_COUNT &&
        c0.logical_cpu > 0 && c0.logical_cpu == c1.logical_cpu &&
        rrc0 == 0 && rrc1 == 0 && r0.ri_proc_start_abstime == birth &&
        r1.ri_proc_start_abstime == birth &&
        r1.ri_user_time >= r0.ri_user_time &&
        r1.ri_system_time >= r0.ri_system_time &&
        identity_ok;
    const char *identity_mode = !raw_ok ? "refused" : carried ? "retained_terminal" :
        live_identity_ok ? "live_bsd" : "stable_terminal_rusage";
    if (raw_ok && live_identity_ok) {
        live_identity = bsd; have_live_identity = true;
    }
    /* A successfully read exit marker is retained. It is NOT proof that all
     * task/thread accounting has settled or that the parent reaped it. */
    if (raw_ok && terminal_identity_ok) {
        retained = r1; have_final = true;
    }
    fprintf(f, "{\"kind\":\"snapshot\",\"seq\":%" PRIu64
               ",\"acquisition_stage\":\"%s\""
               ",\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64
               ",\"continuous_abs\":%" PRIu64 ",\"uptime_ns\":%" PRIu64
               ",\"capacity_before\":%d,\"capacity_after\":%d,"
               "\"host_rc\":[%d,%d,%d],\"host_counts\":[%u,%u,%u],"
               "\"expected_host_counts\":[%u,%u,%u],"
               "\"host_ticks\":[%u,%u,%u,%u],\"rusage_rc\":[%d,%d],"
               "\"rusage_errno\":[%d,%d],\"bsd_bytes\":%d,"
               "\"expected_bsd_bytes\":%zu,\"bsd_errno\":%d,"
               "\"bsd_pid\":%u,\"ppid\":%u,\"bsd_birth\":[%" PRIu64
               ",%" PRIu64 "],\"carried_final\":%s,\"prior_live_identity\":%s,"
               "\"bsd_identity_available\":%s,\"bsd_positive_conflict\":%s,"
               "\"stable_terminal_pair\":%s,\"identity_mode\":\"%s\",\"first\":",
            seq, stage, begin, end, continuous, uptime_ns, c0.logical_cpu, c1.logical_cpu,
            crc0, hrc, crc1, nc0, nh, nc1, HOST_BASIC_INFO_COUNT,
            HOST_CPU_LOAD_INFO_COUNT, HOST_BASIC_INFO_COUNT,
            cpu.cpu_ticks[CPU_STATE_USER], cpu.cpu_ticks[CPU_STATE_SYSTEM],
            cpu.cpu_ticks[CPU_STATE_IDLE], cpu.cpu_ticks[CPU_STATE_NICE],
            rrc0, rrc1, re0, re1, brc, sizeof(bsd), be,
            bsd.pbi_pid, bsd.pbi_ppid, bsd.pbi_start_tvsec,
            bsd.pbi_start_tvusec, carried ? "true" : "false",
            prior_live ? "true" : "false", bsd_available ? "true" : "false",
            bsd_conflict ? "true" : "false", stable_terminal_pair ? "true" : "false",
            identity_mode);
    usage(f, &r0); fputs(",\"last\":", f); usage(f, &r1);
    fprintf(f, ",\"raw_ok\":%s}\n", raw_ok ? "true" : "false");
    ++written;
    return sync_row(f) && raw_ok;
}

static bool protocol_row(const char *direction, const struct ipc_message *m,
                         uint64_t begin, uint64_t end) {
    fprintf(f, "{\"kind\":\"protocol\",\"seq\":%" PRIu64 ",", protocol_seq++);
    ipc_fields(f, direction, m, begin, end);
    return sync_row(f);
}
static bool fail(const char *step, bool eof) {
    fprintf(f, "{\"kind\":\"protocol_failure\",\"step\":\"%s\",\"eof\":%s,"
               "\"abs\":%" PRIu64 ",\"qualified\":false}\n", step, eof ? "true" : "false", a170_arm_clock());
    sync_row(f); return false;
}
static bool reply(int fd, uint64_t kind, uint64_t sequence, uint64_t related, bool status) {
    struct ipc_message m = {0};
    m.kind = kind; m.sequence = sequence; m.parent_pid = parent; m.worker_pid = pid;
    m.collector_pid = (uint64_t)getpid(); m.birth_abs = birth; m.related_seq = related;
    m.status = status ? 1 : 0;
    uint64_t end;
    if (!ipc_send(fd, &m, tb, &end)) return fail("reply_write", false);
    return protocol_row("send", &m, m.sent_abs, end);
}
static bool request(int fd, uint64_t kind, uint64_t sequence, uint64_t related) {
    struct ipc_message m; uint64_t begin, end; bool eof;
    bool received = ipc_receive(fd, &m, tb, &begin, &end, &eof);
    if (!protocol_row("receive", &m, begin, end)) return false;
    if (!received || !ipc_matches(&m, kind, sequence, parent, pid, (uint64_t)getpid(), birth, related) ||
        m.status != 1 || m.sent_abs > end) return fail("request_identity_sequence_deadline", eof);
    return true;
}
static bool interval(void) {
    struct timespec delay = {2, 0};
    return nanosleep(&delay, NULL) == 0;
}
static bool collect(int requests, int replies) {
    bool first = sample("live");
    if (!reply(replies, IPC_READY, 0, 0, first)) return false;
    if (!first) return false;
    bool paused = false;
    while (written < 12) {
        if (!interval()) return fail("live_interval_interrupted", false);
        int ready = ipc_available(requests);
        if (ready < 0) return fail("pause_poll", false);
        bool pause_requested = ready == 1;
        if (pause_requested && !request(requests, IPC_PAUSE, 0, 0)) return false;
        // Even after PAUSE arrives, finish the next scheduled LIVE acquisition.
        // The worker is still held alive. A terminal read here is a refusal.
        if (!sample("live")) return false;
        if (pause_requested) {
            if (!reply(replies, IPC_PAUSED, 1, written - 1, true)) return false;
            paused = true; break;
        }
    }
    if (!paused) return fail("live_budget_exhausted", false);
    uint64_t last_live = written - 1;
    // No acquisition occurs between the PAUSED acknowledgement and receipt of
    // the new CAPTURE frame sent after the parent's WNOWAIT and fresh reads.
    if (!request(requests, IPC_CAPTURE, 1, last_live)) return false;
    if (ipc_available(requests) != 0) return fail("duplicate_or_closed_capture_channel", false);
    if (!sample("terminal")) return false;
    if (!reply(replies, IPC_TERMINAL, 2, written - 1, true)) return false;
    for (unsigned i = 0; i < 2; ++i) {
        if (!interval()) return fail("retained_interval_interrupted", false);
        if (ipc_available(requests) != 0) return fail("unexpected_postcapture_request_or_eof", false);
        if (!sample("retained")) return false;
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc == 1) {
        puts("A181 SOURCE-ONLY two-barrier collector plan; no native calls.\n"
             "--collect PID BIRTH_ABS PARENT_PID REQUEST_FD REPLY_FD OUTPUT_ABSOLUTE\n"
             "Requires A181_COLLECTOR_ACK=A181_ROOT_RAW_QUALIFICATION; remains unqualified.");
        return 0;
    }
    uint64_t requests, replies;
    const char *ack = getenv("A181_COLLECTOR_ACK");
    if (argc != 8 || strcmp(argv[1], "--collect") || !ack ||
        strcmp(ack, "A181_ROOT_RAW_QUALIFICATION") || !decimal(argv[2], &pid) || pid == 0 || pid > INT_MAX ||
        !decimal(argv[3], &birth) || birth == 0 || !decimal(argv[4], &parent) || parent == 0 || parent > INT_MAX ||
        !decimal(argv[5], &requests) || requests < 3 || requests > INT_MAX ||
        !decimal(argv[6], &replies) || replies < 3 || replies > INT_MAX || requests == replies || argv[7][0] != '/') return 64;
    if ((uint64_t)getppid() != parent || pid == parent || pid == (uint64_t)getpid() ||
        !ipc_pipe_end((int)requests, false) || !ipc_pipe_end((int)replies, true)) return 65;
    umask(0077);
    int fd = open(argv[7], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 73;
    f = fdopen(fd, "w");
    if (!f) { close(fd); return 74; }
    if (mach_timebase_info(&tb) != KERN_SUCCESS || !tb.numer || !tb.denom) {
        fail("timebase", false); fclose(f); return 1;
    }
    host = mach_host_self();
    fprintf(f, "{\"kind\":\"start\",\"schema\":\"a181.raw.v1\",\"source_id\":\"%s\","
               "\"pid\":%" PRIu64 ",\"expected_birth_abs\":%" PRIu64 ",\"parent_pid\":%" PRIu64
               ",\"collector_pid\":%d,\"live_budget\":12,\"retained_suffix\":2,\"interval_ms\":2000,"
               "\"numer\":%u,\"denom\":%u,\"clock\":\"mach_absolute_time\","
               "\"host_unit\":\"raw_u32_ticks\",\"process_unit\":\"raw_rusage_info_v0\","
               "\"qualified\":false,\"membership_attested\":false}\n",
            A181_SOURCE_ID, pid, birth, parent, getpid(), tb.numer, tb.denom);
    bool complete = sync_row(f) && collect((int)requests, (int)replies);
    fprintf(f, "{\"kind\":\"end\",\"samples_written\":%" PRIu64
               ",\"sampling_complete\":%s,\"final_counter_observed\":%s,"
               "\"qualified\":false,\"exit_reaped_attested\":false}\n",
            written, complete ? "true" : "false", have_final ? "true" : "false");
    bool saved = sync_row(f);
    mach_port_deallocate(mach_task_self(), host); fclose(f);
    close((int)requests); close((int)replies);
    return complete && saved ? 0 : 1;
}
