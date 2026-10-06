/* A178 raw observer, not a qualified CPU-attribution monitor. No process launch,
 * signal, reap, tree discovery or tick-to-CPU-nanosecond conversion. */
#define _DARWIN_C_SOURCE 1
#include "arm_clock.h"
#include "source_identity.h"
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

int main(int argc, char **argv) {
    if (argc == 1) {
        puts("A178 SOURCE-ONLY raw collector plan. No probes were made.\n"
             "--collect PID BIRTH_ABS SAMPLES INTERVAL_MS OUTPUT_ABSOLUTE\n"
             "requires A178_COLLECTOR_ACK=A178_ROOT_RAW_QUALIFICATION. Units, ownership,\n"
             "final-accounting and runtime qualification remain OPEN.");
        return 0;
    }
    uint64_t pid, birth, count, interval;
    const char *ack = getenv("A178_COLLECTOR_ACK");
    if (argc != 7 || strcmp(argv[1], "--collect") || !ack ||
        strcmp(ack, "A178_ROOT_RAW_QUALIFICATION") ||
        !decimal(argv[2], &pid) || pid == 0 || pid > INT_MAX ||
        !decimal(argv[3], &birth) || birth == 0 ||
        !decimal(argv[4], &count) || count < 2 || count > 120 ||
        !decimal(argv[5], &interval) || interval < 100 || interval > 2500 ||
        argv[6][0] != '/') {
        fputs("Exact explicit qualification arguments required.\n", stderr);
        return 64;
    }
    umask(0077);
    int fd = open(argv[6], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { perror("exclusive output"); return 73; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return 74; }
    mach_timebase_info_data_t tb = {0};
    kern_return_t tbrc = mach_timebase_info(&tb);
    if (tbrc != KERN_SUCCESS || !tb.numer || !tb.denom) {
        fprintf(f, "{\"kind\":\"setup_failure\",\"api_rc\":%d}\n", tbrc);
        sync_row(f); fclose(f); return 1;
    }
    mach_port_t host = mach_host_self();
    fprintf(f, "{\"kind\":\"start\",\"schema\":\"a178.raw.v1\","
               "\"source_id\":\"%s\","
               "\"pid\":%" PRIu64 ",\"expected_birth_abs\":%" PRIu64
               ",\"collector_pid\":%d,\"samples\":%" PRIu64
               ",\"interval_ms\":%" PRIu64 ",\"numer\":%u,\"denom\":%u,"
               "\"clock\":\"mach_absolute_time\",\"host_unit\":\"raw_u32_ticks\","
               "\"process_unit\":\"raw_rusage_info_v0\","
               "\"qualified\":false,\"membership_attested\":false}\n",
            A178_SOURCE_ID, pid, birth, getpid(), count, interval, tb.numer, tb.denom);
    if (!sync_row(f)) { fclose(f); return 74; }
    bool complete = true, have_final = false, have_live_identity = false;
    struct rusage_info_v0 retained = {0};
    struct proc_bsdinfo live_identity = {0};
    uint64_t written = 0;
    for (uint64_t seq = 0; seq < count; ++seq) {
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
        bool identity_ok = carried || live_identity_ok || terminal_identity_ok;
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
                seq, begin, end, continuous, uptime_ns, c0.logical_cpu, c1.logical_cpu,
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
        if (!sync_row(f)) { complete = false; break; }
        if (!raw_ok) { complete = false; break; }
        if (seq + 1 < count) {
            struct timespec delay = {(time_t)(interval / 1000),
                                     (long)((interval % 1000) * 1000000)};
            /* No retry on interrupted sleep; an incomplete terminal is explicit. */
            if (nanosleep(&delay, NULL) != 0) { complete = false; break; }
        }
    }
    fprintf(f, "{\"kind\":\"end\",\"samples_written\":%" PRIu64
               ",\"sampling_complete\":%s,\"final_counter_observed\":%s,"
               "\"qualified\":false,\"exit_reaped_attested\":false}\n",
            written, complete && written == count ? "true" : "false",
            have_final ? "true" : "false");
    bool saved = sync_row(f);
    mach_port_deallocate(mach_task_self(), host);
    fclose(f);
    return complete && written == count && saved ? 0 : 1;
}
