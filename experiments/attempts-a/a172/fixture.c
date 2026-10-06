/* A172: future bounded native fixture. No normalized CPU attribution. */
#define _DARWIN_C_SOURCE 1
#include "../a170-darwin-cpu-collector/arm_clock.h"
#include "source_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static mach_timebase_info_data_t tb;
static FILE *logfile;
static uint64_t seq;
static const char *case_name;
static uint64_t ns_to_ticks(uint64_t ns) {
    return (uint64_t)(((__uint128_t)ns * tb.denom + tb.numer - 1) / tb.numer);
}
static bool pause_ms(unsigned ms) {
    struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
    return nanosleep(&t, NULL) == 0;
}
static bool durable(void) {
    return !ferror(logfile) && fflush(logfile) == 0 && fsync(fileno(logfile)) == 0;
}
static void prefix(const char *kind) {
    fprintf(logfile, "{\"kind\":\"%s\",\"seq\":%" PRIu64 ",", kind, seq++);
}
static void usage(const struct rusage_info_v0 *r) {
    fprintf(logfile, "\"user_raw\":%" PRIu64 ",\"system_raw\":%" PRIu64
                    ",\"birth_abs\":%" PRIu64 ",\"exit_abs\":%" PRIu64,
            r->ri_user_time, r->ri_system_time, r->ri_proc_start_abstime,
            r->ri_proc_exit_abstime);
}
static bool failure(const char *step, pid_t child, pid_t collector) {
    prefix("failure");
    fprintf(logfile, "\"step\":\"%s\",\"child_pid\":%d,\"collector_pid\":%d,"
                    "\"termination_unknown\":true}\n", step, child, collector);
    durable();
    /* No kill, retry, unrelated reap or claim that either process has stopped. */
    return false;
}

struct event {
    uint64_t magic, kind, pid, ppid, birth, begin, end, stage, threads;
    uint64_t iterations[2], checksums[2], thread_begin[2], thread_end[2];
    uint64_t grandchild_pid, grandchild_birth, grandchild_status;
};
#define MAGIC UINT64_C(0x4131373249504331)
static bool send_event(int fd, struct event *e) {
    e->magic = MAGIC;
    const char *p = (const char *)e;
    size_t left = sizeof(*e);
    while (left) {
        ssize_t n = write(fd, p, left);
        if (n <= 0) return false;
        left -= (size_t)n; p += n;
    }
    return true;
}
static bool receive_event(int fd, struct event *e) {
    char *p = (char *)e;
    size_t left = sizeof(*e);
    uint64_t deadline = a170_arm_clock() + ns_to_ticks(UINT64_C(15000000000));
    while (left && a170_arm_clock() < deadline) {
        struct pollfd f = {fd, POLLIN, 0};
        int ready = poll(&f, 1, 100);
        if (ready < 0) return false;
        if (!ready) continue;
        ssize_t n = read(fd, p, left);
        if (n <= 0) return false;
        left -= (size_t)n; p += n;
    }
    return left == 0 && e->magic == MAGIC;
}
struct work { uint64_t deadline, begin, end, iterations, checksum; };
static void *busy(void *arg) {
    struct work *w = arg;
    w->begin = a170_arm_clock();
    uint64_t x = UINT64_C(0x9e3779b97f4a7c15), count = 0;
    while (a170_arm_clock() < w->deadline) {
        for (unsigned j = 0; j < 1024; ++j) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        }
        ++count;
    }
    w->end = a170_arm_clock(); w->iterations = count; w->checksum = x;
    return NULL;
}
static int worker(int control, int events, bool reversed, bool descendant) {
    struct rusage_info_v0 r = {0};
    struct event e = {0};
    e.kind = 1; e.pid = (uint64_t)getpid(); e.ppid = (uint64_t)getppid();
    e.begin = a170_arm_clock();
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V0, (rusage_info_t *)&r) != 0) return 11;
    e.end = a170_arm_clock(); e.birth = r.ri_proc_start_abstime;
    if (!send_event(events, &e)) return 12;
    char token;
    ssize_t n = read(control, &token, 1);
    if (n == 0) return 0; /* Deliberate refused/early-reap negative: no CPU work. */
    if (n != 1 || token != 'G') return 13;
    if (descendant) {
        int identity[2];
        if (pipe(identity)) return 14;
        pid_t gc = fork();
        if (gc == 0) {
            close(identity[0]);
            struct rusage_info_v0 gr = {0};
            int rc = proc_pid_rusage(getpid(), RUSAGE_INFO_V0, (rusage_info_t *)&gr);
            uint64_t birth = gr.ri_proc_start_abstime;
            bool sent = rc == 0 && write(identity[1], &birth, sizeof(birth)) == (ssize_t)sizeof(birth);
            close(identity[1]);
            _exit(sent && pause_ms(50) ? 0 : 15);
        }
        close(identity[1]);
        uint64_t gb = 0;
        ssize_t got = read(identity[0], &gb, sizeof(gb)); close(identity[0]);
        int status = 0;
        if (gc < 0 || got != (ssize_t)sizeof(gb) || waitpid(gc, &status, 0) != gc) return 16;
        memset(&e, 0, sizeof(e)); e.kind = 3; e.pid = (uint64_t)getpid();
        e.grandchild_pid = (uint64_t)gc; e.grandchild_birth = gb;
        e.grandchild_status = (uint64_t)status;
        if (!send_event(events, &e)) return 17;
        return 0; /* This negative is always unsupported for the single-PID ledger. */
    }
    for (uint64_t stage = 0; stage < 4; ++stage) {
        unsigned threads = stage % 2 == 0 ? 0 :
            (stage == 1 ? (reversed ? 2 : 1) : (reversed ? 1 : 2));
        memset(&e, 0, sizeof(e)); e.kind = 2; e.pid = (uint64_t)getpid();
        e.stage = stage; e.threads = threads; e.begin = a170_arm_clock();
        if (!threads) { if (!pause_ms(2000)) return 18; }
        else {
            pthread_t handles[2]; struct work work[2] = {{0}};
            unsigned created = 0;
            for (unsigned i = 0; i < threads; ++i) {
                work[i].deadline = e.begin + ns_to_ticks(UINT64_C(2000000000));
                if (pthread_create(&handles[i], NULL, busy, &work[i])) break;
                ++created;
            }
            for (unsigned i = 0; i < created; ++i) {
                if (pthread_join(handles[i], NULL)) return 19;
                e.iterations[i] = work[i].iterations; e.checksums[i] = work[i].checksum;
                e.thread_begin[i] = work[i].begin; e.thread_end[i] = work[i].end;
            }
            if (created != threads) return 20;
        }
        e.end = a170_arm_clock();
        if (!send_event(events, &e)) return 21;
    }
    return 0;
}

static bool observe_collector_final(const char *path, uint64_t birth,
                                    struct rusage_info_v0 *result, uint64_t *snapshot) {
    uint64_t deadline = a170_arm_clock() + ns_to_ticks(UINT64_C(5000000000));
    char text[32768];
    do {
        int fd = open(path, O_RDWR | O_NOFOLLOW);
        if (fd >= 0) {
            ssize_t n = read(fd, text, sizeof(text) - 1);
            if (n > 0) {
                text[n] = 0;
                char *line = text;
                for (char *next; (next = strchr(line, '\n')); line = next + 1) {
                    *next = 0;
                    char *last = strstr(line, "\"last\":{");
                    int used = 0; uint64_t number = 0;
                    if (last && sscanf(line, "{\"kind\":\"snapshot\",\"seq\":%" SCNu64 ",", &number) == 1 &&
                        sscanf(last, "\"last\":{\"user_raw\":%" SCNu64 ",\"system_raw\":%" SCNu64
                                     ",\"birth_abs\":%" SCNu64 ",\"exit_abs\":%" SCNu64
                                     "},\"raw_ok\":true}%n", &result->ri_user_time,
                                     &result->ri_system_time, &result->ri_proc_start_abstime,
                                     &result->ri_proc_exit_abstime, &used) == 4 &&
                        used > 0 && last[used] == 0 && result->ri_proc_start_abstime == birth &&
                        result->ri_proc_exit_abstime != 0) {
                        *snapshot = number;
                        bool committed = fsync(fd) == 0; close(fd);
                        return committed;
                    }
                }
            }
            close(fd);
        }
        if (!pause_ms(20)) break;
    } while (a170_arm_clock() < deadline);
    return false;
}

/* Parent waits without consuming status. Every successful result must identify
 * this direct child and a normal exit; WNOWAIT leaves it available for rusage. */
static bool capture_and_reap(pid_t child, uint64_t birth, const char *rawpath) {
    siginfo_t si = {0};
    uint64_t begin = a170_arm_clock();
    uint64_t deadline = begin + ns_to_ticks(UINT64_C(15000000000));
    int rc = -1, err = 0;
    do {
        memset(&si, 0, sizeof(si)); errno = 0;
        rc = waitid(P_PID, (id_t)child, &si, WEXITED | WNOWAIT | WNOHANG); err = errno;
        if (rc != 0 || si.si_pid != 0) break;
        if (!pause_ms(20)) break;
    } while (a170_arm_clock() < deadline);
    uint64_t end = a170_arm_clock();
    prefix("waitable");
    fprintf(logfile, "\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64
                    ",\"rc\":%d,\"errno\":%d,\"pid\":%d,\"si_code\":%d,"
                    "\"si_status\":%d,\"expected_cld_exited\":%d}\n",
            begin, end, rc, err, si.si_pid, si.si_code, si.si_status, CLD_EXITED);
    if (!durable() || rc || si.si_pid != child || si.si_code != CLD_EXITED || si.si_status != 0)
        return false;
    struct rusage_info_v0 reads[2] = {{0}};
    bool observations = true;
    for (unsigned i = 0; i < 2; ++i) {
        begin = a170_arm_clock(); errno = 0;
        rc = proc_pid_rusage(child, RUSAGE_INFO_V0, (rusage_info_t *)&reads[i]); err = errno;
        end = a170_arm_clock();
        prefix("zombie_read");
        fprintf(logfile, "\"index\":%u,\"pid\":%d,\"begin_abs\":%" PRIu64
                        ",\"end_abs\":%" PRIu64 ",\"rc\":%d,\"errno\":%d,",
                i, child, begin, end, rc, err);
        usage(&reads[i]); fputs("}\n", logfile);
        observations &= rc == 0 && reads[i].ri_proc_start_abstime == birth &&
            reads[i].ri_proc_exit_abstime >= birth && reads[i].ri_proc_exit_abstime <= end;
        if (!durable()) return false;
    }
    bool stable = observations && reads[0].ri_user_time == reads[1].ri_user_time &&
        reads[0].ri_system_time == reads[1].ri_system_time &&
        reads[0].ri_proc_exit_abstime == reads[1].ri_proc_exit_abstime;
    struct rusage_info_v0 captured = {0}; uint64_t snapshot = 0;
    bool captured_ok = rawpath && observe_collector_final(rawpath, birth, &captured, &snapshot);
    bool matches = captured_ok && captured.ri_user_time == reads[1].ri_user_time &&
        captured.ri_system_time == reads[1].ri_system_time &&
        captured.ri_proc_exit_abstime == reads[1].ri_proc_exit_abstime;
    prefix("collector_final_capture");
    fprintf(logfile, "\"required\":%s,\"observed_and_fsynced\":%s,\"matches_parent_reads\":%s,"
                    "\"snapshot_seq\":%" PRIu64 ",\"abs\":%" PRIu64 ",",
            rawpath ? "true" : "false", captured_ok ? "true" : "false",
            matches ? "true" : "false", snapshot, a170_arm_clock());
    usage(&captured); fputs("}\n", logfile);
    if (!durable()) return false;
    prefix("capture_ack");
    fprintf(logfile, "\"pid\":%d,\"birth_matches\":%s,\"stable_observed\":%s,"
                    "\"settled_accounting_proven\":false}\n", child,
            observations ? "true" : "false", stable ? "true" : "false");
    if (!durable()) return false; /* No reap until capture ACK is fsynced. */
    uint64_t ack_committed = a170_arm_clock();
    struct rusage final = {0}; int status = 0;
    begin = a170_arm_clock(); errno = 0;
    pid_t got = wait4(child, &status, 0, &final); err = errno;
    end = a170_arm_clock();
    prefix("reaped");
    fprintf(logfile, "\"pid\":%d,\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64
                    ",\"ack_committed_abs\":%" PRIu64 ",\"errno\":%d,\"status\":%d,"
                    "\"user_timeval\":[%lld,%d],\"system_timeval\":[%lld,%d],"
                    "\"wait_usage_includes_children\":true}\n", got, begin, end,
            ack_committed, err, status, (long long)final.ru_utime.tv_sec,
            final.ru_utime.tv_usec, (long long)final.ru_stime.tv_sec, final.ru_stime.tv_usec);
    return durable() && stable && (!rawpath || matches) && got == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool first_snapshot(const char *path, bool *raw_ok) {
    uint64_t deadline = a170_arm_clock() + ns_to_ticks(UINT64_C(5000000000));
    char text[8192];
    do {
        FILE *f = fopen(path, "r");
        if (f) {
            size_t n = fread(text, 1, sizeof(text) - 1, f); fclose(f); text[n] = 0;
            char *line = strchr(text, '\n');
            if (line && strchr(line + 1, '\n')) {
                *raw_ok = strstr(line + 1, "\"raw_ok\":true}\n") != NULL;
                return strstr(line + 1, "\"kind\":\"snapshot\",\"seq\":0,") == line + 1;
            }
        }
        if (!pause_ms(20)) break;
    } while (a170_arm_clock() < deadline);
    return false;
}
static bool wait_collector(pid_t pid, int *status) {
    uint64_t deadline = a170_arm_clock() + ns_to_ticks(UINT64_C(30000000000));
    while (a170_arm_clock() < deadline) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid) return true;
        if (got < 0 || !pause_ms(50)) return false;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc == 1) {
        puts("A172 SOURCE-ONLY lifecycle plan; no native probes.\n"
             "--run {order-12|order-21|wrong-birth|early-reap|descendant} COLLECTOR_ABS NEW_DIR_ABS\n"
             "Requires A172_ACK=A172_ROOT_TINY_LIFECYCLE. Raw units remain unqualified.");
        return 0;
    }
    const char *ack = getenv("A172_ACK");
    if (argc != 5 || strcmp(argv[1], "--run") || !ack ||
        strcmp(ack, "A172_ROOT_TINY_LIFECYCLE") || argv[3][0] != '/' || argv[4][0] != '/') return 64;
    case_name = argv[2];
    bool reversed = !strcmp(case_name, "order-21"), wrong = !strcmp(case_name, "wrong-birth"),
        early = !strcmp(case_name, "early-reap"), descendant = !strcmp(case_name, "descendant");
    if (strcmp(case_name, "order-12") && !reversed && !wrong && !early && !descendant) return 64;
    umask(0077);
    if (mkdir(argv[4], 0700)) return 73;
    char logpath[4096], rawpath[4096], outpath[4096], errpath[4096];
    if (snprintf(logpath, sizeof(logpath), "%s/lifecycle.jsonl", argv[4]) >= (int)sizeof(logpath) ||
        snprintf(rawpath, sizeof(rawpath), "%s/raw.jsonl", argv[4]) >= (int)sizeof(rawpath) ||
        snprintf(outpath, sizeof(outpath), "%s/collector.stdout", argv[4]) >= (int)sizeof(outpath) ||
        snprintf(errpath, sizeof(errpath), "%s/collector.stderr", argv[4]) >= (int)sizeof(errpath)) return 64;
    int lfd = open(logpath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (lfd < 0 || !(logfile = fdopen(lfd, "w"))) return 73;
    if (mach_timebase_info(&tb) != KERN_SUCCESS || !tb.numer || !tb.denom) return 1;
    prefix("start");
    fprintf(logfile, "\"schema\":\"a172.lifecycle.v1\",\"case\":\"%s\",\"parent_pid\":%d,"
                    "\"source_id\":\"%s\",\"clock\":\"mach_absolute_time\","
                    "\"numer\":%u,\"denom\":%u,\"collector_qualified\":false}\n",
            case_name, getpid(), A172_SOURCE_ID, tb.numer, tb.denom);
    if (!durable()) return 74;
    int control[2], events[2];
    if (pipe(control) || pipe(events)) return 1;
    pid_t child = fork();
    if (child == 0) {
        close(control[1]); close(events[0]); close(lfd);
        _exit(worker(control[0], events[1], reversed, descendant));
    }
    close(control[0]); close(events[1]);
    if (child < 0) return 1;
    struct event ready = {0};
    if (!receive_event(events[0], &ready) || ready.kind != 1 || ready.pid != (uint64_t)child ||
        ready.ppid != (uint64_t)getpid() || !ready.birth) {
        close(control[1]); failure("ready", child, 0); return 1;
    }
    prefix("child_ready");
    fprintf(logfile, "\"pid\":%d,\"ppid\":%" PRIu64 ",\"birth_abs\":%" PRIu64
                    ",\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64 "}\n",
            child, ready.ppid, ready.birth, ready.begin, ready.end);
    if (!durable()) { close(control[1]); return 74; }
    bool life_ok = true;
    if (early) { close(control[1]); life_ok = capture_and_reap(child, ready.birth, NULL); }
    char pidtext[32], birthtext[32];
    snprintf(pidtext, sizeof(pidtext), "%d", child);
    snprintf(birthtext, sizeof(birthtext), "%" PRIu64, ready.birth + (wrong ? 1 : 0));
    uint64_t fork_begin = a170_arm_clock();
    pid_t collector = fork();
    if (collector == 0) {
        if (!early) close(control[1]);
        close(events[0]); close(lfd);
        int out = open(outpath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        int err = open(errpath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (out < 0 || err < 0 || dup2(out, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0) _exit(126);
        close(out); close(err);
        if (setenv("A170_ACK", "A170_ROOT_RAW_QUALIFICATION", 1)) _exit(126);
        execl(argv[3], argv[3], "--collect", pidtext, birthtext, "12", "2000", rawpath, (char *)NULL);
        _exit(127);
    }
    uint64_t fork_end = a170_arm_clock();
    prefix("collector_started");
    fprintf(logfile, "\"pid\":%d,\"observed_pid\":%d,\"supplied_birth_abs\":%s,"
                    "\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64 "}\n",
            collector, child, birthtext, fork_begin, fork_end);
    if (!durable() || collector < 0) { if (!early) close(control[1]); return 1; }
    bool raw_ok = false;
    bool first = first_snapshot(rawpath, &raw_ok);
    prefix("first_snapshot_seen");
    fprintf(logfile, "\"seen\":%s,\"raw_ok\":%s,\"abs\":%" PRIu64 "}\n",
            first ? "true" : "false", raw_ok ? "true" : "false", a170_arm_clock());
    if (!durable()) { if (!early) close(control[1]); return 74; }
    unsigned stage_count = 0, descendant_count = 0;
    if (!early) {
        bool go = first && raw_ok && !wrong;
        if (go && write(control[1], "G", 1) != 1) go = false;
        close(control[1]);
        if (go) {
            unsigned expected = descendant ? 1 : 4;
            for (unsigned i = 0; i < expected; ++i) {
                struct event e = {0};
                if (!receive_event(events[0], &e) || e.pid != (uint64_t)child) {
                    failure("worker_event", child, collector); return 1;
                }
                if (e.kind == 3 && descendant) {
                    ++descendant_count; prefix("descendant_observed");
                    fprintf(logfile, "\"parent_pid\":%d,\"pid\":%" PRIu64
                                    ",\"birth_abs\":%" PRIu64 ",\"status\":%" PRIu64
                                    ",\"single_pid_coverage_supported\":false}\n",
                            child, e.grandchild_pid, e.grandchild_birth, e.grandchild_status);
                } else if (e.kind == 2 && !descendant && e.stage == i) {
                    ++stage_count; prefix("stage");
                    fprintf(logfile, "\"pid\":%d,\"stage\":%" PRIu64 ",\"threads\":%" PRIu64
                                    ",\"begin_abs\":%" PRIu64 ",\"end_abs\":%" PRIu64
                                    ",\"iterations\":[%" PRIu64 ",%" PRIu64
                                    "],\"checksums\":[%" PRIu64 ",%" PRIu64
                                    "],\"thread_begin\":[%" PRIu64 ",%" PRIu64
                                    "],\"thread_end\":[%" PRIu64 ",%" PRIu64 "]}\n",
                            child, e.stage, e.threads, e.begin, e.end, e.iterations[0], e.iterations[1],
                            e.checksums[0], e.checksums[1], e.thread_begin[0], e.thread_begin[1],
                            e.thread_end[0], e.thread_end[1]);
                } else { failure("worker_schema", child, collector); return 1; }
                if (!durable()) return 74;
            }
        }
        life_ok = capture_and_reap(child, ready.birth, wrong ? NULL : rawpath);
    }
    close(events[0]);
    int status = 0;
    bool collector_done = wait_collector(collector, &status);
    prefix("collector_reaped");
    fprintf(logfile, "\"pid\":%d,\"reaped\":%s,\"status\":%d,\"abs\":%" PRIu64 "}\n",
            collector, collector_done ? "true" : "false", status, a170_arm_clock());
    if (!durable()) return 74;
    bool refused = wrong || early;
    bool pass = first && life_ok && collector_done && WIFEXITED(status) &&
        WEXITSTATUS(status) == (refused ? 1 : 0) && raw_ok == !refused &&
        stage_count == (refused || descendant ? 0 : 4) && descendant_count == (descendant ? 1 : 0);
    prefix("summary");
    fprintf(logfile, "\"case\":\"%s\",\"fixture_pass\":%s,\"stages\":%u,"
                    "\"descendants\":%u,\"expected_refusal\":%s,"
                    "\"single_pid_coverage_supported\":%s,\"collector_qualified\":false,"
                    "\"cpu_units_justified\":false,\"settled_accounting_proven\":false}\n",
            case_name, pass ? "true" : "false", stage_count, descendant_count,
            refused ? "true" : "false", descendant ? "false" : "true");
    bool saved = durable(); fclose(logfile);
    return pass && saved ? 0 : 1;
}
