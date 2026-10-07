/* Source-only A193 local worker clock gate. No host collector or unit selection. */
#include "protocol.h"
#include "source_identity.h"
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

static mach_timebase_info_data_t tb;
static FILE *logfile;
static uint64_t record_seq, process_calls, thread_calls;
static pid_t parent_pid, worker_pid;
static uint64_t worker_birth;
static int worker_output=-1;
static uint64_t worker_stage_sequence;

static bool commit(void) { return fflush(logfile)==0 && fsync(fileno(logfile))==0; }
static void record(const char *kind) { fprintf(logfile,"{\"kind\":\"%s\",\"seq\":%"PRIu64,kind,record_seq++); }
static void clock_json(const struct clock_obs *c) {
    fprintf(logfile,"{\"caller_pid\":%d,\"caller_tid\":%"PRIu64",\"clock_id\":%d,\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64
        ",\"seconds\":%"PRId64",\"nanoseconds\":%"PRId64",\"status\":%d,\"errno\":%d}",c->caller_pid,c->caller_tid,c->clock_id,
        c->begin_abs,c->end_abs,c->seconds,c->nanoseconds,c->status,c->error);
}
static void usage_json(const struct usage_obs *u) {
    fprintf(logfile,"{\"pid\":%d,\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64",\"user_raw\":%"PRIu64",\"system_raw\":%"PRIu64
        ",\"birth_abs\":%"PRIu64",\"exit_abs\":%"PRIu64",\"status\":%d,\"errno\":%d}",u->pid,u->begin_abs,u->end_abs,
        u->user_raw,u->system_raw,u->birth_abs,u->exit_abs,u->status,u->error);
}
static void io_json(const struct io_obs *o) {
    fprintf(logfile,"{\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64",\"deadline_abs\":%"PRIu64",\"bytes\":%"PRIu64
        ",\"errno\":%d,\"eof\":%s}",o->begin_abs,o->end_abs,o->deadline_abs,o->bytes,o->error,o->eof?"true":"false");
}
static void frame_header(const struct frame *f) {
    fprintf(logfile,"\"header\":{\"magic\":%"PRIu64",\"version\":%"PRIu64",\"bytes\":%"PRIu64",\"kind\":%"PRIu64
        ",\"sequence\":%"PRIu64",\"step\":%"PRIu64",\"parent_pid\":%"PRIu64",\"worker_pid\":%"PRIu64",\"birth_abs\":%"PRIu64
        ",\"sent_abs\":%"PRIu64",\"process_clock_calls\":%"PRIu64",\"thread_clock_calls\":%"PRIu64"}",
        f->magic,f->version,f->bytes,f->kind,f->sequence,f->step,f->parent_pid,f->worker_pid,f->birth_abs,f->sent_abs,f->process_clock_calls,f->thread_clock_calls);
}
static bool frame_record(const char *kind,const struct frame *f,const struct io_obs *io) {
    record(kind);fprintf(logfile,",\"io\":");io_json(io);fprintf(logfile,",");frame_header(f);
    if (f->kind==READY) {
        fprintf(logfile,",\"identity\":");usage_json(&f->data.ready.identity);fprintf(logfile,",\"resolutions\":[");
        clock_json(&f->data.ready.resolutions[0]);fprintf(logfile,",");clock_json(&f->data.ready.resolutions[1]);fprintf(logfile,"]");
    } else if (f->kind==STAGE) {
        const struct stage_data *s=&f->data.stage;
        fprintf(logfile,",\"stage\":{\"threads\":%d,\"sleep_calls\":%d,\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64
            ",\"deadline_abs\":%"PRIu64",\"process\":[",s->threads,s->sleep_calls,s->begin_abs,s->end_abs,s->deadline_abs);
        clock_json(&s->process[0]);fprintf(logfile,",");clock_json(&s->process[1]);fprintf(logfile,"],\"threads_data\":[");
        for (int i=0;i<s->threads;i++) {
            if(i)fprintf(logfile,",");fprintf(logfile,"{\"slot\":%d,\"thread_id_status\":%d,\"iterations\":%"PRIu64",\"checksum\":%"PRIu64",\"clocks\":[",i,s->thread_id_status[i],s->iterations[i],s->checksum[i]);
            clock_json(&s->thread[i][0]);fprintf(logfile,",");clock_json(&s->thread[i][1]);fprintf(logfile,"]}");
        }
        fprintf(logfile,"]}");
    } else {
        fprintf(logfile,",\"before\":");clock_json(&f->data.boundary.before);
        if (f->kind!=REQUEST) {
            fprintf(logfile,",\"reads\":[");usage_json(&f->data.boundary.reads[0]);fprintf(logfile,",");usage_json(&f->data.boundary.reads[1]);fprintf(logfile,"]");
        }
        if (f->kind==RECEIPT || f->kind==RELEASE) {fprintf(logfile,",\"after\":");clock_json(&f->data.boundary.after);}
    }
    fprintf(logfile,"}\n");return commit();
}
static bool read_clock(clockid_t id,uint64_t tid,struct clock_obs *c,bool resolution,uint64_t *counter) {
    memset(c,0,sizeof(*c));c->caller_pid=getpid();c->caller_tid=tid;c->clock_id=(int32_t)id;
    struct timespec value={0};c->begin_abs=a170_arm_clock();errno=0;
    c->status=resolution?clock_getres(id,&value):clock_gettime(id,&value);c->error=errno;c->end_abs=a170_arm_clock();
    if (counter)++*counter;
    c->seconds=value.tv_sec;c->nanoseconds=value.tv_nsec;
    return c->status==0 && c->seconds>=0 && c->nanoseconds>=0 && c->nanoseconds<1000000000;
}
static bool read_usage(pid_t pid,struct usage_obs *u) {
    struct rusage_info_v0 value={0};memset(u,0,sizeof(*u));u->pid=pid;
    u->begin_abs=a170_arm_clock();errno=0;u->status=proc_pid_rusage(pid,RUSAGE_INFO_V0,(rusage_info_t*)&value);u->error=errno;u->end_abs=a170_arm_clock();
    u->user_raw=value.ri_user_time;u->system_raw=value.ri_system_time;u->birth_abs=value.ri_proc_start_abstime;u->exit_abs=value.ri_proc_exit_abstime;
    return u->status==0;
}
static bool worker_send(int fd,struct frame *f) {
    struct io_obs io;f->process_clock_calls=process_calls;f->thread_clock_calls=thread_calls;
    return transfer(fd,f,true,tb,&io);
}
static int worker_failure_status(int out,uint64_t sequence,uint64_t step,int code,int status) {
    struct frame f=message(WORKER_FAILURE,sequence,step,parent_pid,worker_pid,worker_birth);
    f.data.failure[0]=code;f.data.failure[1]=errno;f.data.failure[2]=status;
    (void)worker_send(out,&f);return code;
}
static int worker_failure(int out,uint64_t sequence,uint64_t step,int code) {
    return worker_failure_status(out,sequence,step,code,0);
}
struct work { uint64_t deadline, iterations, checksum, calls; struct clock_obs clocks[2]; int id_status; bool ok; };
static void *busy(void *arg) {
    struct work *w=arg;uint64_t tid=0;
    w->id_status=pthread_threadid_np(NULL,&tid);
    if (w->id_status || !tid || !read_clock(CLOCK_THREAD_CPUTIME_ID,tid,&w->clocks[0],false,&w->calls)) return NULL;
    uint64_t x=UINT64_C(0x93ad91a7),n=0;
    while(a170_arm_clock()<w->deadline) {for(int j=0;j<1024;j++){x^=x<<13;x^=x>>7;x^=x<<17;}++n;}
    w->iterations=n;w->checksum=x;
    w->ok=read_clock(CLOCK_THREAD_CPUTIME_ID,tid,&w->clocks[1],false,&w->calls) && n>0;return NULL;
}
static bool stage_work(int step,int first_threads,struct stage_data *s) {
    memset(s,0,sizeof(*s));s->threads=(step%2)?(step==1?first_threads:3-first_threads):0;
    if(!read_clock(CLOCK_PROCESS_CPUTIME_ID,0,&s->process[0],false,&process_calls))return false;
    s->begin_abs=a170_arm_clock();
    if(!deadline_from(tb,s->begin_abs,UINT64_C(2000000000),&s->deadline_abs))return false;
    if(!s->threads) {
        for(;;) {
            uint64_t current=a170_arm_clock();
            if(current>=s->deadline_abs)break;
            uint64_t left=s->deadline_abs-current;
            __uint128_t ns=(__uint128_t)left*tb.numer/tb.denom;
            struct timespec sleep_for={(time_t)(ns/1000000000),(long)(ns%1000000000)};
            ++s->sleep_calls;errno=0;
            if(nanosleep(&sleep_for,NULL) && errno!=EINTR)return false;
        }
    } else {
        pthread_t handles[2];struct work jobs[2]={{0}};int created=0;
        for(int i=0;i<s->threads;i++){jobs[i].deadline=s->deadline_abs;if(pthread_create(&handles[i],NULL,busy,&jobs[i]))break;++created;}
        bool good=created==s->threads;
        for(int i=0;i<created;i++) {
            int joined=pthread_join(handles[i],NULL);
            if(joined) {
                /* This is the worker's own process. Keep the jobs stack alive
                 * while reporting failure, then exit this process without ever
                 * reading the unjoined job or unwinding its storage. No external
                 * process is signaled and no join retry is attempted. */
                _exit(worker_failure_status(worker_output,worker_stage_sequence,(uint64_t)step,24,joined));
            }
            thread_calls+=jobs[i].calls;s->thread_id_status[i]=jobs[i].id_status;
            memcpy(s->thread[i],jobs[i].clocks,sizeof(jobs[i].clocks));s->iterations[i]=jobs[i].iterations;s->checksum[i]=jobs[i].checksum;
            good=good&&jobs[i].ok;
        }
        if(!good)return false;
    }
    s->end_abs=a170_arm_clock();
    return read_clock(CLOCK_PROCESS_CPUTIME_ID,0,&s->process[1],false,&process_calls);
}
static int worker(int input,int output,int first_threads) {
    worker_pid=getpid();worker_output=output;uint64_t sequence=0;
    struct frame ready=message(READY,sequence++,0,parent_pid,worker_pid,0);
    if(!read_usage(worker_pid,&ready.data.ready.identity))return worker_failure(output,0,0,11);
    worker_birth=ready.data.ready.identity.birth_abs;ready.birth_abs=worker_birth;
    if(!worker_birth || ready.data.ready.identity.exit_abs)return worker_failure(output,0,0,12);
    if(!read_clock(CLOCK_PROCESS_CPUTIME_ID,0,&ready.data.ready.resolutions[0],true,NULL) ||
       !read_clock(CLOCK_THREAD_CPUTIME_ID,0,&ready.data.ready.resolutions[1],true,NULL))return worker_failure(output,0,0,13);
    if(!worker_send(output,&ready))return 14;
    for(uint64_t step=0;step<5;step++) {
        struct frame request=message(REQUEST,sequence++,step,parent_pid,worker_pid,worker_birth),reply;
        if(!read_clock(CLOCK_PROCESS_CPUTIME_ID,0,&request.data.boundary.before,false,&process_calls))return worker_failure(output,sequence-1,step,15);
        if(!worker_send(output,&request))return 16;
        struct io_obs io;
        if(!transfer(input,&reply,false,tb,&io) || !matches(&reply,REPLY,2*step,step,parent_pid,worker_pid,worker_birth) ||
           memcmp(&reply.data.boundary.before,&request.data.boundary.before,sizeof(struct clock_obs)))return worker_failure(output,sequence,step,17);
        struct frame receipt=reply;receipt.kind=RECEIPT;receipt.sequence=sequence++;
        if(!read_clock(CLOCK_PROCESS_CPUTIME_ID,0,&receipt.data.boundary.after,false,&process_calls))return worker_failure(output,sequence-1,step,18);
        if(!worker_send(output,&receipt))return 19;
        struct frame release;
        if(!transfer(input,&release,false,tb,&io) || !matches(&release,RELEASE,2*step+1,step,parent_pid,worker_pid,worker_birth) ||
           memcmp(&release.data.boundary,&receipt.data.boundary,sizeof(struct boundary_data)))return worker_failure(output,sequence,step,20);
        if(step<4) {
            struct frame event=message(STAGE,sequence++,step,parent_pid,worker_pid,worker_birth);
            worker_stage_sequence=event.sequence;
            if(!stage_work((int)step,first_threads,&event.data.stage))return worker_failure(output,sequence-1,step,21);
            if(!worker_send(output,&event))return 22;
        }
    }
    return process_calls==18 && thread_calls==6 ? 0 : 23;
}
static bool parent_receive(int fd,struct frame *f,struct io_obs *io,uint64_t kind,uint64_t sequence,uint64_t step) {
    return transfer(fd,f,false,tb,io) && matches(f,kind,sequence,step,parent_pid,worker_pid,worker_birth);
}
static int failure(const char *where,const struct frame *f,const struct io_obs *io) {
    record("first_failure");fprintf(logfile,",\"where\":\"%s\",\"worker_pid\":%d,\"worker_state\":\"UNKNOWN_NO_SIGNAL_SENT\",\"io\":",where,worker_pid);
    io_json(io);fprintf(logfile,",\"frame_hex\":\"");
    for(size_t i=0;i<sizeof(*f);i++)fprintf(logfile,"%02x",((const unsigned char*)f)[i]);
    fprintf(logfile,"\"}\n");(void)commit();return 1;
}
static int parent(int input,int output,const char *order) {
    struct frame f={0};struct io_obs io={0};uint64_t child_sequence=0;
    record("start");fprintf(logfile,",\"schema\":\"a193.worker_clock.v1\",\"case\":\"%s\",\"source_id\":\"%s\",\"parent_pid\":%d,\"worker_pid\":%d,\"numer\":%u,\"denom\":%u,\"frame_bytes\":%zu,\"selected_scale\":null,\"normalized_occupancy\":null}\n",order,A193_SOURCE_ID,parent_pid,worker_pid,tb.numer,tb.denom,sizeof(f));
    if(!commit())return 2;
    if(!transfer(input,&f,false,tb,&io))return failure("ready_receive",&f,&io);
    worker_birth=f.birth_abs;
    if(!matches(&f,READY,child_sequence++,0,parent_pid,worker_pid,worker_birth) || !worker_birth ||
       f.data.ready.identity.pid!=worker_pid || f.data.ready.identity.birth_abs!=worker_birth || f.data.ready.identity.exit_abs || f.data.ready.identity.status)
       return failure("ready_identity",&f,&io);
    if(!frame_record("ready",&f,&io))return 2;
    for(uint64_t step=0;step<5;step++) {
        if(!parent_receive(input,&f,&io,REQUEST,child_sequence++,step))return failure("request",&f,&io);
        if(!frame_record("request",&f,&io))return 2;
        struct frame reply=f;reply.kind=REPLY;reply.sequence=2*step;
        for(int j=0;j<2;j++) {
            bool ok=read_usage(worker_pid,&reply.data.boundary.reads[j]);struct usage_obs *u=&reply.data.boundary.reads[j];
            record("live_usage");fprintf(logfile,",\"step\":%"PRIu64",\"index\":%d,\"usage\":",step,j);usage_json(u);fprintf(logfile,"}\n");
            if(!commit())return 2;
            if(!ok || u->birth_abs!=worker_birth || u->exit_abs)return failure("live_usage",&reply,&io);
        }
        if(!transfer(output,&reply,true,tb,&io))return failure("reply_send",&reply,&io);
        if(!frame_record("reply",&reply,&io))return 2;
        if(!parent_receive(input,&f,&io,RECEIPT,child_sequence++,step) ||
           memcmp(&f.data.boundary.before,&reply.data.boundary.before,sizeof(struct clock_obs)) ||
           memcmp(f.data.boundary.reads,reply.data.boundary.reads,sizeof(reply.data.boundary.reads)))return failure("receipt",&f,&io);
        if(!frame_record("receipt",&f,&io))return 2; /* durable complete S0/read/read/S1 BEFORE release */
        struct frame release=f;release.kind=RELEASE;release.sequence=2*step+1;
        if(!transfer(output,&release,true,tb,&io))return failure("release_send",&release,&io);
        if(!frame_record("release",&release,&io))return 2;
        if(step<4) {
            if(!parent_receive(input,&f,&io,STAGE,child_sequence++,step))return failure("stage",&f,&io);
            if(f.data.stage.threads<0 || f.data.stage.threads>2)return failure("stage_payload_geometry",&f,&io);
            if(!frame_record("stage",&f,&io))return 2;
        }
    }
    uint64_t end;if(!deadline(tb,UINT64_C(15000000000),&end))return failure("wait_deadline",&f,&io);
    unsigned polls=0;siginfo_t si={0};int rc=0;
    for(;;) {
        uint64_t begin=a170_arm_clock();memset(&si,0,sizeof(si));errno=0;
        rc=waitid(P_PID,(id_t)worker_pid,&si,WEXITED|WNOWAIT|WNOHANG);int error=errno;uint64_t finish=a170_arm_clock();
        record("wait_poll");fprintf(logfile,",\"poll\":%u,\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64",\"deadline_abs\":%"PRIu64",\"status\":%d,\"errno\":%d,\"pid\":%d,\"si_code\":%d,\"si_status\":%d}\n",polls++,begin,finish,end,rc,error,si.si_pid,si.si_code,si.si_status);
        if(!commit())return 2;
        if(rc || finish>end || polls>301 || (si.si_pid && (si.si_pid!=worker_pid || si.si_code!=CLD_EXITED || si.si_status)))return failure("waitable",&f,&io);
        if(si.si_pid==worker_pid)break;
        struct timespec pause={0,50000000};if(nanosleep(&pause,NULL) && errno!=EINTR)return failure("wait_pause",&f,&io);
    }
    for(int i=0;i<2;i++) {
        struct usage_obs usage;bool ok=read_usage(worker_pid,&usage);
        record("terminal_usage");fprintf(logfile,",\"index\":%d,\"usage\":",i);usage_json(&usage);fprintf(logfile,"}\n");
        if(!commit())return 2;
        if(!ok || usage.birth_abs!=worker_birth || !usage.exit_abs)return failure("terminal_usage",&f,&io);
    }
    int status=0;struct rusage usage={0};uint64_t begin=a170_arm_clock();errno=0;
    pid_t reaped=wait4(worker_pid,&status,0,&usage);int error=errno;uint64_t finish=a170_arm_clock();
    record("reaped");fprintf(logfile,",\"pid\":%d,\"status\":%d,\"errno\":%d,\"begin_abs\":%"PRIu64",\"end_abs\":%"PRIu64
        ",\"user_timeval\":[%ld,%d],\"system_timeval\":[%ld,%d],\"includes_children_scope\":true}\n",reaped,status,error,begin,finish,(long)usage.ru_utime.tv_sec,usage.ru_utime.tv_usec,(long)usage.ru_stime.tv_sec,usage.ru_stime.tv_usec);
    if(!commit())return 2;
    if(reaped!=worker_pid || !WIFEXITED(status) || WEXITSTATUS(status)!=0)return failure("wait4",&f,&io);
    record("summary");fprintf(logfile,",\"status\":\"A193_NATIVE_SEQUENCE_COMPLETE\",\"worker_process_clock_reads\":18,\"worker_thread_clock_reads\":6,\"worker_clock_getres_calls\":2,\"thread_id_calls\":3,\"worker_identity_v0_reads\":1,\"parent_live_v0_reads\":10,\"parent_terminal_v0_reads\":2,\"waitid_calls\":%u,\"wait4_calls\":1,\"records\":%"PRIu64",\"selected_scale\":null,\"normalized_occupancy\":null,\"settlement_proven\":false}\n",polls,record_seq);
    return commit()?0:2;
}
int main(int argc,char **argv) {
    if(argc==1) {puts("{\"status\":\"SOURCE_ONLY_PLAN_NO_NATIVE_WORK\",\"cases\":[\"order-12\",\"order-21\"],\"stages\":4,\"live_references\":5,\"unit_selection\":false}");return 0;}
    if(argc!=4 || strcmp(argv[1],"--run") || (strcmp(argv[2],"order-12") && strcmp(argv[2],"order-21")) ||
       !getenv("A193_NATIVE_ACK") || strcmp(getenv("A193_NATIVE_ACK"),"A193_WORKER_CPU_ROOT_ONLY") ||
       !getenv("A193_SOURCE_SHA256") || strcmp(getenv("A193_SOURCE_SHA256"),A193_SOURCE_ID))return 2;
    if(mach_timebase_info(&tb)!=KERN_SUCCESS || !tb.numer || !tb.denom)return 2;
    if(mkdir(argv[3],0700))return 2;
    char path[PATH_MAX];if(snprintf(path,sizeof(path),"%s/raw.jsonl",argv[3])>=(int)sizeof(path))return 2;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return 2;
    logfile=fdopen(fd,"w");if(!logfile){close(fd);return 2;}
    int directory=open(argv[3],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(directory<0){fclose(logfile);return 2;}
    int outer=openat(directory,"..",O_RDONLY|O_DIRECTORY);
    bool persisted=outer>=0 && fsync(directory)==0 && fsync(outer)==0;
    if(outer>=0)close(outer);close(directory);
    if(!persisted){fclose(logfile);return 2;}
    int down[2],up[2];if(!pipe_pair(down)){fclose(logfile);return 2;}
    if(!pipe_pair(up)){close(down[0]);close(down[1]);fclose(logfile);return 2;}
    parent_pid=getpid();worker_pid=fork();
    if(worker_pid<0){fclose(logfile);return 2;}
    if(!worker_pid) {
        fclose(logfile);logfile=NULL;close(down[1]);close(up[0]);
        int code=worker(down[0],up[1],strcmp(argv[2],"order-12")==0?1:2);
        close(down[0]);close(up[1]);_exit(code);
    }
    close(down[0]);close(up[1]);int result=parent(up[0],down[1],argv[2]);
    /* On first failure close owned IPC; never signal, retry or guess that the
     * worker has terminated. Its bounded receive/work path sees EOF/EPIPE. */
    close(up[0]);close(down[1]);if(fclose(logfile) && result==0)result=2;return result;
}
