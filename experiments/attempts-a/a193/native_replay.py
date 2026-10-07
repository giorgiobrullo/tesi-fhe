"""Independent captured-record protocol replay. No native calls or unit selection."""
import json
import sys
from fractions import Fraction
import model

sys.dont_write_bytecode = True
MAGIC = 0x4131393343505531
FRAME = 504
KINDS = dict(ready=1, request=2, reply=3, receipt=4, release=5, stage=6)


def need(value, why):
    if not value:
        raise ValueError(why)


def eq(a, b, why):
    need(type(a) is type(b), why + " type")
    if isinstance(a, dict):
        need(a.keys() == b.keys(), why + " keys")
        for k in a:
            eq(a[k], b[k], why + "." + k)
    elif isinstance(a, (tuple, list)):
        need(len(a) == len(b), why + " length")
        for x, y in zip(a, b):
            eq(x, y, why)
    else:
        need(a == b, why)


def obj(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()), "exact fields")


def uint(x, minimum=0):
    need(type(x) is int and minimum <= x <= 2**64 - 1, "unsigned integer")
    return x


def parse(data):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate JSON field")
            out[key] = value
        return out
    def bad(_):
        raise ValueError("nonfinite JSON")
    def no_float(_):
        raise ValueError("native records contain no floats")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad, parse_float=no_float)


def records(data):
    need(data.endswith(b"\n"), "complete final newline")
    result = [parse(line) for line in data.splitlines()]
    need(1 <= len(result) <= 342, "bounded raw shape")
    for i, row in enumerate(result):
        need(type(row) is dict, "record object")
        eq(row.get("seq"), i, "record sequence")
    return result


def cmodel(c):
    return model.Clock(**{k: c[k] for k in model.Clock.__dataclass_fields__})


def umodel(u):
    return model.Usage(**{k: u[k] for k in model.Usage.__dataclass_fields__})


def replay(rows, case, source_id, actual_parent, exit_code):
    need(case in ("order-12", "order-21"), "fixed case")
    need(rows, "nonempty records")
    for i, row in enumerate(rows):
        eq(row.get("seq"), i, "sequence")
    start = rows[0]
    obj(start, "kind seq schema case source_id parent_pid worker_pid numer denom frame_bytes selected_scale normalized_occupancy")
    expected = dict(kind="start", seq=0, schema="a193.worker_clock.v1", case=case,
                    source_id=source_id, parent_pid=actual_parent,
                    worker_pid=uint(start["worker_pid"], 1), numer=uint(start["numer"], 1),
                    denom=uint(start["denom"], 1), frame_bytes=FRAME,
                    selected_scale=None, normalized_occupancy=None)
    eq(start, expected, "start identity")
    worker = start["worker_pid"]
    need(worker != actual_parent, "separate direct worker")
    need(start["numer"] < 2**32 and start["denom"] < 2**32, "timebase width")
    ticks = lambda ns: (ns * start["denom"] + start["numer"] - 1) // start["numer"]
    failures = [r for r in rows if r.get("kind") == "first_failure"]
    if failures:
        eq(exit_code, 1, "first-failure native exit")
        need(len(failures) == 1 and rows[-1] is failures[0], "terminal first failure")
        f = failures[0]
        obj(f, "kind seq where worker_pid worker_state io frame_hex")
        eq(f["worker_pid"], worker, "failure worker")
        eq(f["worker_state"], "UNKNOWN_NO_SIGNAL_SENT", "failure scope")
        need(type(f["where"]) is str and f["where"], "failure location")
        need(type(f["frame_hex"]) is str and len(f["frame_hex"]) == 2 * FRAME, "captured failure frame")
        need(len(bytes.fromhex(f["frame_hex"])) == FRAME, "failure bytes")
        return dict(status="RECORDED_BOUND_FIRST_FAILURE", gate_pass=False,
                    records=len(rows), worker_pid=worker, native_exit=exit_code,
                    first_failure=f["where"], prefix_semantics_qualified=False,
                    worker_terminal_attested=False, selected_scale=None,
                    normalized_occupancy=None, collector_qualified=False)
    eq(exit_code, 0, "complete native exit")
    index = 1
    def take(kind, fields):
        nonlocal index
        need(index < len(rows), "incomplete schedule")
        row = rows[index]
        obj(row, "kind seq " + fields)
        eq(row["kind"], kind, "record order")
        index += 1
        return row
    def bracket(value):
        uint(value["begin_abs"]); uint(value["end_abs"])
        need(value["begin_abs"] <= value["end_abs"], "ordered acquisition")
    def clock(c, clock_id=12, tid=0):
        obj(c, "caller_pid caller_tid clock_id begin_abs end_abs seconds nanoseconds status errno")
        eq(c["caller_pid"], worker, "actual calling process")
        eq(c["caller_tid"], tid, "actual calling thread")
        eq(c["clock_id"], clock_id, "actual CPU clock ID")
        eq(c["status"], 0, "clock success"); eq(c["errno"], 0, "clock errno")
        bracket(c)
        uint(c["seconds"]); uint(c["nanoseconds"])
        need(c["nanoseconds"] < 10**9, "timespec range")
        return c["seconds"] * 10**9 + c["nanoseconds"]
    birth = None
    def usage(u, terminal=False):
        obj(u, "pid begin_abs end_abs user_raw system_raw birth_abs exit_abs status errno")
        eq(u["pid"], worker, "usage exact worker")
        eq(u["birth_abs"], birth, "usage same birth")
        eq(u["status"], 0, "V0 success"); eq(u["errno"], 0, "V0 errno")
        bracket(u)
        uint(u["user_raw"]); uint(u["system_raw"]); uint(u["exit_abs"])
        need(birth <= u["begin_abs"], "birth precedes acquisition")
        if terminal:
            need(birth <= u["exit_abs"] <= u["begin_abs"] and u["exit_abs"] > 0, "terminal identity")
        else:
            eq(u["exit_abs"], 0, "live identity")
    def frame(kind, sequence, step, pc, tc, fields):
        row = take(kind, "io header " + fields)
        h = row["header"]
        obj(h, "magic version bytes kind sequence step parent_pid worker_pid birth_abs sent_abs process_clock_calls thread_clock_calls")
        want = dict(magic=MAGIC, version=1, bytes=FRAME, kind=KINDS[kind], sequence=sequence,
                    step=step, parent_pid=actual_parent, worker_pid=worker, birth_abs=birth,
                    sent_abs=uint(h["sent_abs"]), process_clock_calls=pc, thread_clock_calls=tc)
        eq(h, want, "frame header")
        io = row["io"]
        obj(io, "begin_abs end_abs deadline_abs bytes errno eof")
        bracket(io); eq(io["deadline_abs"], io["begin_abs"] + ticks(15*10**9), "fixed transfer deadline")
        eq(io["bytes"], FRAME, "complete frame"); eq(io["errno"], 0, "IPC errno"); eq(io["eof"], False, "no EOF")
        need(h["sent_abs"] <= io["end_abs"] <= io["deadline_abs"], "bounded IPC")
        if kind in ("reply", "release"):
            need(io["begin_abs"] <= h["sent_abs"], "parent send contained")
        return row
    need(index < len(rows), "ready exists")
    birth = uint(rows[index].get("header", {}).get("birth_abs"), 1)
    ready = frame("ready", 0, 0, 0, 0, "identity resolutions")
    usage(ready["identity"])
    eq(len(ready["resolutions"]), 2, "two getres calls")
    end = ready["identity"]["end_abs"]
    for c, cid in zip(ready["resolutions"], [12, 16]):
        clock(c, cid)
        need(end <= c["begin_abs"], "ready call order")
        end = c["end_abs"]
    need(end <= ready["header"]["sent_abs"], "ready completed before send")
    tc = 0; boundaries = []; stages = []; previous_cpu = 0
    prior_worker_end = ready["header"]["sent_abs"]
    for step in range(5):
        request = frame("request", 3*step+1, step, 4*step+1, tc, "before")
        before = request["before"]; before_ns = clock(before)
        need(prior_worker_end <= before["begin_abs"], "worker program order")
        need(previous_cpu <= before_ns, "represented process monotonicity")
        need(before["end_abs"] <= request["header"]["sent_abs"], "S0 before request")
        reads=[]; end=request["io"]["end_abs"]
        for j in range(2):
            row=take("live_usage", "step index usage")
            eq(row["step"],step,"live step"); eq(row["index"],j,"live index")
            usage(row["usage"]); need(end <= row["usage"]["begin_abs"], "parent V0 order")
            reads.append(row["usage"]); end=reads[-1]["end_abs"]
        reply=frame("reply",2*step,step,4*step+1,tc,"before reads")
        eq(reply["before"],before,"reply S0"); eq(reply["reads"],reads,"reply exact acquisitions")
        need(end <= reply["io"]["begin_abs"], "reads before reply send")
        receipt=frame("receipt",3*step+2,step,4*step+2,tc,"before reads after")
        eq(receipt["before"],before,"receipt S0"); eq(receipt["reads"],reads,"receipt actual reads")
        after=receipt["after"]; after_ns=clock(after)
        need(reply["header"]["sent_abs"] <= after["begin_abs"] and after["end_abs"] <= receipt["header"]["sent_abs"], "reply S1 receipt causality")
        need(before_ns <= after_ns, "reference monotonicity")
        release=frame("release",2*step+1,step,4*step+2,tc,"before reads after")
        for key in ("before","reads","after"):
            eq(release[key],receipt[key],"release full receipt")
        need(receipt["io"]["end_abs"] <= release["io"]["begin_abs"], "durable receipt precedes release")
        # Raw-counter compatibility is reported, never selected as a structural gate.
        try:
            comparison=model.compare_live(worker,birth,cmodel(before),[umodel(u) for u in reads],cmodel(after),start["numer"],start["denom"])
        except ValueError as error:
            comparison={"status":"CONDITIONAL_MODEL_INAPPLICABLE", "reason":str(error), "selected_scale":None}
        boundaries.append(comparison)
        previous_cpu=after_ns; prior_worker_end=release["header"]["sent_abs"]
        if step < 4:
            threads=[0,int(case[-2]),0,int(case[-1])][step]
            tc += 2*threads
            row=frame("stage",3*step+3,step,4*step+4,tc,"stage")
            s=row["stage"]
            obj(s,"threads sleep_calls begin_abs end_abs deadline_abs process threads_data")
            eq(s["threads"],threads,"registered busy threads"); uint(s["sleep_calls"])
            eq(len(s["process"]),2,"two stage process reads"); eq(len(s["threads_data"]),threads,"all actual busy threads")
            c0,c1=s["process"]; cpu0,cpu1=clock(c0),clock(c1)
            bracket(s)
            need(previous_cpu <= cpu0 <= cpu1,"stage represented process monotonicity")
            need(prior_worker_end <= c0["begin_abs"] <= c0["end_abs"] <= s["begin_abs"],"release before stage")
            eq(s["deadline_abs"],s["begin_abs"]+ticks(2*10**9),"registered stage deadline")
            need(s["deadline_abs"] <= s["end_abs"] <= c1["begin_abs"] <= c1["end_abs"] <= row["header"]["sent_abs"],"stage completed before event")
            tids=[]
            for slot,t in enumerate(s["threads_data"]):
                obj(t,"slot thread_id_status iterations checksum clocks")
                eq(t["slot"],slot,"thread slot"); eq(t["thread_id_status"],0,"own thread ID API")
                uint(t["iterations"],1); uint(t["checksum"])
                eq(len(t["clocks"]),2,"own thread bracket")
                a,b=t["clocks"]; tid=uint(a["caller_tid"],1); tids.append(tid)
                need(clock(a,16,tid) <= clock(b,16,tid),"thread represented CPU monotonicity")
                need(s["begin_abs"] <= a["begin_abs"] <= a["end_abs"] <= b["begin_abs"] <= b["end_abs"] <= s["end_abs"],"thread calls contained in actual stage")
                need(a["end_abs"] <= s["deadline_abs"] <= b["begin_abs"],"positive busy work crosses deadline")
            need(len(set(tids))==threads,"distinct simultaneous busy TIDs")
            if threads:
                eq(s["sleep_calls"],0,"busy no sleep calls")
            # A sleep stage can be preempted across its full deadline before its
            # first sleep call. Its exact observed call count remains diagnostic.
            stages.append(model.stage_cpu(worker,cmodel(c0),cmodel(c1)))
            prior_worker_end=row["header"]["sent_abs"];previous_cpu=cpu1
    polls=[]; end=release["io"]["end_abs"]; wait_deadline=None
    while index<len(rows) and rows[index].get("kind")=="wait_poll":
        p=take("wait_poll","poll begin_abs end_abs deadline_abs status errno pid si_code si_status")
        eq(p["poll"],len(polls),"poll index"); bracket(p)
        need(end <= p["begin_abs"],"ordered wait calls")
        if wait_deadline is None:
            wait_deadline=uint(p["deadline_abs"])
            need(p["begin_abs"] <= wait_deadline <= p["begin_abs"]+ticks(15*10**9),"bounded WNOWAIT acquisition")
        eq(p["deadline_abs"],wait_deadline,"one original wait deadline")
        need(p["end_abs"]<=wait_deadline,"WNOWAIT deadline")
        eq(p["status"],0,"waitid status"); eq(p["errno"],0,"waitid errno")
        uint(p["pid"]);uint(p["si_code"]);uint(p["si_status"])
        polls.append(p);end=p["end_abs"]
    need(1<=len(polls)<=301,"bounded actual wait count")
    for p in polls[:-1]:
        eq([p["pid"],p["si_code"],p["si_status"]],[0,0,0],"no earlier terminal notice")
    eq([polls[-1]["pid"],polls[-1]["si_code"],polls[-1]["si_status"]],[worker,1,0],"exact exited child WNOWAIT")
    terminal=[]
    for j in range(2):
        t=take("terminal_usage","index usage");eq(t["index"],j,"terminal index");usage(t["usage"],True)
        need(end<=t["usage"]["begin_abs"],"whole terminal read after waitable notice")
        need(t["usage"]["exit_abs"] <= polls[-1]["end_abs"],"observed exit before WNOWAIT completion")
        terminal.append(t["usage"]);end=t["usage"]["end_abs"]
    eq(terminal[0]["exit_abs"],terminal[1]["exit_abs"],"same terminal birth/exit identity")
    r=take("reaped","pid status errno begin_abs end_abs user_timeval system_timeval includes_children_scope")
    bracket(r);need(end<=r["begin_abs"],"terminal captures before reap")
    eq(r["pid"],worker,"reaped exact child");eq(r["status"],0,"zero wait status");eq(r["errno"],0,"wait4 errno")
    eq(r["includes_children_scope"],True,"wait4 scope")
    for key in ("user_timeval","system_timeval"):
        need(type(r[key]) is list and len(r[key])==2,"timeval shape")
        uint(r[key][0]);uint(r[key][1]);need(r[key][1]<10**6,"timeval microseconds")
    summary=take("summary","status worker_process_clock_reads worker_thread_clock_reads worker_clock_getres_calls thread_id_calls worker_identity_v0_reads parent_live_v0_reads parent_terminal_v0_reads waitid_calls wait4_calls records selected_scale normalized_occupancy settlement_proven")
    eq(summary,dict(kind="summary",seq=index-1,status="A193_NATIVE_SEQUENCE_COMPLETE",worker_process_clock_reads=18,worker_thread_clock_reads=6,worker_clock_getres_calls=2,thread_id_calls=3,worker_identity_v0_reads=1,parent_live_v0_reads=10,parent_terminal_v0_reads=2,waitid_calls=len(polls),wait4_calls=1,records=40+len(polls),selected_scale=None,normalized_occupancy=None,settlement_proven=False),"exact completed ledger")
    eq(index,len(rows),"no trailing records");eq(len(rows),40+len(polls),"observed P-dependent cardinality")
    return dict(status="PASS_BOUND_WORKER_CLOCK_PROTOCOL",gate_pass=True,records=len(rows),
                case=case,worker_pid=worker,birth_abs=birth,counts={k:v for k,v in summary.items() if k not in ("kind","seq","status","selected_scale","normalized_occupancy","settlement_proven")},
                live_comparisons=boundaries,stage_observations=stages,
                terminal_raw_counter_pairs=[[u["user_raw"],u["system_raw"]] for u in terminal],
                terminal_counters_settled=False,selected_scale=None,normalized_occupancy=None,
                collector_qualified=False,accounting_equivalence_proven=False,
                reference_measurement_error_bound_ns=None,
                timebase_ns_per_tick=[Fraction(start["numer"],start["denom"]).numerator,Fraction(start["numer"],start["denom"]).denominator])
