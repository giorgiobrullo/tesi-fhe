"""Small synthetic source-protocol fixtures; no native clock or process calls."""

from copy import deepcopy
import native_replay as replay

PARENT = 100
WORKER = 101
BIRTH = 50
SOURCE = "a" * 64


class Builder:
    def __init__(self):
        self.rows = []
        self.ticks = 1000
        self.cpu = 100

    def tick(self):
        self.ticks += 10
        return self.ticks

    def add(self, kind, **fields):
        row = dict(kind=kind, seq=len(self.rows), **deepcopy(fields))
        self.rows.append(row)
        return row

    def clock(self, clock_id=12, tid=0, resolution=False):
        self.cpu += 10
        value = 1 if resolution else self.cpu
        return dict(caller_pid=WORKER, caller_tid=tid, clock_id=clock_id,
                    begin_abs=self.tick(), end_abs=self.tick(),
                    seconds=value // 10**9, nanoseconds=value % 10**9,
                    status=0, errno=0)

    def usage(self, exit_abs=0):
        return dict(pid=WORKER, begin_abs=self.tick(), end_abs=self.tick(),
                    user_raw=12345, system_raw=6789, birth_abs=BIRTH,
                    exit_abs=exit_abs, status=0, errno=0)

    def frame(self, kind, sequence, step, pc, tc, **fields):
        begin = self.tick()
        sent = self.tick()
        end = self.tick()
        header = dict(magic=replay.MAGIC, version=1, bytes=replay.FRAME,
                      kind=replay.KINDS[kind], sequence=sequence, step=step,
                      parent_pid=PARENT, worker_pid=WORKER, birth_abs=BIRTH,
                      sent_abs=sent, process_clock_calls=pc, thread_clock_calls=tc)
        io = dict(begin_abs=begin, end_abs=end, deadline_abs=begin + 15*10**9,
                  bytes=replay.FRAME, errno=0, eof=False)
        return self.add(kind, io=io, header=header, **fields)


def complete(case="order-12"):
    b = Builder()
    b.add("start", schema="a193.worker_clock.v1", case=case, source_id=SOURCE,
          parent_pid=PARENT, worker_pid=WORKER, numer=1, denom=1,
          frame_bytes=replay.FRAME, selected_scale=None, normalized_occupancy=None)
    identity = b.usage()
    resolutions = [b.clock(12, resolution=True), b.clock(16, resolution=True)]
    b.frame("ready", 0, 0, 0, 0, identity=identity, resolutions=resolutions)
    tc = 0
    for step in range(5):
        before = b.clock()
        b.frame("request", 3*step+1, step, 4*step+1, tc, before=before)
        reads = []
        for index in range(2):
            usage = b.usage()
            reads.append(usage)
            b.add("live_usage", step=step, index=index, usage=usage)
        b.frame("reply", 2*step, step, 4*step+1, tc, before=before, reads=reads)
        after = b.clock()
        b.frame("receipt", 3*step+2, step, 4*step+2, tc,
                before=before, reads=reads, after=after)
        release = b.frame("release", 2*step+1, step, 4*step+2, tc,
                          before=before, reads=reads, after=after)
        if step == 4:
            break
        threads = [0, int(case[-2]), 0, int(case[-1])][step]
        process_start = b.clock()
        begin = b.tick()
        deadline = begin + 2*10**9
        data = []
        for slot in range(threads):
            tid = 1000 + step*10 + slot
            data.append(dict(slot=slot, thread_id_status=0, iterations=2,
                             checksum=99, clocks=[b.clock(16, tid)]))
        b.ticks = deadline
        for thread in data:
            thread["clocks"].append(b.clock(16, thread["clocks"][0]["caller_tid"]))
        end = b.tick()
        process_end = b.clock()
        tc += 2*threads
        b.frame("stage", 3*step+3, step, 4*step+4, tc,
                stage=dict(threads=threads, sleep_calls=0 if threads else 1,
                           begin_abs=begin, end_abs=end, deadline_abs=deadline,
                           process=[process_start, process_end], threads_data=data))
    exit_abs = release["io"]["end_abs"] + 1
    begin = b.tick()
    b.add("wait_poll", poll=0, begin_abs=begin, end_abs=b.tick(),
          deadline_abs=begin + 15*10**9, status=0, errno=0,
          pid=WORKER, si_code=1, si_status=0)
    for index in range(2):
        b.add("terminal_usage", index=index, usage=b.usage(exit_abs))
    b.add("reaped", pid=WORKER, status=0, errno=0,
          begin_abs=b.tick(), end_abs=b.tick(), user_timeval=[0, 100],
          system_timeval=[0, 20], includes_children_scope=True)
    b.add("summary", status="A193_NATIVE_SEQUENCE_COMPLETE",
          worker_process_clock_reads=18, worker_thread_clock_reads=6,
          worker_clock_getres_calls=2, thread_id_calls=3,
          worker_identity_v0_reads=1, parent_live_v0_reads=10,
          parent_terminal_v0_reads=2, waitid_calls=1, wait4_calls=1,
          records=41, selected_scale=None, normalized_occupancy=None,
          settlement_proven=False)
    return b.rows


def first_failure():
    start = complete()[0]
    return [start, dict(kind="first_failure", seq=1, where="ready_receive",
                       worker_pid=WORKER, worker_state="UNKNOWN_NO_SIGNAL_SENT",
                       io={}, frame_hex="00" * replay.FRAME)]
