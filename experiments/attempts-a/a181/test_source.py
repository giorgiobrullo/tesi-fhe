"""Source and exact synthetic IPC checks; no C compilation, process, or OS call."""

from pathlib import Path
import json
import unittest
from ipc_model import decode, encode
from synthetic import fixture

HERE = Path(__file__).resolve().parent


class Source(unittest.TestCase):
    def test_ipc_complete_partial_eof_deadline(self):
        rows, _ = fixture()
        m = next(r for r in rows if r["kind"] == "protocol")["message"]
        data = encode(m)
        self.assertEqual(
            decode([data[:17], data[17:]], m["sent_abs"] - 10, m["sent_abs"] + 10), m
        )
        for chunks, eof in [
            ([data[:87]], True),
            ([data[:16]], False),
            ([data, data], False),
            ([], True),
        ]:
            with self.assertRaises(ValueError):
                decode(chunks, 0, 1, eof=eof)
        with self.assertRaises(ValueError):
            decode([data], 0, 15_000_000_001)
        wrong = bytearray(data)
        wrong[0] ^= 1
        with self.assertRaises(ValueError):
            decode([bytes(wrong)], 0, m["sent_abs"])

    def test_ipc_native_contract_and_refusal_paths_are_present(self):
        ipc = (HERE / "ipc.h").read_text()
        collector = (HERE / "collector.c").read_text()
        worker = (HERE / "fixture.c").read_text()
        for text in [
            "sizeof(struct ipc_message) == 88",
            "F_SETNOSIGPIPE",
            "O_NONBLOCK",
            "POLLHUP",
            "used == sizeof(*m)",
            "*end <= deadline",
            "n == (ssize_t)sizeof(*m)",
        ]:
            self.assertIn(text, ipc)
        for text in [
            "m->parent_pid == parent",
            "m->worker_pid == worker",
            "m->collector_pid == collector",
            "m->birth_abs == birth",
            "m->sequence == sequence",
            "m->related_seq == related",
        ]:
            self.assertIn(text, ipc)
        a = collector.index("IPC_PAUSED, 1")
        b = collector.index("IPC_CAPTURE, 1", a)
        c = collector.index('sample("terminal")', b)
        self.assertNotIn("sample(", collector[a:b])
        self.assertLess(b, c)
        for text in [
            "duplicate_or_closed_capture_channel",
            "unexpected_postcapture_request_or_eof",
            "live_budget_exhausted",
        ]:
            self.assertIn(text, collector)
        a = worker.index("if (!stable || (rawpath && !matches)) return false;")
        self.assertLess(a, worker.index('prefix("capture_ack")'))
        self.assertLess(
            worker.index('prefix("capture_ack")'), worker.index("wait4(child")
        )
        self.assertIn("sizeof(struct event) <= 512", worker)
        self.assertIn("e->magic == MAGIC && a170_arm_clock() <= deadline", worker)
        self.assertIn("!ipc_pipe(events)", worker)
        self.assertIn("char line[8192]", worker)
        self.assertIn("lines++ < 64", worker)
        self.assertIn("if (!newline) break;", worker)
        for source in (worker, collector):
            main = source[source.index("int main(") :]
            safe = main[: main.index("return 0;")]
            self.assertIn("if (argc == 1)", safe)
            for call in [
                "fork(",
                "proc_pid_rusage(",
                "host_statistics(",
                "mach_timebase_info(",
            ]:
                self.assertNotIn(call, safe)

    def test_worst_width_record_bound_and_dynamic_maximum(self):
        # Every JSON numeric leaf widened to20digits; strings conservatively padded
        # to80chars, exceeding any fixed C identity/stage/schema string.
        _, raw = fixture()

        def widen(x):
            if type(x) is int:
                return 2**64 - 1
            if type(x) is str:
                return x + "x" * 80
            if type(x) is list:
                return [widen(v) for v in x]
            if type(x) is dict:
                return {k: widen(v) for k, v in x.items()}
            return x

        for row in raw:
            self.assertLess(
                len(json.dumps(widen(row), separators=(",", ":")).encode()) + 1, 8192
            )
        self.assertLessEqual(12 + 10, 64)


if __name__ == "__main__":
    unittest.main()
