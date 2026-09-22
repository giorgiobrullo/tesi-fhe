"""Measured request spans, using the same OS clock as the native adapter."""
import time


def clock_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


class Timeline:
    # The service lock protects updates and snapshots.
    def __init__(self):
        self.origin_ns = clock_ns()
        self.spans = {}
        self.begin("job", "job", None, self.origin_ns)
        self.begin("queue", "queue", "job", self.origin_ns)

    def begin(self, identifier, kind, parent_id, now=None, *, engine=None):
        span = {"id": identifier, "kind": kind, "parent_id": parent_id,
                "start_ns": clock_ns() if now is None else now, "end_ns": None}
        if engine is not None:
            span["engine"] = engine
        self.spans[identifier] = span

    def end(self, identifier, now=None):
        self.spans[identifier]["end_ns"] = clock_ns() if now is None else now

    def add_phases(self, engine, phases):
        """Import measured native/client intervals only inside their parent."""
        parent = self.spans[engine]
        previous = parent["start_ns"]
        previous_kind = -1
        kinds = ("setup", "encryption", "fhe", "decryption")
        additions = {}
        for phase in phases:
            kind, start, end = phase["kind"], phase["start_ns"], phase["end_ns"]
            identifier = f"{engine}/{kind}"
            if (kind not in kinds or identifier in self.spans
                    or identifier in additions or type(start) is not int or type(end) is not int
                    or not previous <= start <= end <= parent["end_ns"]):
                raise ValueError("Intervallo del motore non valido.")
            position = kinds.index(kind)
            if position <= previous_kind:
                raise ValueError("Ordine delle fasi non valido.")
            additions[identifier] = {"id": identifier, "kind": kind, "engine": engine,
                                     "parent_id": engine, "start_ns": start, "end_ns": end}
            previous = end
            previous_kind = position
        self.spans.update(additions)

    def finish(self, *, error=False):
        now = clock_ns()
        for span in self.spans.values():
            if span["end_ns"] is None:
                span["end_ns"] = now
                if error:
                    span["status"] = "error"

    def snapshot(self):
        end = self.spans["job"]["end_ns"]
        now = clock_ns() if end is None else end
        result = []
        for span in self.spans.values():
            public = {key: value for key, value in span.items() if key not in {"start_ns", "end_ns"}}
            public["start_ms"] = (span["start_ns"] - self.origin_ns) / 1_000_000
            public["end_ms"] = None if span["end_ns"] is None else (span["end_ns"] - self.origin_ns) / 1_000_000
            result.append(public)
        return {"elapsed_ms": (now - self.origin_ns) / 1_000_000, "spans": result}
