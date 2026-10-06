"""Read-only A181 completion binding followed by unchanged A189 hypotheses.

No arguments read no actual data. --review requires the frozen adapter digest
and root's explicit frontier-pass acknowledgement. Output remains private and
unqualified; all five cases must bind before either positive calculation runs.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
A189 = HERE.parents[1]
A181 = A189.parent / "a181-native-parent-handshake-gate"
A189_MANIFEST = "96e3b5ad3bc50bc4e12c64d3f2afafe80741d7b13bfe14097a2d014be4821ca2"
A181_SOURCE = "44ba04f2064d918ef70fc294ad3cbd719c7e1092ca789f53cc429f345c86259c"
A181_ARTIFACT = "6aa8a81d9d477200ae2237239a0e20d46d4784b17631072bc0695e3e7752f447"
CALCULATOR = "567471ca579ac093948f1040ce21f547547a822d755b0e4e1c11682b93abc9c3"
FIXTURE = A181 / "build-artifacts/fixture-compile-r1/a181-fixture"
COLLECTOR = A181 / "build-artifacts/collector-compile-r1/a181-collector"
FIXTURE_HASH = "376fd3693e543a5702471d551b1e296865f4b37cd9a3bd5b429581ea960d6393"
COLLECTOR_HASH = "f534b2ce770a01f2303be2bf035c4593c5cd9cd6a195912270b5a90e3b725377"
CASES = ("order-12", "order-21", "wrong-birth", "early-reap", "descendant")
STATUS = {
    case: "RAW_LIFECYCLE_CONSISTENT"
    if case.startswith("order-")
    else "UNSUPPORTED_DESCENDANT_OBSERVED"
    if case == "descendant"
    else "EXPECTED_REFUSAL_OBSERVED"
    for case in CASES
}
NAMES = (
    "launch.json",
    "child.json",
    "parent-reaped.json",
    "exit.json",
    "validation.json",
    "native/lifecycle.jsonl",
    "native/raw.jsonl",
    "stdout.log",
    "stderr.log",
    "native/collector.stdout",
    "native/collector.stderr",
)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def eq(a, b):
    need(type(a) is type(b), "strict type mismatch")
    if isinstance(b, dict):
        need(a.keys() == b.keys(), "field coverage")
        for key in b:
            eq(a[key], b[key])
    elif isinstance(b, (list, tuple)):
        need(len(a) == len(b), "sequence coverage")
        for x, y in zip(a, b):
            eq(x, y)
    else:
        need(a == b, "value mismatch")


def integer(x, low=0):
    need(type(x) is int and low <= x < 2**64, "integer type/range")
    return x


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse(data, lines=False):
    need(type(data) is bytes, "captured bytes")
    options = dict(
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )
    if lines:
        need(data.endswith(b"\n"), "truncated JSONL")
        return [json.loads(line, **options) for line in data.splitlines()]
    return json.loads(data, **options)


def private(path, directory=False):
    need(path.is_absolute(), "absolute evidence path")
    for x in (path, *path.parents):
        need(not x.is_symlink(), "symlink evidence ancestry")
    info = path.stat()
    need(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
        "evidence type",
    )
    eq(stat.S_IMODE(info.st_mode), 0o700 if directory else 0o600)
    eq(info.st_uid, os.getuid())
    if not directory:
        eq(info.st_nlink, 1)


def read_private(path):
    private(path.parent, True)
    private(path)
    return path.read_bytes()


def manifest(path, expected):
    data = path.read_bytes()
    eq(sha(data), expected)
    value = parse(data)
    seen = set()
    captured = {}
    for row in value["files"]:
        eq(set(row), {"path", "sha256"})
        name = row["path"]
        need(
            type(name) is str and Path(name).name == name and name not in seen,
            "manifest leaf path",
        )
        seen.add(name)
        blob = (path.parent / name).read_bytes()
        eq(sha(blob), row["sha256"])
        captured[name] = blob
    return data, captured


def source_binding():
    _, old = manifest(A189 / "MANIFEST.json", A189_MANIFEST)
    eq(sha(old["calculate.py"]), CALCULATOR)
    evidence = parse(old["SOURCE_EVIDENCE.json"])
    source_hashes = {}
    for row in evidence["inputs"]:
        path = Path(row["path"])
        eq(str(path.resolve()), row["resolved_path"])
        data = path.read_bytes()
        eq(sha(data), row["sha256"])
        source_hashes[str(path)] = sha(data)
        text = data.decode().splitlines()
        for section in row["intervals"]:
            first, last = section["first"], section["last"]
            integer(first, 1)
            integer(last, first)
            need(last <= len(text), "source excerpt range")
            eq("\n".join(text[first - 1 : last]), section["text"])
    _, a181 = manifest(A181 / "SOURCE_MANIFEST.json", A181_SOURCE)
    manifest(A181 / "ARTIFACT_MANIFEST.json", A181_ARTIFACT)
    eq((A181 / "SOURCE_DIGEST.txt").read_bytes(), (A181_SOURCE + "\n").encode())
    eq(
        (A181 / "source_identity.h").read_bytes(),
        ('#define A181_SOURCE_ID "' + A181_SOURCE + '"\n').encode(),
    )
    for row in parse(a181["SOURCE_PINS.json"])["inputs"]:
        data = Path(row["path"]).read_bytes()
        eq(sha(data), row["sha256"])
        source_hashes[row["path"]] = sha(data)
    return dict(
        a189_manifest=A189_MANIFEST,
        a181_source=A181_SOURCE,
        a181_artifact=A181_ARTIFACT,
        calculator_sha256=CALCULATOR,
        pinned_inputs=source_hashes,
    )


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def frozen_functions():
    for name in ("replay", "lifecycle_core", "protocol", "raw_check"):
        if name in sys.modules:
            need(
                Path(sys.modules[name].__file__).resolve().parent == A181,
                "foreign frozen-replay module collision",
            )
    sys.path.insert(0, str(A181))
    replay = module("a189_bound_a181_replay", A181 / "replay.py")
    calculator = module("a189_bound_calculator", A189 / "calculate.py")
    return replay.verify, calculator.calculate


def utc(value):
    need(type(value) is str, "UTC type")
    result = datetime.fromisoformat(value)
    need(
        result.tzinfo is not None and result.utcoffset().total_seconds() == 0,
        "aware UTC",
    )
    return result


def check_case(case, data, replay):
    eq(set(data), set(NAMES))
    hashes = {name: sha(blob) for name, blob in data.items()}
    launch, child, reaped, terminal, saved = (parse(data[name]) for name in NAMES[:5])
    records = parse(data["native/lifecycle.jsonl"], True)
    raw = parse(data["native/raw.jsonl"], True)
    run = A181 / "runs" / case
    command = [str(FIXTURE), "--run", case, str(COLLECTOR), str(run / "native")]
    eq(
        launch,
        dict(
            schema="a181.launch.v1",
            case=case,
            command=command,
            source_id=A181_SOURCE,
            binary_sha256=FIXTURE_HASH,
            collector_binary_sha256=COLLECTOR_HASH,
            prepared_utc=launch["prepared_utc"],
            root_exclusive_assertion=True,
            os_membership_attested=False,
        ),
    )
    pid = integer(child["pid"], 1)
    eq(
        child,
        dict(
            schema="a181.child.v1",
            pid=pid,
            started_utc=child["started_utc"],
            command=command,
            source_id=A181_SOURCE,
        ),
    )
    eq(
        reaped,
        dict(
            schema="a181.parent-reaped.v1",
            pid=pid,
            ended_utc=reaped["ended_utc"],
            exit_code=0,
            source_id=A181_SOURCE,
        ),
    )
    eq(
        terminal,
        dict(
            schema="a181.exit.v1",
            pid=pid,
            ended_utc=terminal["ended_utc"],
            exit_code=0,
            source_id=A181_SOURCE,
            binary_sha256=FIXTURE_HASH,
            collector_binary_sha256=COLLECTOR_HASH,
            fixture_binary_unchanged=True,
            collector_binary_unchanged=True,
            source_unchanged=True,
            errors=[],
        ),
    )
    stamps = [
        utc(launch["prepared_utc"]),
        utc(child["started_utc"]),
        utc(reaped["ended_utc"]),
        utc(terminal["ended_utc"]),
    ]
    need(stamps == sorted(stamps), "prepared/start/reaped/terminal chronology")
    need(stamps[-1] <= datetime.now(timezone.utc), "future terminal metadata")
    for name in NAMES[7:]:
        eq(data[name], b"")
    eq(records[0]["parent_pid"], pid)
    fresh = replay(records, raw, case, A181_SOURCE)
    eq(fresh["status"], STATUS[case])
    eq(fresh["collector_qualified"], False)
    fresh.update(
        fixture_binary_sha256=FIXTURE_HASH,
        collector_binary_sha256=COLLECTOR_HASH,
        parent_pid=pid,
        parent_exit_code=0,
        lifecycle_sha256=hashes["native/lifecycle.jsonl"],
        raw_sha256=hashes["native/raw.jsonl"],
        source_id=A181_SOURCE,
        launch_sha256=hashes["launch.json"],
        child_sha256=hashes["child.json"],
        exit_sha256=hashes["exit.json"],
        parent_reaped_sha256=hashes["parent-reaped.json"],
    )
    eq(saved, fresh)
    ready = records[1]
    return (
        dict(
            case=case,
            status=fresh["status"],
            files_sha256=hashes,
            prepared_utc=launch["prepared_utc"],
            terminal_utc=terminal["ended_utc"],
            parent_pid=pid,
            worker_pid=ready["pid"],
            worker_birth_abs=ready["birth_abs"],
            lifecycle_records=len(records),
            raw_records=len(raw),
            collector_qualified=False,
        ),
        records,
        raw,
    )


def collect_case(case):
    path = A181 / "runs" / case
    private(path, True)
    private(path / "native", True)
    for name in ("interrupted.json", "validation-rejected.json"):
        marker = path / name
        need(
            not marker.is_symlink() and not marker.exists(),
            "failure marker refuses sequence",
        )
    return {name: read_private(path / name) for name in NAMES}


def bind_sequence(all_data, replay):
    eq(tuple(all_data), CASES)
    summaries = []
    bound = {}
    prior = None
    identities = set()
    for case in CASES:
        summary, records, raw = check_case(case, all_data[case], replay)
        if prior is not None:
            need(
                prior <= utc(summary["prepared_utc"]),
                "overlapping/reordered fixed sequence",
            )
        prior = utc(summary["terminal_utc"])
        identity = (
            integer(summary["worker_pid"], 1),
            integer(summary["worker_birth_abs"], 1),
        )
        need(identity not in identities, "reused worker identity")
        identities.add(identity)
        summaries.append(summary)
        bound[case] = (records, raw)
    return summaries, bound


def save(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def review(expected_adapter):
    adapter_bytes, _ = manifest(HERE / "ADAPTER_MANIFEST.json", expected_adapter)
    sources = source_binding()
    for path, expected in ((FIXTURE, FIXTURE_HASH), (COLLECTOR, COLLECTOR_HASH)):
        for part in (path, *path.parents):
            need(not part.is_symlink(), "binary symlink ancestry")
        need(path.is_file(), "actual binary file")
        eq(sha(path.read_bytes()), expected)
    replay, calculate = frozen_functions()
    all_data = {case: collect_case(case) for case in CASES}
    summaries, bound = bind_sequence(all_data, replay)
    # Complete binding is persisted independently of later hypothesis admissibility.
    eq(source_binding(), sources)
    eq(sha(FIXTURE.read_bytes()), FIXTURE_HASH)
    eq(sha(COLLECTOR.read_bytes()), COLLECTOR_HASH)
    save(
        HERE / "BOUND_SEQUENCE.json",
        dict(
            schema="a189.bound-a181-sequence.v1",
            adapter_manifest_sha256=sha(adapter_bytes),
            sources=sources,
            case_bindings=summaries,
            collector_qualified=False,
        ),
    )
    save(
        HERE / "CAPTURED_INPUT_BYTES.json",
        dict(
            schema="a189.exact-input-bytes.v1",
            encoding="base64",
            cases={
                case: {
                    name: base64.b64encode(data).decode()
                    for name, data in files.items()
                }
                for case, files in all_data.items()
            },
        ),
    )
    results = {}
    # No calculation until the complete five-case binding above succeeds.
    for case in CASES[:2]:
        receipt = dict(
            source_id=A181_SOURCE,
            case=case,
            native_exit_zero=True,
            source_binary_envelope_verified=True,
            a181_replay_pass=True,
            fixed_a181_sequence_complete=True,
        )
        save(
            HERE / (case + "-calculation-started.json"),
            dict(
                case=case,
                calculator_sha256=CALCULATOR,
                receipt=receipt,
                collector_qualified=False,
            ),
        )
        try:
            results[case] = calculate(receipt, *bound[case])
        except Exception as error:
            raise ValueError(
                "unchanged calculator refused " + case + ": " + repr(error)
            ) from error
        eq(results[case]["collector_qualified"], False)
        eq(results[case]["selected_scale"], None)
        eq(results[case]["normalized_occupancy"], None)
    # Source or binary mutations during replay remain a first refusal.
    eq(source_binding(), sources)
    eq(sha(FIXTURE.read_bytes()), FIXTURE_HASH)
    eq(sha(COLLECTOR.read_bytes()), COLLECTOR_HASH)
    return dict(
        schema="a189.observed-data-adapter.v1",
        status="BOUND_ACTUAL_A181_CONDITIONAL_HYPOTHESES",
        adapter_manifest_sha256=sha(adapter_bytes),
        sources=sources,
        case_bindings=summaries,
        results=results,
        actual_record_consistency=True,
        os_membership_attested=False,
        actual_cpu_units_justified=False,
        counter_errors_justified=False,
        settlement_proven=False,
        normalized_occupancy=None,
        selected_scale=None,
        collector_qualified=False,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--review", action="store_true")
    p.add_argument("--expected-adapter-sha256")
    p.add_argument("--frontier-pass-ack")
    args = p.parse_args()
    if not args.review:
        print(
            json.dumps(
                dict(
                    status="FROZEN_ADAPTER_PLAN_NO_ACTUAL_READ",
                    cases=CASES,
                    collector_qualified=False,
                )
            )
        )
        return 0
    need(
        args.frontier_pass_ack == "A189_ROOT_CONFIRMED_FRONTIER_PASS",
        "explicit root frontier-pass notice required",
    )
    need(
        type(args.expected_adapter_sha256) is str
        and len(args.expected_adapter_sha256) == 64,
        "frozen adapter identity",
    )
    private(HERE, True)
    for name in (
        "REVIEW_STARTED.json",
        "BOUND_SEQUENCE.json",
        "ACTUAL_REPORT.json",
        "REJECTED.json",
    ):
        path = HERE / name
        need(
            not path.is_symlink() and not path.exists(),
            "one frozen first review; preserve first outcome",
        )
    save(
        HERE / "REVIEW_STARTED.json",
        dict(
            expected_adapter_sha256=args.expected_adapter_sha256,
            root_frontier_ack=args.frontier_pass_ack,
            started_utc=datetime.now(timezone.utc).isoformat(),
            collector_qualified=False,
        ),
    )
    try:
        result = review(args.expected_adapter_sha256)
    except Exception as error:
        save(
            HERE / "REJECTED.json",
            dict(
                status="REJECTED_FIRST_ADAPTER_REVIEW",
                error=repr(error),
                collector_qualified=False,
            ),
        )
        print("A189 observed adapter rejected; preserve the first result.")
        return 1
    save(HERE / "ACTUAL_REPORT.json", result)
    summary = dict(
        status=result["status"],
        cases=[
            dict(
                case=x["case"],
                status=x["status"],
                lifecycle_records=x["lifecycle_records"],
                raw_records=x["raw_records"],
            )
            for x in result["case_bindings"]
        ],
        positive_calculations=list(result["results"]),
        collector_qualified=False,
        selected_scale=None,
        normalized_occupancy=None,
        settlement_proven=False,
        report_sha256=sha((HERE / "ACTUAL_REPORT.json").read_bytes()),
    )
    save(HERE / "SUMMARY.json", summary)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
