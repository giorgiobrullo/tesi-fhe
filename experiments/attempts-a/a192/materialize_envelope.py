"""Adapt only private one-shot envelope identity and staged progression from A187."""

from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a187-padding-precision-runtime-gate"


def main():
    run = (
        (OLD / "run_gate.py")
        .read_text()
        .replace("A187", "A192")
        .replace("a187", "a192")
    )
    run = run.replace("A192_FIRST_N4_AUTHORIZED", "A192_FIXED_N4_AUTHORIZED")
    run = run.replace(
        'RUN = HERE / "runs/first-precision"',
        'def run_path(stage):\n    require(stage in ("n4-smoke", "n4-full"), "fixed stage")\n    return HERE / "runs" / stage',
    )
    run = run.replace(
        '    parser.add_argument("--run", action="store_true")',
        '    parser.add_argument("--run", action="store_true")\n    parser.add_argument("--stage", choices=("n4-smoke", "n4-full"), default="n4-smoke")',
    )
    run = run.replace(
        "    args = parser.parse_args()",
        "    args = parser.parse_args()\n    RUN = run_path(args.stage)",
    )
    begin = run.index('                    suite="first-precision",')
    end = run.index("                    actual_fhe=False,", begin)
    run = (
        run[:begin]
        + """                    stage=args.stage,
                    keysets=3,
                    planned_components=6 if args.stage=="n4-smoke" else 48,
                    records_if_pass=1268 if args.stage=="n4-smoke" else 10130,
"""
        + run[end:]
    )
    run = run.replace(
        "    binding = source_check()",
        "    from verify import predecessor_binding\n    predecessor = predecessor_binding(args.stage)\n    binding = source_check()",
    )
    run = run.replace(
        'command = [str(BINARY), "--run", "--expected-binary-sha256=" + args.binary_sha256]',
        'command = [str(BINARY), "--run", "--stage="+args.stage, "--expected-binary-sha256=" + args.binary_sha256]',
    )
    run = run.replace(
        'schema="a192.a192.first.v1",',
        'schema="a192.stage_envelope.v1",\n        stage=args.stage, predecessor=predecessor,',
    )
    run = run.replace(
        '    require(clearance["matching_workloads"] == [], "root workload clear")',
        """    require(clearance["matching_workloads"] == [], "root workload clear")
    if args.stage == "n4-full":
        require(observed >= datetime.fromisoformat(predecessor["ended_at_utc"]),
                "clearance observation must follow predecessor termination")""",
    )
    (HERE / "run_gate.py").write_text(run)
    verify = (
        (OLD / "verify.py").read_text().replace("A187", "A192").replace("a187", "a192")
    )
    verify = verify.replace(
        'def envelope(run):\n    r.eq(run, b.RUN, "fixed one-shot run path")',
        'def envelope(run, stage):\n    r.eq(run, b.run_path(stage), "fixed one-shot run path")',
    )
    verify = verify.replace(
        'r.eq(p["schema"], "a192.a192.first.v1")',
        'r.eq(p["schema"], "a192.stage_envelope.v1")\n    r.eq(p["stage"],stage)\n    r.eq(p["predecessor"],predecessor_binding(stage),"bound predecessor exact fresh replay")',
    )
    verify = verify.replace(
        '[str(b.BINARY), "--run", "--expected-binary-sha256=" + p["binary_sha256"]]',
        '[str(b.BINARY), "--run", "--stage="+stage, "--expected-binary-sha256=" + p["binary_sha256"]]',
    )
    verify = verify.replace(
        'r.eq(records[1]["child_pid"], c["child_pid"], "raw producer/direct-child PID")',
        'r.need(len(records)>=3,"first complete provenance")\n    r.eq(records[2]["child_pid"], c["child_pid"], "raw producer/direct-child PID")',
    )
    verify = verify.replace(
        "complete changed-precision gate failed; preserve old and new outcomes without retry",
        "fixed expansion stopped at first complete negative; no retry",
    )
    verify = verify.replace(
        "        files_sha256=hashes,",
        '        files_sha256=hashes, stage=stage, predecessor=p["predecessor"],',
    )
    verify = verify.replace(
        'def verify(run):\n    records, binding = envelope(run)\n    result = r.replay(records, binding["binary_sha256"], binding["exit_code"])',
        """def verify(run, stage):
    records, binding = envelope(run, stage)
    forbidden=[h for pair in binding["predecessor"].get("key_hashes",[]) for h in pair]
    result = r.replay(records, binding["binary_sha256"], binding["exit_code"], stage, forbidden_keys=forbidden)""",
    )
    verify = verify.replace(
        '    parser.add_argument("--verify", action="store_true")',
        '    parser.add_argument("--verify", action="store_true")\n    parser.add_argument("--stage", choices=r.STAGES, default="n4-smoke")',
    )
    verify = verify.replace(
        'dict(status="PLAN_ONLY_NO_RAW_READ", run=str(b.RUN), records=211)',
        'dict(status="PLAN_ONLY_NO_RAW_READ", stage=args.stage, run=str(b.run_path(args.stage)), records_if_pass=r.plan(args.stage)["raw_records_if_pass"])',
    )
    verify = verify.replace(
        "result = verify(b.RUN)", "result = verify(b.run_path(args.stage), args.stage)"
    )
    marker = "\ndef main():"
    predecessor = """
def predecessor_binding(stage):
    r.need(stage in r.STAGES,"fixed stage")
    anchor_bytes=(b.HERE/"PASSING_FIRST.json").read_bytes()
    anchor=r.parse(anchor_bytes)
    r.eq(anchor["status"],"INDEPENDENT_VALID_A187_FIRST_PASS")
    r.eq(anchor["gate_pass"],True)
    if stage=="n4-smoke":
        return dict(kind="frozen_A187_first_pass",report_sha256=r.sha_bytes(anchor_bytes),
                    source_id=anchor["source_manifest_sha256"],raw_sha256=anchor["raw_sha256"])
    prior=b.run_path("n4-smoke")
    report=prior/"validation.json"
    b.private(report)
    captured=report.read_bytes()
    saved=r.parse(captured)
    r.eq(saved["gate_pass"],True,"negative predecessor stops expansion")
    fresh=verify(prior,"n4-smoke")
    r.eq(saved,fresh,"saved predecessor equals exact fresh replay")
    return dict(kind="bound_A192_smoke_pass",report_sha256=r.sha_bytes(captured),
                source_id=fresh["source_id"],raw_sha256=fresh["launch_binding"]["files_sha256"]["stdout.jsonl"],
                key_hashes=fresh["key_hashes"],ended_at_utc=fresh["launch_binding"]["exited_at_utc"])

"""
    verify = verify.replace(marker, "\n" + predecessor + marker)
    # Full stage chronology is also bound to its validated predecessor's terminal record.
    verify = verify.replace(
        '    r.eq(p["timing_allowed"], False)',
        '    r.eq(p["timing_allowed"], False)\n    if stage=="n4-full":\n        r.need(utc(p["predecessor"]["ended_at_utc"]) < utc(p["prepared_at_utc"]), "predecessor terminal before full preparation")',
    )
    verify = verify.replace(
        'if k not in ("reports", "launch_binding")',
        'if k in ("status", "stage", "gate_pass", "records", "completed_components", "planned_components", "events", "source_id", "binary_sha256")',
    )
    verify = verify.replace(
        '    if stage=="n4-full":',
        """    if stage=="n4-full":
        r.need(utc(clearance["observed_at_utc"]) >= utc(p["predecessor"]["ended_at_utc"]),
               "clearance observation after predecessor termination")""",
    )
    (HERE / "verify.py").write_text(verify)


if __name__ == "__main__":
    main()
