"""Materialize explicitly adapted A187 private one-shot envelope; never launch."""

from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a187-padding-precision-runtime-gate"
s = (OLD / "run_gate.py").read_text()
s = s.replace("A187", "A191").replace("a187.a187.first.v1", "a191.first_composition.v1")
s = s.replace("SOURCE = HERE\n", 'SOURCE = HERE / "candidate"\n')
s = s.replace(
    'BINARY = SOURCE / "target-a187-only/release/a149_padding_coefficient_gate"',
    'BINARY = HERE / "target-a191-only/release/a191_pfks_actual_comparator"',
)
s = s.replace("runs/first-precision", "runs/first-composition").replace(
    "A191_FIRST_N4_AUTHORIZED", "A191_FIRST_COMPARATOR_AUTHORIZED"
)
s = s.replace("import subprocess\n", "import subprocess\nimport shutil\n")
start = s.index("    origins = json.loads(")
end = s.index('    return digest(HERE / "MANIFEST.json")', start)
s = s[:start] + s[end:]
s = s.replace(
    "        os.fsync(handle.fileno())\n",
    "        os.fsync(handle.fileno())\n    sync_directory(path.parent)\n",
    1,
)
pos = s.index("\ndef source_check():")
s = (
    s[:pos]
    + """\ndef sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

"""
    + s[pos:]
)
start = s.index('                    suite="first-precision",')
end = s.index("                    actual_fhe=False,", start)
s = (
    s[:start]
    + """                    suite="first-composition",
                    keysets=1,
                    fixture_index=7,
                    left=[0, 1, 0, 126], right=[0, 0, 15, 127],
                    selector_arms=3, comparator_stages=4,
                    raw_records=48, pfks=20, ks=10, br=10, samples=16,
"""
    + s[end:]
)
s = s.replace(
    "    RUN.mkdir(mode=0o700, exist_ok=False)\n",
    """    require(shutil.disk_usage(HERE).free >= 2 * (1 << 30), "two GiB free disk prerequisite")
    RUN.mkdir(mode=0o700, exist_ok=False)
    sync_directory(RUN.parent)
""",
)
s = s.replace(
    "    require(digest(BINARY) == args.binary_sha256,",
    '    require(BINARY.is_file() and not any(p.is_symlink() for p in [BINARY, *BINARY.parents]), "regular binary without symlink ancestry")\n    require(digest(BINARY) == args.binary_sha256,',
)
s = s.replace(
    "    command = [str(BINARY)",
    "    sync_directory(RUN)\n    command = [str(BINARY)",
    1,
)
s = s.replace(
    '        schema="a191.first_composition.v1",',
    '        schema="a191.first_composition.v1",\n        run_directory=str(RUN),',
)
s = s.replace(
    '    return code or (0 if terminal["postchecks_complete"] else 2)',
    '    return (code if code in (0, 1) else 2) if terminal["postchecks_complete"] else 2',
)
s = s.replace(
    "    raise SystemExit(main())",
    """    try:
        result = main()
    except Exception as error:
        print(json.dumps(dict(status="INVALID_OR_INCOMPLETE_A191_LAUNCH", error=str(error))), flush=True)
        result = 2
    raise SystemExit(result)""",
)
(HERE / "run_gate.py").write_text(s)
s = (
    (OLD / "verify.py")
    .read_text()
    .replace("A187", "A191")
    .replace("a187.a187.first.v1", "a191.first_composition.v1")
)
s = s.replace(
    "import replay as r\n",
    "import replay as r\nfrom model import need, eq\nimport hashlib\n",
)
s = (
    s.replace("r.need(", "need(")
    .replace("r.eq(", "eq(")
    .replace("r.sha_bytes(raw)", "hashlib.sha256(raw).hexdigest()")
)
s = s.replace(
    "def envelope(run):", "def envelope(run, expected_artifact, expected_binary):"
)
s = s.replace(
    "    artifact = b.source_check()",
    """    artifact = b.source_check()
    eq(artifact, expected_artifact, "explicit frozen artifact")
    eq(p["binary_sha256"], expected_binary, "explicit actual binary")""",
)
s = s.replace(
    "    artifact = b.source_check()",
    '    need(b.BINARY.is_file() and not any(p.is_symlink() for p in [b.BINARY, *b.BINARY.parents]), "regular binary without symlink ancestry")\n    artifact = b.source_check()',
)
s = s.replace(
    '    eq(p["schema"], "a191.first_composition.v1")',
    '    eq(set(p), {"schema", "run_directory", "driver_pid", "command", "cwd", "environment", "binary_sha256", "source_manifest_sha256", "launcher_manifest_sha256", "prepared_at_utc", "clearance_sha256", "timing_allowed"}, "prepared fields")\n    eq(p["schema"], "a191.first_composition.v1")',
)
s = s.replace(
    '    eq(p["cwd"], str(b.HERE))',
    '    eq(p["cwd"], str(b.SOURCE))\n    eq(p["run_directory"], str(b.RUN))',
)
s = s.replace('records[1]["child_pid"]', 'records[1]["process_id"]')
s = s.replace(
    'b"A191_ERROR: complete changed-precision gate failed; preserve old and new outcomes without retry\\n"',
    'b"A191_COMPLETE_NEGATIVE: preserve first comparator/selector outcomes without retry\\n"',
)
s = s.replace(
    'def verify(run):\n    records, binding = envelope(run)\n    result = r.replay(records, binding["binary_sha256"], binding["exit_code"])',
    'def verify(run, expected_artifact, expected_binary):\n    records, binding = envelope(run, expected_artifact, expected_binary)\n    result = r.replay(records, binding["binary_sha256"], binding["child_pid"], binding["exit_code"])',
)
s = s.replace(
    '    result["local_direct_child_record_binding"] = True',
    '    result["local_direct_child_record_binding"] = True\n    result["launch_envelope_verified"] = True',
)
s = s.replace(
    '    parser.add_argument("--output", type=Path)',
    '    parser.add_argument("--output", type=Path)\n    parser.add_argument("--artifact-sha256")\n    parser.add_argument("--binary-sha256")',
)
s = s.replace("records=211", "records=48")
s = s.replace(
    '    need(args.output is not None, "new exclusive private report required")',
    '    need(args.output is not None and args.artifact_sha256 and args.binary_sha256, "new exclusive private report and expected artifact/binary required")',
)
s = s.replace(
    "result = verify(b.RUN)",
    "result = verify(b.RUN, args.artifact_sha256, args.binary_sha256)",
)
s = s.replace(
    '{k: v for k, v in result.items() if k not in ("reports", "launch_binding")}',
    '{k: result[k] for k in ("status", "gate_pass", "records", "keysets", "fixture_index", "comparator_pass", "actual_support_pass", "direct_class", "d1_class", "scalar_pass", "all_six_control_bytes_equal", "source_id", "binary_sha256", "child_pid", "ledger", "launch_envelope_verified") if k in result}',
)
(HERE / "verify.py").write_text(s)
