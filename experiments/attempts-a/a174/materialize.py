"""Explicit envelope-only successor; no producer/binary copy or execution."""

from pathlib import Path
import hashlib
import difflib
import json

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a171-pfks-d1-runtime-gate/execution-readiness"


def replace(source, old, new, count=1):
    assert source.count(old) == count, (old, source.count(old), count)
    return source.replace(old, new)


binding = (OLD / "binding.py").read_text()
binding = replace(
    binding, "BASE = HERE.parent", 'BASE = HERE.parent / "a171-pfks-d1-runtime-gate"'
)
binding = replace(
    binding,
    'SCHEMA = "a171-direct-child-envelope-v1"',
    'SCHEMA = "a174-a171-progression-envelope-v1"',
)
binding = replace(
    binding,
    'RUN_ID = "offset0-key1"',
    'RUN_IDS = {1: "offset1-key2", 2: "offset2-key3"}\nBINARY_HASH = "03405436a6d9412ac42b31bc0c556d8b99c97500ce148a8444bdc79650ec2cc5"\nFIRST_MANIFEST_HASH = "4b7aa7267fd8ddb4a4331f472e549057053d8f8fe83c8946f6e81a5da64f2c5c"\nFIRST_VALIDATION_HASH = "c0e2d4f51eb428eaa7e7bad3fe2f32f0d4e4c1f5e5e4c2eaa6026174635fcf5c"',
)
binding = replace(
    binding,
    '    own = load(HERE / "MANIFEST.json")',
    '    first = load(HERE / "FIRST_PINS.json")\n    for name, expected in first["files"].items():\n        eq(digest(no_symlinks(BASE / name)), expected, "actual first-gate pin " + name)\n    eq(digest(BASE / "execution-readiness/MANIFEST.json"), FIRST_MANIFEST_HASH, "frozen first envelope")\n    first_binding = import_path("a174_first_binding", BASE / "execution-readiness/binding.py")\n    first_binding.source_check()\n    own = load(HERE / "MANIFEST.json")',
)
binding = replace(
    binding,
    '        "source_sha256": SOURCE_ID,',
    '        "first_gate_pins_sha256": digest(HERE / "FIRST_PINS.json"),\n        "source_sha256": SOURCE_ID,',
)
binding = replace(
    binding,
    'def fixed_paths(base=BASE):\n    return (base / BINARY_REL, base / "candidate", base / "runs" / RUN_ID)',
    'def fixed_paths(offset, base=BASE, run_base=HERE):\n    need(type(offset) is int and offset in RUN_IDS, "registered later offset1 or2")\n    return (base / BINARY_REL, base / "candidate", run_base / "runs" / RUN_IDS[offset])\n\n\ndef environment(offset):\n    fixed_paths(offset)\n    return dict(ENV, A171_ORDER_OFFSET=str(offset))\n\n\ndef report_path(offset):\n    return HERE / "artifacts" / (RUN_IDS[offset] + "-validation.json")\n\n\ndef first_verifier():\n    old_binding = import_path("a174_first_bound_binding", BASE / "execution-readiness/binding.py")\n    previous = sys.modules.get("binding")\n    sys.modules["binding"] = old_binding\n    try:\n        return import_path("a174_first_bound_verifier", BASE / "execution-readiness/verify.py")\n    finally:\n        if previous is None:\n            sys.modules.pop("binding", None)\n        else:\n            sys.modules["binding"] = previous',
)

binding = replace(
    binding,
    'def eq(actual, expected, reason):\n    need(type(actual) is type(expected), reason + " type")\n    need(actual == expected, reason)\n',
    "def strictly_equal(actual, expected):\n    if type(actual) is not type(expected):\n        return False\n    if isinstance(expected, dict):\n        if not strictly_equal(set(actual), set(expected)):\n            return False\n        return all(strictly_equal(actual[key], value) for key, value in expected.items())\n    if isinstance(expected, (list, tuple)):\n        return len(actual) == len(expected) and all(\n            strictly_equal(a, e) for a, e in zip(actual, expected)\n        )\n    if isinstance(expected, set):\n        return len(actual) == len(expected) and all(\n            any(strictly_equal(a, e) for a in actual) for e in expected\n        )\n    return actual == expected\n\n\ndef eq(actual, expected, reason):\n    need(strictly_equal(actual, expected), reason)\n",
)

runner = (OLD / "run_gate.py").read_text()
runner = replace(
    runner,
    "Root-only one-shot A171 offset-0 launch.",
    "Root-only one-shot A171 offset1 or2 progression; predecessor pass required.",
)
runner = replace(
    runner,
    "def plan():\n    binary, cwd, run = b.fixed_paths()",
    "def plan(offset=1):\n    binary, cwd, run = b.fixed_paths(offset)",
)
runner = replace(
    runner,
    "        exact_environment=b.ENV,",
    "        exact_environment=b.environment(offset),",
)
runner = replace(
    runner, "        order_offset=0,", "        order_offset=offset,", count=2
)
runner = replace(
    runner,
    "        later_offsets_supported=False,",
    "        registered_progression=[1, 2],\n        required_prior_offset=offset-1,\n        automatic_progression=False,",
)
runner = replace(
    runner,
    "                        run_id=b.RUN_ID,",
    '                        run_id=prepared["run_id"],',
)
runner = replace(
    runner,
    '    parser.add_argument("--binary-sha256")',
    '    parser.add_argument("--order-offset", type=int, choices=(1, 2))\n    parser.add_argument("--binary-sha256")',
)
runner = replace(
    runner,
    "print(json.dumps(plan(), indent=2))",
    "print(json.dumps(plan(args.order_offset or 1), indent=2))",
)
runner = replace(
    runner,
    "    binding = b.source_check()\n    binary, cwd, run = b.fixed_paths()",
    '    b.need(args.order_offset is not None, "explicit registered order offset required")\n    offset = args.order_offset\n    binding = b.source_check()\n    import verify as verifier\n    prior = verifier.require_prior(offset)\n    binary, cwd, run = b.fixed_paths(offset)\n    b.eq(args.binary_sha256, b.BINARY_HASH, "same frozen A171 binary")',
)
runner = replace(
    runner,
    "    b.clearance_check(clearance, prepared_at)",
    '    b.clearance_check(clearance, prepared_at)\n    b.need(b.utc(clearance["observed_at_utc"]) >= b.utc(prior[-1]["exited_at_utc"]), "fresh clearance after preceding terminal gate")',
)
runner = replace(
    runner, "        run_id=b.RUN_ID,", "        run_id=b.RUN_IDS[offset],"
)
runner = replace(
    runner,
    "        source_binding=binding,",
    "        source_binding=binding,\n        prior_gate_bindings=prior,",
)
runner = replace(
    runner,
    "        environment=dict(b.ENV),",
    "        environment=b.environment(offset),",
)

verifier = (OLD / "verify.py").read_text()
verifier = replace(
    verifier,
    "Independent A171 private envelope + frozen semantic replay, never a launcher.",
    "A174 independently bound A171 progression and aggregate, never a launcher.",
)
verifier = replace(verifier, "import argparse", "import argparse\nimport itertools")
verifier = replace(
    verifier,
    'def verify_envelope(run, binding, base=None):\n    base = b.BASE if base is None else base\n    binary, cwd, expected_run = b.fixed_paths(base)\n    b.eq(run, expected_run, "fixed first offset0 run path")',
    'def verify_envelope(run, binding, offset, prior, base=None, run_base=None):\n    base = b.BASE if base is None else base\n    run_base = b.HERE if run_base is None else run_base\n    binary, cwd, expected_run = b.fixed_paths(offset, base, run_base)\n    b.eq(run, expected_run, "fixed registered progression run path")',
)
verifier = replace(
    verifier, "        run_id=b.RUN_ID,", "        run_id=b.RUN_IDS[offset],"
)
verifier = replace(
    verifier,
    "        source_binding=binding,",
    "        source_binding=binding,\n        prior_gate_bindings=prior,",
    count=2,
)
verifier = replace(
    verifier, "        environment=b.ENV,", "        environment=b.environment(offset),"
)
verifier = replace(verifier, "        order_offset=0,", "        order_offset=offset,")
verifier = replace(
    verifier,
    '    b.hexhash(pre["binary_sha256"])',
    '    b.hexhash(pre["binary_sha256"])\n    b.eq(pre["binary_sha256"], b.BINARY_HASH, "same frozen binary")',
)
verifier = replace(
    verifier,
    '    b.clearance_check(b.load(run / "preflight.json"), pre["prepared_at_utc"])',
    '    clearance = b.load(run / "preflight.json")\n    b.clearance_check(clearance, pre["prepared_at_utc"])\n    b.need(b.utc(clearance["observed_at_utc"]) >= b.utc(prior[-1]["exited_at_utc"]), "clearance after prior complete gate")',
)
verifier = replace(
    verifier,
    '        child_pid=child["child_pid"],',
    '        order_offset=offset,\n        child_pid=child["child_pid"],',
)
verifier = replace(
    verifier,
    '        b.eq(row["order_offset"], 0, "actual first offset0")',
    '        b.eq(row["order_offset"], envelope["order_offset"], "actual registered offset")',
)
verifier = replace(
    verifier,
    "        component_gate_pass=passed,",
    '        order_offset=envelope["order_offset"],\n        component_gate_pass=passed,',
)
verifier = verifier[: verifier.index("\ndef verify(run):")]
verifier += (HERE / "progression.py.in").read_text()

for name, text in [
    ("binding.py", binding),
    ("run_gate.py", runner),
    ("verify.py", verifier),
]:
    (HERE / name).write_text(text)
    patch = "".join(
        difflib.unified_diff(
            (OLD / name).read_text().splitlines(True),
            text.splitlines(True),
            fromfile="frozen-a171/" + name,
            tofile="a174/" + name,
        )
    )
    (HERE / (name + ".patch")).write_text(patch)

first_names = [
    "execution-readiness/MANIFEST.json",
    "execution-readiness/artifacts/offset0-key1-validation.json",
]
first_names += [
    "runs/offset0-key1/" + n
    for n in [
        "preflight.json",
        "prepared.json",
        "child.json",
        "wait-complete.json",
        "exit.json",
        "stdout.jsonl",
        "stderr.log",
    ]
]
first = {
    "schema": "a174-frozen-first-actual-gate-pins-v1",
    "files": {
        n: hashlib.sha256((OLD.parent / n).read_bytes()).hexdigest()
        for n in first_names
    },
}
assert (
    first["files"]["execution-readiness/artifacts/offset0-key1-validation.json"]
    == "c0e2d4f51eb428eaa7e7bad3fe2f32f0d4e4c1f5e5e4c2eaa6026174635fcf5c"
)
(HERE / "FIRST_PINS.json").write_text(json.dumps(first, indent=2) + "\n")
