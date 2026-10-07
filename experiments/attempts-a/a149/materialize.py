"""A149 preparation: compose frozen A143 observation with frozen A145 evaluation.

No arguments verifies source pins. --write creates a fresh candidate; it never
rewrites a candidate, runs Cargo, or starts cryptography.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PADDING = ROOT / "tmp/a145-padding-flag-ingress-gate"
OBSERVER = ROOT / "tmp/a143-nibble-coefficient-observer"


def replace_once(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after, 1)


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for name, expected in pins.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    return len(pins)


def render_main():
    source = (PADDING / "src/main.rs").read_text()
    source = replace_once(
        source,
        'include!("a34_tables.rs");',
        'include!("a34_tables.rs");\nmod coefficient_observer;',
    )
    source = source.replace("A145_ERROR", "A149_ERROR").replace(
        "target-a145-only", "target-a149-only"
    )
    source = replace_once(
        source, '"stage":"padding_flags_n4"', '"stage":"padding_coefficients_n4"'
    )
    source = replace_once(
        source,
        '"runtime_executed":false',
        '"execution_requested":execute,"key_sensitive_client_local_only":true,"timing_invalid":true',
    )
    source = replace_once(
        source,
        '"tables_sha256":format!',
        '"observer_sha256":format!("{:x}",Sha256::digest(include_bytes!("coefficient_observer.rs"))),"tables_sha256":format!',
    )
    source = replace_once(
        source,
        '"secret_keys_saved":false',
        '"raw_secret_key_bits_serialized":false,"key_sensitive_client_local_only":true',
    )
    source = replace_once(
        source,
        "    let mut cases = 0usize;",
        "    let mut cases = 0usize;\n    let mut coefficient_events = 0usize;\n    let mut coefficient_failures = 0usize;",
    )
    source = replace_once(
        source,
        "                    let raw = event.body[address % 2048];",
        """                    let coefficient_witness = coefficient_observer::observe(event.switched.as_ref(), small_secret.as_ref(), small_phase, address, keyset);
                    coefficient_events += 1;
                    coefficient_failures += usize::from(coefficient_witness["closure_pass"].as_bool() != Some(true));
                    let raw = event.body[address % 2048];""",
    )
    source = replace_once(
        source,
        '"record":"event","keyset":keyset,',
        '"record":"event","coefficient_observer":coefficient_witness,"keyset":keyset,',
    )
    source = replace_once(
        source,
        "        && cases == selected_indices.len() * keysets;",
        "        && cases == selected_indices.len() * keysets\n        && coefficient_events == selected_indices.len() * keysets * 346\n        && coefficient_failures == 0;",
    )
    source = replace_once(
        source,
        '"BOUNDED_PADDING_COMPOSED_GATE_PASS"',
        '"BOUNDED_PADDING_COEFFICIENT_GATE_PASS"',
    )
    source = replace_once(
        source,
        '"case_count":cases,',
        '"case_count":cases,"coefficient_events":coefficient_events,"coefficient_failures":coefficient_failures,"key_sensitive_client_local_only":true,"timing_invalid":true,',
    )
    return subprocess.run(
        ["rustfmt", "--edition", "2021", "--emit", "stdout"],
        input=source,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def render_replay():
    source = (PADDING / "replay.py").read_text()
    source = source.replace("A145", "A149").replace(
        "from check import ", "from contract import "
    )
    source = replace_once(
        source,
        "import regions\n",
        'import regions\nfrom coefficients import verify_event\n\nif not __debug__:\n    raise RuntimeError("assertions must remain enabled")\n',
    )
    source = replace_once(source, '"padding_flags_n4"', '"padding_coefficients_n4"')
    source = replace_once(
        source,
        '    keys = plan["keysets"]',
        '    assert plan["key_sensitive_client_local_only"] is True and plan["timing_invalid"] is True\n    keys = plan["keysets"]',
    )
    source = replace_once(
        source,
        '        ("tables_sha256", "src/a34_tables.rs"),',
        '        ("tables_sha256", "src/a34_tables.rs"),\n        ("observer_sha256", "src/coefficient_observer.rs"),',
    )
    source = replace_once(
        source,
        "    reports = []",
        "    reports = []\n    coefficient_events, coefficient_failures = 0, 0",
    )
    source = replace_once(
        source,
        "        graph = Graph(",
        """        coefficient_reports = [verify_event(e) for e in events[key]]
        coefficient_events += len(coefficient_reports)
        coefficient_failures += sum(not r["coefficient_closure_pass"] for r in coefficient_reports)
        graph = Graph(""",
    )
    source = replace_once(
        source,
        "                domains=graph.reports,",
        '                domains=graph.reports,\n                coefficient_closure_pass=all(r["coefficient_closure_pass"] for r in coefficient_reports),\n                coefficient_observations=coefficient_reports,',
    )
    source = replace_once(
        source,
        '    assert summary["positive_arm_failures"] == failures',
        """    functional_pass = passed
    assert coefficient_events == keys * len(indices) * 346
    assert summary["coefficient_events"] == coefficient_events
    assert summary["coefficient_failures"] == coefficient_failures
    assert summary["key_sensitive_client_local_only"] is True and summary["timing_invalid"] is True
    passed = passed and coefficient_failures == 0
    joint_pass = passed and all(r["conditional_region_pass"] and r["native_msb_outputs_pass"] for r in reports if r["arm"] in [a["name"] for a in ARMS[:4]])
    assert summary["positive_arm_failures"] == failures""",
    )
    source = source.replace(
        '"BOUNDED_PADDING_COMPOSED_GATE_PASS"',
        '"BOUNDED_PADDING_COEFFICIENT_GATE_PASS"',
    )
    source = replace_once(
        source,
        "        functional_gate_pass=passed,",
        """        functional_gate_pass=functional_pass,
        coefficient_gate_pass=passed,
        joint_witness_pass=joint_pass,
        coefficient_events=coefficient_events,
        coefficient_failures=coefficient_failures,
        public_coefficient_rounding_verified=True,
        secret_aggregate_key_membership_attested=False,
        key_sensitive_client_local_only=True,
        timing_invalid=True,""",
    )
    source = replace_once(
        source,
        '    with args.output.open("x") as output:',
        "    with private_text(args.output) as output:",
    )
    source = replace_once(
        source,
        "from pathlib import Path",
        "from pathlib import Path\nfrom private_io import private_text",
    )
    source = replace_once(
        source,
        'if not result.get("functional_gate_pass"):',
        'if not result.get("joint_witness_pass"):',
    )
    return source


def rendered_files():
    source = (PADDING / "check.py").read_text()
    constants_and_helpers = source[
        source.index("FIXTURES =") : source.index("def rust_function")
    ]
    start = constants_and_helpers.index("def verify_sources():")
    end = constants_and_helpers.index("def evaluate(")
    constants_and_helpers = constants_and_helpers[:start] + constants_and_helpers[end:]
    contract = (
        '"""Frozen A145 schedules and graph, source-pinned by A149."""\nfrom pathlib import Path\nfrom graph import Graph\nfrom materialize import verify_sources as verify_sources\nHERE = Path(__file__).resolve().parent\n'
        + constants_and_helpers
    )
    runner = (
        (PADDING / "run_gate.py")
        .read_text()
        .replace("target-a145-only", "target-a149-only")
        .replace("a145_padding_flag_ingress_gate", "a149_padding_coefficient_gate")
    )
    runner = replace_once(
        runner,
        "HERE = Path(__file__).resolve().parent",
        "from private_io import private_text\n\nHERE = Path(__file__).resolve().parent",
    )
    runner = (
        runner.replace(
            'with path.open("x") as output:', "with private_text(path) as output:"
        )
        .replace(
            '(directory / "stdout.jsonl").open("x") as out,',
            'private_text(directory / "stdout.jsonl") as out,',
        )
        .replace(
            '(directory / "stderr.txt").open("x") as err,',
            'private_text(directory / "stderr.txt") as err,',
        )
    )
    result = {
        "src/main.rs": render_main(),
        "src/coefficient_observer.rs": (
            OBSERVER / "candidate/src/coefficient_observer.rs"
        ).read_text(),
        "coefficients.py": (OBSERVER / "coefficients.py").read_text(),
        "contract.py": contract,
        "replay.py": render_replay(),
        "run_gate.py": runner,
    }
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "src/a34_tables.rs",
        "graph.py",
        "regions.py",
        "a138_model.py",
        "a135_model.py",
    ]:
        result[name] = (
            (PADDING / name)
            .read_text()
            .replace("a145_padding_flag_ingress_gate", "a149_padding_coefficient_gate")
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    count = verify_sources()
    if args.write:
        assert not (HERE / "src").exists(), "preserve an already materialized candidate"
        for name, content in rendered_files().items():
            path = HERE / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x") as stream:
                stream.write(content)
    print(
        json.dumps(
            dict(
                pinned_inputs=count, source_materialized=args.write, cargo_or_fhe=False
            )
        )
    )


if __name__ == "__main__":
    main()
