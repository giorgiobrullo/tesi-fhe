"""Deterministic A138 successor. No Cargo, build, keygen or FHE."""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = ROOT / "tmp/a138-nibble-ingress-gate"


def verify_sources():
    for pin in json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]:
        source_path = Path(pin["path"])
        assert hashlib.sha256(source_path.read_bytes()).hexdigest() == pin["sha256"], (
            pin["path"]
        )
        if source_path.parent.name == "a142-nibble-joint-noise-domain":
            assert (
                HERE / "frozen_a142" / source_path.name
            ).read_bytes() == source_path.read_bytes(), source_path.name


def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after, 1)


def formatted(source):
    result = subprocess.run(
        ["rustfmt", "--edition", "2021", "--emit", "stdout"],
        input=source,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def render_main():
    source = (BASE / "src/main.rs").read_text()
    source = replace_once(
        source,
        'include!("a34_tables.rs");',
        'include!("a34_tables.rs");\nmod coefficient_observer;',
    )
    source = replace_once(
        source, 'eprintln!("A138_ERROR: {error}");', 'eprintln!("A143_ERROR: {error}");'
    )
    source = source.replace("target-a138-only", "target-a143-only")
    source = replace_once(
        source,
        "    for a in &args {",
        """    let stage = args.iter().find_map(|x| x.strip_prefix("--stage=")).unwrap_or("smoke");
    if !matches!(stage, "smoke" | "full") { return Err("stage must be smoke or full".into()); }
    for a in &args {""",
    )
    source = replace_once(
        source,
        '            && !a.starts_with("--keysets=")',
        '            && !a.starts_with("--keysets=")\n            && !a.starts_with("--stage=")',
    )
    source = replace_once(
        source,
        """        [16, 16, 15, 15],
    ];""",
        """        [16, 16, 15, 15],
    ];
    let source_fixture_indices: Vec<usize> = if stage == "smoke" { vec![2, 4] } else { (0..fixtures.len()).collect() };
    let fixtures: Vec<[u64;4]> = source_fixture_indices.iter().map(|i| fixtures[*i]).collect();
    let stage_id = if stage == "smoke" { "coefficient_smoke_n4" } else { "coefficient_full_n4" };""",
    )
    source = replace_once(
        source,
        '"stage":"first_composed_n4","fixtures":fixtures',
        '"stage":stage_id,"source_fixture_indices":source_fixture_indices,"full_fixture_count":8,"fixtures":fixtures',
    )
    source = replace_once(
        source,
        '"formal_bound":false}',
        '"formal_bound":false,"key_sensitive_client_local_only":true,"timing_invalid":true}',
    )
    source = replace_once(
        source, '"runtime_executed":false', '"execution_requested":execute'
    )
    source = replace_once(
        source,
        '"secret_keys_saved":false',
        '"raw_secret_key_bits_serialized":false,"key_sensitive_client_local_only":true',
    )
    source = replace_once(
        source,
        '"tables_sha256":format!',
        '"observer_sha256":format!("{:x}",Sha256::digest(include_bytes!("coefficient_observer.rs"))),"tables_sha256":format!',
    )
    source = replace_once(
        source,
        "    let mut cases = 0usize;",
        "    let mut cases = 0usize;\n    let mut coefficient_events = 0usize;\n    let mut coefficient_failures = 0usize;",
    )
    source = replace_once(
        source,
        """                    let raw = event.body[address % 2048];""",
        """                    let coefficient_witness = coefficient_observer::observe(event.switched.as_ref(), small_secret.as_ref(), small_phase, address, keyset);
                    coefficient_events += 1;
                    coefficient_failures += usize::from(coefficient_witness["closure_pass"].as_bool() != Some(true));
                    let raw = event.body[address % 2048];""",
    )
    source = replace_once(
        source,
        '"record":"event","keyset":keyset,"case":case,',
        '"record":"event","keyset":keyset,"case":case,"source_fixture_index":source_fixture_indices[case],"coefficient_observer":coefficient_witness,',
    )
    source = replace_once(
        source,
        '"record":"case","keyset":keyset,"case":case,',
        '"record":"case","keyset":keyset,"case":case,"source_fixture_index":source_fixture_indices[case],',
    )
    source = replace_once(
        source,
        "        && cases == 8 * keysets;",
        "        && cases == fixtures.len() * keysets\n        && coefficient_events == fixtures.len() * keysets * (55 + 63 + 55)\n        && coefficient_failures == 0;",
    )
    source = replace_once(
        source,
        'if pass {"BOUNDED_COMPOSED_GATE_PASS"} else {"GATE_FAIL"}',
        'if pass {if stage == "smoke" {"BOUNDED_COEFFICIENT_SMOKE_PASS"} else {"BOUNDED_COEFFICIENT_FULL_PASS"}} else {"GATE_FAIL"}',
    )
    source = replace_once(
        source,
        '"case_count":cases,"p_fail_certified":false',
        '"case_count":cases,"stage":stage_id,"source_fixture_indices":source_fixture_indices,"full_schedule_complete":stage=="full","coefficient_events":coefficient_events,"coefficient_failures":coefficient_failures,"timing_invalid":true,"key_sensitive_client_local_only":true,"p_fail_certified":false',
    )
    return formatted(source)


def rendered_files():
    verify_sources()
    return {
        "src/main.rs": render_main(),
        "src/coefficient_observer.rs": formatted(
            (HERE / "coefficient_observer.rs").read_text()
        ),
        "src/a34_tables.rs": (BASE / "src/a34_tables.rs").read_text(),
        "Cargo.toml": (BASE / "Cargo.toml")
        .read_text()
        .replace("a138_nibble_ingress_gate", "a143_nibble_coefficient_observer"),
        "Cargo.lock": (BASE / "Cargo.lock")
        .read_text()
        .replace(
            'name = "a138_nibble_ingress_gate"',
            'name = "a143_nibble_coefficient_observer"',
            1,
        ),
        ".cargo/config.toml": (BASE / ".cargo/config.toml")
        .read_text()
        .replace("target-a138-only", "target-a143-only"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    outputs = rendered_files()
    candidate = HERE / "candidate"
    if args.write:
        assert not candidate.exists(), (
            "preserve existing candidate; use read-only default check"
        )
        for name, content in outputs.items():
            path = candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        diff = difflib.unified_diff(
            (BASE / "src/main.rs").read_text().splitlines(True),
            outputs["src/main.rs"].splitlines(True),
            fromfile="A138/src/main.rs",
            tofile="A143/src/main.rs",
        )
        (HERE / "source.patch").write_text("".join(diff))
    else:
        for name, content in outputs.items():
            assert (candidate / name).read_text() == content, name
    print(
        json.dumps(
            {
                "source_inputs_verified": True,
                "candidate_files": len(outputs),
                "rustfmt_only": True,
                "cargo_or_fhe": False,
            }
        )
    )


if __name__ == "__main__":
    main()
