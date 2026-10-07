"""Deterministic A187 successor source transformations; never native execution."""

from pathlib import Path
import hashlib
import json
import difflib

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a187-padding-precision-runtime-gate"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    unchanged = [
        "Cargo.toml",
        "Cargo.lock",
        "src/main.rs",
        "src/precision.rs",
        "src/input_construction.rs",
        "src/a34_tables.rs",
        "src/coefficient_observer.rs",
        "precision_model.py",
        "graph.py",
        "regions.py",
        "a138_model.py",
        "a135_model.py",
        "coefficients.py",
    ]
    for name in unchanged:
        target = HERE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((OLD / name).read_bytes())
    (HERE / ".cargo").mkdir(exist_ok=True)
    (HERE / ".cargo/config.toml").write_text(
        '[build]\ntarget-dir = "target-a192-only"\n\n[net]\noffline = true\n'
    )
    source = (OLD / "src/gate.rs").read_text()
    source = (
        source.replace("A187", "A192")
        .replace("a187", "a192")
        .replace("run187", "run192")
    )
    source = source.replace(
        'let execute = args.iter().any(|x| x == "--run");',
        'let execute = args.iter().any(|x| x == "--run");\n    let stage = args.iter().find_map(|x| x.strip_prefix("--stage=")).unwrap_or("n4-smoke");\n    if stage != "n4-smoke" && stage != "n4-full" { return Err("fixed N4 stage required".into()); }',
    )
    source = source.replace(
        "if execute { 2 } else { 0 }", "if execute { 3 } else { 0 }"
    )
    source = source.replace(
        'x != "--run" && !x.starts_with("--expected-binary-sha256=")',
        'x != "--run" && !x.starts_with("--expected-binary-sha256=") && !x.starts_with("--stage=")',
    )
    source = source.replace(
        "only noargs PLAN or --run plus one binary hash is permitted",
        "only noargs PLAN or --run plus one stage and one binary hash is permitted",
    )
    source = source.replace(
        "    let arms = [",
        """    if execute && (args.iter().filter(|x| x.as_str()=="--run").count()!=1
        || args.iter().filter(|x| x.starts_with("--stage=")).count()!=1
        || args.iter().filter(|x| x.starts_with("--expected-binary-sha256=")).count()!=1) {
        return Err("exactly one explicit stage, run flag and binary hash required".into());
    }
    let arms = [""",
    )
    begin = source.index("    let scores = &[255u64, 256, 254, 4095];")
    end = source.index("    if !execute {", begin)
    component_plan = source[begin:end].split("\n", 1)[1]
    component_plan = component_plan.replace(
        '"fixture_index":2',
        '"fixture_index":fixture_index,"keyset":keyset,"control_required":fixture_index==0',
    )
    component_plan = component_plan.replace(
        '"execution_requested":execute', '"execution_requested":true'
    )
    source = (
        source[:begin]
        + """    let fixture_count = if stage == "n4-smoke" { 2usize } else { 16 };
    let total_components = 3 * fixture_count;
    println!("{}", json!({"record":"stage_plan","schema":"a192.precision_expansion.v1",
        "execution_requested":execute,"stage":stage,"keysets":3,"fixture_indices":(0..fixture_count).collect::<Vec<_>>(),
        "planned_components":total_components,"component_records":211,"raw_records_if_pass":2+211*total_components,
        "pbs_if_pass":205*total_components,"ks_if_pass":205*total_components,"input_encryptions_if_pass":total_components,
        "total_extractions_if_pass":213*total_components,"stop_first_component_negative":true,
        "fresh_stage_keys":true,"timing_allowed":false,"automatic_expansion":false}));
"""
        + source[end:]
    )
    source = source.replace("A192_FIRST_N4_AUTHORIZED", "A192_FIXED_N4_AUTHORIZED")
    key_start = source.index("    let client = ClientKey::new(")
    input_start = source.index(
        '    let (full, low) = include!("input_construction.rs");'
    )
    key_block = source[key_start:input_start]
    source = (
        source[:key_start]
        + """    let fixtures: serde_json::Value = serde_json::from_str(include_str!("../FIXTURES.json")).map_err(|e| e.to_string())?;
    let mut completed = 0usize;
    let mut gate_all = true;
    let mut key_hashes = std::collections::HashSet::new();
    'keys: for keyset in 0..3usize {
"""
        + key_block
        + """    let big_hash = hash_words(big_secret.as_ref());
    let small_hash = hash_words(small_secret.as_ref());
    if !key_hashes.insert(big_hash.clone()) || !key_hashes.insert(small_hash.clone()) {
        return Err("fresh key hash collision; no resampling".into());
    }
    for fixture_index in 0..fixture_count {
    let score_values: Vec<u64> = fixtures["fixtures"][fixture_index]["scores"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    let scores = score_values.as_slice();
    let reference = &reference["fixtures"][fixture_index];
"""
        + component_plan
        + source[input_start:]
    )
    source = source.replace(
        "    let expected = [0u64, 0, 1, 0];",
        "    let minimum = *scores.iter().min().unwrap();\n    let expected: Vec<u64> = scores.iter().map(|x| u64::from(minimum<=1023 && *x==minimum)).collect();",
    )
    source = source.replace(
        '"keyset":0,"case":2', '"keyset":keyset,"case":fixture_index'
    )
    source = source.replace(
        '"arm":arm,"arm_name":arms[arm],"keyset":0,"case":2',
        '"arm":arm,"arm_name":arms[arm],"keyset":keyset,"case":fixture_index',
    )
    source = source.replace(
        "ev.flags.iter().zip(expected).all",
        "ev.flags.iter().zip(expected.iter().copied()).all",
    )
    source = source.replace(
        '&& cases[2]["wrong_scale_detected"] == true',
        '&& (fixture_index != 0 || cases[2]["wrong_scale_detected"] == true)',
    )
    source = source.replace("A192_FIRST_N4_GATE_PASS", "A192_COMPONENT_PASS").replace(
        "A192_COMPLETE_NEGATIVE", "A192_COMPONENT_NEGATIVE"
    )
    old_tail = """    if !gate {
        return Err(
            "complete changed-precision gate failed; preserve old and new outcomes without retry"
                .into(),
        );
    }
    Ok(())
}
"""
    assert source.endswith(old_tail)
    source = (
        source[: -len(old_tail)]
        + """    completed += 1;
    if !gate { gate_all = false; break 'keys; }
    }
    }
    println!("{}",json!({"record":"stage_summary","schema":"a192.precision_expansion.v1",
        "stage":stage,"gate_pass":gate_all,"status":if gate_all {"A192_STAGE_PASS"} else {"A192_PREFIX_NEGATIVE"},
        "completed_components":completed,"planned_components":total_components,"generated_keysets":(completed+fixture_count-1)/fixture_count,
        "pbs":205*completed,"ks":205*completed,"input_glwe_encryptions":completed,"public_glwe_products":4*completed,
        "input_sample_extractions":8*completed,"pbs_output_sample_extractions":205*completed,"total_sample_extractions":213*completed,
        "actual_coefficient_degree_replays":205*completed,"extra_crypto_ms_calls":0,"refresh_calls":0,
        "raw_records":2+211*completed,"full_id":false,"formal_tail":false,"timing_claim":false}));
    if !gate_all { return Err("fixed expansion stopped at first complete negative; no retry".into()); }
    Ok(())
}
"""
    )
    (HERE / "src/gate.rs").write_text(source)
    component = (
        (OLD / "replay.py").read_text().replace("A187", "A192").replace("a187", "a192")
    )
    component = component.replace("SCORES = [255, 256, 254, 4095]\n", "")
    component = component.replace(
        "def nominal_reference():", "def nominal_reference(scores):"
    )
    component = component.replace("SCORES", "scores")
    a = component.index('        eq(\n            result["final_flags_pass"],')
    b = component.index("    return dict(", a)
    component = component[:a] + component[b:]
    a = component.index("def source_check():")
    b = component.index("def output_predicates", a)
    component = component[:a] + component[b:]
    component = component.replace(
        "def output_predicates(outputs, log):",
        "def output_predicates(outputs, log, scores):",
    )
    component = component.replace(
        "def replay(records, binary_hash, exit_code, verify_source=True):",
        "def replay(records, binary_hash, exit_code, scores, keyset, fixture_index, source_id):",
    )
    component = component.replace(
        '    source_id = source_check() if verify_source else "SYNTHETIC_SOURCE"\n', ""
    )
    component = component.replace("nominal_reference()", "nominal_reference(scores)")
    component = component.replace(
        "fixture_index=2,",
        "fixture_index=fixture_index, keyset=keyset, control_required=fixture_index == 0,",
    )
    component = component.replace(
        'if not verify_source and field == "source_id":',
        'if source_id == "SYNTHETIC_SOURCE" and field == "source_id":',
    )
    component = component.replace(
        'eq(case["keyset"], 0)', 'eq(case["keyset"], keyset)'
    ).replace('eq(case["case"], 2)', 'eq(case["case"], fixture_index)')
    component = component.replace(
        'eq(event["keyset"], 0)', 'eq(event["keyset"], keyset)'
    ).replace('eq(event["case"], 2)', 'eq(event["case"], fixture_index)')
    component = component.replace(
        "output_predicates(outputs, 51 if arm == 0 else 54)",
        "output_predicates(outputs, 51 if arm == 0 else 54, scores)",
    )
    component = component.replace(
        'and reports[2]["wrong_scale_detected"]',
        'and (fixture_index != 0 or reports[2]["wrong_scale_detected"])',
    )
    component = component.replace(
        "A192_FIRST_N4_GATE_PASS", "A192_COMPONENT_PASS"
    ).replace("A192_COMPLETE_NEGATIVE", "A192_COMPONENT_NEGATIVE")
    (HERE / "component.py").write_text(component)
    synthetic = (
        (OLD / "synthetic.py")
        .read_text()
        .replace("import replay as r", "import component as r")
    )
    synthetic = synthetic.replace(
        "def records(new_changes=None, old_changes=None):",
        "def records(scores, keyset=0, fixture_index=0, new_changes=None, old_changes=None):",
    )
    synthetic = synthetic.replace(
        "r.nominal_reference()", "r.nominal_reference(scores)"
    ).replace("r.SCORES", "scores")
    synthetic = synthetic.replace("a187.", "a192.").replace(
        "fixture_index=2,",
        "fixture_index=fixture_index, keyset=keyset, control_required=fixture_index == 0,",
    )
    synthetic = synthetic.replace(
        "keyset=0,\n                case=2",
        "keyset=keyset,\n                case=fixture_index",
    ).replace(
        "keyset=0,\n            case=2",
        "keyset=keyset,\n            case=fixture_index",
    )
    synthetic = synthetic.replace(
        "r.output_predicates(outputs, 51 if arm == 0 else 54)",
        "r.output_predicates(outputs, 51 if arm == 0 else 54, scores)",
    )
    synthetic = synthetic.replace(
        'and cases[2]["wrong_scale_detected"]',
        'and (fixture_index != 0 or cases[2]["wrong_scale_detected"])',
    )
    synthetic = synthetic.replace(
        "A187_FIRST_N4_GATE_PASS", "A192_COMPONENT_PASS"
    ).replace("A187_COMPLETE_NEGATIVE", "A192_COMPONENT_NEGATIVE")
    synthetic = synthetic.replace(
        'big_key_sha256="c" * 64,',
        'big_key_sha256=r.sha_bytes(f"big/key{keyset}".encode()),',
    ).replace(
        'small_key_sha256="d" * 64,',
        'small_key_sha256=r.sha_bytes(f"small/key{keyset}".encode()),',
    )
    (HERE / "synthetic.py").write_text(synthetic)
    origins = {
        str(OLD / f): sha(OLD / f)
        for f in unchanged
        + [
            "src/gate.rs",
            "replay.py",
            "synthetic.py",
            "run_gate.py",
            "verify.py",
            "MANIFEST.json",
            "SOURCE_MANIFEST.json",
            "artifacts/first-precision-validation.json",
            "artifacts/independent-review/review.json",
            "artifacts/independent-review/MANIFEST.json",
        ]
    }
    (HERE / "SOURCE_ORIGINS.json").write_text(
        json.dumps(dict(files=origins, unchanged=unchanged), indent=2) + "\n"
    )
    (HERE / "SOURCE_PINS.json").write_bytes((OLD / "SOURCE_PINS.json").read_bytes())
    diff = difflib.unified_diff(
        (OLD / "src/gate.rs").read_text().splitlines(True),
        source.splitlines(True),
        fromfile="A187/src/gate.rs",
        tofile="A192/src/gate.rs",
    )
    (HERE / "HARNESS.patch").write_text("".join(diff))


if __name__ == "__main__":
    main()
