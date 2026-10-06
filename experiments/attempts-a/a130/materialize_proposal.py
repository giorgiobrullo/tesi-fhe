#!/usr/bin/env python3
"""Emit a reviewable patch in A130 only. Never writes the frozen A125 source."""

import difflib
import hashlib
import json
import shutil
import subprocess

import audit

audit.source_check()
source_path = "tmp/a125-low-extraction-gate/src/diagnostic.rs"
source = (audit.ROOT / source_path).read_text()
proposed = source


def replace(old, new):
    global proposed
    assert proposed.count(old) == 1, old[:100]
    proposed = proposed.replace(old, new)


replace(
    "fn emit(record: Value) {",
    """// Frozen A66 target-one raw body: N=2048; coefficients [64,192) equal Delta59.
// This client-only scalar phase observer assumes an exact candidate, ideal KS,
// and zero coefficientwise modulus-switch displacement. It is NOT a PBS run or
// an integrated correctness certificate. The actual consumer is a later gate.
fn a50_target_one_from_scalar_phase(phase: u64) -> i64 {
    let rotation = (((phase as u128) * 4096 + (1u128 << 63)) >> 64) as usize % 4096;
    let value = i64::from((64..192).contains(&(rotation % 2048)));
    if rotation >= 2048 { -value } else { value }
}

fn emit(record: Value) {""",
)
replace(
    "    let mut failures = [0usize; 3];",
    "    let mut failures = [0usize; 3];\n    let mut native_decode_failures = [0usize; 3];\n    let mut consumer_phase_failures = [0usize; 3];",
)
replace(
    "                    let mut bit_mismatches = 0;",
    "                    let mut bit_mismatches = 0;\n                    let mut consumer_phase_mismatches = 0usize;",
)
replace(
    """                        bit_mismatches += usize::from(actual != expected);
                        emit(""",
    """                        bit_mismatches += usize::from(actual != expected);
                        let weight = if bit < 3 { 1u64 << (bit + 1) } else { 1 };
                        let expected_p16 = expected * weight;
                        let p16_error = phase.wrapping_sub(expected_p16 << 59) as i64;
                        let level = 7 - bit;
                        let source_multiplier = [-1i64, -1, -1, -1, -1, 1, -1, -1][level];
                        // Before each four-level refresh, reachable candidates are
                        // -(level % 4)..=1. Probe both live and inactive states.
                        for candidate in -(level as i64 % 4)..=1 {
                            let input = (candidate as u64).wrapping_shl(59)
                                .wrapping_add(phase.wrapping_mul(source_multiplier as u64));
                            let observed = a50_target_one_from_scalar_phase(input);
                            let wanted = i64::from(candidate == 1 && expected == 0);
                            consumer_phase_mismatches += usize::from(observed != wanted);
                            emit(json!({"record":"consumer_scalar_phase","keyset":keyset,
                                "scene":scene,"x":x,"arm":arm.name,"bit":bit,"level":level,
                                "candidate":candidate,"actual":observed,"expected":wanted,
                                "pass":observed==wanted,"input_torus":input.to_string(),
                                "ideal_candidate_and_keyswitch":true,
                                "coefficientwise_modulus_switch_error_assumed_zero":true,
                                "actual_pbs_executed":false}));
                        }
                        emit(json!({"record":"weighted_p16_margin","keyset":keyset,
                            "scene":scene,"x":x,"arm":arm.name,"bit":bit,
                            "expected_p16":expected_p16,"actual_p16":decode(phase,59),
                            "signed_error":p16_error.to_string(),
                            "error_in_delta59":p16_error as f64/(1u64<<59) as f64,
                            "inside_open_half_slot":p16_error.unsigned_abs() < (1u64<<58),
                            "composed_noise_margin_certified":false}));
                        emit(""",
)
replace(
    """                    let top = decode(decrypt_lwe_ciphertext(&big_secret, &arm.top_residual).0, 60);
                    let passed = bit_mismatches == 0
                        && top == x >> 8
                        && arm.frozen_control_identical != Some(false);""",
    """                    let top_phase = decrypt_lwe_ciphertext(&big_secret, &arm.top_residual).0;
                    let top = decode(top_phase, 60);
                    let native_decode_pass = bit_mismatches == 0 && top == x >> 8;
                    let consumer_phase_pass = consumer_phase_mismatches == 0;
                    let passed = native_decode_pass && consumer_phase_pass
                        && arm.frozen_control_identical != Some(false);
                    let actual_low_sha256 = arm.trace.iter()
                        .find(|point| point.stage == "score.low")
                        .map(|point| digest(&point.ciphertext));""",
)
replace(
    """                        failures[arm_index] += usize::from(!passed);""",
    """                        failures[arm_index] += usize::from(!passed);
                        native_decode_failures[arm_index] += usize::from(!native_decode_pass);
                        consumer_phase_failures[arm_index] += usize::from(!consumer_phase_pass);""",
)
replace(
    """"pass":passed,"bit_mismatches":bit_mismatches,"top_actual":top""",
    """"pass":passed,"native_decode_pass":native_decode_pass,"consumer_scalar_phase_pass":consumer_phase_pass,"consumer_scalar_phase_mismatches":consumer_phase_mismatches,"bit_mismatches":bit_mismatches,"top_signed_error":(top_phase.wrapping_sub((x>>8)<<60) as i64).to_string(),"top_actual":top""",
)
replace(
    """"input_low_sha256":digest(&low)""",
    """"input_low_sha256":actual_low_sha256,"source_packed_low_sha256":digest(&low)""",
)
replace(
    """"failures_baseline_shift_single":failures""",
    """"failures_baseline_shift_single":failures,"native_decode_failures_baseline_shift_single":native_decode_failures,"consumer_scalar_phase_failures_baseline_shift_single":consumer_phase_failures,"both_candidates_native_decode_pass":native_decode_failures[1..].iter().all(|count| *count == 0),"both_candidates_consumer_scalar_phase_pass":consumer_phase_failures[1..].iter().all(|count| *count == 0),"both_candidates_all_checks_pass":failures[1..].iter().all(|count| *count == 0)""",
)

# Keep the original package/lockfile graph, but require a distinct executable path.
assert proposed.count("target-a125-only") == 2
proposed = proposed.replace("target-a125-only", "target-a130-a125-only")
proposed = subprocess.run(
    ["rustfmt", "--edition", "2021", "--emit", "stdout"],
    input=proposed,
    text=True,
    capture_output=True,
    check=True,
).stdout
candidate = audit.HERE / "candidate"
candidate.mkdir(exist_ok=True)
for relative in (
    "Cargo.toml",
    "Cargo.lock",
    "src/main.rs",
    "src/frozen_extract.rs",
    "SOURCE_PINS.json",
    "LICENSE.tfhe-rs-BSD-3-Clause-Clear",
):
    destination = candidate / relative
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(audit.ROOT / "tmp/a125-low-extraction-gate" / relative, destination)
(candidate / ".cargo").mkdir(exist_ok=True)
(candidate / ".cargo/config.toml").write_text(
    '[build]\ntarget-dir = "target-a130-a125-only"\n\n[net]\noffline = true\n'
)
(candidate / "src/diagnostic.rs").write_text(proposed)

out = audit.HERE / "artifacts"
(out / "proposed_diagnostic.rs").write_text(proposed)
(out / "proposed_a125.patch").write_text(
    "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            proposed.splitlines(keepends=True),
            fromfile="a/" + source_path,
            tofile="b/" + source_path,
        )
    )
)
hashes = {
    str(path.relative_to(audit.HERE)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(candidate.rglob("*"))
    if path.is_file()
}
(out / "candidate_hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
print(
    "Revised isolated candidate emitted in A130 only; A125 unchanged; no Rust/FHE run."
)
