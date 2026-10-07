"""One-shot source materializer from pinned A165; no build/runtime operations."""

from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a165-low-correction-b1-repair"


def function(source, name):
    match = re.search(r"\bfn " + name + r"\s*\(", source)
    start = source.index("{", match.end())
    depth = 1
    cursor = start + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[match.start() : cursor]


def main():
    old = (OLD / "candidate/src/diagnostic.rs").read_text()
    new = (
        old.replace("A165", "A169")
        .replace("a165.low_b1_direct_scale.v1", "a169.low_b0_b1_direct_scale.v1")
        .replace(
            "A169_EXCLUSIVE_B1_REPAIR_AUTHORIZED",
            "A169_EXCLUSIVE_B0_B1_REPAIR_AUTHORIZED",
        )
        .replace("target-a165-b1-only", "target-a169-b0-b1-only")
    )
    # Keep the complete original b1 function byte-identical, including its legacy panic label.
    new = new.replace(
        function(new, "repaired_b1_arm"), function(old, "repaired_b1_arm")
    )
    addition = """
/// Extend the complete unchanged b1 repair. The consumed b0 output changes;
/// its original full-scale residual correction and all later small inputs do not.
fn repaired_b0_b1_arm(full: &Lwe, sk: &ServerKey) -> Arm {
    let mut arm = repaired_b1_arm(full, sk);
    let retained = arm.trace.iter().find(|point| point.stage == "full.ks_b0").unwrap();
    assert!(retained.small_key);
    let small = retained.ciphertext.clone();
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A169 requires classic BSK"),
    };
    let extra_pbs = AtomicU64::new(0);
    let direct = correction_from_small_bit(
        &small, &accumulator(bsk, 60, false), bsk, full.lwe_size(),
        1u64 << 59, &extra_pbs,
    );
    assert!(direct.boolean.is_none());
    snapshot_raw_correction(&mut arm.trace, "repair_b0", 0, 60, &direct.correction);
    snapshot(&mut arm.trace, "repair_b0.pbs_correction_b0", &direct.correction, false,
        Expectation::Bit { bit: 0, delta_log: 60 });
    arm.weighted_bits[0] = direct.correction;
    arm.pbs += extra_pbs.load(Ordering::Relaxed);
    assert_eq!((arm.pbs, arm.ks), (10, 8));
    arm.name = "single_full_direct_b0_b1";
    arm
}

"""
    new = new.replace("fn boundary_targets(", addition + "fn boundary_targets(", 1)
    new = new.replace(
        '"single_full_direct_b1","negative_drop_first_correction"',
        '"single_full_direct_b1","single_full_direct_b0_b1","negative_drop_first_correction"',
    )
    new = new.replace(
        '"pbs_per_score":[11,11,8,9,8]', '"pbs_per_score":[11,11,8,9,10,8]'
    )
    new = new.replace(
        '"ks_per_score":[8,8,8,8,8]',
        '"ks_per_score":[8,8,8,8,8,8],"repair_pair_records_per_score":2',
    )
    new = (
        new.replace("let mut failures = [0usize; 4]", "let mut failures = [0usize; 5]")
        .replace(
            "let mut native_decode_failures = [0usize; 4]",
            "let mut native_decode_failures = [0usize; 5]",
        )
        .replace(
            "let mut consumer_phase_failures = [0usize; 4]",
            "let mut consumer_phase_failures = [0usize; 5]",
        )
    )
    new = new.replace(
        "let mut repair_pair_failures = 0usize;",
        "let mut repair_pair_failures = 0usize;\n    let mut repair_b0_pair_failures = 0usize;",
        1,
    )
    new = new.replace(
        "                    repaired_b1_arm(&full, &server),",
        "                    repaired_b1_arm(&full, &server),\n                    repaired_b0_b1_arm(&full, &server),",
        1,
    )
    new = new.replace("All five server arms", "All six server arms")
    b0_pair = """
                // A second comparison retains the entire A165 b1 repair as the control.
                let original_b1 = &arms[3];
                let repair_b0_b1 = &arms[4];
                let old_b1_trace_identical = repair_b0_b1.trace.len() == original_b1.trace.len() + 2
                    && original_b1.trace.iter().zip(&repair_b0_b1.trace).all(|(a,b)| {
                        a.stage == b.stage && a.small_key == b.small_key && same_lwe(&a.ciphertext,&b.ciphertext)
                    });
                let b0_top_identical = same_lwe(&original_b1.top_residual,&repair_b0_b1.top_residual);
                let b0_other_weighted_identical = (1..8).all(|bit| same_lwe(&original_b1.weighted_bits[bit],&repair_b0_b1.weighted_bits[bit]));
                let b0_small = repair_b0_b1.trace.iter().find(|point| point.stage == "full.ks_b0").unwrap();
                let b1_small = repair_b0_b1.trace.iter().find(|point| point.stage == "full.ks_b1").unwrap();
                let b0_direct_trace = repair_b0_b1.trace.iter().find(|point| point.stage == "repair_b0.pbs_correction_b0").unwrap();
                let b0_direct_consumed = same_lwe(&repair_b0_b1.weighted_bits[0],&b0_direct_trace.ciphertext);
                let b0_pair_pass = old_b1_trace_identical && b0_top_identical && b0_other_weighted_identical && b0_direct_consumed
                    && original_b1.pbs == 9 && repair_b0_b1.pbs == 10 && original_b1.ks == 8 && repair_b0_b1.ks == 8;
                repair_b0_pair_failures += usize::from(!b0_pair_pass);
                emit(json!({"record":"repair_pair_b0","keyset":keyset,"scene":scene,"x":x,
                    "original_arm":original_b1.name,"repair_arm":repair_b0_b1.name,
                    "old_b1_trace_byte_identical":old_b1_trace_identical,
                    "top_byte_identical":b0_top_identical,"other_weighted_byte_identical":b0_other_weighted_identical,
                    "direct_output_consumed":b0_direct_consumed,"pass":b0_pair_pass,
                    "retained_small_input_sha256":digest(&b0_small.ciphertext),
                    "retained_b1_small_input_sha256":digest(&b1_small.ciphertext),
                    "direct_weighted_b0_sha256":digest(&repair_b0_b1.weighted_bits[0]),
                    "original_x256_b0_sha256":digest(&original_b1.weighted_bits[0]),
                    "original_direct_b1_sha256":digest(&original_b1.weighted_bits[1]),
                    "preserved_direct_b1_sha256":digest(&repair_b0_b1.weighted_bits[1]),
                    "original_top_sha256":digest(&original_b1.top_residual),
                    "repair_top_sha256":digest(&repair_b0_b1.top_residual),
                    "additional_pbs":1,"additional_ks":0,"full_residual_corrections_retained":true}));
"""
    new = new.replace(
        "                // The client now inspects every arm.",
        b0_pair + "                // The client now inspects every arm.",
        1,
    )
    new = new.replace("if arm_index < 4 {", "if arm_index < 5 {", 1)
    new = new.replace(
        '    emit(\n        json!({"record":"summary"',
        '    let repair_b0_b1_gate_pass = controls_valid && repair_pair_failures == 0 && repair_b0_pair_failures == 0 && failures[4] == 0;\n    emit(\n        json!({"record":"summary"',
        1,
    )
    new = new.replace(
        '"single_full_direct_b1"],',
        '"single_full_direct_b1","single_full_direct_b0_b1"],',
    )
    new = new.replace(
        "failures_baseline_shift_single_repair",
        "failures_baseline_shift_single_b1_b0_b1",
    )
    new = new.replace(
        '        "repair_pair_failures":repair_pair_failures,"repair_gate_pass":repair_gate_pass,',
        """        "repair_pair_failures":repair_pair_failures,"repair_gate_pass":repair_gate_pass,
        "repair_b0_pair_failures":repair_b0_pair_failures,
        "repair_b0_b1_native_decode_pass":native_decode_failures[4] == 0,
        "repair_b0_b1_consumer_scalar_phase_pass":consumer_phase_failures[4] == 0,
        "repair_b0_b1_all_checks_pass":failures[4] == 0,
        "repair_b0_b1_gate_pass":repair_b0_b1_gate_pass,""",
        1,
    )
    new = new.replace(
        '    if !repair_gate_pass {\n        return Err("A169 repair or control gate failed; all original outcomes retained".into());',
        '    if !repair_b0_b1_gate_pass {\n        return Err("A169 b0+b1 repair or control gate failed; all prior outcomes retained".into());',
        1,
    )
    (HERE / "candidate/src/diagnostic.rs").write_text(new)


if __name__ == "__main__":
    main()
