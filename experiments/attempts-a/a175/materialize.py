"""Materialize only the A175 isolated source; never build or execute cryptography."""

from pathlib import Path
import difflib
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a169-low-correction-b0-b1-repair"


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError("nonunique source anchor: " + before[:100])
    return text.replace(before, after, 1)


def materialize():
    old = (OLD / "candidate/src/diagnostic.rs").read_text()
    text = old
    for before, after in [
        (
            '"A169_EXCLUSIVE_B0_B1_REPAIR_AUTHORIZED"',
            '"A175_ACTUAL_CONSUMER_AUTHORIZED"',
        ),
        ('"A169_RUN_ACK"', '"A175_RUN_ACK"'),
        ('"A169_SOURCE_SHA256"', '"A175_SOURCE_SHA256"'),
    ]:
        text = replace(text, before, after)
    text = text.replace("target-a169-b0-b1-only", "target-a175-actual-consumer-only")
    text = replace(
        text,
        "pub fn run() -> Result<(), String> {",
        'include!("actual_consumer.rs");\n\npub fn run() -> Result<(), String> {',
    )
    text = replace(
        text,
        "    let targets = boundary_targets(&stage)?;",
        """    let targets = boundary_targets(&stage)?;
    a175_emit(json!({"record":"consumer_plan","stage":stage,"keysets":keysets,
        "producer_schema":A169_SCHEMA,"consumer_arms":["baseline_dual","single_full_direct_b0_b1"],
        "scores":28,"consumer_states_per_arm_per_score":28,"consumer_calls":1568,
        "candidate_encryptions":784,"consumer_ks":1568,"consumer_traced_br":1568,
        "consumer_stock_br":1568,"consumer_samples":3136,
        "producer_br":1988,"producer_ks":1792,"producer_samples_including_score_extraction":2884,
        "total_br":5124,"total_ks":3360,"total_samples":6020,"total_records":17703,
        "candidate_provenance":"fresh_client_lwe_not_prior_selector_round",
        "first_key_only":true,"automatic_retry":false,"automatic_expansion":false,
        "native_zero_mask_branch_retained":true,"stock_equivalence_required":true,
        "p_fail_certified":false,"latency_claim_allowed":false}));""",
    )
    text = replace(
        text,
        "    let mut failures = [0usize; 5];",
        """    let mut consumer_failure_counts = [[0usize; 6]; 2];
    let mut consumer_case_failures = [0usize; 2];
    let mut failures = [0usize; 5];""",
    )
    text = replace(
        text,
        '        for scene in ["sparse_nonzero", "dense_nonzero"] {',
        '        a175_key_record(&server, keyset);\n        for scene in ["sparse_nonzero", "dense_nonzero"] {',
    )
    text = replace(
        text,
        "                // All six server arms finished before comparisons or any client decryption.",
        """                // Original six producer arms are complete. Encrypt each registered
                // candidate once and share that same ciphertext between the two consumers.
                // These are fresh client LWEs, not outputs of preceding selector rounds.
                let mut actual_consumers = Vec::new();
                for bit in 0..8usize {
                    let level = 7 - bit;
                    for candidate_state in -(level as i64 % 4)..=1 {
                        let encrypted_candidate = allocate_and_encrypt_new_lwe_ciphertext(
                            &big_secret, Plaintext((candidate_state as u64).wrapping_shl(59)),
                            parameters.glwe_noise_distribution(), modulus, &mut generator,
                        );
                        for arm_index in [0usize, 4usize] {
                            let multiplier = if bit == 2 { 1i64 } else { -1i64 };
                            let (input, switched, output, receipt, stock_glwe_identical,
                                stock_output_identical, traced_glwe_sha256, stock_glwe_sha256,
                                stock_output_sha256) = a175_consume(&encrypted_candidate,
                                    &arms[arm_index].weighted_bits[bit], multiplier, &server);
                            actual_consumers.push(A175Consumer { arm_index, bit, candidate_state,
                                candidate: encrypted_candidate.clone(), input, switched, output,
                                receipt, stock_glwe_identical, stock_output_identical,
                                traced_glwe_sha256, stock_glwe_sha256, stock_output_sha256 });
                        }
                    }
                }
                // All producer and actual-consumer server work is complete before client decryption.""",
    )
    text = replace(
        text,
        "                cases += 1;",
        """                let mut local_failures = [[0usize; 6]; 2];
                for consumer in &actual_consumers {
                    let arm_slot = usize::from(consumer.arm_index == 4);
                    let gates = a175_observe(consumer,
                        &arms[consumer.arm_index].weighted_bits[consumer.bit],
                        &big_secret, &small_secret, &server, keyset, scene, x);
                    for (index, gate) in gates.into_iter().enumerate() {
                        local_failures[arm_slot][index] += usize::from(!gate);
                        consumer_failure_counts[arm_slot][index] += usize::from(!gate);
                    }
                }
                for arm in 0..2 { consumer_case_failures[arm] += usize::from(local_failures[arm].iter().any(|n|*n!=0)); }
                a175_emit(json!({"record":"consumer_case","keyset":keyset,"scene":scene,"x":x,
                    "consumers":56,"candidate_encryptions":28,"failure_counts":local_failures,
                    "gate_order":["candidate_native","actual_address","output_at_actual_address","semantic_output","stock_equivalence","observer_closure"],
                    "all_consumer_gates_pass":local_failures.iter().flatten().all(|n|*n==0)}));
                cases += 1;""",
    )
    text = replace(
        text,
        "    if !repair_b0_b1_gate_pass {",
        """    let actual_consumer_gate_pass = consumer_failure_counts.iter().flatten().all(|n|*n==0);
    let complete_gate_pass = repair_b0_b1_gate_pass && actual_consumer_gate_pass;
    a175_emit(json!({"record":"consumer_summary","status":if complete_gate_pass {"PASS_A175_ACTUAL_CONSUMER"} else {"FAIL_A175_ACTUAL_CONSUMER"},
        "cases":cases,"consumer_calls":cases*56,"candidate_encryptions":cases*28,
        "producer_gate_pass":repair_b0_b1_gate_pass,"actual_consumer_gate_pass":actual_consumer_gate_pass,
        "complete_gate_pass":complete_gate_pass,"failure_counts":consumer_failure_counts,
        "case_failures":consumer_case_failures,"total_br":cases*183,"total_ks":cases*120,
        "total_samples":cases*215,"process_id":std::process::id(),
        "candidate_is_previous_selector_output":false,"full_exact_id_validated":false,
        "actual_p_fail":null,"latency_claim_allowed":false}));
    if !complete_gate_pass {
        return Err("A175 complete first-key gate failed; preserve every producer/consumer outcome without retry".into());
    }
    if !repair_b0_b1_gate_pass {""",
    )
    text = subprocess.run(
        ["rustfmt", "--edition", "2021", "--emit", "stdout"],
        input=text,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    (HERE / "candidate/src/diagnostic.rs").write_text(text)
    (HERE / "DIAGNOSTIC.patch").write_text(
        "".join(
            difflib.unified_diff(
                old.splitlines(True),
                text.splitlines(True),
                fromfile="frozen-a169/diagnostic.rs",
                tofile="a175/diagnostic.rs",
            )
        )
    )
    return hashlib.sha256(text.encode()).hexdigest()


if __name__ == "__main__":
    print(
        json.dumps(
            {"diagnostic_sha256": materialize(), "cryptographic_execution": False}
        )
    )
