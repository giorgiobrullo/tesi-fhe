// A176 orchestration only. The included A155 helpers and four crypto/model modules are frozen.
const A176_ACK: &str = "A176_FIXED_THREE_KEY_C1_AUTHORIZED";

fn anchor(client: &ClientKeys, key: &EvaluationKeys, key_index: usize) -> bool {
    emit(json!({"type":"meta","experiment":"A176","suite":"witness",
        "key_index":key_index,"source_sha256":SOURCE_DIGEST.trim()}));
    emit(
        json!({"type":"key_ready","key_id":format!("fixed-key-{key_index}"),
        "original_added_payload_bytes":key.added_payload_bytes,
        "zero_pool_payload_bytes":key.zero_pool_payload_bytes,"zero_rows":1515,"payload_is_rss":false}),
    );
    let (stock_positive, unmet_negative) = run_stock(client, key);
    let w = run_witness(client, key);
    let old_pass = stock_positive && unmet_negative && w.positive && w.original_graph_negatives;
    let a155_pass = stock_positive
        && unmet_negative
        && w.positive
        && w.non_wrong_graph_negatives
        && w.margin_controls;
    let passed = stock_positive && unmet_negative && w.positive && w.non_wrong_graph_negatives;
    emit(json!({"type":"summary","suite":"witness","fresh_keys":1,
        "stock_pair_pass":stock_positive,"forced_unmet_detected":unmet_negative,
        "n4_pair_pass":w.positive,"graph_negatives_pass":w.original_graph_negatives,
        "bounded_diagnostic_gate_pass":old_pass,
        "original_a150_bounded_diagnostic_gate_pass":old_pass,
        "original_a150_graph_negatives_pass":w.original_graph_negatives,
        "original_non_wrong_graph_negatives_pass":w.non_wrong_graph_negatives,
        "egress_margin_controls_pass":w.margin_controls,"a155_margin_control_gate_pass":a155_pass,
        "full_c1_requirement_satisfied":false,"noise_improvement_claim":false,
        "formal_failure_claim":false,"service_claim":false,"timing_claim":false}));
    emit(
        json!({"type":"a176_anchor_result","key_index":key_index,"passed":passed,
        "original_a150_gate_pass":old_pass,"original_a155_gate_pass":a155_pass,
        "wrong_map_and_finite_coverage_are_diagnostic":true,"key_resampling":false}),
    );
    passed
}

fn same_ciphertexts(left: &[crypto::Lwe], right: &[crypto::Lwe]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.as_ref() == b.as_ref())
}

fn expanded_pair(
    client: &ClientKeys,
    key: &EvaluationKeys,
    fixture: &Fixture,
    layout: Layout,
    key_index: usize,
    pair_index: usize,
) -> (bool, bool) {
    let id = format!("k{key_index}/p{pair_index}");
    emit(
        json!({"type":"a176_pair_begin","key_index":key_index,"pair_index":pair_index,
        "fixture":fixture.name,"bit":layout.bit,"n":fixture.active.len(),
        "public_active":fixture.active,"public_bits":fixture.bits,"fixture_preparation_pbs":2*fixture.active.len()}),
    );
    let (active, bits, trace) = prepare(client, key, fixture, layout);
    let saved_active = active.clone();
    let saved_bits = bits.clone();
    // Both evaluations finish before either client check. One preparation is shared.
    let plain = crypto::run_round(key, &active, &bits, layout, Mutation::None, Policy::Plain);
    let adapted = crypto::run_round(
        key,
        &active,
        &bits,
        layout,
        Mutation::None,
        Policy::SharedZerosStockAssumption,
    );
    let input_unchanged =
        same_ciphertexts(&active, &saved_active) && same_ciphertexts(&bits, &saved_bits);
    let a = check(
        client,
        fixture,
        layout,
        Mutation::None,
        &trace,
        &plain,
        &format!("{id}/plain"),
    );
    let b = check(
        client,
        fixture,
        layout,
        Mutation::None,
        &trace,
        &adapted,
        &format!("{id}/shared_zero"),
    );
    let complete = plain.completed && adapted.completed;
    let passed = a.passed && b.passed && input_unchanged;
    emit(
        json!({"type":"a176_pair_result","key_index":key_index,"pair_index":pair_index,
        "plain_pass":a.passed,"shared_zero_pass":b.passed,"both_completed":complete,
        "source_asserted_input_ciphertexts_unchanged":input_unchanged,"passed":passed,
        "status":if passed {"PASS_ROUND_PAIR"} else if !complete {"INCONCLUSIVE_ESTIMATOR_PREFIX"}
            else {"FAILED_CORRECTNESS_PREFIX"},"no_ciphertext_membership_attestation":true}),
    );
    (passed, complete)
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--plan"] {
        emit(
            json!({"type":"a176_plan","status":"NO_KEYGEN_PLAN_ONLY","source_sha256":SOURCE_DIGEST.trim(),
            "stages":["n4-smoke","n4-exhaustive","n127"],"fresh_keysets_per_stage":3,
            "n4_smoke_rounds":192,"n4_exhaustive_rounds":12288,"n127_rounds":432,
            "first_gate":"n4-smoke","automatic_stage_progression":false,"timing_claim":false}),
        );
        return;
    }
    assert_eq!(args.len(), 3, "use --run-authorized --stage STAGE");
    assert_eq!(args[0], "--run-authorized");
    assert_eq!(args[1], "--stage");
    let stage = args[2].as_str();
    let suite = match stage {
        "n4-smoke" => "smoke",
        "n4-exhaustive" => "n4-exhaustive",
        "n127" => "n127",
        _ => panic!("unregistered stage"),
    };
    assert_eq!(std::env::var("A176_RUN_ACK").unwrap_or_default(), A176_ACK);
    assert_eq!(
        std::env::var("A176_SOURCE_SHA256").unwrap_or_default(),
        SOURCE_DIGEST.trim()
    );
    let binary = std::env::var("A176_BINARY_SHA256").expect("hash-verifying runner required");
    assert!(binary.len() == 64 && binary.bytes().all(|b| b.is_ascii_hexdigit()));
    let fixtures = model::fixtures(suite);
    let expected_pairs = 3 * fixtures.len() * LAYOUTS.len();
    emit(
        json!({"type":"a176_meta","schema":"a176-c1-expansion-v1","stage":stage,
        "pid":std::process::id(),"source_sha256":SOURCE_DIGEST.trim(),"runner_verified_binary_sha256":binary,
        "fresh_keysets_requested":3,"pairs_requested":expected_pairs,"rounds_requested":2*expected_pairs,
        "fixed_layout_order":[7,6,5,4,3,2,1,0],"policies":["Plain","SharedZerosStockAssumption"],
        "input_variance_justified":false,"ordinary_cmnr":false,"timing_claim":false,
        "multi_round_composition":false,"client_local_key_sensitive":true}),
    );
    let mut keys = 0;
    let mut pairs = 0;
    let mut passed = true;
    let mut inconclusive = false;
    for key_index in 1..=3 {
        emit(json!({"type":"a176_key_begin","key_index":key_index}));
        let (client, key) = crypto::generate_keys();
        keys += 1;
        let anchor_pass = anchor(&client, &key, key_index);
        let mut key_pass = anchor_pass;
        let mut key_pairs = 0;
        if anchor_pass {
            'cases: for fixture in &fixtures {
                for layout in LAYOUTS {
                    let (okay, complete) =
                        expanded_pair(&client, &key, fixture, layout, key_index, key_pairs);
                    pairs += 1;
                    key_pairs += 1;
                    if !okay {
                        key_pass = false;
                        inconclusive = !complete;
                        break 'cases;
                    }
                }
            }
        }
        emit(
            json!({"type":"a176_key_end","key_index":key_index,"anchor_pass":anchor_pass,
            "pairs_observed":key_pairs,"passed":key_pass}),
        );
        if !key_pass {
            passed = false;
            break;
        }
    }
    let complete = keys == 3 && pairs == expected_pairs;
    let gate = passed && complete;
    emit(
        json!({"type":"a176_summary","stage":stage,"fresh_keysets_created":keys,
        "pairs_observed":pairs,"rounds_observed":2*pairs,"schedule_complete":complete,"gate_pass":gate,
        "status":if gate {"PASS_FIXED_C1_ROUND_SCHEDULE"} else if inconclusive {"INCONCLUSIVE_ESTIMATOR_PREFIX"} else {"FAILED_CORRECTNESS_OR_ANCHOR_PREFIX"},
        "wrong_map_diagnostics_select_keys":false,"eight_round_composition_validated":false,
        "input_variance_justified":false,"formal_failure_claim":false,"timing_claim":false}),
    );
    if !gate {
        std::process::exit(2);
    }
}
