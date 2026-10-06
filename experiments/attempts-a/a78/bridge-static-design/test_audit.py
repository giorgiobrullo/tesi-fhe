import pathlib
import unittest

import audit


class A78BridgeStaticAuditTests(unittest.TestCase):
    def test_all_repository_and_tfhe_sources_are_pinned(self) -> None:
        observed = audit.source_pin_audit()
        self.assertEqual(
            len(observed), len(audit.REPOSITORY_PINS) + len(audit.TFHE_PINS)
        )
        self.assertTrue(all(len(digest) == 64 for digest in observed.values()))

    def test_required_tfhe_1_7_apis_exist_but_u2_feature_is_not_enabled(self) -> None:
        witnesses = audit.api_witness_audit()
        self.assertEqual(set(witnesses), set(audit.API_WITNESSES))
        decision = audit.decision()
        self.assertIn("experimental", decision.required_u2_manifest_change)
        self.assertIn("SOURCE_GO_ONLY", decision.u2_tfhe_1_7_source_bridge)
        self.assertIn("NO_GO", decision.legacy_tfhe_0_11_direct_bridge)
        self.assertIn("cancel the mask", decision.same_key_same_mask_failure)
        self.assertIn("independent", decision.proper_common_mask_invariant)

    def test_representation_boundaries_are_exact(self) -> None:
        rows = {row.name: row for row in audit.representations()}
        self.assertEqual(
            (
                rows["U2/A44 big Boolean"].mask_dimension,
                rows["U2/A44 big Boolean"].container_u64s,
                rows["U2/A44 big Boolean"].delta_log,
            ),
            (2048, 2049, 59),
        )
        self.assertEqual(
            (
                rows["U2/A44 small PBS input"].mask_dimension,
                rows["U2/A44 small PBS input"].container_u64s,
            ),
            (859, 860),
        )
        self.assertEqual(
            (
                rows["A78 CM-small w2"].mask_dimension,
                rows["A78 CM-small w2"].bodies,
                rows["A78 CM-small w2"].container_u64s,
                rows["A78 CM-small w2"].delta_log,
            ),
            (762, 2, 764, 61),
        )
        self.assertEqual(
            (
                rows["A78 CM-big w2"].mask_dimension,
                rows["A78 CM-big w2"].bodies,
                rows["A78 CM-big w2"].container_u64s,
            ),
            (1536, 2, 1538),
        )

    def test_selected_evaluation_key_payloads_follow_container_formulas(self) -> None:
        ingress, egress = audit.evaluation_keys()
        self.assertEqual(ingress.u64_elements, 2 * 2048 * 4 * (762 + 2))
        self.assertEqual(ingress.payload_bytes, 100_139_008)
        self.assertEqual(egress.u64_elements, 1536 * 5 * (859 + 1))
        self.assertEqual(egress.payload_bytes, 52_838_400)
        totals = audit.bridge_key_totals()
        self.assertEqual(totals["bridge_only_bytes"], 152_977_408)
        self.assertEqual(totals["bridge_only_mib"], 145.890625)
        self.assertEqual(
            totals["existing_a78_core_pmk_bsk_cmks_bytes"], 115_683_328
        )
        self.assertEqual(
            totals["combined_extra_evaluation_payload_bytes"], 268_660_736
        )
        self.assertEqual(totals["combined_extra_evaluation_payload_mib"], 256.21484375)
        self.assertEqual(totals["cm_ggsw_payload_bytes_each"], 102_400)
        self.assertEqual(totals["cm_bsk_cm_ggsw_count"], 762)
        self.assertEqual(totals["pmk_cm_ggsw_count"], 1)
        self.assertEqual(totals["stored_cm_ggsw_count"], 763)

    def test_pareto_bridge_options_keep_latency_and_memory_axes_separate(self) -> None:
        rows = {(row.boundary, row.name): row for row in audit.bridge_options()}
        self.assertEqual(
            rows[("ingress", "direct A44-big packing")].additional_key_payload_bytes,
            100_139_008,
        )
        self.assertEqual(
            rows[("ingress", "reuse A44 big-to-small KSK before CM packing")]
            .additional_key_payload_bytes,
            42_001_664,
        )
        self.assertEqual(
            rows[("egress", "stock-spacing scale restore")]
            .additional_key_payload_bytes,
            52_838_400,
        )
        fast = rows[("egress", "direct big-key egress")]
        self.assertEqual(fast.additional_key_payload_bytes, 125_890_560)
        self.assertIn("UNPROMOTED", fast.status)

    def test_per_group_operation_ledger_matches_source_loops(self) -> None:
        full = audit.group_bridge_operations(4)
        tail = audit.group_bridge_operations(3)
        n2 = audit.group_bridge_operations(2)
        self.assertEqual(
            (full.a44_big_pair_additions, tail.a44_big_pair_additions, n2.a44_big_pair_additions),
            (2, 1, 1),
        )
        self.assertEqual(
            (
                full.a44_big_cleartext_multiplications,
                tail.a44_big_cleartext_multiplications,
                n2.a44_big_cleartext_multiplications,
            ),
            (2, 2, 1),
        )
        self.assertEqual(full.packing_vector_updates, 16_384)
        self.assertEqual(full.packing_coefficient_updates, 12_517_376)
        self.assertEqual(full.packing_output_clear_u64s, 764)
        self.assertEqual(full.packing_body_additions, 2)
        self.assertEqual(full.cm_blind_rotations_inside_or4, 2)
        self.assertEqual(
            (full.cm_bsk_external_products_min, full.cm_bsk_external_products_max),
            (0, 1_524),
        )
        self.assertEqual(full.pmk_external_products, 1)
        self.assertEqual(full.cm_glwe_additions, 1)
        self.assertEqual(full.cm_sample_extractions_inside_or4, 2)
        self.assertEqual(full.cm_keyswitches_inside_or4, 1)
        self.assertEqual(full.cm_big_lane_copy_u64s, 1_537)
        self.assertEqual(full.egress_ks_vector_updates, 7_680)
        self.assertEqual(full.egress_ks_coefficient_updates, 6_604_800)
        self.assertEqual(full.scale_restore_a44_blind_rotations, 1)

    def test_n127_conservative_bridge_restores_ordinary_counts(self) -> None:
        row = audit.n127_ledger()
        self.assertEqual((row.groups, row.full_groups, row.tail_groups), (32, 31, 1))
        self.assertEqual((row.pair_additions, row.cleartext_multiplications_by_four), (63, 64))
        self.assertEqual((row.cm_packing_calls, row.cm_blind_rotations_inside_or4), (32, 64))
        self.assertEqual(
            (row.cm_bsk_external_products_min, row.cm_bsk_external_products_max),
            (0, 48_768),
        )
        self.assertEqual((row.pmk_external_products, row.cm_glwe_additions), (32, 32))
        self.assertEqual((row.structural_lane0_copies, row.egress_classic_keyswitches), (32, 32))
        self.assertEqual(row.packing_output_clear_u64s, 24_448)
        self.assertEqual(row.packing_body_additions, 64)
        self.assertEqual(row.packing_vector_updates, 524_288)
        self.assertEqual(row.packing_coefficient_updates, 400_556_032)
        self.assertEqual(row.structural_lane0_copy_u64s, 49_184)
        self.assertEqual(row.egress_ks_vector_updates, 245_760)
        self.assertEqual(row.egress_ks_coefficient_updates, 211_353_600)
        self.assertEqual((row.scale_restore_a44_blind_rotations, row.scale_restore_a44_sample_extractions), (32, 32))
        self.assertEqual(
            (
                row.ordinary_a53_blind_rotations_after_replacement,
                row.ordinary_a53_classic_keyswitches_after_replacement,
            ),
            (3390, 3009),
        )

    def test_clear_phase_bridge_and_first_id_semantics(self) -> None:
        self.assertEqual(audit.clear_bridge_flag((0, 0)), 0)
        self.assertEqual(audit.clear_bridge_flag((0, 1)), 1)
        self.assertEqual(audit.clear_bridge_flag((0, 0, 1)), 1)
        self.assertEqual(audit.clear_bridge_flag((0, 0, 0, 1)), 1)
        with self.assertRaises(ValueError):
            audit.clear_bridge_flag((0, 2, 0, 0))
        result = audit.functional_audit()
        self.assertEqual(result["small_patterns_checked"], 8190)
        self.assertEqual(result["n127_reject_singleton_tie_cases_checked"], 133)
        self.assertEqual(result["mismatches"], 0)

    def test_noise_is_symbolic_and_no_paper_runtime_ratio_is_used(self) -> None:
        rows = audit.noise_ledger()
        self.assertTrue(all(row.numeric_bound is None for row in rows))
        self.assertIn("4*(epsilon_i+epsilon_j)", rows[1].exact_phase_relation)
        decision = audit.decision()
        self.assertFalse(decision.paper_one_over_1000_used)
        self.assertIn("cycle", decision.security_assumption_gap)

    def test_rust_scaffold_is_isolated_server_side_and_contains_no_decryption(self) -> None:
        root = pathlib.Path(__file__).parent
        source = (root / "bridge_scaffold.rs").read_text()
        for token in (
            "UNCOMPILED_STATIC_DRAFT",
            "allocate_and_generate_new_cm_lwe_packing_key",
            "pack_lwe_ciphertexts_into_cm",
            "lwe_ciphertext_cleartext_mul_assign",
            "extract_lwe_ciphertext(0)",
            "allocate_and_generate_new_lwe_keyswitch_key",
            "programmable_bootstrap_lwe_ciphertext",
            "INGRESS_PACKING_KEY_BYTES",
            "EGRESS_TO_A44_SMALL_KEY_BYTES",
        ):
            self.assertIn(token, source)
        self.assertNotIn("decrypt_lwe_ciphertext", source)
        self.assertNotIn("decrypt_cm_lwe_ciphertext", source)
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
