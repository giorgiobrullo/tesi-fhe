#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
MODULE_DIR = HERE.parent
sys.path.insert(0, str(MODULE_DIR))

import a84_accumulator_binding as a84  # noqa: E402


class A84AccumulatorBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.bundle = a84.build_manifest_and_bundle(127)
        cls.digest = a84.canonical_manifest_sha256(cls.manifest)

    def fresh_manifest(self) -> dict[str, object]:
        return copy.deepcopy(self.manifest)

    def a79_contracts(self, manifest: dict[str, object]) -> dict[str, object]:
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        return {
            accumulator_id: record["a79_contract"]
            for accumulator_id, record in accumulators.items()
        }

    def verify(
        self,
        manifest: dict[str, object],
        bundle: bytes | None = None,
        *,
        digest: str | None = None,
    ) -> dict[str, object]:
        return a84.verify_manifest_and_bundle(
            manifest,
            self.bundle if bundle is None else bundle,
            expected_manifest_sha256=(
                a84.canonical_manifest_sha256(manifest) if digest is None else digest
            ),
        )

    def rehash_body_record(
        self,
        manifest: dict[str, object],
        bundle: bytes | bytearray,
        accumulator_id: str,
    ) -> None:
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        record = accumulators[accumulator_id]
        self.assertIsInstance(record, dict)
        offset = record["body_offset_bytes"]
        length = record["body_length_bytes"]
        body = bytes(bundle[offset : offset + length])
        body_digest = hashlib.sha256(body).hexdigest()
        record["body_sha256"] = body_digest
        record["body_id"] = f"sha256:{body_digest}"
        pre_rotation = record["expected_pre_rotation_glwe"]
        self.assertIsInstance(pre_rotation, dict)
        pre_rotation["full_glwe_sha256"] = hashlib.sha256(
            bytes(2_048 * 8) + body
        ).hexdigest()
        raw_bundle = manifest["bundle"]
        self.assertIsInstance(raw_bundle, dict)
        raw_bundle["sha256"] = hashlib.sha256(bundle).hexdigest()

    def test_pinned_sources_and_n127_bundle_pass(self) -> None:
        evidence = a84.verify_source_pins()
        self.assertEqual(len(evidence), 9)
        result = self.verify(self.fresh_manifest(), digest=self.digest)
        self.assertEqual(
            result["status"], "PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES"
        )
        self.assertEqual(result["accumulator_instances"], 35)
        self.assertEqual(result["body_coefficients_verified"], 71_680)
        self.assertEqual(result["strict_plateau_evaluations"], 78_105)
        self.assertEqual(result["actual_a79_contracts_parsed"], 35)
        self.assertEqual(result["actual_a79_samples_parsed"], 67)
        self.assertFalse(result["runtime_accumulator_bytes_attested"])
        self.assertFalse(result["runtime_input_domain_attested"])

    def test_every_projection_passes_and_matches_the_actual_a79_v3_parser(self) -> None:
        result = a84.verify_with_actual_a79_parser(
            self.a79_contracts(self.fresh_manifest()), 2_048
        )
        self.assertEqual(result["contracts_parsed"], 35)
        self.assertEqual(result["samples_parsed"], 67)
        self.assertEqual(
            result["parser_sha256"],
            a84.SOURCE_PINS["a79_manifest_parser"].sha256,
        )
        self.assertEqual(
            result["crypto_domain_model_sha256"],
            a84.SOURCE_PINS["a79_crypto_domain_model"].sha256,
        )

    def test_native_alias_is_rejected_by_a84_and_actual_a79_parser(self) -> None:
        manifest = self.fresh_manifest()
        contracts = self.a79_contracts(manifest)
        contracts["a53.group_or"]["input_crypto_domain"]["ciphertext_modulus"] = (
            "native"
        )
        with self.assertRaisesRegex(
            a84.BindingError, "actual A79 parser rejected projections"
        ):
            a84.verify_with_actual_a79_parser(contracts, 2_048)
        with self.assertRaisesRegex(a84.BindingError, "input crypto domain"):
            self.verify(manifest)

    def test_out_of_period_input_reachable_is_rejected_by_both_verifiers(self) -> None:
        manifest = self.fresh_manifest()
        contracts = self.a79_contracts(manifest)
        contracts["a53.group_or"]["input_reachable_overapprox"].append(999)
        with self.assertRaisesRegex(
            a84.BindingError, "reachable value is outside the declared encoding"
        ):
            a84.verify_with_actual_a79_parser(contracts, 2_048)
        with self.assertRaisesRegex(a84.BindingError, "outside the declared encoding"):
            self.verify(manifest)

    def test_build_is_byte_and_digest_deterministic(self) -> None:
        second_manifest, second_bundle = a84.build_manifest_and_bundle(127)
        self.assertEqual(second_bundle, self.bundle)
        self.assertEqual(second_manifest, self.manifest)
        self.assertEqual(a84.canonical_manifest_sha256(second_manifest), self.digest)

    def test_every_n127_record_is_one_full_u64_polynomial(self) -> None:
        bundle = self.manifest["bundle"]
        self.assertIsInstance(bundle, dict)
        self.assertEqual(bundle["length_bytes"], 35 * 2_048 * 8)
        accumulators = self.manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        self.assertEqual(len(accumulators), 35)
        self.assertEqual(
            [
                name for name in accumulators if name.startswith("a53.selector")
            ].__len__(),
            32,
        )
        self.assertIn("a53.selector.g31.len3", accumulators)

    def test_negative_selector_phases_and_both_samples_cover_full_margin(self) -> None:
        model = a84.load_source_model()
        selector = next(
            record
            for record in a84.derive_records(model, 127)
            if record.accumulator_id == "a53.selector.g30.len4"
        )
        phases = {case.input_phase_signed for case in selector.truth_cases}
        self.assertEqual(phases, set(range(-4, 5)))
        checks = a84.verify_truth_table(
            selector.torus_coefficients, selector.truth_cases, model
        )
        self.assertEqual(checks, 9 * 127 * 2)
        case = next(
            case for case in selector.truth_cases if case.input_phase_signed == -4
        )
        self.assertEqual(
            {output.sample_degree for output in case.outputs},
            {0, 1024},
        )

    def test_truth_checker_compares_exact_torus_words_not_only_decoded_residues(
        self,
    ) -> None:
        model = a84.load_source_model()
        group_or = a84.derive_records(model, 127)[0]
        coefficients = list(group_or.torus_coefficients)
        coefficients[0] += 1
        with self.assertRaisesRegex(a84.BindingError, "truth-table mismatch"):
            a84.verify_truth_table(coefficients, group_or.truth_cases, model)

    def test_one_bit_body_mutation_is_rejected_even_after_rehash(self) -> None:
        manifest = self.fresh_manifest()
        bundle = bytearray(self.bundle)
        bundle[0] ^= 1
        self.rehash_body_record(manifest, bundle, "a53.group_or")
        with self.assertRaisesRegex(a84.BindingError, "pinned Rust construction"):
            self.verify(manifest, bytes(bundle))

    def test_per_word_endian_swap_is_rejected_even_after_rehash(self) -> None:
        manifest = self.fresh_manifest()
        bundle = bytearray(self.bundle)
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        record = accumulators["a53.local_first"]
        self.assertIsInstance(record, dict)
        offset = record["body_offset_bytes"]
        length = record["body_length_bytes"]
        for start in range(offset, offset + length, 8):
            bundle[start : start + 8] = reversed(bundle[start : start + 8])
        self.rehash_body_record(manifest, bundle, "a53.local_first")
        with self.assertRaisesRegex(a84.BindingError, "pinned Rust construction"):
            self.verify(manifest, bytes(bundle))

    def test_truth_table_mutation_is_rejected_after_rehash(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        record = accumulators["a53.selector.g00.len4"]
        self.assertIsInstance(record, dict)
        truth = record["truth_table"]
        self.assertIsInstance(truth, list)
        outputs = truth[-1]["outputs"]
        outputs[0]["expected_residue"] = (outputs[0]["expected_residue"] + 1) % 16
        record["truth_table_sha256"] = hashlib.sha256(
            a84.canonical_json_bytes(truth)
        ).hexdigest()
        with self.assertRaisesRegex(a84.BindingError, "truth table differs"):
            self.verify(manifest)

    def test_wrong_public_offset_is_rejected_after_rehash(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        record = accumulators["a53.selector.g14.len4"]
        truth = record["truth_table"]
        truth[0]["outputs"][1]["public_offset"] ^= 1
        record["truth_table_sha256"] = hashlib.sha256(
            a84.canonical_json_bytes(truth)
        ).hexdigest()
        with self.assertRaisesRegex(a84.BindingError, "truth table differs"):
            self.verify(manifest)

    def test_a79_reachable_output_may_not_exclude_an_actual_value(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        self.assertIsInstance(accumulators, dict)
        contract = accumulators["a53.group_or"]["a79_contract"]
        contract["samples"][0]["reachable_overapprox"] = [0]
        with self.assertRaisesRegex(a84.BindingError, "excludes a truth-table output"):
            self.verify(manifest)

    def test_a79_reachable_input_may_not_exclude_a_declared_phase(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        contract = accumulators["a53.selector.g31.len3"]["a79_contract"]
        contract["input_reachable_overapprox"].remove(31)
        with self.assertRaisesRegex(
            a84.BindingError, "excludes a declared truth-table phase"
        ):
            self.verify(manifest)

    def test_a79_mode_margin_and_sample_degree_mutations_are_rejected(self) -> None:
        for field, value, message in (
            ("pbs_mode", "checked_classic_ks_pbs", "raw_br_small_input"),
            ("strict_margin_radius", 62, "strict margin differs"),
            ("strict_margin_unit", "torus", "wrong coordinate"),
        ):
            with self.subTest(field=field):
                manifest = self.fresh_manifest()
                accumulators = manifest["accumulators"]
                contract = accumulators["a53.group_or"]["a79_contract"]
                contract[field] = value
                with self.assertRaisesRegex(a84.BindingError, message):
                    self.verify(manifest)
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        contract = accumulators["a53.selector.g00.len4"]["a79_contract"]
        contract["samples"][1]["sample_degree"] = 1023
        with self.assertRaisesRegex(a84.BindingError, "sample map differs"):
            self.verify(manifest)

    def test_pre_rotation_glwe_mask_and_full_digest_are_explicit(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        record = accumulators["a53.group_or"]
        pre_rotation = record["expected_pre_rotation_glwe"]
        self.assertTrue(pre_rotation["mask_expected_all_zero"])
        self.assertEqual(pre_rotation["glwe_size"], 2)
        self.assertEqual(pre_rotation["mask_coefficient_count"], 2_048)

        pre_rotation["mask_expected_all_zero"] = False
        with self.assertRaisesRegex(a84.BindingError, "pre-rotation GLWE is invalid"):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        pre_rotation = accumulators["a53.group_or"]["expected_pre_rotation_glwe"]
        pre_rotation["full_glwe_sha256"] = "0" * 64
        with self.assertRaisesRegex(a84.BindingError, "pre-rotation GLWE is invalid"):
            self.verify(manifest)

    def test_body_and_contract_identifiers_cannot_be_substituted(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        accumulators["a53.group_or"]["body_id"] = accumulators["a53.local_first"][
            "body_id"
        ]
        with self.assertRaisesRegex(
            a84.BindingError, "body ID is not content-addressed"
        ):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        accumulators["a53.group_or"]["contract_id"] = "forged"
        with self.assertRaisesRegex(a84.BindingError, "contract ID is not canonical"):
            self.verify(manifest)

    def test_missing_extra_reordered_and_overlapping_records_are_rejected(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        del accumulators["a53.group_or"]
        with self.assertRaisesRegex(a84.BindingError, "accumulator set differs"):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        accumulators["forged"] = copy.deepcopy(accumulators["a53.group_or"])
        with self.assertRaisesRegex(a84.BindingError, "accumulator set differs"):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        raw_bundle = manifest["bundle"]
        raw_bundle["record_order"][0], raw_bundle["record_order"][1] = (
            raw_bundle["record_order"][1],
            raw_bundle["record_order"][0],
        )
        with self.assertRaisesRegex(a84.BindingError, "record order differs"):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        accumulators["a53.local_first"]["body_offset_bytes"] = 0
        with self.assertRaisesRegex(a84.BindingError, "layout is non-canonical"):
            self.verify(manifest)

    def test_unindexed_trailing_bytes_and_truncated_bundle_are_rejected(self) -> None:
        manifest = self.fresh_manifest()
        bundle = self.bundle + b"\x00" * 8
        raw_bundle = manifest["bundle"]
        raw_bundle["length_bytes"] = len(bundle)
        raw_bundle["sha256"] = hashlib.sha256(bundle).hexdigest()
        with self.assertRaisesRegex(a84.BindingError, "trailing bytes"):
            self.verify(manifest, bundle)

        with self.assertRaisesRegex(a84.BindingError, "byte length"):
            self.verify(self.fresh_manifest(), self.bundle[:-8], digest=self.digest)

    def test_manifest_mutation_fails_the_independently_supplied_digest_first(
        self,
    ) -> None:
        manifest = self.fresh_manifest()
        manifest["scope"] = "coherently invented replacement"
        with self.assertRaisesRegex(a84.BindingError, "independently supplied digest"):
            self.verify(manifest, digest=self.digest)

    def test_boolean_offsets_and_noncanonical_hashes_are_rejected(self) -> None:
        manifest = self.fresh_manifest()
        accumulators = manifest["accumulators"]
        record = accumulators["a53.group_or"]
        record["body_offset_bytes"] = False
        with self.assertRaisesRegex(a84.BindingError, "must be an integer"):
            self.verify(manifest)

        manifest = self.fresh_manifest()
        raw_bundle = manifest["bundle"]
        raw_bundle["sha256"] = raw_bundle["sha256"].upper()
        with self.assertRaisesRegex(a84.BindingError, "lowercase SHA-256"):
            self.verify(manifest)

    def test_source_pin_rejects_wrong_bytes_and_missing_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.rs"
            path.write_text("anchor\n", encoding="utf-8")
            wrong_digest = "0" * 64
            with mock.patch.dict(
                a84.SOURCE_PINS,
                {
                    "fixture": a84.SourcePin(path, wrong_digest, ("anchor",)),
                },
                clear=True,
            ):
                with self.assertRaisesRegex(a84.BindingError, "source drift"):
                    a84.verify_source_pins()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with mock.patch.dict(
                a84.SOURCE_PINS,
                {
                    "fixture": a84.SourcePin(path, digest, ("missing",)),
                },
                clear=True,
            ):
                with self.assertRaisesRegex(
                    a84.BindingError, "missing pinned fragment"
                ):
                    a84.verify_source_pins()

    def test_json_round_trip_preserves_the_verifiable_manifest(self) -> None:
        round_tripped = json.loads(json.dumps(self.manifest))
        result = self.verify(round_tripped, digest=self.digest)
        self.assertEqual(result["manifest_sha256"], self.digest)


if __name__ == "__main__":
    unittest.main()
