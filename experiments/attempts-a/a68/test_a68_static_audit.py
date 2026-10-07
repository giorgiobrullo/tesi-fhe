#!/usr/bin/env python3
"""Clear-only tests for the A68 source, provenance, and A64 ledger audit."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a68_static_audit as audit  # noqa: E402


class RustLexerTests(unittest.TestCase):
    def test_comments_and_strings_do_not_trigger_forbidden_terms(self) -> None:
        source = r'''
            // unchecked_bitand core_crypto
            const NOTE: &str = "smart_bitxor and into_raw_parts";
            /* outer default_bitand /* nested unsafe */ ManyLookupTable */
            let value = r###"apply_lookup_table unchecked_bitor"###;
            approved.checked_bitand(&left, &right)?;
        '''
        active = audit.strip_rust_comments_and_strings(source)
        self.assertEqual(audit.forbidden_active_constructs(active), [])
        self.assertIn("checked_bitand", active)

    def test_each_forbidden_family_is_detected_in_active_code(self) -> None:
        examples = {
            "core": "use crate::core_crypto::prelude::*;",
            "raw": "thing.into_raw_parts();",
            "unchecked": "server.unchecked_bitand(&a, &b);",
            "smart": "server.smart_bitxor(&mut a, &mut b);",
            "default": "server.bitand(&a, &b);",
            "metadata": "ciphertext.set_noise_level(level);",
            "lookup": "server.apply_lookup_table(&a, &lut);",
            "blocks": "ciphertext.blocks_mut();",
            "unsafe": "unsafe { escape(); }",
        }
        for label, source in examples.items():
            with self.subTest(label=label):
                self.assertTrue(audit.forbidden_active_constructs(source))

    def test_unterminated_construct_is_rejected(self) -> None:
        with self.assertRaises(audit.AuditFailure):
            audit.strip_rust_comments_and_strings('let note = "unterminated')


class ContractAuditTests(unittest.TestCase):
    def test_full_static_audit_passes(self) -> None:
        report = audit.run_audit()
        self.assertEqual(report["rust"]["forbidden_constructs"], 0)
        self.assertEqual(
            report["rust"]["checked_call_sites"],
            ["checked_bitand", "checked_bitor", "checked_bitxor"],
        )
        self.assertEqual(report["ledger"]["selected_totals"]["128"], 2_453_981)
        self.assertEqual(report["ledger"]["a64_transitive_pins_verified"], 18)

    def test_manifest_is_exact_and_local_lock_is_absent(self) -> None:
        result = audit.verify_cargo_manifest()
        self.assertEqual(result["tfhe"]["version"], "=0.11.3")
        self.assertFalse(result["tfhe"]["default-features"])
        self.assertEqual(result["tfhe"]["features"], ["integer"])

    def test_a64_ledger_matches_materialized_constants(self) -> None:
        result = audit.verify_a64_ledger()
        self.assertEqual(result["formula"], "M(N) = 24029 + 18984*N")
        self.assertEqual(
            result["selected_totals"],
            {"1": 43_013, "8": 175_901, "127": 2_434_997, "128": 2_453_981},
        )

    def test_current_a64_and_tfhe_sources_are_pinned(self) -> None:
        results = audit.verify_source_pins()
        identifiers = {result["id"] for result in results}
        self.assertIn("a64_tests_current", identifiers)
        self.assertIn("a64_model", identifiers)
        self.assertIn("tfhe_0113_checked_integer_bitops", identifiers)
        self.assertIn("tfhe_0113_parameter", identifiers)
        self.assertGreaterEqual(len(results), 12)

    def test_checked_only_source_contract(self) -> None:
        result = audit.verify_checked_only_rust()
        self.assertEqual(result["bit_newtype"], "private one-block RadixCiphertext")
        self.assertEqual(result["failure_policy"], "Result::Err, no identity response")


if __name__ == "__main__":
    unittest.main()
