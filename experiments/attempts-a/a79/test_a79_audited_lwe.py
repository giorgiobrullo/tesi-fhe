#!/usr/bin/env python3
from __future__ import annotations

import math
import sys
import unittest
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a79_audited_lwe as audit  # noqa: E402


DOMAIN = audit.a44_domain("a79-unit-test-keyset")


def official_atom(atom_id: str, family: str, correlation_id: str) -> audit.NoiseAtom:
    del family
    return audit._fresh_encryption_atom(
        atom_id=atom_id,
        correlation_id=correlation_id,
    )


def fresh_value(
    label: str,
    *,
    degree: int,
    reachable: set[int],
) -> audit.AuditedLwe:
    return audit.audited_fresh_encryption(
        label=label,
        encoding=audit.Encoding("p16", 59, 32, 16, False),
        crypto_domain=DOMAIN,
        reachable_overapprox=reachable,
        shortint_degree=degree,
    )


class A79AuditedLweTests(unittest.TestCase):
    def test_provenance_and_obligation_objects_reject_inconsistent_state(self) -> None:
        atom = official_atom("tracked", "test", "group")
        with self.assertRaisesRegex(ValueError, "keys must match"):
            audit.LinearProvenance(
                atoms={},
                coefficients={"untracked": Fraction(1)},
            )
        with self.assertRaisesRegex(ValueError, "equal"):
            audit.LinearProvenance(
                atoms={"alias": atom},
                coefficients={"alias": Fraction(1)},
            )
        atoms = {"tracked": atom}
        coefficients = {"tracked": Fraction(1)}
        provenance = audit.LinearProvenance(atoms, coefficients)
        atoms.clear()
        coefficients.clear()
        self.assertEqual(set(provenance.atoms), {"tracked"})
        self.assertEqual(set(provenance.coefficients), {"tracked"})
        with self.assertRaisesRegex(ValueError, "Boolean"):
            audit.ProofObligation("id", "premise", "false")
        with self.assertRaisesRegex(ValueError, "needs non-empty evidence"):
            audit.ProofObligation("id", "premise", True)

    def test_encoding_binds_physical_period_to_delta(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly match"):
            audit.Encoding("bad-old-p16", 59, 16, 16, False)
        with self.assertRaisesRegex(ValueError, "exactly match"):
            audit.Encoding("bad-nonphysical", 59, 17, 16, False)
        with self.assertRaisesRegex(ValueError, "must divide"):
            audit.Encoding("bad-logical", 59, 32, 7, False)

    def test_all_inputs_are_hash_locked(self) -> None:
        evidence = audit.verify_source_pins()
        self.assertEqual(set(evidence), set(audit.SOURCE_PINS))
        self.assertTrue(all(record["fragment_lines"] for record in evidence.values()))

    def test_a62_stage_ledger_reconciles(self) -> None:
        ledger = audit.a62_stage_ledger()
        self.assertEqual(
            ledger["total"],
            {"blind_rotations": 3390, "key_switches": 3009, "marginals": 3930},
        )
        self.assertEqual(
            ledger["extract"]["marginals"] - ledger["extract"]["blind_rotations"], 508
        )
        self.assertEqual(
            ledger["scan_output"]["marginals"]
            - ledger["scan_output"]["blind_rotations"],
            32,
        )

    def test_linear_provenance_preserves_cancellation_and_correlation(self) -> None:
        encoding = audit.Encoding("bit", 59, 32, 16, False)
        atom = audit.NoiseAtom(
            "e", "test", "shared", audit.Contract.DERIVED, rms_bound=2.0
        )
        left = audit.AuditedLwe(
            "left",
            encoding,
            DOMAIN,
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            1,
        )
        right = audit.AuditedLwe(
            "right",
            encoding,
            DOMAIN,
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            1,
        )
        zero = audit.linear_combine("cancel", [(1, left), (-1, right)])
        self.assertEqual(zero.provenance.coefficients, {})
        self.assertEqual(zero.provenance.correlation_groups(), frozenset())
        self.assertEqual(zero.provenance.rms_minkowski_upper(), 0.0)

    def test_raw_many_lut_never_self_certifies_nominal(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        atom = audit.NoiseAtom("raw", "raw", "raw", audit.Contract.CONDITIONAL)
        source = audit.AuditedLwe(
            "source",
            encoding,
            DOMAIN.with_role(audit.LweRole.SMALL),
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            None,
        )
        low, high = audit.many_lut(
            label="dual",
            source=source,
            reachable_outputs=({0, 1}, {0, 1}),
            sample_degrees=(0, 1024),
            blind_rotation_id="br:0",
            pbs_mode=audit.PbsMode.RAW_BR_SMALL_INPUT,
            strict_margin_radius=63,
            strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
        )
        self.assertIsNone(low.official_noise_level)
        self.assertIsNone(high.official_noise_level)
        self.assertFalse(low.formally_closed)
        self.assertFalse(high.formally_closed)
        self.assertEqual(
            low.provenance.correlation_groups(), high.provenance.correlation_groups()
        )
        self.assertNotEqual(low.provenance.coefficients, high.provenance.coefficients)

    def test_checked_many_lut_requires_a_valid_input_level(self) -> None:
        source = fresh_value("source", degree=1, reachable={0, 1})
        (output,) = audit.many_lut(
            label="checked",
            source=source,
            reachable_outputs=({0, 1},),
            sample_degrees=(0,),
            blind_rotation_id="official:0",
            pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
            strict_margin_radius=63,
            strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
            input_max_degree=15,
            output_shortint_degrees=(1,),
        )
        self.assertEqual(output.official_noise_level, 1)
        self.assertFalse(output.formally_closed)
        self.assertEqual(
            {item.obligation_id for item in output.obligations},
            {"official:0:input-tail", "official:0:sample:0:output-map"},
        )
        self.assertTrue(all(not item.discharged for item in output.obligations))

        too_noisy = audit.linear_combine("too-noisy", [(2, source)])
        with self.assertRaisesRegex(ValueError, "A44 shortint"):
            audit.many_lut(
                label="checked",
                source=too_noisy,
                reachable_outputs=tuple({0, 1} for _ in range(8)),
                sample_degrees=tuple(range(0, 2048, 256)),
                blind_rotation_id="official:1",
                pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
                input_max_degree=15,
                output_shortint_degrees=(1,),
            )

    def test_standalone_keyswitch_never_self_certifies(self) -> None:
        source = fresh_value("source", degree=1, reachable={0, 1})
        output = audit.key_switch(
            label="ks",
            source=source,
            key_switch_id="ks:standalone",
        )
        self.assertIsNone(output.official_noise_level)
        self.assertFalse(output.formally_closed)
        self.assertIn(
            audit.Contract.CONDITIONAL,
            output.provenance.contracts(),
        )

    def test_conditional_provenance_cannot_be_promoted_by_checked_many_lut(
        self,
    ) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        atom = audit.NoiseAtom(
            "conditional",
            "external",
            "conditional",
            audit.Contract.CONDITIONAL,
        )
        forged_level = audit.AuditedLwe(
            "source",
            encoding,
            DOMAIN,
            audit.WireKind.A44_SHORTINT,
            1,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            1,
        )
        self.assertTrue(forged_level.proof_obligations_closed)
        self.assertFalse(forged_level.formally_closed)
        (output,) = audit.many_lut(
            label="checked",
            source=forged_level,
            reachable_outputs=({0, 1},),
            sample_degrees=(0,),
            blind_rotation_id="official:conditional",
            pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
            strict_margin_radius=63,
            strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
            input_max_degree=15,
            output_shortint_degrees=(1,),
        )
        self.assertIsNone(output.official_noise_level)
        self.assertFalse(output.formally_closed)

    def test_minkowski_bound_does_not_assume_independence(self) -> None:
        first = audit.NoiseAtom(
            "a", "test", "joint", audit.Contract.DERIVED, rms_bound=3.0
        )
        second = audit.NoiseAtom(
            "b", "test", "joint", audit.Contract.DERIVED, rms_bound=4.0
        )
        form = audit.LinearProvenance.single(first, 2).plus(
            audit.LinearProvenance.single(second, -1)
        )
        self.assertEqual(form.rms_minkowski_upper(), 10.0)
        self.assertEqual(form.correlation_groups(), frozenset({"joint"}))

    def test_certificate_refuses_nontrivial_unconditional_bound(self) -> None:
        report = audit.make_certificate()
        self.assertEqual(report["status"], "PASS_MODEL_OPEN_FORMAL_OBLIGATIONS")
        self.assertFalse(report["nontrivial_numeric_bound_established"])
        self.assertEqual(report["current_formal_e2e_p_fail_upper"], 1.0)
        conditional = report[
            "conditional_union_if_every_raw_marginal_inherits_parameter_contract"
        ]
        self.assertEqual(conditional["events"], 3930)
        self.assertAlmostEqual(
            conditional["union_log2_probability"], math.log2(3930) - 64.088
        )

    def test_representative_trace_keeps_dual_sample_dependence(self) -> None:
        trace = audit.representative_trace()
        self.assertEqual(
            trace["selector_input_reachable_residues"],
            [0, 1, 2, 3, 4, 28, 29, 30, 31],
        )
        self.assertEqual(
            trace["selector_input_reachable_signed"],
            [-4, -3, -2, -1, 0, 1, 2, 3, 4],
        )
        self.assertTrue(trace["group_or_raw_pbs_included"])
        self.assertTrue(trace["local_first_raw_pbs_included"])
        self.assertEqual(trace["output_sample_degrees"], [0, 1024])
        self.assertTrue(trace["outputs_share_correlation_group"])
        self.assertEqual(trace["outputs_formally_closed"], [False, False])
        self.assertFalse(trace["independence_assumed"])

    def test_direct_model_rejects_omitted_or_mistyped_noise_metadata(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        with self.assertRaisesRegex(ValueError, "source-pinned evidence"):
            audit.NoiseAtom(
                "bare-official",
                "test",
                "bare-official",
                audit.Contract.OFFICIAL_TRACKED,
            )
        with self.assertRaisesRegex(ValueError, "positive official noise"):
            audit.AuditedLwe(
                "forged-empty",
                encoding,
                DOMAIN,
                audit.WireKind.A44_SHORTINT,
                1,
                frozenset({0, 1}),
                audit.LinearProvenance(),
                1,
            )

        grounded_atom = official_atom("grounded", "test", "grounded")
        raw_value = audit.AuditedLwe(
            "raw-grounded",
            encoding,
            DOMAIN,
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(grounded_atom),
            1,
        )
        self.assertFalse(raw_value.formally_closed)
        fresh = fresh_value("factory-fresh", degree=1, reachable={0, 1})
        fresh_atom = next(iter(fresh.provenance.atoms.values()))
        manual_shortint = audit.AuditedLwe(
            "manual-shortint",
            encoding,
            DOMAIN,
            audit.WireKind.A44_SHORTINT,
            1,
            frozenset({0, 1}),
            audit.LinearProvenance.single(fresh_atom),
            1,
        )
        self.assertFalse(manual_shortint.formally_closed)
        with self.assertRaisesRegex(ValueError, "complete LWE state"):
            audit.AuditedLwe(
                label=fresh.label,
                encoding=fresh.encoding,
                crypto_domain=fresh.crypto_domain,
                wire_kind=fresh.wire_kind,
                shortint_degree=fresh.shortint_degree,
                reachable_overapprox=fresh.reachable_overapprox,
                provenance=fresh.provenance.scaled(100),
                official_noise_level=fresh.official_noise_level,
                closure_evidence=fresh.closure_evidence,
            )
        atom = official_atom("tracked", "test", "tracked")
        with self.assertRaisesRegex(ValueError, "nonnegative integer"):
            audit.AuditedLwe(
                "forged-bool",
                encoding,
                DOMAIN,
                audit.WireKind.A44_SHORTINT,
                1,
                frozenset({0, 1}),
                audit.LinearProvenance.single(atom),
                True,
            )
        with self.assertRaisesRegex(ValueError, "exceeds trusted"):
            audit.AuditedLwe(
                "forged-padding",
                encoding,
                DOMAIN,
                audit.WireKind.A44_SHORTINT,
                15,
                frozenset({31}),
                audit.LinearProvenance(),
                0,
            )

    def test_typed_factories_and_linear_derivations_carry_bound_closure(self) -> None:
        fresh = fresh_value("fresh-closed", degree=1, reachable={0, 1})
        self.assertTrue(fresh.formally_closed)
        self.assertEqual(
            fresh.closure_evidence.origin,
            audit.ClosureOrigin.FRESH_ENCRYPTION,
        )

        public = audit.audited_public_trivial(
            label="public-one",
            encoding=fresh.encoding,
            crypto_domain=DOMAIN,
            wire_kind=audit.WireKind.A44_SHORTINT,
            shortint_degree=1,
            reachable_overapprox={1},
        )
        self.assertTrue(public.formally_closed)
        self.assertEqual(
            public.closure_evidence.origin,
            audit.ClosureOrigin.PUBLIC_TRIVIAL,
        )

        doubled = audit.linear_combine("doubled", [(2, fresh)])
        self.assertEqual(doubled.official_noise_level, 2)
        self.assertTrue(doubled.formally_closed)
        self.assertEqual(
            doubled.closure_evidence.origin,
            audit.ClosureOrigin.OFFICIAL_LINEAR_COMBINATION,
        )

        zero = audit.linear_combine("same-minus-same", [(1, fresh), (-1, fresh)])
        self.assertEqual(zero.reachable_overapprox, frozenset({0}))
        self.assertTrue(zero.formally_closed)
        self.assertEqual(
            zero.closure_evidence.origin,
            audit.ClosureOrigin.EXACT_ALGEBRAIC_ZERO,
        )
        shifted = audit.add_public_offset("known-seven", zero, 7)
        self.assertTrue(shifted.formally_closed)
        self.assertEqual(shifted.reachable_overapprox, frozenset({7}))
        self.assertEqual(
            shifted.closure_evidence.origin,
            audit.ClosureOrigin.PUBLIC_TRIVIAL,
        )

    def test_distinct_fresh_encryptions_cannot_cancel_on_reused_label(self) -> None:
        left = fresh_value("duplicated-label", degree=0, reachable={0})
        right = fresh_value("duplicated-label", degree=1, reachable={1})
        left_atom = next(iter(left.provenance.atoms.values()))
        right_atom = next(iter(right.provenance.atoms.values()))
        self.assertEqual(left_atom.atom_id, right_atom.atom_id)
        self.assertNotEqual(left_atom, right_atom)
        with self.assertRaisesRegex(ValueError, "conflicting provenance atom"):
            audit.linear_combine("independent-difference", [(1, left), (-1, right)])

    def test_noise_atom_rejects_nonfinite_or_mistyped_metadata(self) -> None:
        for bad_bound in (float("nan"), float("inf"), -1.0, True):
            with self.subTest(bound=bad_bound):
                with self.assertRaisesRegex(ValueError, "finite nonnegative real"):
                    audit.NoiseAtom(
                        "bad-bound",
                        "test",
                        "bad-bound",
                        audit.Contract.CONDITIONAL,
                        rms_bound=bad_bound,
                    )
        with self.assertRaisesRegex(ValueError, "identifiers"):
            audit.NoiseAtom("atom", 7, "correlation", audit.Contract.CONDITIONAL)
        with self.assertRaisesRegex(ValueError, "sample degree"):
            audit.NoiseAtom(
                "sample",
                "test",
                "sample",
                audit.Contract.CONDITIONAL,
                blind_rotation_id="br",
                sample_degree=True,
            )

    def test_derived_contract_is_not_treated_as_formally_closed(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        atom = audit.NoiseAtom(
            "derived", "test", "derived", audit.Contract.DERIVED, rms_bound=1.0
        )
        value = audit.AuditedLwe(
            "derived",
            encoding,
            DOMAIN,
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            1,
        )
        self.assertFalse(value.formally_closed)

    def test_crypto_domain_mismatch_and_wrong_transition_are_rejected(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        atom_a = audit.NoiseAtom("a", "test", "a", audit.Contract.CONDITIONAL)
        atom_b = audit.NoiseAtom("b", "test", "b", audit.Contract.CONDITIONAL)
        left = audit.AuditedLwe(
            "left",
            encoding,
            audit.a44_domain("key-a"),
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom_a),
            None,
        )
        right = audit.AuditedLwe(
            "right",
            encoding,
            audit.a44_domain("key-b"),
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom_b),
            None,
        )
        with self.assertRaisesRegex(ValueError, "crypto domains"):
            audit.linear_combine("cross-key", [(1, left), (1, right)])
        with self.assertRaisesRegex(ValueError, "small-LWE"):
            audit.many_lut(
                label="wrong-raw",
                source=left,
                reachable_outputs=({0, 1},),
                sample_degrees=(0,),
                blind_rotation_id="wrong-raw",
                pbs_mode=audit.PbsMode.RAW_BR_SMALL_INPUT,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
            )
        small = audit.AuditedLwe(
            "small",
            encoding,
            DOMAIN.with_role(audit.LweRole.SMALL),
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom_a),
            None,
        )
        with self.assertRaisesRegex(ValueError, "big-LWE"):
            audit.key_switch(label="double-ks", source=small, key_switch_id="ks:bad")

    def test_lut_degree_and_shared_obligation_regressions(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        atom = audit.NoiseAtom("raw", "raw", "raw", audit.Contract.CONDITIONAL)
        source = audit.AuditedLwe(
            "source",
            encoding,
            DOMAIN.with_role(audit.LweRole.SMALL),
            audit.WireKind.RAW_CORE_LWE,
            None,
            frozenset({0, 1}),
            audit.LinearProvenance.single(atom),
            None,
        )
        with self.assertRaisesRegex(ValueError, "inside the A44 polynomial"):
            audit.many_lut(
                label="bad-degree",
                source=source,
                reachable_outputs=({0, 1},),
                sample_degrees=(audit.A44_POLYNOMIAL_SIZE,),
                blind_rotation_id="bad-degree",
                pbs_mode=audit.PbsMode.RAW_BR_SMALL_INPUT,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
            )
        low, high = audit.many_lut(
            label="siblings",
            source=source,
            reachable_outputs=({0, 1}, {0, 1}),
            sample_degrees=(0, 1024),
            blind_rotation_id="siblings",
            pbs_mode=audit.PbsMode.RAW_BR_SMALL_INPUT,
            strict_margin_radius=63,
            strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
        )
        combined = audit.linear_combine("siblings-sum", [(1, low), (1, high)])
        obligation_ids = [item.obligation_id for item in combined.obligations]
        self.assertEqual(obligation_ids.count("siblings:input-tail"), 1)
        self.assertEqual(len(obligation_ids), 3)

    def test_checked_path_enforces_degree_and_rejects_trivial_fast_path(self) -> None:
        encoding = audit.Encoding("p16", 59, 32, 16, False)
        source = fresh_value("source", degree=3, reachable={0, 1, 2, 3})
        with self.assertRaisesRegex(ValueError, "function count"):
            audit.many_lut(
                label="impossible-one-function-geometry",
                source=source,
                reachable_outputs=({0, 1},),
                sample_degrees=(0,),
                blind_rotation_id="impossible-one-function-geometry",
                pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
                input_max_degree=1,
                output_shortint_degrees=(1,),
            )
        with self.assertRaisesRegex(ValueError, "at most eight"):
            audit.many_lut(
                label="too-many-functions",
                source=source,
                reachable_outputs=tuple({0, 1} for _ in range(9)),
                sample_degrees=tuple(range(9)),
                blind_rotation_id="too-many-functions",
                pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
                input_max_degree=0,
                output_shortint_degrees=(1,) * 9,
            )
        with self.assertRaisesRegex(ValueError, "exceeds the LUT"):
            audit.many_lut(
                label="degree-overflow",
                source=source,
                reachable_outputs=tuple({0, 1} for _ in range(8)),
                sample_degrees=tuple(range(0, 2048, 256)),
                blind_rotation_id="degree-overflow",
                pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
                input_max_degree=1,
                output_shortint_degrees=(1,) * 8,
            )
        trivial = audit.AuditedLwe(
            "trivial",
            encoding,
            DOMAIN,
            audit.WireKind.A44_SHORTINT,
            1,
            frozenset({1}),
            audit.LinearProvenance(),
            0,
        )
        with self.assertRaisesRegex(ValueError, "trivial fast path"):
            audit.many_lut(
                label="trivial",
                source=trivial,
                reachable_outputs=({0, 1},),
                sample_degrees=(0,),
                blind_rotation_id="trivial",
                pbs_mode=audit.PbsMode.CHECKED_CLASSIC_KS_PBS,
                strict_margin_radius=63,
                strict_margin_unit=audit.MarginUnit.ACCUMULATOR_ROTATION_INDEX,
                input_max_degree=15,
                output_shortint_degrees=(1,),
            )


if __name__ == "__main__":
    unittest.main()
