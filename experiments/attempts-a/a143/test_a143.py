import copy
import os
from pathlib import Path
import tempfile
import unittest

from coefficients import (
    DIMENSION,
    Q,
    U,
    digest_words,
    realize_synthetic_event,
    round_degree,
    synthetic_witness,
    verify_event,
)
from materialize import BASE, HERE, rendered_files
from replay import a142, analyze_records, source_info, write_private_json
from run_gate import live_a124, private_directory
from synthetic_cases import FAKE_BINARY_HASH, a142_synthetic, stream


def standalone_event(phase=0, displacement=64):
    event = dict(
        keyset=0,
        small_phase_word=str(phase),
        actual_ms_address=(round_degree(phase) + displacement) % 4096,
    )
    return realize_synthetic_event(event)


def membership_counterexample():
    # Public mask has one nonzero word U+2. A binary secret yields aggregate0 or U+2.
    # Aggregate1 is impossible, yet its coherent degree/residue decomposition passes.
    words = [U + 2] + [0] * (DIMENSION - 1) + [0]
    observation = synthetic_witness(words, [0] * DIMENSION, 0, 0)
    observation["client_weighted_mask_words_hex"] = f"{1:016x}"
    observation["client_weighted_mask_residues_decimal"] = "1"
    observation["direct_phase_word_hex"] = f"{Q - 1:016x}"
    event = dict(
        keyset=0,
        small_phase_word=str(Q - 1),
        actual_ms_address=0,
        small_sha256=digest_words(words),
        coefficient_observer=observation,
        synthetic=True,
    )
    return event


class A143(unittest.TestCase):
    def test_reproducible_source_and_unchanged_crypto_prefix(self):
        for name, content in rendered_files().items():
            self.assertEqual((HERE / "candidate" / name).read_text(), content, name)
        old = (BASE / "src/main.rs").read_text().split("fn main()")[0]
        new = (HERE / "candidate/src/main.rs").read_text().split("fn main()")[0]
        self.assertEqual(new.replace("mod coefficient_observer;\n", ""), old)
        observer = (HERE / "candidate/src/coefficient_observer.rs").read_text()
        self.assertNotIn("keyswitch_lwe_ciphertext(", observer)
        self.assertNotIn("programmable_bootstrap_lwe_ciphertext(", observer)

    def test_public_rounding_ties_and_wrap(self):
        for value in [0, U // 2 - 1, U // 2, U - 1, Q - U // 2 - 1, Q - U // 2, Q - 1]:
            self.assertEqual(round_degree(value), ((value + U // 2) % Q) >> 52)

    def test_zero_phase_nonzero_actual_ms(self):
        event = standalone_event()
        result = verify_event(event)
        self.assertEqual(result["phase_from_body_and_client_aggregate"], "0")
        self.assertEqual(result["observed_ms_displacement"], 64)
        self.assertTrue(result["coefficient_closure_pass"])

    def test_public_words_rounding_and_hash_mutations(self):
        original = standalone_event(displacement=1)
        for field in [
            "words",
            "hash",
            "mask",
            "body",
            "residue",
            "dimension",
            "torus",
            "degree_domain",
            "keyset",
        ]:
            event = copy.deepcopy(original)
            witness = event["coefficient_observer"]
            if field == "words":
                witness["post_ks_words_hex"][0] = (
                    f"{int(witness['post_ks_words_hex'][0], 16) ^ 1:016x}"
                )
            if field == "hash":
                event["small_sha256"] = "0" * 64
            if field == "mask":
                witness["public_mask_degrees"][0] += 1
            if field == "body":
                witness["public_body_degree"] = (
                    witness["public_body_degree"] + 1
                ) % 4096
            if field == "residue":
                witness["public_body_residue_decimal"] = str(
                    int(witness["public_body_residue_decimal"]) + 1
                )
            if field == "dimension":
                witness["lwe_dimension"] = 904
            if field == "torus":
                witness["torus_bits"] = 32
            if field == "degree_domain":
                witness["log_degree_modulus"] = 11
            if field == "keyset":
                witness["keyset"] = 1
            with self.assertRaises(AssertionError, msg=field):
                verify_event(event)

    def test_each_private_aggregate_mutation(self):
        original = standalone_event(displacement=1)
        for field in [
            "client_weighted_mask_words_hex",
            "client_weighted_mask_degrees",
            "client_weighted_mask_residues_decimal",
        ]:
            event = copy.deepcopy(original)
            w = event["coefficient_observer"]
            if field.endswith("_hex"):
                w[field] = f"{int(w[field], 16) ^ 1:016x}"
            elif field.endswith("_decimal"):
                w[field] = str(int(w[field]) - 1)
            else:
                w[field] -= 1
            with self.assertRaises(AssertionError, msg=field):
                verify_event(event)

    def test_aggregate_closure_does_not_attest_binary_key_membership(self):
        event = membership_counterexample()
        self.assertNotIn(1, [0, U + 2])
        result = verify_event(event)
        self.assertTrue(result["coefficient_closure_pass"])
        self.assertFalse(result["private_aggregate_key_membership_attested"])

    def test_public_word_closure_does_not_replace_consumer_region(self):
        case, events, _ = a142_synthetic.make_case(
            [1, 0, 2, 3], perturbations={"middle_round.mask/1": dict(ms=64)}
        )
        events = [realize_synthetic_event(event) for event in events]
        self.assertTrue(
            all(verify_event(e)["coefficient_closure_pass"] for e in events)
        )
        report = a142.analyze_case(case, events)
        self.assertTrue(report["native_decode_pass"])
        self.assertTrue(report["composed_a34_a135_pass"])
        self.assertFalse(report["conditional_joint_safe_region_pass"])

    def test_smoke_schedule_detects_source_negative(self):
        _, fixtures = source_info()
        detected = [
            i
            for i, scores in enumerate(fixtures)
            if not a142_synthetic.make_case(scores, 2)[0]["composed_a34_a135_pass"]
        ]
        self.assertEqual(detected, [2, 3, 4, 5])
        self.assertFalse(any(i in detected for i in [0, 1]))
        self.assertTrue(all(i in detected for i in [2, 4]))

    def test_complete_smoke_and_no_subset_promotion(self):
        records = stream()
        result = analyze_records(records, FAKE_BINARY_HASH)
        self.assertTrue(result["joint_witness_pass"])
        self.assertEqual(result["coefficient_events"], 346)
        self.assertEqual(result["source_fixture_indices"], [2, 4])
        self.assertFalse(result["full_schedule_complete"])
        changed = records[:-1] + [dict(records[-1], full_schedule_complete=True)]
        with self.assertRaises(AssertionError):
            analyze_records(changed, FAKE_BINARY_HASH)
        with self.assertRaises(AssertionError):
            analyze_records(records[:-1], FAKE_BINARY_HASH)
        changed = [dict(records[0], source_fixture_indices=[0, 1])] + records[1:]
        with self.assertRaises(AssertionError):
            analyze_records(changed, FAKE_BINARY_HASH)
        changed = records[:2] + [dict(records[2], body_sha256="0" * 64)] + records[3:]
        with self.assertRaises(AssertionError):
            analyze_records(changed, FAKE_BINARY_HASH)

    def test_owner_only_and_exclusive_artifacts(self):
        with tempfile.TemporaryDirectory(dir=HERE) as name:
            directory = private_directory(Path(name))
            self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)
            path = directory / "report.json"
            write_private_json(path, {"preserved": True})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_private_json(path, {"replace": True})
            self.assertEqual(path.read_bytes(), before)

    def test_scheduler_preflight_is_read_only_refusal(self):
        self.assertEqual(live_a124("12 1 python unrelated.py\n"), [])
        self.assertEqual(
            live_a124("45916 45914 python tmp/a124-a66-thread-sweep/driver.py\n")[0][
                "pid"
            ],
            45916,
        )


if __name__ == "__main__":
    unittest.main()
