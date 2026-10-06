from copy import deepcopy
import unittest

from schema import Q, U, ct_record, verify, verify_sources
from synthetic import make_record


class FirstKS(unittest.TestCase):
    def test_source_pins_and_exact_selected_fixture(self):
        self.assertEqual(verify_sources(), 19)
        record, expected = make_record()
        result = verify(record, expected)
        self.assertTrue(result["selected_prefix_gate_pass"])
        self.assertEqual(result["direct_address"], 3072)
        self.assertEqual(result["a156_public_input"]["reference_degree"], 3072)
        self.assertEqual(result["a156_public_input"]["safe_lifts"], [-1024, 1023])
        self.assertFalse(result["actual_secret_key_membership_attested"])

    def test_correct_native_decode_does_not_hide_ms_boundary_failure(self):
        record, expected = make_record(error=1000 * U, displacement64=True)
        result = verify(record, expected)
        self.assertTrue(result["native_first_bit_decode_pass"])
        self.assertFalse(result["conditional_lut_address_pass"])
        self.assertFalse(result["selected_prefix_gate_pass"])
        self.assertEqual(result["displacement_lift"], 1064)
        self.assertEqual(result["direct_address"], 40)

    def test_component_and_aggregate_mutations(self):
        original, expected = make_record()
        for key in original["client"]:
            record = deepcopy(original)
            record["client"][key] += 1
            with self.assertRaises(AssertionError, msg=key):
                verify(record, expected)
        for index in range(4):
            record = deepcopy(original)
            record["initial_noise_terms_client"][index]["epsilon_lift"] += 1
            with self.assertRaises(AssertionError):
                verify(record, expected)

    def test_word_hash_rounding_and_returned_object_mutations(self):
        original, expected = make_record()
        for kind in original["ciphertexts"]:
            record = deepcopy(original)
            public = [int(x, 16) for x in record["ciphertexts"][kind]["words_hex"]]
            public[0] = (public[0] + 1) % Q
            record["ciphertexts"][kind] = ct_record(public)
            with self.assertRaises(AssertionError, msg=kind):
                verify(record, expected)
        for field, value in [
            ("returned_body_correction_words", 1),
            ("returned_log_modulus", 11),
            ("actual_body_degree", 3073),
            ("subgroup_g", 2),
        ]:
            record = deepcopy(original)
            record[field] = value
            with self.assertRaises(AssertionError, msg=field):
                verify(record, expected)
        record = deepcopy(original)
        record["actual_mask_degrees"][0] += 1
        with self.assertRaises(AssertionError):
            verify(record, expected)

    def test_wrong_bindings_scope_and_false_completeness(self):
        original, expected = make_record()
        for key in expected:
            record = deepcopy(original)
            record["bindings"][key] = "wrong"
            with self.assertRaises(AssertionError, msg=key):
                verify(record, expected)
        for field in (
            "full_n4_evaluation",
            "blind_rotation_consumed",
            "client_key_membership_attested",
        ):
            record = deepcopy(original)
            record[field] = True
            with self.assertRaises(AssertionError, msg=field):
                verify(record, expected)
        record = deepcopy(original)
        record["counts"]["blind_rotations"] = 1
        with self.assertRaises(AssertionError):
            verify(record, expected)
        record = deepcopy(original)
        record["fixture"]["gallery_index"] = 1
        with self.assertRaises(AssertionError):
            verify(record, expected)

    def test_coherent_impossible_small_secret_aggregate_remains_unattested(self):
        record, expected = make_record(impossible_small_aggregate=True)
        result = verify(record, expected)
        self.assertTrue(result["selected_prefix_gate_pass"])
        self.assertNotIn(record["client"]["small_mask_dot_words"], (0, U + 2))
        self.assertFalse(result["actual_secret_key_membership_attested"])
        self.assertFalse(result["independently_attested_client_aggregates"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
