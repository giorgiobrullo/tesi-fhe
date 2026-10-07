"""Small sensitivity tests, not a cryptographic success fixture."""

import copy
import unittest
import model as m
import synthetic as s
import replay as r


class ConsumerTests(unittest.TestCase):
    def test_both_bit_values_and_every_candidate_center(self):
        count = 0
        for bit in range(8):
            for c in m.candidates(bit):
                for value in (0, 1):
                    self.assertEqual(
                        s.check(s.make(bit=bit, candidate=c, x=value << bit)),
                        [True] * 6,
                    )
                    count += 1
        self.assertEqual(count, 56)

    def test_phase_only_pass_does_not_imply_actual_address_pass(self):
        args = s.make(ms_boundary=True)
        row = args[0]
        self.assertEqual(row["phase_only_address"], 128)
        self.assertEqual(row["actual_address"], 192)
        self.assertEqual(m.target(row["phase_only_address"]), 1)
        self.assertEqual(s.check(args), [True, False, True, False, True, True])
        self.assertFalse(row["pass"])

    def test_candidate_noise_separate_from_ks_and_producer(self):
        gates = s.check(s.make(candidate_error=m.DELTA))
        self.assertEqual(gates, [False, False, True, False, True, True])

    def test_ks_noise_separate_from_candidate_and_producer(self):
        gates = s.check(s.make(ks_error=m.DELTA))
        self.assertEqual(gates, [True, False, True, False, True, True])

    def test_br_error_separate_from_address(self):
        gates = s.check(s.make(br_error=m.DELTA))
        self.assertEqual(gates, [True, True, False, False, True, True])

    def test_native_set_bit_outside_conservative_half_slot_can_pass(self):
        args = s.make(x=4, producer_error=m.DELTA)
        self.assertEqual(s.check(args), [True] * 6)
        self.assertGreater(abs(int(args[0]["producer_error"])), m.DELTA // 2)

    def test_zero_bit_same_error_fails_consumer(self):
        self.assertEqual(
            s.check(s.make(producer_error=m.DELTA)),
            [True, False, True, False, True, True],
        )

    def test_rounding_boundary_wrap_and_ties(self):
        for word, want in [
            (0, 0),
            (m.U // 2 - 1, 0),
            (m.U // 2, 1),
            (m.Q - m.U // 2 - 1, 4095),
            (m.Q - m.U // 2, 0),
        ]:
            self.assertEqual(m.rounded(word), want)
        self.assertEqual(m.target(64), 1)
        self.assertEqual(m.target(192), 0)
        self.assertEqual(m.target(2048 + 64), -1)

    def test_record_mutations_cannot_hide_in_pass(self):
        mutations = [
            lambda r: r.update(source_multiplier=-1),
            lambda r: r.update(actual_address=r["phase_only_address"]),
            lambda r: r["receipt_masks"].__setitem__(0, 1),
            lambda r: r.update(
                client_weighted_residues=str(int(r["client_weighted_residues"]) + 1)
            ),
            lambda r: r.update(
                client_weighted_degrees=str(int(r["client_weighted_degrees"]) + 1)
            ),
            lambda r: r.update(body_residue=str(int(r["body_residue"]) + 1)),
            lambda r: r.update(ks_remainder_sum=str(int(r["ks_remainder_sum"]) + m.Q)),
            lambda r: r.update(
                inferred_signed_ks_row_term=str(
                    int(r["inferred_signed_ks_row_term"]) + m.Q
                )
            ),
            lambda r: r["encoded_lwe"].update(
                words_le_hex="ff" + r["encoded_lwe"]["words_le_hex"][2:]
            ),
            lambda r: r["output_lwe"].update(
                phase=str(int(r["output_lwe"]["phase"]) + m.Q)
            ),
            lambda r: r.update(stock_glwe_sha256="b" * 64),
            lambda r: r.update(traced_br_calls=True),
            lambda r: r["receipt_raw_mask_nonzero"].__setitem__(0, 1),
            lambda r: r.update(semantic_output_pass=True),
            lambda r: r.update(candidate_is_previous_selector_output=True),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                args = list(copy.deepcopy(s.make(ms_boundary=True)))
                mutate(args[0])
                with self.assertRaises(ValueError):
                    s.check(args)

    def test_swapped_old_producer_hash_is_rejected(self):
        args = list(s.make())
        args[2] = ("f" * 64, args[2][1])
        with self.assertRaises(ValueError):
            s.check(args)

    def test_coherent_row_local_dot_change_cannot_change_shared_key_relation(self):
        first = s.make()[0]
        aliases = {}
        r.bind_observation_aliases(first, aliases)
        changed = copy.deepcopy(first)
        node = changed["output_lwe"]
        node["phase"] = str((int(node["phase"]) + 1) % m.Q)
        node["client_mask_dot"] = str((int(node["client_mask_dot"]) - 1) % m.Q)
        # The direct phase equation of this individual row still holds.
        self.assertTrue(m.observation(node, 2)[3])
        with self.assertRaises(ValueError):
            r.bind_observation_aliases(changed, aliases)

    def test_exact_state_and_primitive_ledger(self):
        self.assertEqual(sum(len(m.candidates(b)) for b in range(8)), 28)
        self.assertEqual(
            [len(m.candidates(b)) for b in range(8)], [5, 4, 3, 2, 5, 4, 3, 2]
        )
        self.assertEqual(28 * (71 + 2 * 56), 5124)
        self.assertEqual(28 * (64 + 56), 3360)
        self.assertEqual(28 * (103 + 2 * 56), 6020)
        self.assertEqual(16104 + 1 + 1 + 28 * (56 + 1) + 1, 17703)
        for bit in range(8):
            self.assertEqual({(x >> bit) & 1 for x in m.SCORES}, {0, 1})


if __name__ == "__main__":
    unittest.main()
