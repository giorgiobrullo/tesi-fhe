"""Bounded actual-record sensitivity checks; no runtime invocation or retries."""

import copy
import unittest
import diagnose as d


class Diagnosis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = d.source_check()
        cls.failure = d.one(
            cls.rows, record="actual_consumer", arm=d.REPAIR, bit=2, candidate=0
        )

    def test_actual_failed_address_and_countervailing_neighbor(self):
        result = d.analyze(self.rows)
        a = result["six_actual_bit2_consumers"]
        failed = next(x for x in a if x["arm"] == d.REPAIR and x["candidate"] == 0)
        rescued = next(x for x in a if x["arm"] == d.REPAIR and x["candidate"] == 1)
        self.assertEqual(
            failed["degree_by_stage"],
            {
                "producer_only_scalar": 64,
                "actual_encoded_phase_only": 64,
                "actual_post_ks_phase_only": 64,
                "actual_receipt": 73,
            },
        )
        self.assertEqual(rescued["degree_by_stage"]["actual_post_ks_phase_only"], 197)
        self.assertEqual(rescued["degree_by_stage"]["actual_receipt"], 190)
        self.assertEqual(result["failed_repair_scalar_candidate_states"], [0, 1])

    def test_phase_only_is_not_actual_receipt(self):
        row = copy.deepcopy(self.failure)
        row["actual_address"] = row["phase_only_address"]
        with self.assertRaises(ValueError):
            d.validate_one(self.rows, row)

    def test_aggregate_modular_alias_is_rejected(self):
        row = copy.deepcopy(self.failure)
        row["client_weighted_residues"] = str(
            int(row["client_weighted_residues"]) + d.Q
        )
        with self.assertRaises(ValueError):
            d.validate_one(self.rows, row)

    def test_actual_mask_degree_mutation_is_rejected(self):
        row = copy.deepcopy(self.failure)
        row["receipt_masks"][0] = (row["receipt_masks"][0] + 1) % 4096
        with self.assertRaises(ValueError):
            d.validate_one(self.rows, row)

    def test_stock_hash_mutation_is_rejected(self):
        row = copy.deepcopy(self.failure)
        row["stock_glwe_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            d.validate_one(self.rows, row)

    def test_candidate_endpoint_omission_is_rejected(self):
        rows = [
            r
            for r in self.rows
            if not (
                r["record"] == "actual_consumer"
                and r["arm"] == d.REPAIR
                and r["bit"] == 2
                and r["candidate"] == 1
            )
        ]
        with self.assertRaises(AssertionError):
            d.analyze(rows)

    def test_native_zero_bit_does_not_imply_joint_scalar_region(self):
        error = int(self.failure["producer_error"])
        native = ((error + (1 << 61)) % d.Q) // (1 << 62)
        self.assertEqual(native, 0)
        self.assertGreaterEqual(error, 64 * d.U - d.U // 2)
        self.assertEqual(d.model.target(d.model.rounded(error)), 1)


if __name__ == "__main__":
    unittest.main()
