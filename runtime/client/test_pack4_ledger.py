"""Public count anchors distinguishing four-lane packing from repaired B."""
import unittest
from client import ledger, protocol


class Pack4LedgerTests(unittest.TestCase):
    def test_score_and_one_variable_id_share_one_group(self):
        leaves = ledger.digit_constants(2, "uniform_sentinel", [4, 4], -1019, 2329)
        # One equal middle-ID lane is omitted; three scores and low ID fit one BR.
        self.assertEqual(ledger.tree_savings(leaves, 2), (0, 1, 1))

    def test_uniform_service_pair_count_anchor(self):
        actual = ledger.composite_counts(protocol.operation_counts(2, "uniform_sentinel"),
                                         2, "uniform_sentinel", [4, 4], {"l": -1019, "u": 2329})
        self.assertEqual(actual, dict(br=18, ks=18, marginals=26, pfks=6, initial_samples=2))

    def test_mixed_norm671_pair_uses_two_groups(self):
        actual = ledger.composite_counts(protocol.operation_counts(2, "mixed_winner_threshold"),
                                         2, "mixed_winner_threshold", [4, 273], {"l": -987, "u": 2329})
        self.assertEqual(actual, dict(br=19, ks=18, marginals=29, pfks=9, initial_samples=2))

    def test_old_three_lane_ledger_is_not_the_new_contract(self):
        actual = ledger.composite_counts(protocol.operation_counts(127, "uniform_sentinel"),
                                         127, "uniform_sentinel", [4] * 127, {"l": -1019, "u": 2100})
        self.assertEqual(actual, dict(br=1175, ks=1143, marginals=1808, pfks=538, initial_samples=127))
        self.assertNotEqual(actual["br"], 1269)  # Repaired B for this same public plan.

    def test_reject_shortcut_has_no_crypto_work(self):
        actual = ledger.composite_counts(protocol.operation_counts(2, "uniform_all_reject"),
                                         2, "uniform_all_reject", [-100, -100], {"l": -63, "u": 65})
        self.assertEqual(actual, dict(br=0, ks=0, marginals=0, pfks=0, initial_samples=0))


if __name__ == "__main__":
    unittest.main()
