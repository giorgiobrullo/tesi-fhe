import unittest
import check
import model


class NibbleGate(unittest.TestCase):
    def test_all_local_lemmas(self):
        result=check.local_lemmas()
        self.assertEqual(result['mask_states'],32)
        self.assertEqual(result['minimum_pairs_across_seven_scales'],2023)
        self.assertEqual(result['reachable_update_states'],153)

    def test_stock_negacyclic_geometry(self):
        self.assertEqual(check.geometry(),38016)

    def test_complete_round_against_independent_oracle(self):
        self.assertEqual(check.round_cases(),dict(n2_exhaustive=1024,bounded_gallery_rounds=112))

    def test_exact_id_boundaries(self):
        self.assertEqual(check.exact_id_cases(),dict(all_12bit_singleton_scores=4096,
            paired_boundary_and_gallery_cases=756,three_round_argmin_gallery_cases=80))

    def test_no_resurrection_or_unstable_tie(self):
        self.assertEqual(model.exact_uniform1023([1024,1024,4095]),0)
        self.assertEqual(model.exact_uniform1023([256,255,255]),2)
        self.assertEqual(model.independent_exact_id([10,11],[9,100]),0)
        self.assertEqual(check.counterexamples()['heterogeneous_prefilter']['prefilter_then_min'],2)

    def test_ledger_keeps_interfaces_open(self):
        self.assertEqual(model.ledger(127)['two_low_round_pbs'],762)
        self.assertEqual(model.ledger(127)['saved_low_region_pbs'],588)
        self.assertEqual(model.ledger(128)['saved_low_region_pbs'],592)
        self.assertEqual(model.ledger(127)['low_region_interface_adapter_pbs'],'not established')

    def test_source_pins(self):
        self.assertGreater(check.verify_pins(),5)

    def test_direct_padding_flags_alternative(self):
        result=check.padding_alternative()
        self.assertEqual(result['n2_exhaustive_padding_rounds'],1024)
        self.assertEqual(result['exact_id_gallery_cases'],96)
        self.assertFalse(result['same_noise_law_assumed'])


if __name__ == '__main__':
    unittest.main()
