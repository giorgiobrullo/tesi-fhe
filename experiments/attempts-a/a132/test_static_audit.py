import unittest
import static_audit as audit


class StaticGate(unittest.TestCase):
    def test_pinned_source_and_exhaustive_boolean_rounds(self):
        result = audit.main()
        self.assertEqual(result["n4_clear_rounds"], 2048)
        self.assertEqual(result["group_tail_cases"], 161)

    def test_ledgers(self):
        self.assertEqual(audit.ledger(4), dict(packing=3, cm_ks=2, cm_pbs=3,
                                             ordinary_ks=9, ordinary_pbs=7, extraction=8))
        self.assertEqual(audit.ledger(127), dict(packing=65, cm_ks=81, cm_pbs=113,
                                               ordinary_ks=132, ordinary_pbs=130, extraction=131))

    def test_offset_negative_and_non_symmetric_fixture(self):
        active, bits = [1, 1, 1, 1], [0, 1, 1, 1]
        positive, _ = audit.circuit(active, bits, 2, 1)
        negative, _ = audit.circuit(active, bits, 2, 1, omit_offset=True)
        self.assertEqual(positive, [1, 0, 0, 0])
        self.assertNotEqual(positive, negative)

    def test_stock_lut_exact_centers_and_interior(self):
        checks = 0
        for poly, modulus, delta, f in [
            (512, 4, 1 << 61, lambda x: x),
            (512, 4, 1 << 61, lambda x: int(x == 1)),
            (512, 4, 1 << 61, lambda x: int(x == 2)),
            (512, 4, 1 << 61, lambda x: int(x != 0)),
            (2048, 4, 1 << 59, lambda x: x),
            (2048, 4, 1 << 59, lambda x: int(x != 0)),
            (2048, 16, 1 << 59, lambda x: int(x != 0)),
        ]:
            data = audit.lut(poly, modulus, delta, f)
            halfbox = poly // modulus // 2
            for message in range(modulus):
                for offset in range(-halfbox, halfbox):
                    self.assertEqual(audit.lookup(data, message * poly // modulus + offset), f(message) * delta)
                    checks += 1
        self.assertEqual(checks, 8192)

    def test_coefficientwise_rounding_is_not_phase_rounding(self):
        poly = 512
        quantum = (1 << 64) // (2*poly)
        a = quantum * 3 // 5
        body = 2*a
        actual = (audit.modulus_switch(body, poly) - 2*audit.modulus_switch(a, poly)) % (2*poly)
        rounded_phase = audit.modulus_switch((body-2*a) % (1 << 64), poly)
        self.assertEqual(actual, 1023)
        self.assertEqual(rounded_phase, 0)


if __name__ == "__main__":
    unittest.main()
