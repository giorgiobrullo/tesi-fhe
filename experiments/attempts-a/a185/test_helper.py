"""Light integer equivalence: copied segmented helper vs independent ring monomial."""

import unittest
import audit

Q = 1 << 64


def segmented(values, degree):
    n = len(values)
    r = degree % n
    cycles = degree // n
    prefix = values[n - r :]
    suffix = values[: n - r]
    signs = (-1, 1) if cycles % 2 == 0 else (1, -1)
    return [(signs[0] * x - y) % Q for x, y in zip(prefix, values[:r])] + [
        (signs[1] * x - y) % Q for x, y in zip(suffix, values[r:])
    ]


def ring_reference(values, degree):
    out = [(-x) % Q for x in values]
    n = len(values)
    for i, word in enumerate(values):
        cycles, destination = divmod(i + degree, n)
        out[destination] = (out[destination] + (-word if cycles % 2 else word)) % Q
    return out


class HelperTests(unittest.TestCase):
    def test_source_is_exact_private_function_and_only_access_path_changes(self):
        self.assertTrue(audit.check()["exact_original_helper_definition"])

    def test_tiny_all_degrees_multiple_cycles_and_wrap_inputs(self):
        checked = 0
        for n in (1, 2, 4, 8, 16):
            patterns = [
                [0] * n,
                [Q - 1] * n,
                [(i * (Q // 3) + i * i) % Q for i in range(n)],
                [((1 << 63) + i) % Q for i in range(n)],
            ]
            for values in patterns:
                for degree in range(4 * n + 1):
                    self.assertEqual(
                        segmented(values, degree), ring_reference(values, degree)
                    )
                    checked += 1
        self.assertEqual(checked, 516)

    def test_actual_n2048_body_mask_degree_endpoints(self):
        values = [
            (i * (Q // 7) + (1 << 63) + (i % 3) * (Q - 1)) % Q for i in range(2048)
        ]
        for degree in (0, 1, 2047, 2048, 2049, 4095, 4096, 8191):
            self.assertEqual(segmented(values, degree), ring_reference(values, degree))
        self.assertEqual(segmented(values, 0), [0] * 2048)
        self.assertEqual(segmented(values, 2048), [(-2 * x) % Q for x in values])

    def test_negative_controls_wrong_cycle_sign_and_dropped_subtraction(self):
        values = [1, 2, Q - 1, 1 << 63]
        actual = ring_reference(values, 4)
        self.assertNotEqual(actual, segmented(values, 0))
        self.assertNotEqual(actual, [(-x) % Q for x in values])


if __name__ == "__main__":
    unittest.main()
