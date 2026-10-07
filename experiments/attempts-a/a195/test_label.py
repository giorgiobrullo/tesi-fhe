"""Source and exact synthetic controls; never consumes actual runtime records."""

import copy
import unittest
import origin
import coefficients
import synthetic as s
import replay as r
import component as c


class LabelTests(unittest.TestCase):
    def test_exact_successor_and_outer_loop_call_argument(self):
        result = origin.verify()
        self.assertEqual(result["mapped_files"], 30)
        self.assertEqual(result["byte_identical_files"], 20)
        source = (origin.HERE / "src/gate.rs").read_text()
        for wrong in ("0", "fixture_index", "keyset + 1"):
            changed = source.replace(
                "                        address,\n                        keyset,",
                "                        address,\n                        "
                + wrong
                + ",",
            )
            self.assertNotEqual(changed, source)
            with self.assertRaisesRegex(ValueError, "actual outer keyset"):
                origin.producer_label(changed)

    def test_nonzero_keyset_literal_zero_is_rejected_without_changing_arithmetic(self):
        for keyset in (1, 2):
            rows, code = s.records(r.fixtures()[0]["scores"], keyset=keyset)
            self.assertEqual(code, 0)
            positive = c.replay(
                rows,
                s.BINARY,
                code,
                r.fixtures()[0]["scores"],
                keyset,
                0,
                "SYNTHETIC_SOURCE",
            )
            self.assertTrue(positive["gate_pass"])
            event = rows[2]
            self.assertEqual(event["keyset"], keyset)
            self.assertTrue(
                coefficients.verify_event(event)["coefficient_closure_pass"]
            )
            changed = copy.deepcopy(rows)
            for item in changed:
                if item.get("record") == "event":
                    item["coefficient_observer"]["keyset"] = 0
            # This is the old producer-label pattern, applied only to synthetic records.
            with self.assertRaises(AssertionError):
                coefficients.verify_event(changed[2])
            with self.assertRaises(AssertionError):
                c.replay(
                    changed,
                    s.BINARY,
                    code,
                    r.fixtures()[0]["scores"],
                    keyset,
                    0,
                    "SYNTHETIC_SOURCE",
                )

    def test_transformation_cannot_hide_another_crypto_change(self):
        old = origin.HERE.parent / "a192-padding-precision-expansion/src/gate.rs"
        expected = origin.transform(old.read_bytes(), "identity_and_observer_keyset")
        current = (origin.HERE / "src/gate.rs").read_bytes()
        self.assertEqual(expected, current)
        changed = current.replace(
            b"let counts = [63usize, 71, 71];", b"let counts = [63usize, 70, 71];"
        )
        self.assertNotEqual(changed, expected)


if __name__ == "__main__":
    unittest.main()
