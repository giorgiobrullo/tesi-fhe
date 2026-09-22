"""Public-data and estimator checks; no rendering, keys or FHE work."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import shutil
import statistics
import tempfile
import unittest

from benchmark import figure_current_ckks as figure


ROOT = Path(__file__).resolve().parents[1]


class CurrentCKKSFigureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / figure.SOURCE
        self.directory.mkdir(parents=True)
        for name in ("samples.csv", "blocks.csv", "SOURCE_PINS.json"):
            shutil.copyfile(ROOT / figure.SOURCE / name, self.directory / name)

    def rewrite_csv(self, name, mutate):
        path = self.directory / name
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            fields = reader.fieldnames
            rows = list(reader)
        mutate(rows)
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_public_data_matches_published_block_estimator(self):
        data = figure.prepare_data(self.root)
        json.dumps(data, allow_nan=False)
        self.assertEqual(data["counts"], dict(
            queries=216, measured=162, warmups=54, jobs=18,
            blocks=3, cells=18, groups=6, tfhe_families=2, ckks_contexts=6,
        ))
        self.assertEqual([(g["n"], g["category"]) for g in data["groups"]],
                         [(n, c) for n in (64, 128) for c in ("aligned", "general", "mixed")])
        focus = data["focus_n128_general"]
        self.assertAlmostEqual(focus["ckks_seconds"]["median"], 3.41090025, places=12)
        self.assertAlmostEqual(focus["tfhe_reference_seconds"]["median"], 2.6038818755, places=12)
        self.assertAlmostEqual(focus["ckks_over_tfhe_ratio"]["median"], 1.3099289495784197, places=12)
        self.assertAlmostEqual(focus["tfhe_reference_seconds"]["min"], 2.3568674995, places=12)
        self.assertAlmostEqual(focus["tfhe_reference_seconds"]["max"], 2.6492893955000003, places=12)

    def test_tfhe_reference_is_not_the_pooled_query_median(self):
        data = figure.prepare_data(self.root)
        with (self.directory / "samples.csv").open(encoding="utf-8", newline="") as stream:
            queries = list(csv.DictReader(stream))
        pooled = statistics.median(float(q["query_seconds"]) for q in queries
                                   if q["n"] == "128" and q["category"] == "general"
                                   and q["arm"] != "ckks" and q["phase"] == "measured")
        self.assertNotAlmostEqual(data["focus_n128_general"]["tfhe_reference_seconds"]["median"],
                                  pooled, places=8)

    def test_ratio_is_median_of_block_ratios_not_ratio_of_displayed_medians(self):
        # Three synthetic blocks give ratios 1, 5, 1. Their median is 1,
        # whereas median(CKKS) / median(TFHE) would incorrectly give 3/2.
        queries = []
        for block, ckks, tfhe in ((1, 1, 1), (2, 10, 2), (3, 3, 3)):
            for n in (64, 128):
                for category in ("aligned", "general", "mixed"):
                    for arm in ("tfhe-before", "ckks", "tfhe-after"):
                        center = ckks if arm == "ckks" else tfhe
                        for value in (center - 0.1, center, center + 0.1):
                            queries.append(dict(block=block, n=n, category=category,
                                                arm=arm, phase="measured", query_seconds=value))
        _, groups = figure._summarize(queries)
        for group in groups:
            self.assertEqual(group["ckks_over_tfhe_ratio"]["median"], 1)
            self.assertEqual(group["ckks_seconds"]["median"], 3)
            self.assertEqual(group["tfhe_reference_seconds"]["median"], 2)

    def test_warmup_durations_do_not_change_statistics(self):
        expected = figure.prepare_data(self.root)

        def change_warmups(rows):
            for row in rows:
                if row["phase"] == "warmup":
                    row["query_seconds"] = "1000000"

        self.rewrite_csv("samples.csv", change_warmups)
        self.assertEqual(figure.prepare_data(self.root), expected)

    def test_missing_query_is_rejected(self):
        self.rewrite_csv("samples.csv", lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "216 samples"):
            figure.prepare_data(self.root)

    def test_duplicate_sequence_is_rejected_even_with_216_rows(self):
        self.rewrite_csv("samples.csv", lambda rows: rows[1].update(sequence=rows[0]["sequence"]))
        with self.assertRaisesRegex(ValueError, "duplicate sample sequence"):
            figure.prepare_data(self.root)

    def test_changed_warmup_classification_is_rejected(self):
        self.rewrite_csv("samples.csv", lambda rows: rows[0].update(phase="measured"))
        with self.assertRaisesRegex(ValueError, "warmup phase mismatch"):
            figure.prepare_data(self.root)

    def test_wrong_family_is_rejected(self):
        self.rewrite_csv("samples.csv", lambda rows: rows[0].update(tfhe_key="2"))
        with self.assertRaisesRegex(ValueError, "family schedule"):
            figure.prepare_data(self.root)

    def test_wrong_reported_output_is_rejected(self):
        self.rewrite_csv("samples.csv", lambda rows: rows[0].update(decoded_id="0"))
        with self.assertRaisesRegex(ValueError, "decoded output"):
            figure.prepare_data(self.root)

    def test_nonfinite_or_nonpositive_timer_is_rejected(self):
        for invalid in ("nan", "inf", "-inf", "0", "-1"):
            with self.subTest(value=invalid):
                self.rewrite_csv("samples.csv", lambda rows: rows[0].update(query_seconds=invalid))
                with self.assertRaisesRegex(ValueError, "out-of-range value: query_seconds"):
                    figure.prepare_data(self.root)

    def test_ckks_rounding_gate_is_checked(self):
        def change_error(rows):
            next(row for row in rows if row["arm"] == "ckks")["absolute_error"] = "0.5"

        self.rewrite_csv("samples.csv", change_error)
        with self.assertRaisesRegex(ValueError, "rounding gate"):
            figure.prepare_data(self.root)

    def test_changed_block_statistic_is_rejected(self):
        self.rewrite_csv("blocks.csv", lambda rows: rows[0].update(tfhe_reference_seconds="1.5"))
        with self.assertRaisesRegex(ValueError, "Numeric mismatch: blocks.csv/tfhe_reference_seconds"):
            figure.prepare_data(self.root)

    def test_duplicate_block_is_rejected(self):
        self.rewrite_csv("blocks.csv", lambda rows: rows.__setitem__(1, dict(rows[0])))
        with self.assertRaisesRegex(ValueError, "block identity/order mismatch"):
            figure.prepare_data(self.root)

    def test_changed_published_range_is_rejected(self):
        path = self.directory / "SOURCE_PINS.json"
        published = json.loads(path.read_text(encoding="utf-8"))
        published["groups"][0]["ckks_seconds"]["max"] = 99
        path.write_text(json.dumps(published), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Numeric mismatch: groups/ckks_seconds/max"):
            figure.prepare_data(self.root)


if __name__ == "__main__":
    unittest.main()
