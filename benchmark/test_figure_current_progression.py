"""Regressions for the scientific estimators and public-source checks."""

import csv
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from benchmark import figure_current_progression as figures

ROOT = Path(__file__).resolve().parents[1]


class ProgressionTests(unittest.TestCase):
    def copy_sources(self, root: Path) -> None:
        for name in figures.SOURCE_FILES:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())

    def test_linear_quartiles_are_not_inclusive_or_exclusive_hinges(self):
        self.assertEqual(figures.quartile([0, 1, 9, 20], 1), Decimal("0.75"))
        self.assertEqual(figures.quartile([0, 1, 9, 20], 2), Decimal("5"))
        self.assertEqual(figures.quartile([0, 1, 9, 20], 3), Decimal("11.75"))

    def test_public_observations_reproduce_archived_points(self):
        data = figures.prepare_data(ROOT)
        self.assertEqual(data["counts"]["exact_measured"], 300)
        self.assertEqual(data["load"], {"outputs": 300, "high_load": 300, "unknown": 164})
        self.assertEqual(Decimal(data["exact_points"][-1]["median_ns"]), Decimal("1821339396"))
        self.assertEqual(data["historical_prototypes"][0]["count"], 18)

    def test_warmup_never_enters_the_medians(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.copy_sources(root)
            path = root / figures.SOURCE / "misure.csv"
            rows = figures.read_rows(path)
            for row in rows:
                if row["phase"] == "warmup":
                    row["duration_ns"] = "999999999999999"
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            result = figures.prepare_data(root)
            self.assertEqual(result["exact_points"], figures.prepare_data(ROOT)["exact_points"])

    def test_duplicate_replacing_a_missing_observation_is_rejected(self):
        rows = figures.read_rows(ROOT / figures.SOURCE / "misure.csv")
        rows[-1] = dict(rows[-2])
        with self.assertRaisesRegex(ValueError, "Calendario|duplicato"):
            figures.validate_exact_rows(rows)

    def test_reported_failure_is_not_filtered_away(self):
        rows = figures.read_rows(ROOT / figures.SOURCE / "misure.csv")
        rows[0]["semantic_pass"] = "False"
        with self.assertRaisesRegex(ValueError, "non corretto"):
            figures.validate_exact_rows(rows)


if __name__ == "__main__":
    unittest.main()
