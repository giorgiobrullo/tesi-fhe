"""The publication command must refuse changed inputs and existing outputs."""

from pathlib import Path
import tempfile
import unittest

from benchmark import figure_current as figures


class CommandTests(unittest.TestCase):
    def test_existing_destination_is_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "existing"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("original")
            with self.assertRaisesRegex(ValueError, "esiste già"):
                figures.generate(Path(folder), output)
            self.assertEqual(sentinel.read_text(), "original")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_frozen_figure_tree_is_not_an_output_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "output/figures/new"
            with self.assertRaisesRegex(ValueError, "esterna a output/figures"):
                figures.generate(root, output)
            self.assertFalse(output.exists())

    def test_changed_input_is_rejected_before_any_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first_input = root / next(iter(figures.INPUT_SHA256))
            first_input.parent.mkdir(parents=True)
            first_input.write_text("changed")
            output = root / "new-output"
            with self.assertRaisesRegex(ValueError, "Impronta"):
                figures.generate(root, output)
            self.assertFalse(output.exists())

    def test_missing_input_is_rejected_before_any_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "new-output"
            with self.assertRaises(FileNotFoundError):
                figures.generate(root, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
