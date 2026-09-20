"""Asset discovery in a checkout without local research notes."""
from pathlib import Path
import tempfile
import unittest

from runtime.client.configuration import ClientConfiguration


class AssetRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        embedding = self.project / "experiments/08_cnn/embedding.py"
        embedding.parent.mkdir(parents=True)
        embedding.write_text("")

    def configuration(self, relative):
        return ClientConfiguration(self.project / relative, Path("binary"), Path("keys"))

    def test_checkout_needs_project_files_but_no_research_note(self):
        (self.project / "pyproject.toml").write_text("[project]\n")
        self.assertFalse((self.project / "RESEARCH_STATE.md").exists())
        self.assertEqual(self.configuration("runtime").assets, self.project)

    def test_nested_runtime_finds_the_same_project(self):
        (self.project / "pyproject.toml").write_text("[project]\n")
        self.assertEqual(self.configuration(".local/variant/runtime").assets, self.project)

    def test_research_note_is_not_a_project_marker(self):
        (self.project / "RESEARCH_STATE.md").write_text("local notes")
        with self.assertRaises(StopIteration):
            self.configuration("runtime").assets


if __name__ == "__main__":
    unittest.main()
