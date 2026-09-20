"""Legacy startup behavior, using temporary keys and an injected fake runner."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import app
from .configuration import ClientConfiguration
from .pipeline import AccessPipeline


class LegacyStartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.keys = Path(self.temporary.name) / "keys"
        self.runner = mock.Mock(side_effect=self.generate_fake_keys)
        self.transport = mock.Mock(return_value=(b"{}", {}))
        configuration = ClientConfiguration(app.ROOT, Path("/fake-binary"), self.keys)
        self.pipeline = AccessPipeline(configuration, self.transport, self.runner)
        self.pipeline.log = mock.Mock()
        self.pipeline.assicura_chiave = mock.Mock()
        patcher = mock.patch.object(app, "pipeline", self.pipeline)
        patcher.start()
        self.addCleanup(patcher.stop)

    def generate_fake_keys(self, command, directory):
        self.assertEqual(command, "keygen")
        for name in ("client.key", "server.key"):
            (directory / name).write_bytes(b"fake legacy key")
        return {"ok": True}

    def test_legacy_startup_only_creates_keys_when_both_are_absent(self):
        app.avvio()
        self.runner.assert_called_once_with("keygen", self.keys)
        self.assertTrue(self.pipeline.ready)
        before = {path.name: path.read_bytes() for path in self.keys.iterdir()}
        app.avvio()
        self.runner.assert_called_once()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.keys.iterdir()})

    def test_incomplete_legacy_pair_aborts_before_runner_or_transport(self):
        self.keys.mkdir()
        (self.keys / "client.key").write_bytes(b"preserve-this-key")
        with self.assertRaises(RuntimeError):
            app.avvio()
        self.runner.assert_not_called()
        self.transport.assert_not_called()
        self.assertEqual((self.keys / "client.key").read_bytes(), b"preserve-this-key")
        self.assertFalse((self.keys / "server.key").exists())


if __name__ == "__main__":
    unittest.main()
