"""Source and circuit identity regressions; no compiler or FHE work."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runtime import configure


class SourceBindingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.root = self.repository / "runtime"
        (self.root / "core/src").mkdir(parents=True)
        (self.root / "core/src/lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
        (self.root / "client.py").write_text("VALUE = 1\n")
        for name, value in {
            "BASELINE_ORIGINS.json": {"runtime_source_sha256": "a" * 64},
            "circuit.template.json": {"magics": {}, "http_limits_bytes": {}},
            "config.template.json": {"contratto_esatto": {}},
        }.items():
            (self.root / name).write_bytes(configure.encoded(value))

    def build(self, mode="public_parallel"):
        return configure.build_files(mode, self.root)

    def test_bindings_close_over_all_files_and_match_client_configuration(self):
        files = self.build()
        pins = json.loads(files["SOURCE_PINS.json"])
        self.assertEqual(set(pins["all_leaves"]), set(files) - {"SOURCE_PINS.json"})
        for name, digest in pins["all_leaves"].items():
            self.assertEqual(configure.sha(files[name]), digest)
        contract = json.loads(files["CIRCUIT_CONTRACT.json"])
        config = json.loads(files["config.json"])["contratto_esatto"]
        self.assertEqual(config["circuit_sha256"], configure.sha(files["CIRCUIT_CONTRACT.json"]))
        for key in ("variant_id", "wire_version", "core_source_sha256", "service_source_sha256"):
            self.assertEqual(config[key], contract[key])
        self.assertEqual(config["core_source_sha256"].encode(), files["SOURCE_DIGEST.txt"])

    def test_code_changes_rebind_the_circuit_and_generated_files_do_not_feed_back(self):
        before = self.build()
        for name in configure.GENERATED:
            (self.root / name).write_text("stale generated content")
        self.assertEqual(before, self.build())
        (self.root / "client.py").write_text("VALUE = 2\n")
        client_changed = self.build()
        self.assertEqual(before["core-source.sha256"], client_changed["core-source.sha256"])
        self.assertNotEqual(before["circuit.sha256"], client_changed["circuit.sha256"])
        (self.root / "core/src/lib.rs").write_text("pub fn value() -> u8 { 2 }\n")
        core_changed = self.build()
        self.assertNotEqual(client_changed["core-source.sha256"], core_changed["core-source.sha256"])
        self.assertNotEqual(client_changed["circuit.sha256"], core_changed["circuit.sha256"])

    def test_g4_and_unknown_modes_are_explicitly_rejected(self):
        normal = self.build()
        self.assertFalse(json.loads(normal["config.json"])["contratto_esatto"]["g4_required"])
        for mode in ("public_parallel_g4", "typo"):
            with self.assertRaisesRegex(ValueError, "unsupported runtime mode"):
                self.build(mode)

    def test_refresh_and_check_detect_a_later_source_change(self):
        with self.assertRaisesRegex(ValueError, "stale source bindings"):
            configure.check("public_parallel", self.root)
        configure.refresh("public_parallel", self.root)
        configure.check("public_parallel", self.root)
        (self.root / "client.py").write_text("VALUE = 3\n")
        with self.assertRaisesRegex(ValueError, "stale source bindings"):
            configure.check("public_parallel", self.root)

    def test_private_keys_and_symlinks_cannot_enter_the_source_manifest(self):
        key = self.root / "client.key"
        key.write_bytes(b"test sentinel, not a real key")
        with self.assertRaisesRegex(ValueError, "non-source"):
            self.build()
        key.unlink()
        (self.root / "alias").symlink_to(self.root / "client.py")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build()

    def test_create_preserves_source_and_refuses_overwrite_or_nested_destination(self):
        destination = self.repository / ".local/new-variant"
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with patch.object(configure, "ROOT", self.root):
            result = configure.create("public_parallel", destination)
            self.assertEqual(result["destination"], str(destination))
            self.assertEqual((destination / "client.py").read_bytes(), before[Path("client.py")])
            for invalid in (destination, self.root / "nested", self.repository.parent / "outside"):
                with self.assertRaises(ValueError):
                    configure.create("public_parallel", invalid)
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
