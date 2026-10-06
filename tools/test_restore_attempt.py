"""Tests use tiny temporary fixtures only; no research program is imported."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("restore_attempt", Path(__file__).with_name("restore_attempt.py"))
restore_attempt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore_attempt)


class RestoreAttemptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir()
        self.output = self.base / "restored"
        self.manifest = {
            "schema": "attempts-a-source-mapping.v1", "scope": "Test fixture only",
            "files": [], "literal_compile_dependencies": [],
            "attempts": [{"id": "A1", "completeness": "programmi mappati"},
                         {"id": "A99", "completeness": "nessun programma censito"}],
        }
        self.add_file("A1", "tmp/a1/main.py", "sources/main.py", b"first\n")

    def add_file(self, identifier, target, source, data):
        path = self.root / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.manifest["files"].append({
            "archive_relative": target, "canonical": source, "ids": [identifier],
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        })

    def add_dependency(self, source, target, status="mapped_program"):
        self.manifest["literal_compile_dependencies"].append({
            "source": source, "resolved_archive_relative": target, "status": status,
        })

    def save(self):
        path = self.root / restore_attempt.MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_restores_only_selected_id_and_transitive_mapped_dependencies(self):
        self.add_file("A2", "tmp/a2/helper.rs", "sources/helper.rs", b"helper\n")
        self.add_file("A3", "tmp/a3/table.json", "sources/table.json", b"[1]\n")
        self.add_file("A4", "tmp/a4/unrelated.py", "sources/unrelated.py", b"ignore\n")
        self.add_dependency("tmp/a1/main.py", "tmp/a2/helper.rs")
        self.add_dependency("tmp/a2/helper.rs", "tmp/a3/table.json", "mapped_public_compile_input")
        self.add_dependency("tmp/a3/table.json", "tmp/a1/main.py")
        self.add_dependency("tmp/a1/main.py", "external.bin", "not_imported_input_or_external_source_requires_review")
        self.save()
        receipt = restore_attempt.restore("A1", self.root, self.output)
        self.assertEqual(receipt["file_count"], 3)
        self.assertEqual(len(receipt["shared_dependency_files"]), 2)
        self.assertEqual(len(receipt["unresolved_literal_dependencies"]), 1)
        self.assertEqual((self.output / "tmp/a1/main.py").read_bytes(), b"first\n")
        self.assertEqual((self.output / "tmp/a3/table.json").read_bytes(), b"[1]\n")
        self.assertFalse((self.output / "tmp/a4").exists())
        self.assertEqual(json.loads((self.output / restore_attempt.RECEIPT).read_text()), receipt)

    def test_rejects_malformed_attempt_metadata_before_write(self):
        for metadata in ([{"id": "../A1"}], [{"id": "A1"}, {"id": "A1"}], "A1"):
            with self.subTest(metadata=metadata):
                self.manifest["attempts"] = metadata
                self.save()
                with self.assertRaises(restore_attempt.RestoreError):
                    restore_attempt.restore("A1", self.root, self.output)
                self.assertFalse(self.output.exists())

    def test_check_verifies_without_creating_output(self):
        self.save()
        receipt = restore_attempt.restore("A1", self.root)
        self.assertEqual(receipt["mode"], "check")
        self.assertFalse(self.output.exists())
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), ["repository"])

    def test_hash_failure_before_any_destination_write(self):
        self.add_file("A1", "tmp/a1/second.py", "sources/second.py", b"second\n")
        self.save()
        (self.root / "sources/second.py").write_bytes(b"changed\n")
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_destination_is_preserved(self):
        self.save()
        self.output.mkdir()
        marker = self.output / "preserved"
        marker.write_text("do not overwrite")
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.output)
        self.assertEqual(marker.read_text(), "do not overwrite")

    def test_rejects_source_and_target_traversal(self):
        for field in ("canonical", "archive_relative"):
            original = self.manifest["files"][0][field]
            for unsafe in ("../escape", "/absolute", "a/../escape", "a//b", "a\\b", "C:/escape"):
                with self.subTest(field=field, unsafe=unsafe):
                    self.manifest["files"][0][field] = unsafe
                    self.save()
                    with self.assertRaises(restore_attempt.RestoreError):
                        restore_attempt.restore("A1", self.root, self.output)
                    self.assertFalse(self.output.exists())
            self.manifest["files"][0][field] = original

    def test_rejects_source_file_symlink(self):
        self.save()
        source = self.root / "sources/main.py"
        source.unlink()
        outside = self.base / "outside.py"
        outside.write_bytes(b"first\n")
        source.symlink_to(outside)
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_source_directory_symlink(self):
        self.save()
        (self.root / "sources").rename(self.base / "outside")
        (self.root / "sources").symlink_to(self.base / "outside", target_is_directory=True)
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_output_parent_symlink(self):
        self.save()
        (self.base / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.base / "alias/restored")
        self.assertFalse((self.root / "restored").exists())

    def test_rejects_duplicate_or_file_directory_destinations(self):
        original = self.manifest["files"][0]
        for target in ("tmp/a1/main.py", "tmp/a1/main.py/child"):
            with self.subTest(target=target):
                self.manifest["files"] = [original, {**original, "archive_relative": target}]
                self.save()
                with self.assertRaises(restore_attempt.RestoreError):
                    restore_attempt.restore("A1", self.root, self.output)
                self.assertFalse(self.output.exists())

    def test_missing_declared_mapping_fails_but_unmapped_dependency_is_a_limit(self):
        self.add_dependency("tmp/a1/main.py", "tmp/missing.rs")
        self.save()
        with self.assertRaises(restore_attempt.RestoreError):
            restore_attempt.restore("A1", self.root, self.output)
        self.manifest["literal_compile_dependencies"][0]["status"] = "unresolved_external_or_absent_archive_dependency"
        self.save()
        receipt = restore_attempt.restore("A1", self.root)
        self.assertEqual(len(receipt["unresolved_literal_dependencies"]), 1)

    def test_list_preserves_declared_zero_source_id_and_does_not_verify_hashes(self):
        self.save()
        (self.root / "sources/main.py").unlink()
        rows = restore_attempt.list_attempts(self.root)
        self.assertEqual([row["id"] for row in rows], ["A1", "A99"])
        self.assertEqual(rows[1]["mapped_files"], 0)
        self.assertEqual(rows[1]["completeness"], "nessun programma censito")


if __name__ == "__main__":
    unittest.main()
