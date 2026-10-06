"""Check metadata compatibility and safe writes without running research code."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class MaterializeSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / 'repository'
        self.tools = self.repo / 'tools'
        self.tools.mkdir(parents=True)
        self.helper = self.tools / 'materialize_sources.py'
        shutil.copyfile(Path(__file__).with_name('materialize_sources.py'), self.helper)
        self.content = b'public synthetic source fixture\n'
        (self.repo / 'source.txt').write_bytes(self.content)
        self.mapping = {
            'schema': 'research-source-map.v1',
            'files': [{
                'workspace_path': 'crate/src/main.rs',
                'canonical': 'source.txt',
                'bytes': len(self.content),
                'sha256': hashlib.sha256(self.content).hexdigest(),
            }],
            'excluded_inputs': [{'workspace_path': 'fixtures/gallery.json'}],
        }
        self.output = self.base / 'restored'

    def invoke(self, mapping=None, *arguments):
        manifest = self.base / 'manifest.json'
        manifest.write_text(json.dumps(self.mapping if mapping is None else mapping))
        return subprocess.run(
            [sys.executable, str(self.helper), '--map', str(manifest), *arguments],
            capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, mapping, message, *arguments):
        result = self.invoke(mapping, *arguments)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertFalse(self.output.exists())

    def test_legacy_dry_run_verifies_without_writing(self):
        result = self.invoke(None, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['verified_source_files'], 1)
        self.assertEqual(receipt['written_source_files'], 0)
        self.assertTrue(receipt['reconstruction_available'])
        self.assertFalse(self.output.exists())

    def test_v2_materializes_the_original_layout_and_bytes(self):
        package = {'schema': 'research-package.v2', 'source_layout': self.mapping}
        result = self.invoke(package, '--output', str(self.output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / 'crate/src/main.rs').read_bytes(), self.content)
        self.assertFalse((self.output / 'fixtures/gallery.json').exists())
        self.assertEqual(json.loads(result.stdout)['written_source_files'], 1)

    def test_v2_must_contain_a_supported_layout(self):
        for layout in (None, [], {}, {'schema': 'unknown'}):
            with self.subTest(layout=layout):
                self.assert_rejected(
                    {'schema': 'research-package.v2', 'source_layout': layout},
                    'unsupported map schema', '--dry-run',
                )

    def test_dependency_inventory_verifies_but_has_no_reconstruction(self):
        row = dict(self.mapping['files'][0])
        del row['workspace_path']
        dependencies = {'schema': 'research-source-dependencies.v1', 'files': [row]}
        package = {'schema': 'research-package.v2', 'source_layout': dependencies}
        result = self.invoke(package, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['reconstruction_available'])
        self.assert_rejected(package, 'no reconstruction layout', '--output', str(self.output))

    def test_pin_mismatch_prevents_any_output(self):
        second = dict(self.mapping['files'][0], workspace_path='crate/src/other.rs', sha256='0' * 64)
        self.mapping['files'].append(second)
        self.assert_rejected(self.mapping, 'source drift', '--output', str(self.output))

    def test_size_mismatch_prevents_output(self):
        self.mapping['files'][0]['bytes'] += 1
        self.assert_rejected(self.mapping, 'source drift', '--output', str(self.output))

    def test_malformed_pins_are_rejected(self):
        for field, value in (('bytes', True), ('bytes', -1), ('sha256', 'F' * 64)):
            with self.subTest(field=field, value=value):
                mapping = copy.deepcopy(self.mapping)
                mapping['files'][0][field] = value
                self.assert_rejected(mapping, 'SHA-256 digest', '--dry-run')

    def test_duplicate_or_ancestor_paths_are_rejected(self):
        for path in ('crate/src/main.rs', 'crate/src', 'crate/src/main.rs/nested'):
            with self.subTest(path=path):
                mapping = copy.deepcopy(self.mapping)
                mapping['files'].append(dict(mapping['files'][0], workspace_path=path))
                self.assert_rejected(mapping, 'conflicting workspace paths', '--output', str(self.output))

    def test_paths_cannot_traverse_or_be_absolute(self):
        for field in ('canonical', 'workspace_path'):
            for value in ('../source.txt', '/source.txt', 'a//b', 'a/./b', 'C:\\source.txt'):
                with self.subTest(field=field, value=value):
                    mapping = copy.deepcopy(self.mapping)
                    mapping['files'][0][field] = value
                    result = self.invoke(mapping, '--output', str(self.output))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.output.exists())

    def test_source_symlink_cannot_escape_the_repository(self):
        external = self.base / 'external.txt'
        external.write_bytes(self.content)
        (self.repo / 'source.txt').unlink()
        (self.repo / 'source.txt').symlink_to(external)
        self.assert_rejected(self.mapping, 'outside this repository', '--output', str(self.output))

    def test_output_inside_repository_is_rejected(self):
        target = self.repo / 'new-output'
        self.assert_rejected(self.mapping, 'outside this repository', '--output', str(target))
        self.assertFalse(target.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / 'keep.txt'
        sentinel.write_bytes(b'keep')
        result = self.invoke(None, '--output', str(self.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b'keep')
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_dangling_output_symlink_is_rejected(self):
        destination = self.base / 'not-created'
        self.output.symlink_to(destination)
        result = self.invoke(None, '--output', str(self.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('dangling symlink', result.stderr)
        self.assertFalse(destination.exists())

    def test_malformed_input_lists_are_rejected(self):
        for key, value in (('files', {}), ('files', [None]), ('excluded_inputs', None),
                           ('excluded_inputs', [None])):
            with self.subTest(key=key, value=value):
                mapping = copy.deepcopy(self.mapping)
                mapping[key] = value
                result = self.invoke(mapping, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
