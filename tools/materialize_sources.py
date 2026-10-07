#!/usr/bin/env python3
"""Reconstruct mapped research sources; never fetch, compile or run a probe."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--map', type=Path, required=True)
parser.add_argument('--output', type=Path, help='new directory outside this repository')
parser.add_argument('--dry-run', action='store_true', help='verify the source map without writing')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
mapping = json.loads(args.map.read_text())
if isinstance(mapping, dict) and mapping.get('schema') == 'research-package.v2':
    mapping = mapping.get('source_layout')
if not isinstance(mapping, dict) or mapping.get('schema') not in (
        'research-source-map.v1', 'research-source-dependencies.v1'):
    parser.error('unsupported map schema')
dependencies_only = mapping['schema'] == 'research-source-dependencies.v1'
if dependencies_only and not args.dry_run:
    parser.error('this dependency inventory has no reconstruction layout; use --dry-run')
excluded_rows = [] if dependencies_only else mapping.get('excluded_inputs')
if not isinstance(mapping.get('files'), list) or not isinstance(excluded_rows, list):
    parser.error('map must contain files and excluded_inputs lists')

def relative_path(value):
    if not isinstance(value, str) or ':' in value or '\\' in value:
        parser.error('expected a portable relative path')
    if any(part in ('', '.', '..') for part in value.split('/')):
        parser.error('empty, absolute or dot path segments are not allowed')
    path = Path(value)
    if path.is_absolute():
        parser.error('absolute paths are not allowed in the map')
    return path

excluded = []
for row in excluded_rows:
    if not isinstance(row, dict):
        parser.error('each excluded input must be an object')
    excluded.append(str(relative_path(row.get('workspace_path'))))

planned = []
seen = set()
for row in mapping['files']:
    if not isinstance(row, dict):
        parser.error('each file mapping must be an object')
    canonical = relative_path(row.get('canonical'))
    rel = canonical if dependencies_only else relative_path(row.get('workspace_path'))
    expected_hash = row.get('sha256')
    if (not isinstance(expected_hash, str) or len(expected_hash) != 64
            or any(c not in '0123456789abcdef' for c in expected_hash)
            or type(row.get('bytes')) is not int or row['bytes'] < 0):
        parser.error('each file requires a SHA-256 digest and nonnegative byte count')
    if any(rel == other or rel in other.parents or other in rel.parents for other in seen):
        parser.error('duplicate or conflicting workspace paths')
    seen.add(rel)
    source = (repo / canonical).resolve()
    if not source.is_relative_to(repo):
        parser.error('source path is outside this repository')
    content = source.read_bytes()
    if len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
        parser.error(f'source drift: {row["canonical"]}')
    planned.append((rel, content))
if not args.dry_run:
    if args.output is None:
        parser.error('--output is required unless --dry-run is supplied')
    if args.output.exists() or args.output.is_symlink():
        parser.error('output must not already exist, including a dangling symlink')
    output = args.output.resolve()
    if output.is_relative_to(repo) or output.exists():
        parser.error('output must be a new directory outside this repository')
    output.mkdir(parents=True)
    for rel, content in planned:
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
print(json.dumps({'verified_source_files': len(planned),
                  'written_source_files': 0 if args.dry_run else len(planned),
                  'excluded_inputs': excluded,
                  'reconstruction_available': not dependencies_only,
                  'compiled_or_executed': False}, indent=2))
