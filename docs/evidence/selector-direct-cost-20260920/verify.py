"""Replay public statistics and hash bindings; no FHE operations or key access."""
from pathlib import Path
import hashlib
import json

from estimator import estimate


def main():
    base = Path(__file__).resolve().parent
    provenance = json.loads((base / 'PROVENANCE.json').read_text())
    for record in provenance['files']:
        actual = hashlib.sha256((base / record['path']).read_bytes()).hexdigest()
        if actual != record['public_sha256']:
            raise ValueError(f"Public file hash differs: {record['path']}")
    result = json.loads((base / 'TIMING_RESULT.json').read_text())
    pairs = result['all_pairs']
    primary = [row for row in pairs if row['primary']]
    secondary = [row for row in pairs if not row['primary']]
    if (len(primary), len(secondary)) != (60, 12):
        raise ValueError('Measurement budget differs')
    recalculated = {
        'primary': estimate(primary, intervals=True),
        'secondary': estimate(secondary, intervals=True),
        'per_scene': {
            scene: estimate([row for row in pairs if row['scene'] == scene])
            for scene in sorted({row['scene'] for row in pairs})
        },
        'per_family_primary': {
            str(family): estimate([row for row in primary if row['family'] == family])
            for family in range(3)
        },
    }
    for key, value in recalculated.items():
        if value != result[key]:
            raise ValueError(f'Statistics differ: {key}')
    print(json.dumps({'public_hashes_verified': len(provenance['files']),
                      'measured_pairs': len(pairs), 'statistics_match': True,
                      'primary': recalculated['primary']}, indent=2))


if __name__ == '__main__':
    main()
