"""Eight owned local services; same key/ciphertexts, profiling off versus on.

Only the root executes this bounded empirical driver. Reuses the recent HTTP,
decryption and cleanup code; no compilation, key generation or model replay.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import statistics
import sys
import time

sys.dont_write_bytecode = True
BASE_PATH = Path('/workspace/research/tmp/current-build-timing-20261004/root/paired_http.py')
BASE_SHA = '0984f94a95b4bd0c1fcb5d799ad6f0c71453ab6a461e4796b2e107df6ec413ef'
if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA:
    raise RuntimeError('Recent helper driver changed')
loader = importlib.util.spec_from_file_location('recent_empirical_http', BASE_PATH)
base = importlib.util.module_from_spec(loader)
loader.loader.exec_module(base)

SCENES = base.SCENES
STAGES = ('scoring_wall_ns', 'extraction_wall_ns', 'tournament_wall_ns', 'final_wall_ns')
HEADER = 'x-varco-stage-profile'
require = base.require


def schedule():
    return [(0, block, position, role) for block in range(4)
            for position, role in enumerate((0, 1) if block % 2 == 0 else (1, 0))]


def validate_spec(spec):
    require(spec.get('schema') == 'current-core-profile-http.v1', 'wrong spec schema')
    for field, value in (('blocks', 4), ('measured_reps', 2), ('warmups_per_scene', 1)):
        require(type(spec.get(field)) is int and spec[field] == value, 'wrong bounded schedule: ' + field)
    require(type(spec.get('rayon_threads')) is int and spec['rayon_threads'] == 16, 'expected 16 threads')
    require(type(spec.get('stage_tolerance_ns')) is int and 0 <= spec['stage_tolerance_ns'] <= 1_000_000,
            'stage tolerance must be at most 1 ms')
    require(spec.get('key_origin') in ('fresh', 'reused'), 'explicit key origin required')
    require(isinstance(spec.get('compiler_identity'), str) and spec['compiler_identity'], 'compiler required')
    for field in ('python', 'output', 'fixtures', 'runtime', 'binary', 'build_receipt', 'keydir', 'keygen_receipt'):
        require(Path(spec[field]).is_absolute(), 'path must be absolute: ' + field)


def validate_profile(profile, counts, tolerance_ns):
    require(isinstance(profile, dict) and profile.get('schema') == 'smallcuts-stage-profile.v1',
            'missing or wrong stage profile')
    require(profile.get('gallery_size') == 120 and profile.get('mode') == 'both'
            and profile.get('narrow_id_active') is True and profile.get('requested_parallel') is True
            and type(profile.get('tail_cutoff')) is int and profile['tail_cutoff'] == 0,
            'profiling must retain the selected public_parallel N120 algorithm')
    for field in (*STAGES, 'evaluate_wall_ns'):
        require(type(profile.get(field)) is int and profile[field] > 0, 'missing real stage timer: ' + field)
    total = sum(profile[field] for field in STAGES)
    require(total <= profile['evaluate_wall_ns'] + tolerance_ns, 'stage walls exceed evaluate wall')
    require(profile.get('primitive_work_counts') == counts, 'profile work counts differ from public plan')
    require(isinstance(profile.get('duration_semantics'), str)
            and 'levels are included in tournament' in profile['duration_semantics'], 'duration semantics missing')
    levels = profile.get('levels')
    require(isinstance(levels, list), 'invalid level records')
    candidates_seen = []
    for level in levels:
        require(isinstance(level, dict), 'invalid level record')
        n = level.get('candidates')
        require(type(n) is int and 2 <= n <= 120, 'invalid level candidate count')
        require(type(level.get('ready_merges')) is int and level['ready_merges'] == n // 2
                and type(level.get('carried_candidates')) is int and level['carried_candidates'] == n % 2,
                'invalid level merge ledger')
        require(type(level.get('scheduled_parallel')) is bool, 'missing level scheduling metadata')
        require(type(level.get('wall_ns')) is int and level['wall_ns'] >= 0, 'invalid level wall time')
        candidates_seen.append(n)
    require(all(a > b for a, b in zip(candidates_seen, candidates_seen[1:])), 'unordered or repeated levels')
    require(sum(level['wall_ns'] for level in levels) <= profile['tournament_wall_ns'] + tolerance_ns,
            'level walls exceed their tournament parent')
    return profile


def summarize(rows):
    expected = {(block, arm, scene, phase, repetition)
                for block in range(4) for arm in ('off', 'on') for scene in SCENES
                for phase, repetitions in (('warmup', 1), ('measured', 2)) for repetition in range(repetitions)}
    identities = [(row['block'], row['arm'], row['scene'], row['phase'], row['repetition']) for row in rows]
    require(len(rows) == 72 and len(set(identities)) == 72 and set(identities) == expected,
            'incomplete or duplicate bounded coverage')
    require(all(row.get('correct') is True for row in rows), 'unvalidated output')
    for scene in SCENES:
        require(len({row['input_sha256'] for row in rows if row['scene'] == scene}) == 1,
                'ciphertext differs between off/on or blocks')
    require(len({row['server_key_sha256'] for row in rows}) == 1
            and len({row['binary_sha256'] for row in rows}) == 1
            and len({row['circuit_sha256'] for row in rows}) == 1, 'on/off build or key differs')
    require(all((row['stage_profile'] is not None) == (row['arm'] == 'on') for row in rows),
            'unexpected profile coverage')
    result = {}
    measured = [row for row in rows if row['phase'] == 'measured']
    for scene in SCENES:
        arms = {}
        for arm in ('off', 'on'):
            block_ms, http_ms = [], []
            for block in range(4):
                selected = [row for row in measured if row['scene'] == scene and row['arm'] == arm
                            and row['block'] == block]
                require(all(math.isfinite(row['elapsed_ms']) and row['elapsed_ms'] > 0
                            and row['http_elapsed_ns'] > 0 for row in selected), 'invalid timer')
                block_ms.append(statistics.median(row['elapsed_ms'] for row in selected))
                http_ms.append(statistics.median(row['http_elapsed_ns'] / 1e6 for row in selected))
            arms[arm] = {'block_server_median_ms': block_ms, 'block_http_median_ms': http_ms}
        ratios = [arms['on']['block_server_median_ms'][i] / arms['off']['block_server_median_ms'][i]
                  for i in range(4)]
        profiles = [row['stage_profile'] for row in measured if row['arm'] == 'on' and row['scene'] == scene]
        result[scene] = {'arms': arms, 'on_over_off_block_ratios': ratios,
                         'median_block_ratio': statistics.median(ratios),
                         'on_profile_wall_median_ns': {field: statistics.median(p[field] for p in profiles)
                                                      for field in (*STAGES, 'evaluate_wall_ns')}}
    profiles = [row['stage_profile'] for row in measured if row['arm'] == 'on']
    candidate_counts = sorted({level['candidates'] for p in profiles for level in p['levels']}, reverse=True)
    return {'scenes': result, 'warmup_calls': 24, 'measured_calls': 48, 'on_measured_profiles': 24,
            'owned_service_processes': 8, 'key_families': 1, 'fixed_scene_vectors': 3,
            'on_profile_wall_median_ns': {field: statistics.median(p[field] for p in profiles)
                                         for field in (*STAGES, 'evaluate_wall_ns')},
            'on_unassigned_wall_median_ns': statistics.median(p['evaluate_wall_ns'] - sum(p[s] for s in STAGES)
                                                             for p in profiles),
            'levels_included_in_tournament': True,
            'level_records': [{'candidates': n,
                               'profile_count': sum(any(l['candidates'] == n for l in p['levels']) for p in profiles),
                               'wall_median_ns': statistics.median(l['wall_ns'] for p in profiles for l in p['levels']
                                                                  if l['candidates'] == n)} for n in candidate_counts],
            'estimand': 'Per scene: on/off ratio of two-request medians within each block, then median of four block ratios.',
            'limits': 'One key family and host, three fixed precomputed queries. Compares the profiling flag within one patched copy, not the whole patch versus the maintained runtime. No independent-family replication, confidence interval, runtime optimization, browser latency or rare-error guarantee. Levels are nested in tournament; missing level records do not imply zero work.'}


class ProfileRows(list):
    """Attach captured headers before the inherited loop writes each validated row."""
    def __init__(self, pilot):
        super().__init__()
        self.pilot = pilot

    def append(self, row):
        row['stage_profile'] = self.pilot.response_profiles[row['output']]
        super().append(row)


class Pilot(base.Pilot):
    def __init__(self, spec_path):
        self.spec_path = spec_path.resolve(strict=True)
        self.spec = json.loads(self.spec_path.read_text())
        validate_spec(self.spec)
        require(sys.version_info[:2] == (3, 12), 'run with the supplied Python 3.12')
        require(Path(sys.executable).resolve() == Path(self.spec['python']).resolve(), 'Python path differs from spec')
        self.clean_env = dict(os.environ, RAYON_NUM_THREADS='16', PYTHONDONTWRITEBYTECODE='1')
        self.clean_env.pop('VARCO_PROFILE_PHASES', None)
        self.env = self.clean_env.copy()
        self.output = Path(self.spec['output']).resolve()
        self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.fixtures = Path(self.spec['fixtures']).resolve(strict=True)
        self.input_pins, self.arms, self.logs = {}, [], []
        self.process = self.active_directory = self.reference_plan = self.last_http_elapsed_ns = None
        self.current_mode = 'off'
        self.response_profiles = {}
        self.rows = ProfileRows(self)
        for name in ('events.jsonl', 'samples.jsonl'):
            (self.output / name).open('x', encoding='utf-8').close()

    def prepare(self):
        self.pin(self.spec_path)
        self.pin(BASE_PATH)
        self.pin(Path(__file__))
        manifest_path = self.fixtures / 'MANIFEST.json'
        self.pin(manifest_path)
        manifest = json.loads(manifest_path.read_text())
        require(manifest['schema'] == 'web-thread-scaling-fixtures.v1', 'wrong fixture provenance')
        for name, identity in manifest['artifacts'].items():
            path = (self.fixtures / name).resolve(strict=True)
            require(path.is_relative_to(self.fixtures) and base.sha(path) == identity['sha256']
                    and path.stat().st_size == identity['bytes'], 'fixture changed: ' + name)
            self.pin(path)
        self.entries = json.loads((self.fixtures / 'gallery.json').read_text())['entries']
        require(len(self.entries) == 120 and len({e['id'] for e in self.entries}) == 120, 'expected unique N120 gallery')
        bounds = []
        for entry in self.entries:
            norm = sum(x*x for x in entry['vettore'])
            radius = math.isqrt(1024 * norm)
            radius += radius * radius != 1024 * norm
            bounds.append((norm - 2 * radius, norm + 2 * radius))
        require(max(h for _, h in bounds) - min(l for l, _ in bounds) + 1 <= 4096, 'gallery outside admission')
        self.probes = {}
        for scene in SCENES:
            probe = json.loads((self.fixtures / 'probes' / (scene + '.json')).read_text())
            actual = base.oracle(self.entries, probe['query'])
            require(all(probe['expected'][k] == v for k, v in actual.items()), 'integer oracle differs')
            self.probes[scene] = {'query': probe['query'], 'oracle': actual}
        runtime = Path(self.spec['runtime']).resolve(strict=True)
        binary = Path(self.spec['binary']).resolve(strict=True)
        keys = Path(self.spec['keydir']).resolve(strict=True)
        require(not self.output.is_relative_to(runtime) and not self.output.is_relative_to(keys), 'output inside inputs')
        config = json.loads((runtime / 'config.json').read_text())['contratto_esatto']
        require(base.sha(runtime / 'CIRCUIT_CONTRACT.json') == config['circuit_sha256'], 'config/circuit binding differs')
        require(config['runtime_mode'] == 'public_parallel' and config['g4_required'] is False, 'wrong selected mode')
        build_path, key_path = Path(self.spec['build_receipt']), Path(self.spec['keygen_receipt'])
        for path in (binary, keys / 'client.key', keys / 'server.key', build_path, key_path):
            self.pin(path)
        build, receipt = json.loads(build_path.read_text()), json.loads(key_path.read_text())
        require(build['compiler_identity'] == self.spec['compiler_identity']
                and build['binary_sha256'] == base.sha(binary) and build.get('build_settings'), 'build receipt mismatch')
        require(receipt.get('bundle_roundtrip_equal') is True and receipt.get('bundle_validation_pass') is True
                and receipt['server_envelope_sha256'] == base.sha(keys / 'server.key'), 'key roundtrip receipt mismatch')
        require(all(receipt[k] == config[k] for k in base.KEY_BINDINGS), 'keygen bindings differ')
        key_info = {name: base.key_envelope(keys / (name + '.key'), config, magic)
                    for name, magic in (('client', b'VRCCK17!'), ('server', b'VRCHD17!'))}
        parameters = base.parameter_metadata(runtime, config)
        require(parameters['tfhe_rs'] == '1.8.1', 'expected current TFHE-rs 1.8.1')
        protocol = base.load_protocol(runtime, 0)
        source_pins = base.inventory(runtime)
        common = {'family': 'profile-family1', 'key_origin': self.spec['key_origin'], 'runtime': runtime,
                  'binary': binary, 'keys': keys, 'config': config, 'source_pins': source_pins,
                  'key_info': key_info, 'parameters': parameters, 'binary_sha256': base.sha(binary),
                  'protocol': protocol, 'ciphertexts': {}}
        self.arms = [dict(common, name=name, role=role) for role, name in enumerate(('off', 'on'))]
        folder = self.output / 'inputs-shared'
        folder.mkdir()
        for scene, probe in self.probes.items():
            plain, ciphertext = folder / (scene + '.txt'), folder / (scene + '.probe.ct')
            with plain.open('x') as stream:
                stream.write(' '.join(map(str, probe['query'])) + '\n')
            result = self.cli(self.arms[0], folder, scene + '-encrypt', ['encrypt', keys, plain, ciphertext, 'head51'])
            require(result['query_profile'] == 'head51', 'wrong encrypted profile')
            common['ciphertexts'][scene] = ciphertext
            self.pin(ciphertext)
        base.save(self.output / 'PREPARED.json', {
            'schema': 'current-core-profile-preflight.v1', 'spec': self.spec, 'driver_sha256': base.sha(Path(__file__)),
            'helper_driver_sha256': BASE_SHA, 'input_pins': self.input_pins,
            'host': {'platform': platform.platform(), 'machine': platform.machine(), 'python': sys.version},
            'source_pins': source_pins, 'config': config, 'parameters': parameters, 'key_info': key_info,
            'build_receipt': build, 'probes': self.probes, 'schedule': schedule(),
            'calls': {'warmup': 24, 'measured': 48}, 'owned_service_processes': 8,
            'scope': 'One binary/runtime/key family and three shared ciphertexts; only VARCO_PROFILE_PHASES differs.'})

    def request(self, label, method, route, body=b'', content_type='application/octet-stream'):
        data, headers, output = super().request(label, method, route, body, content_type)
        if method == 'POST' and route == '/varco':
            normalized = {k.lower(): v for k, v in headers.items()}
            require((HEADER in normalized) == (self.current_mode == 'on'), 'unexpected profiling header presence')
            profile = None
            if self.current_mode == 'on':
                profile = self.arms[0]['protocol'].strict_json(normalized[HEADER].encode())
                validate_profile(profile, self.reference_plan['conteggi'], self.spec['stage_tolerance_ns'])
                require(profile['evaluate_wall_ns'] <= float(normalized['x-tempo-ms']) * 1e6 + 1_000_000,
                        'core evaluate wall exceeds outer service timer')
            self.response_profiles[str(output)] = profile
        return data, headers, output

    def run_arm(self, family, block, position, role):
        self.current_mode = ('off', 'on')[role]
        self.env = self.clean_env.copy()
        if role == 1:
            self.env['VARCO_PROFILE_PHASES'] = '1'
        super().run_arm(family, block, position, role)

    def run(self):
        faults, summary = [], None
        try:
            self.prepare()
            for step in schedule():
                self.run_arm(*step)
            summary = summarize(self.rows)
        except BaseException as exc:
            faults.append(repr(exc))
        finally:
            try:
                self.stop()
            except Exception as exc:
                faults.append('cleanup: ' + repr(exc))
            for path, pin in self.input_pins.items():
                try:
                    require(Path(path).is_file() and base.sha(path) == pin, 'input changed: ' + path)
                except Exception as exc:
                    faults.append(repr(exc))
            if self.arms:
                try:
                    require(base.inventory(self.arms[0]['runtime']) == self.arms[0]['source_pins'], 'runtime changed')
                except Exception as exc:
                    faults.append(repr(exc))
            result = {'schema': 'current-core-profile-complete.v1', 'passed': summary is not None and not faults,
                      'faults': faults, 'summary': summary, 'completed_unix_ns': time.time_ns(),
                      'artifacts': {str(p.relative_to(self.output)): base.sha(p)
                                    for p in sorted(self.output.rglob('*')) if p.is_file()}}
            base.save(self.output / 'COMPLETE.json', result)
            print(json.dumps({'passed': result['passed'], 'faults': faults,
                              'receipt': str(self.output / 'COMPLETE.json')}), flush=True)
        return 0 if result['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    sys.dont_write_bytecode = True
    return Pilot(args.spec).run()


if __name__ == '__main__':
    raise SystemExit(main())
