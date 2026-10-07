"""One owned service, four FHE queries; one designated merge per evaluation.

Root executes only after offline checks and fresh isolation. No build/keygen.
Recent empirical helpers supply input/oracle, HTTP, CLI and owned-Popen cleanup.
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
import socket
import sys
import time

sys.dont_write_bytecode = True
HELPER_PATH = Path('/workspace/research/tmp/current-core-profile-20261004/root/profile_http.py')
HELPER_SHA = '5a1e079ff99373a320f20ed0176acb34e65117ae752798c148be510d43170269'
if hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest() != HELPER_SHA:
    raise RuntimeError('Recent empirical profile helper changed')
loader = importlib.util.spec_from_file_location('recent_core_profile', HELPER_PATH)
recent = importlib.util.module_from_spec(loader)
loader.loader.exec_module(recent)
base = recent.base
require = base.require
SCENES = base.SCENES
COUNTS = {'br': 1111, 'pfks': 509, 'ks': 1080, 'marginals': 1709, 'initial_samples': 120}
PARTS = ('comparison_wall_ns', 'prepare_control_wall_ns', 'pfks_wall_ns',
         'packing_rotation_wall_ns', 'extraction_addback_wall_ns')


def sequence():
    return [('warmup', 'einstein'), *[('measured', scene) for scene in SCENES]]


def validate_spec(spec):
    require(spec.get('schema') == 'current-merge-profile-http.v1', 'wrong spec schema')
    for field, value in (('service_processes', 1), ('warmup_calls', 1), ('measured_calls', 3), ('rayon_threads', 16)):
        require(type(spec.get(field)) is int and spec[field] == value, 'wrong finite scope: ' + field)
    require(type(spec.get('stage_tolerance_ns')) is int and 0 <= spec['stage_tolerance_ns'] <= 250_000,
            'tolerance must be at most 0.25 ms')
    require(spec.get('key_origin') in ('fresh', 'reused'), 'key origin required')
    require(isinstance(spec.get('compiler_identity'), str) and spec['compiler_identity'], 'compiler identity required')
    for field in ('python', 'output', 'fixtures', 'runtime', 'binary', 'build_receipt', 'keydir', 'keygen_receipt'):
        require(Path(spec[field]).is_absolute(), 'path must be absolute: ' + field)


def validate_designated(profile, counts, tolerance_ns):
    recent.validate_profile(profile, counts, tolerance_ns)
    require(counts == COUNTS, 'wrong selected public_parallel N120 counts')
    node = profile.get('designated_merge')
    require(isinstance(node, dict) and node.get('schema') == 'smallcuts-designated-merge.v1',
            'one designated merge object required')
    for field, value in (('candidates', 120), ('ready_merges', 60), ('level_index', 0), ('index', 0)):
        require(type(node.get(field)) is int and node[field] == value, 'wrong designated node: ' + field)
    require(node.get('internal_parallel') is False and node.get('completed') is True,
            'designated node must complete with sequential internal work')
    for field in (*PARTS, 'node_wall_ns'):
        require(type(node.get(field)) is int and node[field] > 0, 'missing real node timer: ' + field)
    # First public ID1/ID2 pair: three score digits plus varying low ID digit.
    require(type(node.get('payloads')) is int and node['payloads'] == 4
            and type(node.get('group_count')) is int and node['group_count'] == 1,
            'designated public pair must have four payloads in one group')
    require(sum(node[field] for field in PARTS) <= node['node_wall_ns'],
            'disjoint component walls exceed node wall')
    require(type(node.get('unassigned_wall_ns')) is int and node['unassigned_wall_ns'] >= 0,
            'invalid unassigned node time')
    require(node['unassigned_wall_ns'] == max(0, node['node_wall_ns'] - sum(node[p] for p in PARTS)),
            'unassigned node time inconsistent')
    levels = profile['levels']
    require(bool(levels) and levels[0]['candidates'] == 120 and levels[0]['ready_merges'] == 60
            and levels[0]['carried_candidates'] == 0 and levels[0]['scheduled_parallel'] is True,
            'first parallel level missing')
    require(node['node_wall_ns'] <= levels[0]['wall_ns'] + tolerance_ns, 'node exceeds containing first level')
    semantics = node.get('duration_semantics')
    require(isinstance(semantics, str) and 'one worker wall time' in semantics
            and 'node is included in first level' in semantics, 'node scope semantics missing')
    return node


def summarize(rows):
    require(len(rows) == 4 and [(r['phase'], r['scene']) for r in rows] == sequence(),
            'expected only one warmup and three measured queries')
    require(all(r.get('correct') is True for r in rows), 'unvalidated output')
    return {'warmup_calls': 1, 'measured_calls': 3, 'owned_service_processes': 1,
            'key_families': 1, 'fixed_scene_vectors': 3,
            'measured': [{'scene': r['scene'], 'server_ms': r['elapsed_ms'],
                          'http_ms': r['http_elapsed_ns'] / 1e6,
                          'designated_merge': r['stage_profile']['designated_merge']} for r in rows if r['phase'] == 'measured'],
            'limits': 'One observed node in each of three measured queries, one key family and host. Worker wall time includes scheduling delays; first level contains 60 parallel merges. Do not scale the node by 60, sum workers, or infer tournament share, speedup, confidence bounds or rare-error probability.'}


class Pilot(base.Pilot):
    def __init__(self, spec_path):
        self.spec_path = spec_path.resolve(strict=True)
        self.spec = json.loads(self.spec_path.read_text())
        validate_spec(self.spec)
        require(sys.version_info[:2] == (3, 12) and Path(sys.executable).resolve() == Path(self.spec['python']).resolve(),
                'use the exact Python 3.12 from spec')
        self.env = dict(os.environ, RAYON_NUM_THREADS='16', PYTHONDONTWRITEBYTECODE='1', VARCO_PROFILE_PHASES='1')
        self.output = Path(self.spec['output']).resolve()
        self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.fixtures = Path(self.spec['fixtures']).resolve(strict=True)
        self.input_pins, self.arms, self.rows, self.logs = {}, [], [], []
        self.process = self.active_directory = self.reference_plan = self.last_http_elapsed_ns = None
        for name in ('events.jsonl', 'samples.jsonl'):
            (self.output / name).open('x', encoding='utf-8').close()

    def prepare(self):
        # Narrow copy of the recent checks; no inherited 72-call receipt or loop.
        for path in (self.spec_path, Path(__file__), HELPER_PATH, recent.BASE_PATH):
            self.pin(path)
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
        build, key = json.loads(build_path.read_text()), json.loads(key_path.read_text())
        require(build['compiler_identity'] == self.spec['compiler_identity']
                and build['binary_sha256'] == base.sha(binary) and build.get('build_settings'), 'build receipt mismatch')
        require(key.get('bundle_roundtrip_equal') is True and key.get('bundle_validation_pass') is True
                and key['server_envelope_sha256'] == base.sha(keys / 'server.key'), 'key roundtrip receipt mismatch')
        require(all(key[k] == config[k] for k in base.KEY_BINDINGS), 'keygen bindings differ')
        key_info = {name: base.key_envelope(keys / (name + '.key'), config, magic)
                    for name, magic in (('client', b'VRCCK17!'), ('server', b'VRCHD17!'))}
        parameters = base.parameter_metadata(runtime, config)
        require(parameters['tfhe_rs'] == '1.8.1', 'expected TFHE-rs 1.8.1')
        self.arm = {'name': 'merge', 'family': 'merge-family1', 'key_origin': self.spec['key_origin'],
                    'runtime': runtime, 'binary': binary, 'keys': keys, 'config': config,
                    'source_pins': base.inventory(runtime), 'key_info': key_info, 'parameters': parameters,
                    'binary_sha256': base.sha(binary), 'protocol': base.load_protocol(runtime, 0), 'ciphertexts': {}}
        self.arms = [self.arm]
        folder = self.output / 'inputs'
        folder.mkdir()
        for scene, probe in self.probes.items():
            plain, ciphertext = folder / (scene + '.txt'), folder / (scene + '.probe.ct')
            with plain.open('x') as stream:
                stream.write(' '.join(map(str, probe['query'])) + '\n')
            value = self.cli(self.arm, folder, scene + '-encrypt', ['encrypt', keys, plain, ciphertext, 'head51'])
            require(value['query_profile'] == 'head51', 'wrong encrypted profile')
            self.arm['ciphertexts'][scene] = ciphertext
            self.pin(ciphertext)
        base.save(self.output / 'PREPARED.json', {
            'schema': 'current-merge-profile-preflight.v1', 'spec': self.spec,
            'driver_sha256': base.sha(Path(__file__)), 'helper_sha256': HELPER_SHA, 'base_helper_sha256': recent.BASE_SHA,
            'input_pins': self.input_pins, 'source_pins': self.arm['source_pins'], 'config': config,
            'parameters': parameters, 'key_info': key_info, 'build_receipt': build, 'probes': self.probes,
            'host': {'platform': platform.platform(), 'python': sys.version},
            'sequence': sequence(), 'calls': {'warmup': 1, 'measured': 3}, 'owned_service_processes': 1})

    def measure_once(self):
        arm = self.arm
        folder = self.output / 'service'
        folder.mkdir()
        self.active_directory = folder
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.logs = [(folder / ('service.' + name)).open('xb') for name in ('stdout', 'stderr')]
        command = [str(arm['binary']), 'serve', str(self.port), '512', '273']
        pending = []
        try:
            self.process = base.subprocess.Popen(command, env=self.env, stdin=base.subprocess.DEVNULL,
                                                stdout=self.logs[0], stderr=self.logs[1])
            self.event({'event': 'owned_service_started', 'pid': self.process.pid, 'command': command})
            deadline = time.monotonic() + 60
            ready = f'in ascolto su 127.0.0.1:{self.port}'.encode()
            while ready not in (folder / 'service.stdout').read_bytes():
                require(self.process.poll() is None and time.monotonic() < deadline, 'owned service startup failed')
                time.sleep(.05)
            protocol, expected = arm['protocol'], arm['config']
            data, _, _ = self.request('initial', 'GET', '/stato')
            initial = protocol.strict_json(data)
            protocol.validate_status(initial, expected, allow_empty=True)
            require(initial['iscritti'] == 0 and not initial['chiave'], 'new service is not empty')
            data, _, _ = self.request('install-key', 'POST', '/chiave', arm['keys'] / 'server.key')
            installed = protocol.strict_json(data)
            require(installed.get('ok') is True and installed.get('idempotente') is False
                    and installed['chiave_sha256'] == arm['key_info']['server']['sha256'], 'key installation differs')
            for number, entry in enumerate(self.entries):
                require('\n' not in entry['id'] and '\t' not in entry['id'], 'unsafe gallery name')
                body = (entry['id'] + '\t' + str(entry['soglia']) + '\n' + ' '.join(map(str, entry['vettore'])) + '\n').encode()
                data, _, _ = self.request(f'enroll-{number:03}', 'POST', '/iscrivi', body, 'text/plain; charset=utf-8')
                enrolled = protocol.strict_json(data)
                require(enrolled.get('ok') is True and enrolled['indice'] == number
                        and enrolled['iscritti'] == number + 1, 'enrollment differs')
            data, _, _ = self.request('ready-status', 'GET', '/stato')
            state = protocol.strict_json(data)
            snapshot = protocol.validate_status(state, expected)
            require(state['nomi'] == [e['id'] for e in self.entries]
                    and state['soglie'] == [e['soglia'] for e in self.entries]
                    and state['chiave_sha256'] == arm['key_info']['server']['sha256']
                    and state['conteggi'] == COUNTS, 'ready gallery/key/counts differ')
            for phase, scene in sequence():  # Exactly four POST /varco calls; no inherited loop.
                label = phase + '-' + scene
                started = time.time_ns()
                data, headers, output = self.request(label, 'POST', '/varco', arm['ciphertexts'][scene])
                normalized = protocol.validate_headers(headers, expected, snapshot)
                require(normalized.get('content-type') == 'application/octet-stream', 'wrong result type')
                milliseconds = float(normalized['x-tempo-ms'])
                require(math.isfinite(milliseconds) and milliseconds > 0, 'invalid service timer')
                require(recent.HEADER in normalized, 'designated profiling header absent')
                profile = protocol.strict_json(normalized[recent.HEADER].encode())
                validate_designated(profile, state['conteggi'], self.spec['stage_tolerance_ns'])
                require(profile['evaluate_wall_ns'] <= milliseconds * 1e6 + 1_000_000, 'core timer exceeds service')
                pending.append({'phase': phase, 'scene': scene, 'repetition': 0, 'started_unix_ns': started,
                                'elapsed_ms': milliseconds, 'http_elapsed_ns': self.last_http_elapsed_ns,
                                'output': str(output), 'output_sha256': base.sha(output), 'payload_sha256': base.payload_sha(data),
                                'input_sha256': base.sha(arm['ciphertexts'][scene]), 'stage_profile': profile,
                                'counts': state['conteggi'], 'binary_sha256': arm['binary_sha256'],
                                'server_key_sha256': state['chiave_sha256'], 'circuit_sha256': expected['circuit_sha256']})
            data, _, _ = self.request('after-status', 'GET', '/stato')
            require(protocol.validate_status(protocol.strict_json(data), expected) == snapshot, 'gallery changed')
        finally:
            self.stop()
        for row in pending:
            value = self.cli(arm, folder, row['phase'] + '-' + row['scene'] + '-decrypt', ['decrypt', arm['keys'], row['output']])
            protocol.decode_identity(value, snapshot, expected)
            wanted = self.probes[row['scene']]['oracle']['selected_id']
            row.update(selected_id=value['codice'], expected_id=wanted,
                       digits=[value[k] for k in ('low', 'middle', 'high')], correct=value['codice'] == wanted)
            self.rows.append(row)
            with (self.output / 'samples.jsonl').open('a') as stream:
                stream.write(json.dumps(row) + '\n')
            require(row['correct'], 'FHE result differs from the integer oracle')
        self.event({'event': 'four_queries_validated', 'calls': len(self.rows)})

    def run(self):
        faults, summary = [], None
        try:
            self.prepare()
            self.measure_once()  # One service, never parent.run or parent.run_arm.
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
                    require(base.inventory(self.arm['runtime']) == self.arm['source_pins'], 'runtime changed')
                except Exception as exc:
                    faults.append(repr(exc))
            result = {'schema': 'current-merge-profile-complete.v1', 'passed': summary is not None and not faults,
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
