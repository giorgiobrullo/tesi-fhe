"""Finite local POST-to-SSE observations of the real, unmodified web demo."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = Path('/workspace/research')
WORK = Path('/workspace/maintained')
BUILD = ROOT / 'tmp/current-build-timing-20261004'
PREPARED = json.loads((HERE / 'PREPARED.json').read_text())
WEB = PREPARED['ports']['web']
NATIVE = PREPARED['ports']['native']
ORIGIN = f'http://127.0.0.1:{WEB}'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')


def get_json(path, cookie=None):
    conn = http.client.HTTPConnection('127.0.0.1', WEB, timeout=3)
    try:
        conn.request('GET', path, headers={'Cookie': cookie} if cookie else {})
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f'{path}: HTTP {response.status}')
        return json.loads(body), response.getheader('Set-Cookie')
    finally:
        conn.close()


class Events:
    def __init__(self, cookie):
        self.cookie = cookie
        self.condition = threading.Condition()
        self.ready = False
        self.error = None
        self.stop = threading.Event()
        self.records = []
        self.conn = http.client.HTTPConnection('127.0.0.1', WEB, timeout=15)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            self.conn.request('GET', '/api/eventi', headers={
                'Cookie': self.cookie, 'Accept': 'text/event-stream'})
            response = self.conn.getresponse()
            if response.status != 200 or not response.getheader('Content-Type', '').startswith('text/event-stream'):
                raise RuntimeError(f'SSE: HTTP {response.status}')
            name, lines = None, []
            while not self.stop.is_set():
                line = response.readline()
                received_ns = time.perf_counter_ns()
                if not line:
                    raise RuntimeError('SSE ended before explicit cleanup')
                text = line.decode('utf-8').rstrip('\r\n')
                if text.startswith('event:'):
                    name = text[6:].strip()
                elif text.startswith('data:'):
                    lines.append(text[5:].lstrip(' '))
                elif not text:
                    if name and lines:
                        body = json.loads('\n'.join(lines))
                        # Timestamp is taken when the complete event delimiter arrives,
                        # before JSON parsing, matching or any disk/hash work.
                        with self.condition:
                            if name == 'richieste':
                                self.records.append({'received_ns': received_ns, 'body': body})
                                self.ready = True
                                self.condition.notify_all()
                            elif name == 'scaduta':
                                raise RuntimeError('Session expired during measurement')
                    name, lines = None, []
        except BaseException as exc:
            if not self.stop.is_set():
                with self.condition:
                    self.error = repr(exc)
                    self.condition.notify_all()

    def wait_ready(self):
        with self.condition:
            if not self.condition.wait_for(lambda: self.ready or self.error, timeout=15):
                raise TimeoutError('Initial SSE requests snapshot not received')
            if self.error:
                raise RuntimeError(self.error)

    def terminal(self, identifier):
        deadline = time.monotonic() + 180
        with self.condition:
            while True:
                for event in self.records:
                    for row in event['body']['richieste']:
                        if row['id'] == identifier and row['stato'] in ('completata', 'errore'):
                            return event['received_ns'], row
                if self.error:
                    raise RuntimeError(self.error)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('No terminal SSE event for submitted UUID')
                self.condition.wait(min(remaining, 10))

    def close(self):
        self.stop.set()
        self.conn.close()


def main():
    process = None
    events = None
    faults = []
    samples = []
    started_utc = datetime.now(timezone.utc).isoformat()
    cleanup = {}
    command = [PREPARED['python'], '-B', '-m', 'demo.web.launch',
               '--binary', str(BUILD / 'bin/candidate'),
               '--keys', str(BUILD / 'keys/family1/candidate'),
               '--state-root', str(HERE / 'state'),
               '--port', str(WEB), '--native-port', str(NATIVE)]
    environment = os.environ.copy()
    environment.update(PYTHONPATH=PREPARED['overlay'], PYTHONDONTWRITEBYTECODE='1')
    environment.pop('VARCO_WEB_PUBLIC_ORIGIN', None)
    environment.pop('VARCO_WEB_ADDITIONAL_ORIGINS', None)
    try:
        # Preformat all request bodies before starting any request timer.
        bodies = {}
        for scene, photo in PREPARED['photos'].items():
            raw = Path(photo['path']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != photo['sha256']:
                raise RuntimeError('Photo changed after preparation')
            bodies[scene] = json.dumps({'frames': ['data:image/jpeg;base64,' +
                base64.b64encode(raw).decode()], 'motore': 'attuale'},
                separators=(',', ':')).encode()
        if digest(BUILD / 'bin/candidate') != PREPARED['binary_sha256']:
            raise RuntimeError('Binary changed after preparation')
        with (HERE / 'launcher.stdout').open('xb') as out, (HERE / 'launcher.stderr').open('xb') as err:
            process = subprocess.Popen(command, cwd=WORK, env=environment,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        save(HERE / 'LAUNCH.json', {'started_utc': started_utc, 'pid': process.pid,
            'owned_process_group': process.pid, 'command': command,
            'prepared_sha256': digest(HERE / 'PREPARED.json'), 'driver_sha256': digest(__file__)})
        print(json.dumps({'stage': 'startup', 'owned_launcher_pid': process.pid}), flush=True)
        deadline = time.monotonic() + 240
        status, cookie = None, None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Owned launcher exited during startup')
            try:
                status, supplied = get_json('/api/stato', cookie)
                if cookie is None and supplied:
                    cookies = SimpleCookie(); cookies.load(supplied)
                    cookie = 'varco_sessione=' + cookies['varco_sessione'].value
                if status.get('errore'):
                    raise RuntimeError(status['errore'])
                if status['pronto'] and status['iscritti'] == 120 and cookie:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.2)  # Startup only; no polling in measured request intervals.
        else:
            raise TimeoutError('Demo not ready with 120 entries')
        gallery, _ = get_json('/api/galleria', cookie)
        if gallery['totale'] != 120:
            raise RuntimeError('Unexpected gallery size')
        save(HERE / 'READY.json', {'status': status, 'gallery': gallery,
            'startup_ms': (time.monotonic() - (deadline - 240)) * 1000})
        expected_names = {'einstein': 'Albert Einstein', 'curie': 'Marie Curie', 'turing': 'Alan Turing'}
        expected_ids = {}
        for scene, name in expected_names.items():
            indices = [i + 1 for i, row in enumerate(gallery['iscritti']) if row['nome'] == name]
            if len(indices) != 1:
                raise RuntimeError('Reference name absent or duplicate')
            expected_ids[scene] = indices[0]
        events = Events(cookie)
        events.thread.start()
        events.wait_ready()
        print(json.dumps({'stage': 'ready', 'entries': 120, 'sse_open': True}), flush=True)
        sequence = [('warmup', 'einstein'), ('measured', 'einstein'),
                    ('measured', 'curie'), ('measured', 'turing')]
        for phase, scene in sequence:
            conn = http.client.HTTPConnection('127.0.0.1', WEB, timeout=10)
            body = bodies[scene]
            try:
                request_start_ns = time.perf_counter_ns()
                conn.request('POST', '/api/accesso', body=body, headers={
                    'Cookie': cookie, 'Origin': ORIGIN, 'Content-Type': 'application/json'})
                response = conn.getresponse()
                ack_raw = response.read()
                acknowledged_ns = time.perf_counter_ns()
                if response.status != 202:
                    raise RuntimeError(f'POST: HTTP {response.status}')
                identifier = json.loads(ack_raw)['richiesta_id']
            finally:
                conn.close()
            received_ns, row = events.terminal(identifier)
            correct = (row['stato'] == 'completata' and row.get('iscritti') == 120
                and len(row.get('risultati', [])) == 1
                and row['risultati'][0]['selected_id'] == expected_ids[scene]
                and row['risultati'][0].get('selected_name') == expected_names[scene]
                and row['risultati'][0]['esito'] == 'aperto')
            if acknowledged_ns < request_start_ns or received_ns < request_start_ns:
                raise RuntimeError('ACK or matching SSE event predates request start')
            sample = {'phase': phase, 'scene': scene, 'request_id': identifier,
                'request_start_ns': request_start_ns, 'acknowledged_ns': acknowledged_ns,
                'received_ns': received_ns, 'post_to_sse_ms': (received_ns - request_start_ns) / 1e6,
                'post_ack_ms': (acknowledged_ns - request_start_ns) / 1e6,
                'ack_observed_before_terminal_sse': acknowledged_ns <= received_ns,
                'request_bytes': len(body), 'request_sha256': hashlib.sha256(body).hexdigest(),
                'expected_id': expected_ids[scene], 'correct': correct, 'terminal_row': row}
            samples.append(sample)
            save(HERE / f'{len(samples):02d}-{phase}-{scene}.json', sample)
            print(json.dumps({'stage': 'response', 'phase': phase, 'scene': scene,
                'correct': correct, 'post_to_sse_ms': round(sample['post_to_sse_ms'], 3),
                'server_ms': row.get('tempi_ms', {}).get('server')}), flush=True)
            if not correct:
                raise RuntimeError('Terminal result differs from expected enrollment identity')
    except BaseException as exc:
        faults.append(repr(exc))
    finally:
        if events:
            events.close()
        if process is not None:
            if process.poll() is None:
                process.terminate()  # Only the Popen started above; uvicorn drains its native worker.
                try:
                    process.wait(timeout=45)
                    cleanup['method'] = 'owned_launcher_SIGTERM_graceful'
                except subprocess.TimeoutExpired:
                    # A private session was created above; the group cannot contain old services.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    cleanup['method'] = 'owned_new_process_group_SIGKILL_after_timeout'
                    faults.append('Graceful cleanup timed out')
            cleanup['launcher_returncode'] = process.returncode
        if events:
            events.thread.join(timeout=5)
            save(HERE / 'SSE_REQUEST_EVENTS.json', events.records)
            cleanup['sse_thread_finished'] = not events.thread.is_alive()
            if events.thread.is_alive():
                faults.append('SSE reader thread still alive after cleanup')
        changed = [rel for rel, sha in PREPARED['source_sha256'].items() if digest(WORK / rel) != sha]
        if changed:
            faults.append('Source changed: ' + ','.join(changed))
        result = {'started_utc': started_utc, 'finished_utc': datetime.now(timezone.utc).isoformat(),
            'passed': len(samples) == 4 and all(s['correct'] for s in samples) and not faults,
            'faults': faults, 'samples': samples, 'cleanup': cleanup,
            'source_unchanged': not changed, 'timer': PREPARED['plan'],
            'prepared_sha256': digest(HERE / 'PREPARED.json'), 'driver_sha256': digest(__file__)}
        save(HERE / 'COMPLETE.json', result)
        print(json.dumps({'stage': 'complete', 'passed': result['passed'],
            'responses': len(samples), 'faults': faults, 'cleanup': cleanup}), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
