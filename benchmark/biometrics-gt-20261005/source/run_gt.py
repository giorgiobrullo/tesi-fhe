"""Frozen-scale transfer check. No tuning, FHE, download, or replacement."""
from pathlib import Path
import argparse
import ast
import datetime as dt
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import types

R = Path('/workspace/research')
W = Path('/workspace/maintained')
OUT = Path(__file__).resolve().parent
DATA = OUT.parent / 'acquisition/georgia-tech'
SEED = 'varco-gt-transfer-20261005-v1'
T = 273


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(name, value):
    with (OUT / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def rank(tag, name):
    return hashlib.sha256(f'{SEED}:{tag}:{name}'.encode()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare():
    acquisition = json.loads((OUT.parent / 'acquisition/GT_RESULT.json').read_text())
    assert acquisition['status'] == 'downloaded_structure_checked'
    catalogue = json.loads((W / 'demo/web/gallery/catalogue.json').read_text())
    persons, images = [], []

    def photo(path, role, frontend):
        item = {'index': len(images), 'path': str(path), 'role': role,
                'frontend': frontend, 'bytes': path.stat().st_size, 'sha256': sha(path)}
        images.append(item)
        return item

    for entry in catalogue[:100]:
        path = W / 'demo/web/gallery' / entry['foto']
        assert sha(path) == entry['sha256'] and entry['soglia'] == T
        persons.append({'identity': 'preset:' + entry['slug'], 'role': 'preset',
                        'images': [photo(path, 'enrollment', False)]})
    folders = [DATA / name for name in acquisition['identity_counts']]
    folders.sort(key=lambda p: rank('identity', p.name))
    assert len(folders) == 50 and len({p.name for p in folders}) == 50
    for i, folder in enumerate(folders):
        enrolled = i < 20
        files = sorted(folder.glob('*.jpg'), key=lambda p: rank('photo', folder.name + '/' + p.name))
        assert len(files) == 15
        roles = ['enrollment'] * 3 + ['primary'] + ['secondary'] * 3 if enrolled else ['primary'] + ['secondary'] * 3
        persons.append({'identity': 'gt:' + folder.name,
                        'role': 'enrolled' if enrolled else 'unknown',
                        'images': [photo(path, role, True) for path, role in zip(files, roles)]})
    assert len(images) == 360 and len({im['sha256'] for im in images}) == 360
    sources = [W / p for p in ['runtime/config.json', 'demo/web/gallery/catalogue.json',
               'demo/dual_view/static/shared.js', 'demo/dual_view/enrollment.py',
               'runtime/client/embedding.py', 'experiments/08_cnn/embedding.py', 'demo/web/engines.py']]
    sources += [Path(__file__), OUT / 'encode_gt.mjs', OUT / 'GT_PROTOCOL.md']
    config = json.loads((W / 'runtime/config.json').read_text())
    assert config['modello'] == 'resnet100' and config['scala'] == 0.04098006 and config['q_max'] == 3
    # Explicit user-root path: do not depend on HOME or silently fetch weights.
    models = [Path('/opt/models/models/antelopev2/antelopev2/glintr100.onnx'),
              Path('/opt/models/models/buffalo_s/det_500m.onnx')]
    versions = {p: importlib.metadata.version(p) for p in ['numpy', 'scipy', 'onnxruntime', 'insightface', 'opencv-python', 'Pillow']}
    assert versions['Pillow'] == '12.3.0'
    manifest = {'frozen_utc': now(), 'seed': SEED, 'T': T, 'config': config,
                'gallery_entries': 120, 'new_enrolled_identities': 20, 'unknown_identities': 30,
                'persons': persons, 'images': images, 'versions': versions,
                'sources': {str(p): sha(p) for p in sources},
                'models': [{'path': str(p), 'sha256': sha(p)} for p in models],
                'acquisition_sha256': sha(OUT.parent / 'acquisition/GT_RESULT.json'),
                'claims': 'conditional transfer; not120newidentities, population1%, webcam, or FHE'}
    save('GT_MANIFEST.json', manifest)
    save('GT_FREEZE.json', {'utc': now(), 'manifest_sha256': sha(OUT / 'GT_MANIFEST.json')})
    print(json.dumps({'status': 'FROZEN', 'images': len(images), 'new_people': 50}), flush=True)


def evaluate():
    import numpy as np
    import onnxruntime as ort
    from scipy.stats import beta
    from insightface.model_zoo.model_zoo import ModelRouter

    manifest = json.loads((OUT / 'GT_MANIFEST.json').read_text())
    assert sha(OUT / 'GT_MANIFEST.json') == json.loads((OUT / 'GT_FREEZE.json').read_text())['manifest_sha256']
    for path, h in manifest['sources'].items():
        assert sha(path) == h, path
    for package, version in manifest['versions'].items():
        assert importlib.metadata.version(package) == version, package
    for im in manifest['images']:
        assert sha(im['path']) == im['sha256']
    for model in manifest['models']:
        assert sha(model['path']) == model['sha256']
    encoded = json.loads((OUT / 'GT_ENCODING.json').read_text())
    assert encoded['manifest_sha256'] == sha(OUT / 'GT_MANIFEST.json')
    mapping = {item['index']: item for item in encoded['images']}
    expected = {im['index'] for im in manifest['images'] if im['frontend']}
    assert set(mapping) == expected and len(expected) == 260
    for item in mapping.values():
        assert sha(item['path']) == item['sha256']
    save('GT_STARTED.json', {'utc': now(), 'pid': os.getpid(), 'manifest_sha256': sha(OUT / 'GT_MANIFEST.json')})
    ort.set_default_logger_severity(3)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    options.inter_op_num_threads = 1
    paths = {Path(v['path']).name: v['path'] for v in manifest['models']}
    rec = ModelRouter(paths['glintr100.onnx']).get_model(providers=['CPUExecutionProvider'], sess_options=options)
    detector = ModelRouter(paths['det_500m.onnx']).get_model(providers=['CPUExecutionProvider'], sess_options=options)
    rec.prepare(ctx_id=-1)
    detector.prepare(ctx_id=-1, input_size=(160, 160), det_thresh=0.5)
    ec = load('gt_production_embedding', W / 'experiments/08_cnn/embedding.py')
    ec._cache['resnet100'] = rec
    ec._app_cache['mobilefacenet'] = types.SimpleNamespace(det_model=detector)
    original_embedding = ec.embedding

    class ShapeFailure(ValueError):
        pass

    def finite_embedding(images, level):
        result = original_embedding(images, level)
        if result.shape != (len(images), 512):
            raise ShapeFailure('unexpected floating recognizer embedding shape')
        if not np.isfinite(result).all():
            raise FloatingPointError('nonfinite recognizer embedding before quantization')
        return result

    ec.embedding = finite_embedding
    client = load('gt_production_client', W / 'runtime/client/embedding.py')
    face = client.FaceEmbedding(manifest['config'], W, lambda _: None)
    face._model = ec
    decoder = load('gt_production_decoder', W / 'demo/dual_view/enrollment.py')
    source = W / 'demo/web/engines.py'
    tree = ast.parse(source.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'validate_input')
    ns = {'math': math}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), ns)
    validate = ns['validate_input']
    attempts, vectors, gallery = [], {}, []

    def extract(person, role):
        images = [im for im in person['images'] if im['role'] == role]
        key = person['identity'] + ':' + role
        row = {'key': key, 'identity': person['identity'], 'identity_role': person['role'],
               'condition': role, 'attempted_frames': len(images), 'detected_frames': 0, 'status': 'pending'}
        crops = []
        phase = 'decode'
        try:
            for im in images:
                path = mapping[im['index']]['path'] if im['frontend'] else im['path']
                phase = 'decode'
                rgb = np.asarray(decoder.image_from_bytes(Path(path).read_bytes()))
                phase = 'alignment'
                aligned = face.allinea([rgb])
                if aligned is not None:
                    crops.append(aligned[0])
                    row['detected_frames'] = len(crops)
            row['detected_frames'] = len(crops)
            if not crops:
                row['status'] = 'no_face'
            else:
                phase = 'embedding'
                q, _ = face.embedding_fuso(crops, gia_allineati=True)
                if q.shape != (512,):
                    row['status'] = 'shape_failure'
                elif not np.isfinite(q).all():
                    row['status'] = 'nonfinite'
                else:
                    vectors[key] = q.tolist()
                    row.update(status='extracted', qnorm2=int(q @ q))
        except (ValueError, OSError, FloatingPointError) as error:
            status = ('nonfinite' if isinstance(error, FloatingPointError) else
                      'shape_failure' if isinstance(error, ShapeFailure) else phase + '_failure')
            row.update(status=status, failure_phase=phase,
                       error_type=type(error).__name__, error=str(error)[:300])
        attempts.append(row)
        with (OUT / 'GT_ATTEMPTS.jsonl').open('a') as f:
            f.write(json.dumps(row) + '\n')
        return row

    for person in manifest['persons']:
        if person['role'] == 'unknown':
            continue
        row = extract(person, 'enrollment')
        if row['status'] == 'extracted':
            gallery.append({'id': person['identity'], 'vettore': vectors[row['key']], 'soglia': T})
        if len(attempts) % 20 == 0:
            print(json.dumps({'stage': 'enrollment', 'done': len(attempts)}), flush=True)
    errors = [a for a in attempts if a['status'] != 'extracted']
    if len(gallery) == 120:
        try:
            validate([0] * 512, gallery)
        except ValueError as e:
            errors.append({'status': 'gallery_domain_failure', 'error': str(e)})
    save('GT_GALLERY.json', {'entries': gallery, 'errors': errors})
    if errors or len(gallery) != 120:
        save('GT_VECTORS.json', vectors)
        save('GT_SUMMARY.json', {'status': 'SETUP_FAILED', 'ended_utc': now(), 'N': len(gallery), 'queries': 0, 'errors': errors})
        print('SETUP_FAILED', flush=True)
        return
    matrix = np.asarray([g['vettore'] for g in gallery], dtype=np.int64)
    norms = (matrix * matrix).sum(axis=1)
    searches = []
    for condition in ['primary', 'secondary']:
        for person in manifest['persons'][100:]:
            attempt = extract(person, condition)
            row = {**attempt, 'output': None, 'winner_identity': None, 'min_score': None, 'correct_accepted': False,
                   'wrong_accepted': False, 'false_access': False, 'rejected': False}
            if row['status'] == 'extracted':
                q = np.asarray(vectors[row['key']], dtype=np.int64)
                try:
                    code = validate(q.tolist(), gallery)
                    scalar = [sum(v * v for v in g['vettore']) - 2 * sum(v * int(x) for v, x in zip(g['vettore'], q)) for g in gallery]
                    scores = norms - 2 * (matrix @ q)
                    assert scalar == scores.tolist()
                    j = min(range(120), key=lambda i: scalar[i])
                    assert code == (j + 1 if scalar[j] <= T else 0)
                    known = person['role'] == 'enrolled'
                    same = code != 0 and gallery[code - 1]['id'] == person['identity']
                    row.update(status='admissible', output=code, winner_identity=gallery[j]['id'], min_score=scalar[j],
                               correct_accepted=known and same, wrong_accepted=known and bool(code) and not same,
                               false_access=not known and bool(code), rejected=code == 0)
                except ValueError as error:
                    row.update(status='domain_failure', error=str(error))
            searches.append(row)
        print(json.dumps({'stage': condition, 'searches': len(searches)}), flush=True)
    summary = {'status': 'COMPLETE', 'ended_utc': now(), 'N': 120, 'new_enrolled': 20,
               'new_unknown': 30, 'queries': len(searches), 'no_tuning': True, 'no_FHE': True, 'conditions': {}}
    for condition in ['primary', 'secondary']:
        rows = [s for s in searches if s['condition'] == condition]
        known = [s for s in rows if s['identity_role'] == 'enrolled']
        unknown = [s for s in rows if s['identity_role'] == 'unknown']
        n = sum(s['status'] == 'admissible' for s in unknown)
        k = sum(s['false_access'] for s in unknown)
        upper = float(beta.ppf(0.95, k + 1, n - k)) if n > k else 1.0
        summary['conditions'][condition] = {'known_attempted': len(known), 'unknown_attempted': len(unknown),
            'known_admissible': sum(s['status'] == 'admissible' for s in known), 'unknown_admissible': n,
            'correct_accepted': sum(s['correct_accepted'] for s in known),
            'wrong_accepted': sum(s['wrong_accepted'] for s in known), 'false_access': k,
            'unknown_accepted_preset': sum(s['false_access'] and s['winner_identity'].startswith('preset:') for s in unknown),
            'unknown_accepted_GT_enrolled': sum(s['false_access'] and s['winner_identity'].startswith('gt:') for s in unknown),
            'FPIR_conditional': k / n if n else None, 'false_access_per_attempt': k / len(unknown),
            'FPIR_one_sided_95_upper_model_based': upper, 'supports_1_percent': upper <= 0.01}
    save('GT_VECTORS.json', vectors)
    save('GT_SEARCHES.json', searches)
    save('GT_SUMMARY.json', summary)
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['prepare', 'evaluate'])
    mode = parser.parse_args().mode
    prepare() if mode == 'prepare' else evaluate()
