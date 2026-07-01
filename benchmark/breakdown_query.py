"""Breakdown end-to-end di una query 1:N privata (config reale: 512-dim, 4 bit, embedding
ResNet100 veri). Isola il costo di ogni tappa per vedere dove va il tempo oltre l'argmin:
embedding (client), encrypt (client), prodotto scalare cifrato SOLO (server, 0 PBS), argmin
cifrato (server), decrypt (client). La soglia sta in soglia_reale.py. Vedi findings F33.

Richiede compilazione FHE; su macOS beta puo' servire un wrapper di ld (PATH=/tmp/ldfix:$PATH)."""
import time
import pathlib
import sys

import numpy as np
from concrete import fhe

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments" / "08_cnn"))
OUT = ROOT / "benchmark" / "results"
B = np.load(OUT / "_emb_reale_extra.npz")
E_full, y = B["rn100"], B["y"]
rng = np.random.RandomState(0)


def quant(E, q=4):
    qm = 2 ** (q - 1) - 1
    sc = np.percentile(np.abs(E), 99.5) / qm
    return np.clip(np.round(E / sc), -qm, qm).astype(np.int64)


def gallery(N):
    ids = np.unique(y)[:N]
    G = quant(E_full[np.array([np.where(y == s)[0][0] for s in ids])])
    return G, np.sum(G * G, axis=1)


def bench_embedding():
    if not (OUT / "_crops_reale.npz").exists():
        print("  embedding: niente _crops_reale.npz (e' comunque classe-ms)"); return
    import embedding as cnn
    imgs = np.load(OUT / "_crops_reale.npz")["crops"][:8]
    cnn.embedding(imgs[:1], "resnet100")                       # warmup
    t = time.time(); cnn.embedding(imgs[:1], "resnet100"); t1 = (time.time() - t) * 1000
    t = time.time(); cnn.embedding(imgs[:8], "resnet100"); t8 = (time.time() - t) * 1000
    print(f"  embedding ResNet100: 1 img {t1:.0f} ms, batch {t8/8:.0f} ms/img", flush=True)


def bench_dot(N):
    G, bsq = gallery(N)
    fn = lambda a: bsq - 2 * (G @ a)                           # N punteggi, nessuna selezione
    iset = [quant(E_full[k:k + 1])[0] for k in rng.choice(len(E_full), 100, replace=False)]
    circ = fhe.Compiler(fn, {"a": "encrypted"}).compile(iset)
    circ.keygen()
    a = quant(E_full[123:124])[0]
    te, tr, td = [], [], []
    for _ in range(5):
        t = time.time(); enc = circ.encrypt(a); te.append((time.time() - t) * 1000)
        t = time.time(); res = circ.run(enc); tr.append((time.time() - t))
        t = time.time(); circ.decrypt(res); td.append((time.time() - t) * 1000)
    print(f"  N={N:>2}: encrypt {np.mean(te):.0f} ms | prodotto scalare {np.mean(tr):.2f} s "
          f"({circ.statistics['programmable_bootstrap_count']} PBS) | decrypt {np.mean(td):.0f} ms", flush=True)


def bench_argmin(N):
    G, bsq = gallery(N)
    def fn(a):
        p = bsq - 2 * (G @ a)
        idx = fhe.zeros(()); val = p[0]
        for i in range(1, N):
            lt = (p[i] < val).astype(np.int64)
            idx = lt * i + (1 - lt) * idx
            val = np.minimum(val, p[i])
        return idx
    iset = [quant(E_full[k:k + 1])[0] for k in rng.choice(len(E_full), 100, replace=False)]
    cfg = fhe.Configuration(comparison_strategy_preference=[fhe.ComparisonStrategy.CHUNKED],
                            min_max_strategy_preference=[fhe.MinMaxStrategy.CHUNKED])
    circ = fhe.Compiler(fn, {"a": "encrypted"}).compile(iset, cfg)
    circ.keygen()
    a = quant(E_full[123:124])[0]
    atteso = int(np.argmin(bsq - 2 * (G @ a)))
    enc = circ.encrypt(a)
    t = time.time(); res = circ.run(enc); tr = time.time() - t
    ok = int(circ.decrypt(res)) == atteso
    print(f"  N={N:>2}: argmin {tr:.0f} s ({circ.statistics['programmable_bootstrap_count']} PBS) "
          f"{'OK' if ok else 'ERR'}", flush=True)


if __name__ == "__main__":
    print("== client (in chiaro) =="); bench_embedding()
    print("== prodotto scalare + encrypt/decrypt (server/client, 512-dim) ==")
    for N in (8, 64):
        bench_dot(N)
    print("== argmin cifrato (server, 512-dim) ==")
    for N in (4, 8):
        bench_argmin(N)
