"""Varco a soglia (membership, 1 bit) cifrato vs N — il primitivo che serve davvero al varco.
A differenza dell'argmin (catena sequenziale), qui gli N confronti distanza<soglia sono
INDIPENDENTI -> dovrebbero parallelizzare sui 12 core. Misura tempo vs N, con/senza dataflow.
CSV incrementale."""
import time, numpy as np
from concrete import fhe

DIM = 64           # come F28, per confronto diretto con l'argmin (bit ~10)
Q = 2
CSV = "/home/cursedadmin/fhe-bench/risultati_varco.csv"

def gallery(N):
    rng = np.random.RandomState(0)
    G = rng.randint(-Q, Q + 1, size=(N, DIM)).astype(np.int64)
    return G, np.sum(G * G, axis=1).astype(np.int64)

def varco_fn(G, b_sq, T):
    def f(a):
        p = b_sq - 2 * (G @ a)        # N distanze (enc x plaintext, niente PBS)
        below = (p < T).astype(np.int64)   # N confronti con soglia CHIARA, indipendenti
        return np.sum(below)               # conteggio match; il client controlla >0
    return f

def measure(N, df):
    G, b_sq = gallery(N)
    rng = np.random.RandomState(0)
    iset = [rng.randint(-Q, Q + 1, size=DIM).astype(np.int64) for _ in range(80)]
    allp = np.concatenate([b_sq - 2 * (G @ a) for a in iset])
    T = int(np.median(allp))              # soglia nel mezzo della distribuzione (esercita il confronto)
    fn = varco_fn(G, b_sq, T)
    cfg = fhe.Configuration(
        comparison_strategy_preference=[fhe.ComparisonStrategy.CHUNKED],
        min_max_strategy_preference=[fhe.MinMaxStrategy.CHUNKED],
        dataflow_parallelize=df,
    )
    t0 = time.time(); circ = fhe.Compiler(fn, {"a": "encrypted"}).compile(iset, cfg); tc = time.time() - t0
    circ.keygen()
    a = np.random.RandomState(123).randint(-Q, Q + 1, size=DIM).astype(np.int64)
    enc = circ.encrypt(a)
    t0 = time.time(); res = circ.run(enc); tr = time.time() - t0
    out = int(circ.decrypt(res))
    atteso = int(np.sum((b_sq - 2 * (G @ a)) < T))
    try:
        bw = circ.graph.maximum_integer_bit_width()
    except Exception:
        bw = "?"
    return tc, tr, out, atteso, bw

def main():
    f = open(CSV, "w")
    f.write("N,dataflow,bit,compile_s,run_s,conteggio,atteso,ok\n"); f.flush()
    for N in [8, 64, 256, 1024, 2048]:
        for df in [False, True]:
            try:
                tc, tr, out, atteso, bw = measure(N, df)
                line = f"{N},{int(df)},{bw},{tc:.1f},{tr:.2f},{out},{atteso},{int(out == atteso)}"
            except Exception as e:
                line = f"{N},{int(df)},ERR,ERR,ERR,,,{repr(e)[:80]}"
            print(line, flush=True); f.write(line + "\n"); f.flush()
    f.close()

if __name__ == "__main__":
    main()
