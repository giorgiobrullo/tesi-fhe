"""Argmin cifrato: sequenziale vs torneo, con/senza dataflow, al variare di N.
Obiettivo: vedere se ottimizzando la struttura (+ parallelismo Linux) il match
privato sul server scende a 'umano' (pochi secondi) oppure no.
Scrive CSV incrementale: ogni riga appena pronta."""
import time, numpy as np
from concrete import fhe

DIM = 64           # dimensione embedding (bit ~8, accuratezza ~87% da F23)
Q = 2              # quantizzazione +/-2
CSV = "/home/cursedadmin/fhe-bench/risultati.csv"

def gallery(N):
    rng = np.random.RandomState(0)
    G = rng.randint(-Q, Q + 1, size=(N, DIM)).astype(np.int64)
    return G, np.sum(G * G, axis=1).astype(np.int64)

def seq_fn(G, b_sq, N):
    """Argmin sequenziale: catena di N-1 confronti dipendenti (quello attuale)."""
    def f(a):
        p = b_sq - 2 * (G @ a)
        idx = fhe.zeros(()); val = p[0]
        for i in range(1, N):
            lt = (p[i] < val).astype(np.int64)
            idx = lt * i + (1 - lt) * idx
            val = np.minimum(val, p[i])
        return idx
    return f

def tour_fn(G, b_sq, N):
    """Argmin a torneo: confronti a coppie, profondita' log(N).
    Il primo round ha N/2 confronti INDIPENDENTI -> il dataflow puo' parallelizzarli."""
    def f(a):
        p = b_sq - 2 * (G @ a)
        nodes = [(p[i], i) for i in range(N)]   # (valore, indice) ; indice clear all'inizio
        while len(nodes) > 1:
            nxt = []; j = 0
            while j + 1 < len(nodes):
                va, ia = nodes[j]; vb, ib = nodes[j + 1]
                lt = (va < vb).astype(np.int64)
                nxt.append((np.minimum(va, vb), lt * ia + (1 - lt) * ib))
                j += 2
            if j < len(nodes):
                nxt.append(nodes[j])
            nodes = nxt
        return nodes[0][1]
    return f

def measure(mk, G, b_sq, N, df):
    fn = mk(G, b_sq, N)
    iset = [np.random.RandomState(s).randint(-Q, Q + 1, size=DIM).astype(np.int64) for s in range(60)]
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
    return tc, tr, int(circ.decrypt(res))

def main():
    f = open(CSV, "w")
    f.write("struttura,N,dataflow,compile_s,run_s,argmin,atteso,ok\n"); f.flush()
    for N in [4, 8, 16, 32]:
        G, b_sq = gallery(N)
        a = np.random.RandomState(123).randint(-Q, Q + 1, size=DIM).astype(np.int64)
        atteso = int(np.argmin(b_sq - 2 * (G @ a)))
        for name, mk in [("seq", seq_fn), ("tour", tour_fn)]:
            for df in [False, True]:
                try:
                    tc, tr, out = measure(mk, G, b_sq, N, df)
                    line = f"{name},{N},{int(df)},{tc:.1f},{tr:.2f},{out},{atteso},{int(out == atteso)}"
                except Exception as e:
                    line = f"{name},{N},{int(df)},ERR,ERR,,,{repr(e)[:90]}"
                print(line, flush=True); f.write(line + "\n"); f.flush()
    f.close()

if __name__ == "__main__":
    main()
