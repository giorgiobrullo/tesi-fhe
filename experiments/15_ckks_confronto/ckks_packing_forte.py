"""La baseline CKKS con il packing GIUSTO: quanto eravamo depotenziati (F67).

`ckks_varco.py` impacchetta R = slot/dim iscritti per cifrato e per ogni blocco fa un
rotate-and-sum su dim slot: log2(dim) = 9 rotazioni per blocco, piu' una maschera e una rotazione di
compattazione. Il costo in rotazioni e' quindi ~10 * ceil(N/R), cioe' LINEARE in N.

Esiste un packing migliore, che e' lo stesso di Halevi-Shoup in versione "ibrida": si da a ogni
iscritto W = slot/N slot contigui, si ruota il PROBE di W*j per j = 0..rho-1 con rho = N*dim/slot
(le rotazioni del probe sono CONDIVISE da tutti gli iscritti), si moltiplica per il plaintext della
galleria riordinato, e si chiude con log2(W) rotazioni di collasso. Rotazioni eseguite:
(rho - 1) + log2(W), perche' il primo termine usa il probe senza ruotarlo; a parita' di slot*dim
e' molto meno di 10*ceil(N/R) - 1.

  N=128,  slot 16384: attuale 4*10 - 1 = 39   ibrido 4 - 1 + 7 = 10
  N=1024, slot 16384: attuale 32*10 - 1 = 319  ibrido 32 - 1 + 4 = 35

Questo script misura le due versioni sulla stessa macchina, stessa scena, stessi parametri, e
verifica che diano gli stessi punteggi. Serve a dare al confronto TFHE-vs-CKKS una baseline che non
sia paglia.

  uv run python ckks_packing_forte.py [scena] [N,N,...]
"""
import csv
import os
import pathlib
import sys
import time

import numpy as np
from tenseal import sealapi as S

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENA = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else \
    ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results" / "scena_reale_1024_q3.txt"
NS = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else [128, 256, 512, 1024]

r = SCENA.read_text().splitlines()
dim, Nmax, npr, T = map(int, r[0].split())
Gal = np.array([list(map(int, x.split())) for x in r[1:1 + Nmax]], dtype=float)
P = np.array([list(map(int, x.split())) for x in r[1 + Nmax:1 + Nmax + npr]], dtype=float)
bsq = (Gal * Gal).sum(1)
S_all = bsq[None, :] - 2 * (P[:, 1:] @ Gal.T)
q_probe = int(os.environ.get("Q_PROBE", "3"))
if q_probe < 0:
    raise ValueError(f"Q_PROBE deve essere non negativo, ricevuto {q_probe}")
q_osservato = float(np.max(np.abs(P[:, 1:]))) if P.size else 0.0
if q_osservato > q_probe:
    raise ValueError(
        f"la scena contiene |probe|={q_osservato:g}, oltre il dominio Q_PROBE={q_probe}"
    )
range_osservato = float(np.abs(S_all - T).max() + 1)
range_analitico = float(np.max(np.abs(bsq - T) + 2 * q_probe * np.abs(Gal).sum(1)) + 1)
print(f"scena {SCENA.name}: dim={dim} N={Nmax} probe={npr} T={T} "
      f"RANGE analitico={range_analitico:.0f} (test={range_osservato:.0f}, q={q_probe})\n")

POLY, PRIMI, SB = 32768, [50] + [40] * 19 + [50], 40
slots_attesi = POLY // 2
if dim <= 0 or dim & (dim - 1) or slots_attesi % dim:
    raise ValueError(
        f"dim={dim} deve essere una potenza di due che divide i {slots_attesi} slot"
    )
for N in NS:
    if N <= 0 or N & (N - 1):
        raise ValueError(f"N={N} deve essere una potenza di due positiva")
    if N > Nmax:
        raise ValueError(f"N={N} supera i {Nmax} template disponibili nella scena")
    if slots_attesi % N or (N * dim) % slots_attesi:
        raise ValueError(
            f"N={N} non e' compatibile col packing: servono slots % N == 0 "
            f"e (N * dim) % slots == 0"
        )

parms = S.EncryptionParameters(S.SCHEME_TYPE.CKKS)
parms.set_poly_modulus_degree(POLY)
parms.set_coeff_modulus(S.CoeffModulus.Create(POLY, PRIMI))
ctx = S.SEALContext(parms, True, S.SEC_LEVEL_TYPE.TC128)
kg = S.KeyGenerator(ctx)
pk = S.PublicKey(); kg.create_public_key(pk)
sk = kg.secret_key()
rk = S.RelinKeys(); kg.create_relin_keys(rk)
ev, co = S.Evaluator(ctx), S.CKKSEncoder(ctx)
enc, dec = S.Encryptor(ctx, pk), S.Decryptor(ctx, sk)
slots, scale = co.slot_count(), 2.0 ** SB
if slots != slots_attesi:
    raise RuntimeError(f"encoder con {slots} slot, attesi {slots_attesi}")
a = P[3, 1:]


def pt(v, pid=None):
    p = S.Plaintext(); v = list(map(float, v))
    co.encode(v, scale, p) if pid is None else co.encode(v, pid, scale, p)
    return p


def mulpt(ct, p):
    o = S.Ciphertext(); ev.multiply_plain(ct, p, o)
    ev.rescale_to_next_inplace(o); o.scale = scale; return o


def rot(ct, k, gk):
    o = S.Ciphertext(); ev.rotate_vector(ct, k, gk, o); return o


def dcr(ct):
    p = S.Plaintext(); dec.decrypt(ct, p); return np.array(co.decode_double(p))


print(f"{'N':>5} | {'rot. attuale':>12} | {'attuale':>9} | {'rot. ibrido':>11} | {'ibrido':>8} | "
      f"{'guadagno':>8} | {'Galois att/ibr':>16} | err max")
righe = []


def dimensione_galois(passi):
    """Misura il solo insieme richiesto usando una chiave fresca dello stesso parametro.

    Le chiavi fresche non vengono usate nel benchmark; la dimensione serializzata dipende dai
    parametri e dai passi, non dal valore della chiave segreta.
    """
    import tempfile

    kg_misura = S.KeyGenerator(ctx)
    gk_misura = S.GaloisKeys()
    # TenSEAL espone sia `vector<uint32_t>` (elementi di Galois) sia `vector<int>`
    # (passi di rotazione) come `list[int]`: con soli Python int positivi pybind11
    # seleziona l'overload sbagliato. Gli scalari NumPy firmati disambiguano i passi.
    passi_firmati = [np.int64(passo) for passo in sorted(set(passi))]
    kg_misura.create_galois_keys(passi_firmati, gk_misura)
    with tempfile.TemporaryDirectory(prefix="ckks-galois-") as directory:
        path = os.path.join(directory, "galois.keys")
        gk_misura.save(path)
        return os.path.getsize(path) / 2**20


for N in NS:
    R = slots // dim; B = int(np.ceil(N / R))
    W = slots // N; rho = N * dim // slots
    passi_att = [1 << i for i in range(int(np.log2(dim)))] + [-b for b in range(1, B)]
    passi_ib = [W * j for j in range(1, rho)] + [1 << i for i in range(int(np.log2(W)))]
    # L'unione serve solo per eseguire entrambe le varianti con la stessa chiave. Le dimensioni
    # vengono misurate separatamente sotto chiavi fresche equivalenti: attribuire l'unione al solo
    # layout ibrido gonfiava il risultato di F67.
    gk = S.GaloisKeys()
    kg_runtime = S.KeyGenerator(ctx, sk)
    kg_runtime.create_galois_keys(sorted(set(passi_att) | set(passi_ib)), gk)
    gk_a = gk_b = gk
    mb_att = dimensione_galois(passi_att)
    mb_ib = dimensione_galois(passi_ib)

    ct_a = S.Ciphertext(); enc.encrypt(pt(np.tile(a, R)), ct_a)
    masc = np.zeros(slots); masc[::dim] = 1.0
    blocchi_pt = []
    for b in range(B):
        blocco = np.zeros(slots)
        for k in range(R):
            i = b * R + k
            if i < N:
                blocco[k * dim:(k + 1) * dim] = -2.0 * Gal[i]
        blocchi_pt.append(pt(blocco, ct_a.parms_id()))

    def attuale():
        acc = None
        for b in range(B):
            c = mulpt(ct_a, blocchi_pt[b])
            for sh in [1 << j for j in range(int(np.log2(dim)))]:
                ev.add_inplace(c, rot(c, sh, gk_a))
            c = mulpt(c, pt(masc, c.parms_id()))
            if b > 0:
                c = rot(c, -b, gk_a)
            if acc is None:
                acc = c
            else:
                if acc.parms_id() != c.parms_id():
                    ev.mod_switch_to_inplace(acc, c.parms_id())
                ev.add_inplace(acc, c)
        cost = np.zeros(slots)
        for i in range(N):
            b, k = divmod(i, R); cost[k * dim + b] = bsq[i]
        ev.add_plain_inplace(acc, pt(cost, acc.parms_id()))
        return acc

    q, u = np.arange(slots) // W, np.arange(slots) % W
    PJ = []
    for j in range(rho):
        col = W * ((q + j) % rho) + u
        p = -2.0 * Gal[np.minimum(q, N - 1), col]; p[q >= N] = 0.0
        PJ.append(pt(p, ct_a.parms_id()))
    mascH = np.zeros(slots); mascH[::W] = 1.0

    def ibrido():
        acc = None
        for j in range(rho):
            cj = ct_a if j == 0 else rot(ct_a, W * j, gk_b)
            t = mulpt(cj, PJ[j])
            if acc is None:
                acc = t
            else:
                ev.add_inplace(acc, t)
        for sh in [1 << i for i in range(int(np.log2(W)))]:
            ev.add_inplace(acc, rot(acc, sh, gk_b))
        acc = mulpt(acc, pt(mascH, acc.parms_id()))
        cost = np.zeros(slots)
        for i in range(N):
            cost[i * W] = bsq[i]
        ev.add_plain_inplace(acc, pt(cost, acc.parms_id()))
        return acc

    atteso = S_all[3, :N]
    tempi = {}
    for nome, fn, leggi in (("att", attuale, lambda v: [v[(i % R) * dim + i // R] for i in range(N)]),
                            ("ib", ibrido, lambda v: [v[i * W] for i in range(N)])):
        fn()
        ts = []
        for _ in range(3):
            t0 = time.time(); out = fn(); ts.append(time.time() - t0)
        tempi[nome] = float(np.mean(ts))
        tempi[nome + "_err"] = float(np.abs(np.array(leggi(dcr(out))) - atteso).max())
    rot_att = 9 * B + max(B - 1, 0)
    rot_ib = len(set(passi_ib))
    print(f"{N:>5} | {rot_att:>12} | {tempi['att']:>8.3f}s | {rot_ib:>11} | "
          f"{tempi['ib']:>7.3f}s | {tempi['att'] / tempi['ib']:>7.2f}x | "
          f"{mb_att:>7.0f}/{mb_ib:<7.0f} MB | "
          f"{max(tempi['att_err'], tempi['ib_err']):.4f}")
    righe.append({"N": N, "rot_attuale": rot_att, "t_attuale_s": round(tempi["att"], 3),
                  "rot_ibrido": rot_ib, "t_ibrido_s": round(tempi["ib"], 3),
                  "guadagno": round(tempi["att"] / tempi["ib"], 2),
                  "galois_attuale_mb": round(mb_att), "galois_ibrido_mb": round(mb_ib),
                  "err_max": round(max(tempi["att_err"], tempi["ib_err"]), 4),
                  "probe_timed": 1, "repetitions": 3,
                  "q_probe": q_probe, "range_analitico": int(range_analitico),
                  "range_osservato_test": int(range_osservato)})

out = pathlib.Path(os.environ.get(
    "OUTPUT_CSV",
    str(pathlib.Path(__file__).resolve().parent / "results" / "ckks_packing_forte.csv"),
))
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="") as fp:
    w = csv.DictWriter(fp, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
print(f"\nscritto {out}")
