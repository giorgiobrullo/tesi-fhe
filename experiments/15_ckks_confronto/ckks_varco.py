"""Il varco in CKKS: quanto vale lo schema? (confronto chiesto da Carnemolla, findings F39)

Stesso problema di experiments/14 (varco_leveled.rs): N iscritti a 512 dimensioni, probe cifrato,
galleria in chiaro, esito "s_i <= T" per ogni iscritto. Qui in CKKS (Microsoft SEAL via TenSEAL
`sealapi`, parametri a 128 bit), con il packing SIMD che e' il motivo per cui la letteratura
sceglie CKKS:

  distanze  il probe (512 valori) e' replicato R = slot/512 volte in UN cifrato; per ogni blocco di R
            iscritti una moltiplicazione per il plaintext -2*G_blocco, poi rotate-and-sum
            (9 rotazioni) porta il prodotto scalare nello slot 512k di ogni segmento; i blocchi si
            compattano con una rotazione ciascuno -> tutti gli N punteggi in un solo cifrato.
  soglia    x = (T + 1/2 - s)/RANGE in [-1, 1], poi il SEGNO come polinomio composto
            f_n^(d_f) o g_n^(d_g) (Cheon, Kim, Kim, ASIACRYPT 2020): una sola valutazione per
            tutti gli N punteggi insieme, il costo non dipende da N (finche' N <= slot). Il prezzo e'
            la profondita' moltiplicativa (ogni composizione consuma livelli -> parametri piu'
            grandi, operazioni piu' lente) e una banda intorno a T dove il segno non e' ancora +-1.

Misura, per ogni configurazione (grado del polinomio, primi, n, d_g, d_f): keygen, dimensioni,
tempo delle distanze in funzione di N, tempo della soglia, la banda (misurata su uno sweep di
d = s - T sugli slot: una valutazione = tutta la curva) e l'esatto cifrato/chiaro sui probe reali
della scena di experiments/14 (esporta_dati.py). SEAL e' single-thread: si confronta con il
run a 1 thread di tfhe-rs (e a 16, notando che i blocchi CKKS sarebbero parallelizzabili).
"""
import csv
import pathlib
import sys
import time

import numpy as np
from tenseal import sealapi as S

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)
SCENA = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results" / "scena_reale.txt"

# --- polinomi di Cheon-Kim-Kim (ASIACRYPT 2020), verificati sul testo: p(x) = sum c_k x^(2k+1) ---
F = {1: [3 / 2, -1 / 2],
     2: [15 / 8, -10 / 8, 3 / 8],
     3: [35 / 16, -35 / 16, 21 / 16, -5 / 16],
     4: [315 / 128, -420 / 128, 378 / 128, -180 / 128, 35 / 128]}
G = {1: [2126 / 2**10, -1359 / 2**10],
     2: [3334 / 2**10, -6108 / 2**10, 3796 / 2**10],
     3: [4589 / 2**10, -16577 / 2**10, 25614 / 2**10, -12860 / 2**10],
     4: [5850 / 2**10, -34974 / 2**10, 97015 / 2**10, -113492 / 2**10, 46623 / 2**10]}


def poly_odd_clear(c, x):
    y = x * x
    return x * sum(ck * y**k for k, ck in enumerate(c))


def carica_scena():
    righe = SCENA.read_text().splitlines()
    dim, n, np_, t = map(int, righe[0].split())
    g = np.array([list(map(int, r.split())) for r in righe[1:1 + n]])
    pr = np.array([list(map(int, r.split())) for r in righe[1 + n:1 + n + np_]])
    return dim, g, pr[:, 0], pr[:, 1:], t


class Ckks:
    def __init__(self, poly, primi, scale_bits):
        self.poly, self.scale = poly, 2.0 ** scale_bits
        parms = S.EncryptionParameters(S.SCHEME_TYPE.CKKS)
        parms.set_poly_modulus_degree(poly)
        parms.set_coeff_modulus(S.CoeffModulus.Create(poly, primi))
        self.ctx = S.SEALContext(parms, True, S.SEC_LEVEL_TYPE.TC128)
        kg = S.KeyGenerator(self.ctx)
        self.pk = S.PublicKey(); kg.create_public_key(self.pk)
        self.sk = kg.secret_key()
        self.rk = S.RelinKeys(); kg.create_relin_keys(self.rk)
        self.gk = None; self.kg = kg
        self.enc = S.Encryptor(self.ctx, self.pk); self.dec = S.Decryptor(self.ctx, self.sk)
        self.ev = S.Evaluator(self.ctx); self.co = S.CKKSEncoder(self.ctx)
        self.slots = self.co.slot_count()
        self.livelli = len(primi) - 2

    def galois(self, passi):
        self.gk = S.GaloisKeys(); self.kg.create_galois_keys(passi, self.gk)

    def livello(self, ct):
        return self.ctx.get_context_data(ct.parms_id()).chain_index()

    def pt(self, vals, parms_id=None):
        p = S.Plaintext()
        v = list(map(float, vals)) + [0.0] * (self.slots - len(vals))
        if parms_id is None:
            self.co.encode(v, self.scale, p)
        else:
            self.co.encode(v, parms_id, self.scale, p)
        return p

    def encrypt(self, vals):
        c = S.Ciphertext(); self.enc.encrypt(self.pt(vals), c); return c

    def decrypt(self, ct):
        p = S.Plaintext(); self.dec.decrypt(ct, p); return np.array(self.co.decode_double(p))

    def mul_pt(self, ct, vals):
        """ct * plaintext(vals), rescale, scala riallineata."""
        out = S.Ciphertext(); self.ev.multiply_plain(ct, self.pt(vals, ct.parms_id()), out)
        self.ev.rescale_to_next_inplace(out); out.scale = self.scale; return out

    def mul_ct(self, a, b):
        if a.parms_id() != b.parms_id():
            deep = min([a, b], key=self.livello).parms_id()
            a, b = self.al_livello(a, deep), self.al_livello(b, deep)
        out = S.Ciphertext(); self.ev.multiply(a, b, out); self.ev.relinearize_inplace(out, self.rk)
        self.ev.rescale_to_next_inplace(out); out.scale = self.scale; return out

    def allinea(self, cts):
        """porta tutti al livello del piu' profondo (mod switch), per sommarli."""
        deep = min(cts, key=self.livello).parms_id()
        for c in cts:
            if c.parms_id() != deep:
                self.ev.mod_switch_to_inplace(c, deep)
        return cts

    def al_livello(self, ct, parms_id):
        """copia di ct portata a parms_id (mod switch non in place: SEAL non espone il copy ctor)."""
        out = S.Ciphertext(); self.ev.mod_switch_to(ct, parms_id, out); return out

    def somma(self, cts):
        if len(cts) == 1:
            return cts[0]
        cts = self.allinea(cts); acc = S.Ciphertext(); self.ev.add(cts[0], cts[1], acc)
        for c in cts[2:]:
            self.ev.add_inplace(acc, c)
        return acc

    def rot(self, ct, k):
        out = S.Ciphertext(); self.ev.rotate_vector(ct, k, self.gk, out); return out

    def poly_odd(self, c, x):
        """p(x) = sum_k c_k x y^k con y = x^2: profondita' 2 per grado 3, 3 per grado 5, 4 per 7 e 9."""
        y = self.mul_ct(x, x)
        pot = {1: y}
        if len(c) > 2:
            pot[2] = self.mul_ct(y, y)
        if len(c) > 3:
            pot[3] = self.mul_ct(pot[2], y)
        if len(c) > 4:
            pot[4] = self.mul_ct(pot[2], pot[2])
        termini = [self.mul_pt(x, [c[0]] * self.slots)]
        for k in range(1, len(c)):
            cx = self.mul_pt(x, [c[k]] * self.slots)
            deep = min([cx, pot[k]], key=self.livello).parms_id()
            cx = self.al_livello(cx, deep); yk = self.al_livello(pot[k], deep)
            termini.append(self.mul_ct(cx, yk))
        return self.somma(termini)

    def segno(self, x, n, dg, df):
        for _ in range(dg):
            x = self.poly_odd(G[n], x)
        for _ in range(df):
            x = self.poly_odd(F[n], x)
        return x


def esegui(cfg, dim, Gal, labels, P, T, n_probe_esatto):
    poly, primi, n, dg, df = cfg["poly"], cfg["primi"], cfg["n"], cfg["dg"], cfg["df"]
    t0 = time.time(); K = Ckks(poly, primi, cfg["scale_bits"]); t_key = time.time() - t0
    R = K.slots // dim                               # iscritti per cifrato
    N_max = Gal.shape[0]
    B_max = int(np.ceil(N_max / R))
    t0 = time.time(); K.galois([1 << i for i in range(int(np.log2(dim)))] + [-b for b in range(1, B_max)]); t_gal = time.time() - t0
    bsq = (Gal * Gal).sum(1)
    S_all = bsq[None, :] - 2 * (P @ Gal.T)
    RANGE = float(np.abs(S_all - T).max() + 1)       # il server lo maggiora dalle norme; qui dal dato
    print(f"\n=== poly {poly}, {len(primi) - 2} livelli, n={n} g^{dg} f^{df}: keygen {t_key:.2f}s, galois {t_gal:.2f}s, "
          f"slot {K.slots}, {R} iscritti/cifrato, RANGE {RANGE:.0f} ===")

    def cifra_probe(a):
        return K.encrypt(np.tile(a, R))

    maschera_512k = np.zeros(K.slots); maschera_512k[::dim] = 1.0

    def distanze(ct_a, N):
        """N punteggi s_i = bsq_i - 2 g_i.a, compattati negli slot 512k + b."""
        B = int(np.ceil(N / R))
        acc = None
        for b in range(B):
            blocco = np.zeros(K.slots)
            for k in range(R):
                i = b * R + k
                if i < N:
                    blocco[k * dim:(k + 1) * dim] = -2.0 * Gal[i]
            c = K.mul_pt(ct_a, blocco)
            for sh in [1 << j for j in range(int(np.log2(dim)))]:
                K.ev.add_inplace(c, K.rot(c, sh))
            # il rotate-and-sum lascia somme parziali in TUTTI gli slot: senza maschera i blocchi
            # compattati si contaminerebbero a vicenda (costa un livello e un mult_plain per blocco)
            c = K.mul_pt(c, maschera_512k)
            if b > 0:
                c = K.rot(c, -b)
            acc = c if acc is None else K.somma([acc, c])
        costante = np.zeros(K.slots)
        for i in range(N):
            b, k = divmod(i, R); costante[k * dim + b] = bsq[i]
        K.ev.add_plain_inplace(acc, K.pt(costante, acc.parms_id()))
        return acc

    def soglia(ct_s, N):
        """x = (T + 1/2 - s)/RANGE sugli slot dei punteggi (maschera), poi il segno."""
        m = np.zeros(K.slots); c0 = np.zeros(K.slots)
        for i in range(N):
            b, k = divmod(i, R); m[k * dim + b] = -1.0 / RANGE; c0[k * dim + b] = (T + 0.5) / RANGE
        x = K.mul_pt(ct_s, m)
        K.ev.add_plain_inplace(x, K.pt(c0, x.parms_id()))
        return K.segno(x, n, dg, df)

    def leggi(ct_out, N):
        v = K.decrypt(ct_out)
        return np.array([v[(i % R) * dim + i // R] for i in range(N)])

    # --- 1) la banda: uno sweep di d = s - T sugli slot, una sola valutazione del segno ---
    ds = np.arange(-(K.slots // 2), K.slots // 2)
    x = K.encrypt(np.clip((0.5 - ds) / RANGE, -1.0, 1.0))   # oltre RANGE il polinomio divergerebbe
    t0 = time.time(); out = K.decrypt(K.segno(x, n, dg, df)); t_segno = time.time() - t0
    atteso = np.where(ds <= 0, 1.0, -1.0)
    ambigui = np.abs(out - atteso) > 0.5
    banda = (int(ds[ambigui].min()), int(ds[ambigui].max())) if ambigui.any() else (0, 0)
    print(f"  segno (tutti gli slot insieme): {t_segno:.2f}s; banda d in [{banda[0]}, {banda[1]}] "
          f"({ambigui.sum()} valori ambigui su {len(ds)}), livello finale {K.livello(x)}->{cfg['livelli_usati']}")

    # --- 2) distanze e pipeline per N, tempi su alcuni probe; esattezza sui probe reali a N=128 ---
    righe = []
    # la lista delle N era cablata a 128: ora arriva fino alla galleria della scena (serve per
    # misurare dove il packing CKKS comincia ad ammortizzare, F67)
    _ns = [8, 16, 32, 64, 128]
    while _ns[-1] * 2 <= Gal.shape[0]:
        _ns.append(_ns[-1] * 2)
    for N in _ns:
        tt_d, tt_s = [], []
        for a in P[:4]:
            ct_a = cifra_probe(a)
            t0 = time.time(); ct_s = distanze(ct_a, N); tt_d.append(time.time() - t0)
            t0 = time.time(); ct_o = soglia(ct_s, N); tt_s.append(time.time() - t0)
        err_dist = np.abs(leggi(ct_s, N) - S_all[3, :N]).max()
        print(f"  N={N:>3}: distanze {np.mean(tt_d):.3f}s ({int(np.ceil(N / R))} blocchi), soglia {np.mean(tt_s):.2f}s, "
              f"totale {np.mean(tt_d) + np.mean(tt_s):.2f}s | errore CKKS sui punteggi: {err_dist:.3f}")
        righe.append({"poly": poly, "n": n, "dg": dg, "df": df, "N": N, "t_distanze": round(float(np.mean(tt_d)), 4),
                      "t_soglia": round(float(np.mean(tt_s)), 3), "banda_lo": banda[0], "banda_hi": banda[1],
                      "err_punteggi": round(float(err_dist), 4), "keygen_s": round(t_key + t_gal, 2)})
    # esattezza: tutti i probe a N=128
    N = N_max; errori = 0; conf = 0; err_d = []; gen_ok = gen_tot = imp_acc = imp_tot = 0
    # ATTENZIONE (correzione F62): la scena mette prima tutti i genuini e poi tutti gli impostori,
    # quindi P[:n] erano SOLO genuini e la colonna "impostori accettati" leggeva 0/0. Si prende un
    # campione bilanciato: meta' genuini e meta' impostori.
    import numpy as _np
    _lab = _np.asarray(labels)
    _g = _np.where(_lab >= 0)[0][: n_probe_esatto // 2]
    _i = _np.where(_lab < 0)[0][: n_probe_esatto - len(_g)]
    _sel = _np.concatenate([_g, _i])
    for a, lab, s_row in zip([P[k] for k in _sel], [labels[k] for k in _sel], [S_all[k] for k in _sel]):
        bit = leggi(soglia(distanze(cifra_probe(a), N), N), N) > 0
        att = s_row[:N] <= T
        conf += N; errori += int((bit != att).sum()); err_d += [int(abs(d)) for d in (s_row[:N] - T)[bit != att]]
        sotto = np.where(bit)[0]
        if lab >= 0:
            gen_tot += 1; gen_ok += int(len(sotto) == 1 and sotto[0] == lab)
        else:
            imp_tot += 1; imp_acc += int(len(sotto) > 0)
    print(f"  esattezza a N={N} su {n_probe_esatto} probe: {errori}/{conf} discrepanze {sorted(err_d)[:10]}; "
          f"genuini one-hot giusto {gen_ok}/{gen_tot}, impostori accettati {imp_acc}/{imp_tot}")
    for r in righe:
        r.update({"discrepanze": errori, "confronti": conf})
    return righe


if __name__ == "__main__":
    dim, Gal, labels, P, T = carica_scena()
    CONFIG = [
        # 16384: 9 livelli -> 3 (distanze, maschera blocco, maschera soglia) + g_1^2 (4) + f_1^1 (2) = 9
        {"poly": 16384, "primi": [50] + [35] * 9 + [50], "scale_bits": 35, "n": 1, "dg": 2, "df": 1, "livelli_usati": 9},
        # 32768 con catena corta: 13 livelli -> 3 + g_1^4 (8) + f_1^1 (2) = 13 (operazioni piu' leggere, banda piu' larga)
        {"poly": 32768, "primi": [50] + [40] * 13 + [50], "scale_bits": 40, "n": 1, "dg": 4, "df": 1, "livelli_usati": 13},
        # 32768: 19 livelli -> 3 + g_1^6 (12) + f_1^2 (4) = 19
        {"poly": 32768, "primi": [50] + [40] * 19 + [50], "scale_bits": 40, "n": 1, "dg": 6, "df": 2, "livelli_usati": 19},
        # 32768: 3 + g_3^3 (12) + f_3^1 (4) = 19, meno composizioni ma piu' moltiplicazioni
        {"poly": 32768, "primi": [50] + [40] * 19 + [50], "scale_bits": 40, "n": 3, "dg": 3, "df": 1, "livelli_usati": 19},
    ]
    n_probe = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    tutte = []
    # CFG_FHE=indice per girare una sola configurazione (le altre costano minuti di keygen)
    _sel = _os.environ.get("CFG_FHE")
    _cfgs = [CONFIG[int(_sel)]] if _sel is not None else CONFIG
    for cfg in _cfgs:
        tutte += esegui(cfg, dim, Gal, labels, P, T, n_probe)
    with open(OUT / "ckks_varco.csv", "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=list(tutte[0].keys())); w.writeheader(); w.writerows(tutte)
    print(f"\nscritto {OUT / 'ckks_varco.csv'}")
