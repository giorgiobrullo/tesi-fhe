"""Calibrazione del varco per la demo: scala di quantizzazione e soglia T.

Un sistema vero si taratura una volta, all'installazione: qui facciamo la stessa cosa sui dati di
riferimento (ResNet100 su VGGFace2, volti reali), nella configurazione finale della tesi —
quantizzazione a 3 bit (F47) e fusione multi-frame (F48: 2 foto per iscritto, 3 frame per query).

  scala   dalla distribuzione degli embedding (percentile 99,5 / valore massimo a 3 bit)
  T       soglia a FPIR=1%: primo percentile dei punteggi minimi degli impostori, cioe' solo
          l'1% degli sconosciuti viene accettato per errore. Calibrata su impostori REALI
          (caso duro): un volto reale contro la galleria. Dipende da N, quindi la calcoliamo
          per la dimensione di galleria della demo.

Scrive demo/config.json, letto sia dal client sia dal server della demo.
"""
import json
import pathlib
import sys

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = pathlib.Path(__file__).resolve().parent
BIT = 3
QM = 2 ** (BIT - 1) - 1            # 3 bit -> valori in [-3, 3]
N_GALLERIA = int(sys.argv[1]) if len(sys.argv) > 1 else 128
K_GAL, K_PROBE = 2, 3              # fusione multi-frame (F48)
SEED_N = 7

z = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")
E, y = z["rn100"].astype(np.float32), z["y"]
E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)
per_id = {}
for i, v in enumerate(y):
    per_id.setdefault(int(v), []).append(i)
ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= K_GAL + K_PROBE))

scala = float(np.percentile(np.abs(E), 99.5) / QM)


def q(v):
    return np.clip(np.round(v / scala), -QM, QM).astype(np.int64)


def fondi(idx):
    v = E[idx].mean(0)
    return v / (np.linalg.norm(v) + 1e-9)


Ts, dir_ok = [], []
for seed in range(SEED_N):
    rng = np.random.RandomState(seed)
    sel = ids.copy(); rng.shuffle(sel)
    iscritti, altri = sel[:N_GALLERIA], sel[N_GALLERIA:N_GALLERIA + 600]
    G, gen, imp = [], [], []
    for sid in iscritti:
        im = per_id[sid][:]; rng.shuffle(im)
        G.append(q(fondi(im[:K_GAL])))
        gen.append(q(fondi(im[K_GAL:K_GAL + K_PROBE])))
    for sid in altri:
        im = per_id[sid][:]; rng.shuffle(im)
        imp.append(q(fondi(im[:K_PROBE])))
    G, gen, imp = np.array(G), np.array(gen), np.array(imp)
    bsq = (G * G).sum(1)
    s_imp = (bsq[None, :] - 2 * (imp @ G.T)).min(1)
    T = float(np.quantile(s_imp, 0.01, method="lower"))
    s_gen = bsq[None, :] - 2 * (gen @ G.T)
    accettati = s_gen <= T
    dir_ok.append(float(np.mean((accettati.sum(1) == 1) & (accettati.argmax(1) == np.arange(len(gen))))))
    Ts.append(T)

T_reale = int(np.median(Ts))

# --- seconda calibrazione: il dominio della galleria della demo (volti SINTETICI DigiFace).
# La soglia non e' una costante del sistema ma un parametro di INSTALLAZIONE: dipende dal dominio
# dei volti iscritti. Sul sintetico le distanze sono compresse (il divario di dominio di F30) e la
# soglia giusta e' molto piu' stretta; usare quella dei volti reali farebbe entrare il 91% degli
# impostori. Qui calcoliamo entrambe e mettiamo in config quella della galleria che la demo carica.
Z = ROOT / "datasets" / "digiface" / "_emb_5img_resnet100.npz"
T_sint = None
if Z.exists():
    zz = np.load(Z)
    Es, ys = zz["E"].astype(np.float32), zz["y"]
    Es = Es / (np.linalg.norm(Es, axis=1, keepdims=True) + 1e-9)
    ps = {}
    for i, v in enumerate(ys):
        ps.setdefault(int(v), []).append(i)
    ids_s = np.array(sorted(k for k, v in ps.items() if len(v) >= K_GAL + K_PROBE))[:3000]
    rng = np.random.RandomState(0); sel = ids_s.copy(); rng.shuffle(sel)
    fondi_s = lambda ix: (lambda v: v / (np.linalg.norm(v) + 1e-9))(Es[ix].mean(0))
    Gs = np.array([q(fondi_s(ps[s][:K_GAL])) for s in sel[:N_GALLERIA]])
    imps = np.array([q(fondi_s(ps[s][:K_PROBE])) for s in sel[N_GALLERIA:N_GALLERIA + 1000]])
    s_imp_s = ((Gs * Gs).sum(1)[None, :] - 2 * (imps @ Gs.T)).min(1)
    T_sint = int(np.quantile(s_imp_s, 0.01, method="lower"))

DOMINIO = sys.argv[2] if len(sys.argv) > 2 else "sintetico"     # galleria della demo
T = T_sint if (DOMINIO == "sintetico" and T_sint is not None) else T_reale
# range dei punteggi (per Delta): |s - T| massimo osservato, con margine
rng = np.random.RandomState(0)
sel = ids.copy(); rng.shuffle(sel)
G = np.array([q(fondi(per_id[s][:K_GAL])) for s in sel[:N_GALLERIA]])
Pr = np.array([q(fondi(per_id[s][K_GAL:K_GAL + K_PROBE])) for s in sel[:400]])
S = (G * G).sum(1)[None, :] - 2 * (Pr @ G.T)
max_d = int(np.abs(S - T_reale).max() * 1.5)             # margine 1,5x per volti fuori distribuzione
log_delta = 63 - int(np.ceil(np.log2(max_d + 1)))

cfg = {"dim": 512, "bit": BIT, "q_max": QM, "scala": round(scala, 8), "T": T,
       "dominio_galleria": DOMINIO, "T_reale_vggface2": T_reale, "T_sintetico_digiface": T_sint,
       "log_delta": log_delta, "k_galleria": K_GAL, "k_probe": K_PROBE,
       "n_galleria_calibrazione": N_GALLERIA, "modello": "resnet100"}
(OUT / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
print(f"scala {scala:.6f} (3 bit, valori in [-{QM}, {QM}])")
print(f"T volti REALI (VGGFace2)   = {T_reale}  (FPIR=1%, galleria {N_GALLERIA}, fusione {K_GAL}+{K_PROBE}), DIR {np.mean(dir_ok):.1%}")
print(f"T volti SINTETICI (DigiFace) = {T_sint}  (stesso protocollo; le distanze sintetiche sono compresse, F30)")
print(f"-> in config va T = {T} (galleria della demo: {DOMINIO})")
print(f"|s-T| max osservato x1,5 = {max_d} -> Delta = 2^{log_delta}")
print(f"scritto {OUT / 'config.json'}")
