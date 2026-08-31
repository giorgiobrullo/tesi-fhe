"""I quattro numeri della demo, resi riproducibili (correzione F62).

F49 afferma: con la soglia del dominio REALE (T=269) applicata a una galleria SINTETICA,
"il 91% degli impostori verrebbe accettato (7,25 iscritti sotto soglia per query invece di 1)",
mentre con la soglia giusta (T=23) il varco torna a "98,4% di one-hot corretti e 1,1% di
impostori". Nessuno script produceva quelle cifre. Questo le ricalcola, con lo stesso protocollo
della demo: ResNet100, 3 bit, fusione 2 foto in galleria + 3 frame per query, N=128 iscritti
sintetici (DigiFace), impostori = identita' sintetiche non iscritte.
"""
import csv
import pathlib

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIT, QM, K_GAL, K_PROBE, N = 3, 3, 2, 3, 128
Z = ROOT / "datasets" / "digiface" / "_emb_5img_resnet100.npz"
z = np.load(Z)
E, y = z["emb"].astype(np.float32) if "emb" in z else z[list(z.keys())[0]].astype(np.float32), z["y"]
E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)
per_id = {}
for i, v in enumerate(y):
    per_id.setdefault(int(v), []).append(i)
ids = np.array(sorted(k for k, v in per_id.items() if len(v) >= K_GAL + K_PROBE))
# la scala di quantizzazione e' quella dei volti REALI, come nella demo (config.json)
zr = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")
Er = zr["rn100"].astype(np.float32)
Er = Er / (np.linalg.norm(Er, axis=1, keepdims=True) + 1e-9)
scala = float(np.percentile(np.abs(Er), 99.5) / QM)
q = lambda v: np.clip(np.round(v / scala), -QM, QM).astype(np.int64)
fondi = lambda idx: (lambda v: v / (np.linalg.norm(v) + 1e-9))(E[idx].mean(0))

righe = []
for T, etichetta in ((269, "T del dominio REALE (sbagliata qui)"), (23, "T del dominio SINTETICO (giusta)")):
    d, f, sotto, uno = [], [], [], []
    for seed in range(7):
        rng = np.random.RandomState(seed)
        sel = ids.copy(); rng.shuffle(sel)
        G, gen, imp = [], [], []
        for sid in sel[:N]:
            im = per_id[sid][:]; rng.shuffle(im)
            G.append(q(fondi(im[:K_GAL]))); gen.append(q(fondi(im[K_GAL:K_GAL + K_PROBE])))
        for sid in sel[N:N + 300]:
            im = per_id[sid][:]; rng.shuffle(im)
            imp.append(q(fondi(im[:K_PROBE])))
        G, gen, imp = np.array(G), np.array(gen), np.array(imp)
        bsq = (G * G).sum(1)
        Sg, Si = bsq[None, :] - 2 * (gen @ G.T), bsq[None, :] - 2 * (imp @ G.T)
        ag, ai = Sg <= T, Si <= T
        d.append(np.mean((ag.sum(1) == 1) & (ag.argmax(1) == np.arange(N))))
        f.append(np.mean(ai.any(1)))
        sotto.append(ai.sum(1).mean())
        uno.append(ag.sum(1).mean())
    print(f"{etichetta:38s}  one-hot corretti {np.mean(d):>6.1%} | impostori accettati {np.mean(f):>6.1%} | "
          f"iscritti sotto soglia per query: genuini {np.mean(uno):.2f}, impostori {np.mean(sotto):.2f}")
    righe.append({"T": T, "one_hot": round(float(np.mean(d)), 4), "fpir": round(float(np.mean(f)), 4),
                  "sotto_soglia_genuini": round(float(np.mean(uno)), 2),
                  "sotto_soglia_impostori": round(float(np.mean(sotto)), 2)})
out = ROOT / "benchmark" / "results" / "soglia_dominio.csv"
with open(out, "w", newline="") as fp:
    w = csv.DictWriter(fp, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
print(f"\nscritto {out}")
