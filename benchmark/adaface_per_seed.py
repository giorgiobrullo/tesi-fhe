"""Per-seed DIR@FPIR=1% sui modelli reali (VGGFace2), con intervallo di confidenza.
Risponde al dubbio: il vantaggio di AdaFace su ResNet50 (~+0,6 punti) è reale o rumore di
split? Ripete lo split open-set su molti seed dagli embedding in cache (niente ri-embedding),
e dà media ± IC 95% per modello e il margine appaiato AdaFace−ResNet50 seed per seed."""
import csv
import pathlib
import sys
import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core import dataset                                  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
A = np.load(OUT / "_emb_reale.npz")       # mfn, rn (resnet50), y
B = np.load(OUT / "_emb_reale_extra.npz")  # rn100, ada, y
assert np.array_equal(A["y"], B["y"]), "ordine y non combacia tra le due cache"
y = A["y"]
EMB = {"mobilefacenet": A["mfn"], "resnet50": A["rn"], "resnet100": B["rn100"], "adaface": B["ada"]}
ISCRITTI = [4000, 4300]
SEEDS = list(range(20))


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01):
    gnorm = np.einsum("ij,ij->i", Eg, Eg)
    def nn(P):
        sn = np.empty(len(P)); idx = np.empty(len(P), int)
        for i in range(0, len(P), 1024):
            Pb = P[i:i + 1024]
            d = np.einsum("ij,ij->i", Pb, Pb)[:, None] - 2.0 * (Pb @ Eg.T) + gnorm[None, :]
            j = d.argmin(1); idx[i:i + len(Pb)] = j; sn[i:i + len(Pb)] = d[np.arange(len(Pb)), j]
        return sn, idx
    sn, k = nn(Epn); si, _ = nn(Epi)
    return float(np.mean((yg[k] == ypn) & (sn <= np.quantile(si, fpir))))


ids = np.unique(y)
rows = []          # per-seed grezzi (da committare)
per = {}           # (modello, iscritti) -> [dir per seed]
for iscritti in ISCRITTI:
    T = iscritti * 2
    if T > len(ids):
        continue
    sel = set(ids[:T].tolist()); m = np.array([v in sel for v in y])
    ym = y[m]
    for modello, E in EMB.items():
        Em = E[m]
        ds = []
        for s in SEEDS:
            sp = dataset.split_openset(Em, ym, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=s)
            d = dir_at_fpir(sp["galleria"][0], sp["galleria"][1],
                            sp["probe_noti"][0], sp["probe_noti"][1], sp["probe_ignoti"][0])
            ds.append(d); rows.append({"modello": modello, "iscritti": iscritti, "seed": s, "dir_fpir1": round(d, 5)})
        per[(modello, iscritti)] = np.array(ds)
        print(f"iscritti={iscritti} {modello:>13}: media {np.mean(ds):.2%} ± {1.96*np.std(ds, ddof=1)/np.sqrt(len(ds)):.2%} (IC95)", flush=True)

# margine appaiato AdaFace - ResNet50 (stesso seed -> differenza appaiata)
print("\n--- margine appaiato AdaFace - ResNet50 ---")
for iscritti in ISCRITTI:
    if ("adaface", iscritti) not in per:
        continue
    diff = per[("adaface", iscritti)] - per[("resnet50", iscritti)]
    ci = 1.96 * np.std(diff, ddof=1) / np.sqrt(len(diff))
    print(f"iscritti={iscritti}: +{np.mean(diff)*100:.2f} pt ± {ci*100:.2f} (IC95) | "
          f"positivo in {int(np.sum(diff>0))}/{len(diff)} seed", flush=True)
# margine AdaFace - ResNet100
print("--- margine appaiato AdaFace - ResNet100 ---")
for iscritti in ISCRITTI:
    if ("adaface", iscritti) not in per:
        continue
    diff = per[("adaface", iscritti)] - per[("resnet100", iscritti)]
    ci = 1.96 * np.std(diff, ddof=1) / np.sqrt(len(diff))
    print(f"iscritti={iscritti}: {np.mean(diff)*100:+.2f} pt ± {ci*100:.2f} (IC95) | "
          f"positivo in {int(np.sum(diff>0))}/{len(diff)} seed", flush=True)

with open(OUT / "adaface_per_seed.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["modello", "iscritti", "seed", "dir_fpir1"])
    w.writeheader(); w.writerows(rows)
print(f"\nscritto {OUT / 'adaface_per_seed.csv'} ({len(rows)} righe)")
