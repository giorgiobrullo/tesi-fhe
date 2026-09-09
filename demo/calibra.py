"""Calibra scala, soglie e dominio intero per la configurazione corrente del varco.

La decisione finale e' identificazione open-set: il server trova l'argmin esatto, applica la
soglia ``T_i`` associata soltanto a quel vincitore e restituisce un solo cifrato che codifica
``0=rifiuto`` oppure ``i+1=identita' accettata``. La metrica primaria sui genuini e' quindi il
DIR: identita' corretta al Rank-1 *e* punteggio del vincitore sotto soglia. ``any_match`` non e'
il contratto del sistema e resta soltanto una diagnostica quando tutte le soglie sono uguali.

Per DigiFace questo script usa esattamente le cartelle e le prime 2+3 immagini che la demo carica,
non il vecchio cache a cinque immagini campionate casualmente. I primi 127 soggetti formano la
galleria sintetica; 500 identita' disgiunte tarano FPIR e altre 500 la verificano. Gli embedding
esatti vengono messi in un cache gitignorato sotto ``datasets/``.

La soglia VGGFace2 resta una calibrazione di dominio su sette split: per ogni split usa impostori
distinti per tuning e verifica. Viene assegnata alle iscrizioni webcam, le cui prestazioni non sono
state validate. Una galleria mista conserva la soglia insieme a ciascun template e il circuito
seleziona quella del vincitore; il suo FPIR aggregato richiede comunque una misura dedicata.

Scrive ``demo/config.json`` e ``demo/config.env``.
"""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import sys
import time

import numpy as np


ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = pathlib.Path(__file__).resolve().parent
BIT = 3
QM = 2 ** (BIT - 1) - 1
N_CAPACITA = int(sys.argv[1]) if len(sys.argv) > 1 else 128
N_SINTETICI = N_CAPACITA - 1  # lascia un posto per l'iscrizione webcam nella demo
DOMINIO = sys.argv[2] if len(sys.argv) > 2 else "sintetico"
K_GAL, K_PROBE = 2, 3
N_IMPOSTORI_DEV = 500
N_IMPOSTORI_TEST = 500
SEED_N = 7
TARGET_FPIR = 0.01
MAX_GALLERY = 128
PROBE_NORM2_MAX = 1024
SCORE_BITS = 12
SCORE_DOMAIN_WIDTH_MAX = 1 << SCORE_BITS
FULL_DELTA_LOG = 52
LOW_MOD16_OFFSET = 1024
LOW_MOD16_DELTA_LOG = 60
CODE_DELTA_LOG = 56

if not 2 <= N_CAPACITA <= MAX_GALLERY:
    raise ValueError(
        f"la capacita' deve essere fra 2 e {MAX_GALLERY}: include il posto lasciato alla webcam"
    )
if DOMINIO not in {"sintetico", "reale"}:
    raise ValueError("il dominio deve essere 'sintetico' oppure 'reale'")


def soglia_inclusiva(scores_minimi: np.ndarray, target: float = TARGET_FPIR) -> int:
    """Massimo T intero per cui mean(score <= T) non supera il target empirico.

    Usare direttamente il percentile inferiore e poi ``<=`` puo' superare il target in presenza
    di pareggi, frequenti dopo la quantizzazione.
    """

    valori, conteggi = np.unique(scores_minimi.astype(np.int64), return_counts=True)
    cumulati = np.cumsum(conteggi)
    ammessi = np.flatnonzero(cumulati / len(scores_minimi) <= target)
    return int(valori[ammessi[-1]]) if len(ammessi) else int(valori[0] - 1)


def intervallo_wilson(
    successi: int, totale: int, z: float = 1.959963984540054
) -> list[float]:
    """Intervallo Wilson bilaterale, senza approssimare una proporzione rara come gaussiana."""

    p = successi / totale
    denominatore = 1 + z * z / totale
    centro = (p + z * z / (2 * totale)) / denominatore
    raggio = z * np.sqrt(p * (1 - p) / totale + z * z / (4 * totale * totale))
    raggio /= denominatore
    return [round(float(centro - raggio), 6), round(float(centro + raggio), 6)]


def normalizza(v: np.ndarray) -> np.ndarray:
    return v / (np.linalg.norm(v) + 1e-9)


def sha_array(*array: np.ndarray) -> str:
    h = hashlib.sha256()
    for a in array:
        h.update(np.ascontiguousarray(a).tobytes())
    return h.hexdigest()


def ceil_sqrt(value: int) -> int:
    """Radice quadrata intera superiore, senza arrotondamenti floating point."""

    if value < 0:
        raise ValueError("radicando negativo")
    root = math.isqrt(value)
    return root if root * root == value else root + 1


def dominio_score_cauchy(galleria: np.ndarray) -> dict[str, int]:
    """Inviluppo inclusivo di ``||g||^2 - 2<g,q>`` dato ``||q||^2 <= 1024``."""

    norm2 = (galleria.astype(np.int64) ** 2).sum(1)
    raggi = np.array(
        [2 * ceil_sqrt(int(value) * PROBE_NORM2_MAX) for value in norm2],
        dtype=np.int64,
    )
    lower = int((norm2 - raggi).min())
    upper = int((norm2 + raggi).max())
    width = upper - lower + 1
    if width > SCORE_DOMAIN_WIDTH_MAX:
        raise ValueError(
            f"dominio score largo {width}, massimo {SCORE_DOMAIN_WIDTH_MAX}"
        )
    return {"lower": lower, "upper": upper, "width": width}


# La scala e' una proprieta' del modello sul dominio reale di riferimento, non dei probe della
# singola installazione. Il cache e' gitignorato e richiede VGGFace2; `scaling_modelli.py` lo
# rigenera localmente. La configurazione gia' versionata basta invece per avviare la demo.
CACHE_REALE = ROOT / "benchmark" / "results" / "_emb_reale_extra.npz"
if not CACHE_REALE.exists():
    raise FileNotFoundError(
        f"manca {CACHE_REALE}; generarlo con benchmark/scaling_modelli.py su VGGFace2 "
        "oppure usare demo/config.json senza ricalibrare"
    )
z_reale = np.load(CACHE_REALE)
E_reale, y_reale = z_reale["rn100"].astype(np.float32), z_reale["y"]
E_reale /= np.linalg.norm(E_reale, axis=1, keepdims=True) + 1e-9
scala = float(np.percentile(np.abs(E_reale), 99.5) / QM)


def quantizza(v: np.ndarray) -> np.ndarray:
    return np.clip(np.round(v / scala), -QM, QM).astype(np.int64)


# ------------------------------------------------------------------ dominio reale / webcam
per_id_reale: dict[int, list[int]] = {}
for i, label in enumerate(y_reale):
    per_id_reale.setdefault(int(label), []).append(i)
ids_reali = np.array(
    sorted(k for k, indici in per_id_reale.items() if len(indici) >= K_GAL + K_PROBE)
)

soglie_reali: list[int] = []
dir_reale: list[float] = []
tar_reale: list[float] = []
fpir_reale: list[float] = []
multipli_reali: list[float] = []
score_gen_reali: list[np.ndarray] = []
score_dev_reali: list[np.ndarray] = []
score_test_reali: list[np.ndarray] = []
domini_reali: list[dict[str, int]] = []

for seed in range(SEED_N):
    rng = np.random.RandomState(seed)
    selezionati = ids_reali.copy()
    rng.shuffle(selezionati)
    iscritti = selezionati[:N_CAPACITA]
    dev = selezionati[N_CAPACITA : N_CAPACITA + N_IMPOSTORI_DEV]
    test = selezionati[
        N_CAPACITA + N_IMPOSTORI_DEV : N_CAPACITA + N_IMPOSTORI_DEV + N_IMPOSTORI_TEST
    ]

    def fuso_reale(sid: int, inizio: int, quanti: int) -> np.ndarray:
        indici = per_id_reale[int(sid)][inizio : inizio + quanti]
        return normalizza(E_reale[indici].mean(0))

    galleria = np.array([quantizza(fuso_reale(sid, 0, K_GAL)) for sid in iscritti])
    domini_reali.append(dominio_score_cauchy(galleria))
    genuini = np.array([quantizza(fuso_reale(sid, K_GAL, K_PROBE)) for sid in iscritti])
    impostori_dev = np.array([quantizza(fuso_reale(sid, 0, K_PROBE)) for sid in dev])
    impostori_test = np.array([quantizza(fuso_reale(sid, 0, K_PROBE)) for sid in test])
    bsq = (galleria * galleria).sum(1)
    s_dev = bsq[None, :] - 2 * (impostori_dev @ galleria.T)
    t_seed = soglia_inclusiva(s_dev.min(1))
    s_gen = bsq[None, :] - 2 * (genuini @ galleria.T)
    s_test = bsq[None, :] - 2 * (impostori_test @ galleria.T)
    hit_gen = s_gen <= t_seed

    soglie_reali.append(t_seed)
    tar_reale.append(float(hit_gen.any(1).mean()))
    dir_reale.append(
        float(
            (
                (s_gen.argmin(1) == np.arange(len(iscritti))) & (s_gen.min(1) <= t_seed)
            ).mean()
        )
    )
    fpir_reale.append(float((s_test.min(1) <= t_seed).mean()))
    multipli_reali.append(float((hit_gen.sum(1) > 1).mean()))
    score_gen_reali.append(s_gen)
    score_dev_reali.append(s_dev)
    score_test_reali.append(s_test)

T_REALE = int(np.median(soglie_reali))
# Il client usa T_REALE per ogni enrollment webcam. Le metriche a soglia fissa devono quindi usare
# questa stessa soglia, non la soglia t_seed impiegata soltanto per le metriche per-split.
osservato_reale = max(
    int(np.abs(score).max())
    for gruppo in (score_dev_reali, score_gen_reali, score_test_reali)
    for score in gruppo
)
hit_gen_t_fissa = [score <= T_REALE for score in score_gen_reali]
acc_test_t_fissa = sum(
    int(np.count_nonzero(score.min(1) <= T_REALE)) for score in score_test_reali
)
tot_test_reale = sum(len(score) for score in score_test_reali)
METRICHE_REALI_T_FISSA = {
    "T": T_REALE,
    "metrica_primaria": "dir",
    "tar_any_match_diagnostica": round(
        float(np.mean([hit.any(1).mean() for hit in hit_gen_t_fissa])), 6
    ),
    "dir": round(
        float(
            np.mean(
                [
                    (
                        (score.argmin(1) == np.arange(len(score)))
                        & (score.min(1) <= T_REALE)
                    ).mean()
                    for score in score_gen_reali
                ]
            )
        ),
        6,
    ),
    "fpir_test": round(acc_test_t_fissa / tot_test_reale, 6),
    "accettati_test": acc_test_t_fissa,
    "impostori_test": tot_test_reale,
    "genuini_match_multipli": round(
        float(np.mean([(hit.sum(1) > 1).mean() for hit in hit_gen_t_fissa])), 6
    ),
}


# --------------------------------------------------------- esatta galleria sintetica della demo
DIR_DIGIFACE = ROOT / "datasets" / "digiface" / "estratto"
CACHE_DIGIFACE = ROOT / "datasets" / "digiface" / "_q_demo_calibrazione_resnet100.npz"
cartelle = sorted(p for p in DIR_DIGIFACE.iterdir() if p.is_dir())
necessarie = N_SINTETICI + N_IMPOSTORI_DEV + N_IMPOSTORI_TEST
if len(cartelle) < necessarie:
    raise RuntimeError(
        f"servono {necessarie} identita' DigiFace, trovate {len(cartelle)}"
    )

# Il manifest replica esattamente l'ordine della demo: per i primi 127 soggetti G usa [:2],
# mentre ogni query (genuina o impostore) usa [2:5]. Lo calcoliamo su tutte le cartelle disponibili
# cosi' il cache resta utile anche se si cambia il numero di impostori di test.
selezionati: list[tuple[str, int, pathlib.Path]] = []
firma = hashlib.sha256()
for i, cartella in enumerate(cartelle):
    file = sorted(cartella.glob("*.png"))
    if len(file) < K_GAL + K_PROBE:
        raise RuntimeError(
            f"{cartella}: servono {K_GAL + K_PROBE} immagini, trovate {len(file)}"
        )
    gruppi = []
    if i < N_SINTETICI:
        gruppi.extend(("G", path) for path in file[:K_GAL])
    gruppi.extend(("P", path) for path in file[K_GAL : K_GAL + K_PROBE])
    for ruolo, path in gruppi:
        stat = path.stat()
        firma.update(
            f"{ruolo}\t{i}\t{path.relative_to(ROOT)}\t{stat.st_size}\t{stat.st_mtime_ns}\n".encode()
        )
        selezionati.append((ruolo, i, path))
firma_file = firma.hexdigest()
nomi = np.array([cartella.name for cartella in cartelle])
cache_valido = False
if CACHE_DIGIFACE.exists():
    cache = np.load(CACHE_DIGIFACE, allow_pickle=False)
    cache_valido = (
        str(cache["manifest_sha256"].item()) == firma_file
        and np.array_equal(cache["names"], nomi)
        and int(cache["n_galleria"].item()) == N_SINTETICI
        and int(cache["q_max"].item()) == QM
        and int(cache["k_galleria"].item()) == K_GAL
        and int(cache["k_probe"].item()) == K_PROBE
        and str(cache["modello"].item()) == "resnet100"
        and np.isclose(float(cache["scala"].item()), scala, rtol=0, atol=5e-9)
    )

if cache_valido:
    G_SINT = cache["G"].astype(np.int64)
    P_TUTTI = cache["P"].astype(np.int64)
    print(f"vettori DigiFace esatti da cache ({len(P_TUTTI)} identita')")
else:
    import imageio.v2 as imageio

    sys.path.insert(0, str(ROOT / "experiments" / "08_cnn"))
    import embedding as ec

    parti: list[np.ndarray] = []
    t0 = time.perf_counter()
    percorsi = [path for _, _, path in selezionati]
    for inizio in range(0, len(percorsi), 256):
        file = percorsi[inizio : inizio + 256]
        immagini = np.stack([imageio.imread(p)[..., :3] for p in file])
        parti.append(ec.embedding(immagini, "resnet100").astype(np.float32))
        print(
            f"embedding DigiFace {min(inizio + len(file), len(percorsi))}/{len(percorsi)}",
            flush=True,
        )
    embedding = np.vstack(parti)
    G, P = [], []
    cursore = 0
    for i in range(len(cartelle)):
        if i < N_SINTETICI:
            G.append(
                quantizza(normalizza(embedding[cursore : cursore + K_GAL].mean(0)))
            )
            cursore += K_GAL
        P.append(quantizza(normalizza(embedding[cursore : cursore + K_PROBE].mean(0))))
        cursore += K_PROBE
    G_SINT, P_TUTTI = np.array(G), np.array(P)
    np.savez_compressed(
        CACHE_DIGIFACE,
        G=G_SINT,
        P=P_TUTTI,
        names=nomi,
        scala=np.array(scala),
        q_max=np.array(QM),
        k_galleria=np.array(K_GAL),
        k_probe=np.array(K_PROBE),
        n_galleria=np.array(N_SINTETICI),
        modello=np.array("resnet100"),
        manifest_sha256=np.array(firma_file),
        manifest_entries=np.array(len(selezionati)),
        manifest_format=np.array(
            "sha256: ruolo\\tindice\\tpath_relativo\\tsize\\tmtime_ns\\n; G poi P per identita'"
        ),
    )
    print(f"cache esatto scritto in {time.perf_counter() - t0:.1f}s: {CACHE_DIGIFACE}")

P_SINT = P_TUTTI[:N_SINTETICI]
I_DEV = P_TUTTI[N_SINTETICI : N_SINTETICI + N_IMPOSTORI_DEV]
I_TEST = P_TUTTI[
    N_SINTETICI + N_IMPOSTORI_DEV : N_SINTETICI + N_IMPOSTORI_DEV + N_IMPOSTORI_TEST
]
# Tutto cio' che segue il tuning e' un holdout non-tuning. I primi 500 elementi di questo
# insieme sono anche il test primario: le due righe vanno riportate come annidate, non sommate.
I_HOLDOUT = P_TUTTI[N_SINTETICI + N_IMPOSTORI_DEV :]
BSQ_SINT = (G_SINT * G_SINT).sum(1)
S_DEV = BSQ_SINT[None, :] - 2 * (I_DEV @ G_SINT.T)
T_SINT = soglia_inclusiva(S_DEV.min(1))
S_GEN = BSQ_SINT[None, :] - 2 * (P_SINT @ G_SINT.T)
S_TEST = BSQ_SINT[None, :] - 2 * (I_TEST @ G_SINT.T)
S_HOLDOUT = BSQ_SINT[None, :] - 2 * (I_HOLDOUT @ G_SINT.T)
HIT_GEN = S_GEN <= T_SINT
HIT_TEST = S_TEST <= T_SINT
HIT_HOLDOUT = S_HOLDOUT <= T_SINT

ACC_DEV = int(np.count_nonzero(S_DEV.min(1) <= T_SINT))
ACC_TEST = int(np.count_nonzero(HIT_TEST.any(1)))
ACC_HOLDOUT = int(np.count_nonzero(HIT_HOLDOUT.any(1)))

METRICHE_SINT = {
    "dominio_valutazione": "clear_numpy",
    "metrica_primaria": "dir_at_fpir",
    "iscritti": N_SINTETICI,
    "impostori_tuning": N_IMPOSTORI_DEV,
    "impostori_test": N_IMPOSTORI_TEST,
    "impostori_holdout_non_tuning": len(I_HOLDOUT),
    "fpir_target": TARGET_FPIR,
    "fpir_tuning": round(float((S_DEV.min(1) <= T_SINT).mean()), 6),
    "fpir_test": round(float(HIT_TEST.any(1).mean()), 6),
    "fpir_holdout_non_tuning": round(float(HIT_HOLDOUT.any(1).mean()), 6),
    "accettati_tuning": ACC_DEV,
    "accettati_test": ACC_TEST,
    "accettati_holdout_non_tuning": ACC_HOLDOUT,
    "wilson_95_test": intervallo_wilson(ACC_TEST, len(I_TEST)),
    "wilson_95_holdout_non_tuning": intervallo_wilson(ACC_HOLDOUT, len(I_HOLDOUT)),
    "tar_any_match_diagnostica": round(float(HIT_GEN.any(1).mean()), 6),
    "dir": round(
        float(
            (
                (S_GEN.argmin(1) == np.arange(N_SINTETICI)) & (S_GEN.min(1) <= T_SINT)
            ).mean()
        ),
        6,
    ),
    "genuini_match_multipli": round(float((HIT_GEN.sum(1) > 1).mean()), 6),
    "impostori_match_multipli": round(float((HIT_TEST.sum(1) > 1).mean()), 6),
    "scene_sha256": sha_array(G_SINT, P_SINT, I_DEV, I_TEST),
    "holdout_sha256": sha_array(I_HOLDOUT),
    # Questo hash copre ruolo/path/size/mtime; `scene_sha256` sopra copre i vettori quantizzati
    # effettivamente usati ed e' l'ancora piu' forte per ripetere la scena.
    "file_metadata_manifest_sha256": firma_file,
}

T_DOMINIO = T_SINT if DOMINIO == "sintetico" else T_REALE
DOMINIO_SCORE_SINT = dominio_score_cauchy(G_SINT)
DOMINI_SCORE_REALI = {
    "per_split": domini_reali,
    "width_max": max(dominio["width"] for dominio in domini_reali),
    "lower_min": min(dominio["lower"] for dominio in domini_reali),
    "upper_max": max(dominio["upper"] for dominio in domini_reali),
}
osservato = max(
    osservato_reale,
    int(np.abs(S_DEV).max()),
    int(np.abs(S_GEN).max()),
    int(np.abs(S_HOLDOUT).max()),
)

cfg = {
    "dim": 512,
    "bit": BIT,
    "q_max": QM,
    "scala": round(scala, 8),
    "T": T_DOMINIO,
    "decisione": "exact_argmin_then_selected_threshold",
    "contratto_esatto": {
        "wire_version": 2,
        "probe_layout": 1,
        "score_delta_log": FULL_DELTA_LOG,
        "low_mod16_offset": LOW_MOD16_OFFSET,
        "low_mod16_delta_log": LOW_MOD16_DELTA_LOG,
        "output_mode": 2,
        "code_delta_log": CODE_DELTA_LOG,
        "codice": "0=rifiuto; i+1=identita_accettata",
        "un_solo_lwe": True,
        "score_bits": SCORE_BITS,
        "probe_norm2_max": PROBE_NORM2_MAX,
        "score_domain_width_max": SCORE_DOMAIN_WIDTH_MAX,
        "tie_break": "primo_indice_galleria",
        "selezione_soglia": "solo_del_vincitore_argmin",
    },
    "comparatore_fhe": {
        "stato": "argmin_esatto_bucket_bits_dual_glwe",
        "audit": (
            "experiments/14_pipeline_tfhe_rs/results/"
            "argmin_bucket_bits_exact_norm12_2026-09-01.md"
        ),
        "audit_low_bits": (
            "experiments/14_pipeline_tfhe_rs/results/score_mod16_lowbits_2026-09-01.md"
        ),
        "nota": (
            "argmin intero esatto, pareggio al primo indice e soglia privata selezionata "
            "soltanto per il vincitore; l'uscita e' un solo codice cifrato"
        ),
        "pbs_dipende_da_n": True,
    },
    "dominio_galleria": DOMINIO,
    "T_reale_vggface2": T_REALE,
    "T_sintetico_digiface": T_SINT,
    "k_galleria": K_GAL,
    "k_probe": K_PROBE,
    "capacita_galleria": N_CAPACITA,
    "n_galleria_demo": N_SINTETICI,
    "posti_riservati_webcam_demo": N_CAPACITA - N_SINTETICI,
    "modello": "resnet100",
    "calibrazione_sintetica": METRICHE_SINT,
    "calibrazione_reale": {
        "dominio_valutazione": "clear_numpy",
        "split": SEED_N,
        "impostori_tuning_per_split": N_IMPOSTORI_DEV,
        "impostori_test_per_split": N_IMPOSTORI_TEST,
        "soglie_per_split": soglie_reali,
        "metriche_con_soglia_per_split": {
            "metrica_primaria": "dir",
            "tar_any_match_diagnostica_media": round(float(np.mean(tar_reale)), 6),
            "dir_media": round(float(np.mean(dir_reale)), 6),
            "fpir_test_media": round(float(np.mean(fpir_reale)), 6),
            "genuini_match_multipli_media": round(float(np.mean(multipli_reali)), 6),
        },
        "metriche_con_T_mediana_fissa": METRICHE_REALI_T_FISSA,
    },
    "dominio_score_cauchy": {
        "formula": "norm2(g) +/- 2*ceil_sqrt(norm2(g)*1024)",
        "galleria_sintetica_base": DOMINIO_SCORE_SINT,
        "gallerie_reali_di_calibrazione": DOMINI_SCORE_REALI,
    },
    "score_abs_massimo_osservato": osservato,
}
(OUT / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
(OUT / "config.env").write_text(
    f"DIM={cfg['dim']}\nSOGLIA={cfg['T']}\n"
    "# Le scale del wire sono fisse nel binario: "
    f"score 2^{FULL_DELTA_LOG}, residui mod16 2^{LOW_MOD16_DELTA_LOG}, "
    f"codice 2^{CODE_DELTA_LOG}.\n"
)

print(f"scala {scala:.6f} (3 bit, valori in [-{QM}, {QM}])")
print(
    f"T reale mediana = {T_REALE}; a T fisso DIR {METRICHE_REALI_T_FISSA['dir']:.1%}, "
    f"TAR diagnostica {METRICHE_REALI_T_FISSA['tar_any_match_diagnostica']:.1%}, "
    f"FPIR test {METRICHE_REALI_T_FISSA['fpir_test']:.2%} "
    f"({METRICHE_REALI_T_FISSA['accettati_test']}/{METRICHE_REALI_T_FISSA['impostori_test']})"
)
print(
    f"T sintetico esatto = {T_SINT}; DIR {METRICHE_SINT['dir']:.1%}, "
    f"TAR diagnostica {METRICHE_SINT['tar_any_match_diagnostica']:.1%}, "
    f"FPIR test {METRICHE_SINT['fpir_test']:.2%}, "
    f"holdout non-tuning {METRICHE_SINT['fpir_holdout_non_tuning']:.2%}"
)
print(
    f"dominio Cauchy DigiFace = {DOMINIO_SCORE_SINT}; |score| osservato max = {osservato}"
)
print(f"scritto {OUT / 'config.json'}")
print(f"scritto {OUT / 'config.env'}")
