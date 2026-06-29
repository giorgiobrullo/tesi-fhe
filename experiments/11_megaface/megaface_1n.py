"""1:N open-set a scala MegaFace: il test che usa la letteratura (HERS & co.: 1M distrattori).

Idea (semplificata, niente FaceScrub): le **probe** sono identità note che già abbiamo e
allineate (LFW / VGGFace2 reali); i **distrattori** sono volti MegaFace (fino a 1M) che
"sporcano" la galleria. Misuriamo Rank-1 e DIR@FPIR al crescere dei distrattori
(10 → 100 → 1k → 10k → 100k → 1M): è la curva 1:N a scala reale, confrontabile con la
letteratura.

STATO: il PROTOCOLLO (sotto) è pronto e indipendente dal formato, opera su embedding.
Manca solo il LOADER MegaFace (`carica_distrattori_megaface`), che scriverò quando i dati
sono su disco (il formato dipende dal mirror: crop allineati vs immagini grezze da allineare).
MegaFace è dietro auth UW (registrazione), vedi README; una volta scaricato in
datasets/megaface/, si riempie il loader e si lancia.
"""
import sys, pathlib
import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "08_cnn"))


# ---------------------------------------------------------------------------
# PROTOCOLLO (pronto): opera su embedding L2-normalizzati, indipendente dal dataset.
# ---------------------------------------------------------------------------
def rank1_dir_con_distrattori(E_gal, y_gal, E_probe, y_probe, E_distr, n_distr,
                              fpir=0.01, seed=0):
    """1:N open-set con `n_distr` distrattori aggiunti alla galleria.

    E_gal/y_gal : un embedding iscritto per identità nota (galleria "vera").
    E_probe/y_probe : query delle identità note (alcune note = match attesi).
    E_distr : pool di distrattori (volti MegaFace, identità NON in galleria).
    Ritorna (rank1, dir_at_fpir): rank1 = il nearest è l'identità giusta;
    dir_at_fpir = come rank1 ma con soglia tarata perché solo `fpir` dei probe-impostori passi.
    """
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(E_distr), size=min(n_distr, len(E_distr)), replace=False)
    D = E_distr[idx]                                   # distrattori campionati
    G = np.concatenate([E_gal, D], axis=0)             # galleria = noti + distrattori
    yG = np.concatenate([y_gal, np.full(len(D), -1)])  # -1 = distrattore (mai un match valido)

    # distanza euclidea² (embedding L2-norm, monotona col coseno)
    # per ogni probe: nearest neighbor in G
    sim = E_probe @ G.T                                # coseno (più grande = più vicino)
    nn = sim.argmax(axis=1)
    nn_sim = sim[np.arange(len(E_probe)), nn]
    nn_id = yG[nn]

    rank1 = float(np.mean(nn_id == y_probe))           # closed-set: il più vicino è giusto?

    # open-set DIR@FPIR: soglia tale che solo `fpir` degli impostori (probe la cui vera
    # identità NON è in galleria) superi. Qui tutte le probe sono note, quindi usiamo i distrattori
    # come "impostori" campionando alcune probe-distrattore se disponibili; in mancanza,
    # riportiamo rank1 con soglia sul nn_sim dei match corretti.
    corretti = nn_id == y_probe
    if corretti.sum() == 0:
        return rank1, 0.0
    # soglia al quantile (1-fpir) delle similarità dei NON-corretti (proxy impostore)
    impostori_sim = nn_sim[~corretti]
    if len(impostori_sim) > 0:
        soglia = np.quantile(impostori_sim, 1 - fpir)
    else:
        soglia = -np.inf
    dir_fpir = float(np.mean(corretti & (nn_sim >= soglia)))
    return rank1, dir_fpir


def sweep(E_gal, y_gal, E_probe, y_probe, E_distr,
          distrattori=(10, 100, 1000, 10000, 100000, 1000000)):
    print(f"{'distrattori':>12} | {'Rank-1':>7} | {'DIR@FPIR1%':>10}")
    print("-" * 38)
    righe = []
    for n in distrattori:
        if n > len(E_distr):
            print(f"{n:>12} | (solo {len(E_distr)} distrattori disponibili), stop")
            break
        r1, dir1 = rank1_dir_con_distrattori(E_gal, y_gal, E_probe, y_probe, E_distr, n)
        print(f"{n:>12} | {r1:>6.1%} | {dir1:>9.1%}")
        righe.append({"distrattori": n, "rank1": round(r1, 4), "dir_fpir1": round(dir1, 4)})
    return righe


# ---------------------------------------------------------------------------
# LOADER MegaFace, DA COMPLETARE quando i dati sono su disco.
# ---------------------------------------------------------------------------
def carica_distrattori_megaface(livello="mobilefacenet", max_n=None):
    """Carica/allinea/embedda i distrattori MegaFace -> (N,512) L2-norm.

    DA SCRIVERE in base al formato effettivo in datasets/megaface/:
      - se crop 112x112 già allineati: embedding diretto (08_cnn/embedding.embedding).
      - se immagini grezze: detect+align (08_cnn/embedding.embedding_allineato), poi embed.
    Conviene cache-are gli embedding (datasets/megaface/_emb_<livello>.npz), è il pezzo lento.
    """
    raise NotImplementedError(
        "Loader MegaFace da completare: mettere i dati in datasets/megaface/ e adattare al formato."
    )


if __name__ == "__main__":
    print(__doc__)
    print(">>> Protocollo pronto. Manca il loader MegaFace (servono i dati + credenziali UW).")
