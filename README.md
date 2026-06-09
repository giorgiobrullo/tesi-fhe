# Tesi-FHE -- Riconoscimento facciale che preserva la privacy con FHE

Un sistema di riconoscimento facciale in cui il client cifra un
volto, il server lo confronta con un database **senza mai vedere il volto né
l'esito**, e solo il client decifra il risultato. Costruito su
[Zama Concrete](https://docs.zama.ai/concrete) (crittografia completamente
omomorfica, basata su TFHE, aritmetica intera, modello a circuito).

## I due filoni

1. **FHE (Concrete)** — capire il modello a circuito e i suoi vincoli (input
   interi a dimensione fissa), far girare il matching su dati cifrati e
   **misurare i tempi** (il costo che conta è la *valutazione* FHE per ogni query).
2. **Riconoscimento facciale (ML)** — costruire un dataset di volti (split 80/20,
   foto diverse della stessa persona tra galleria e probe), implementare le
   tecniche dalla più semplice alla più complessa, ottenere accuratezze di base.

Convergenza: il client calcola l'embedding in chiaro, il server calcola la
distanza cifrata contro la galleria — la *stessa* operazione vive su entrambi i
filoni.

## Implementazione: cosa gira dove

Il sistema separa nettamente i due ruoli:

| | client | server |
|---|---|---|
| **ha** | chiave segreta, base PCA, elenco dei nomi iscritti | galleria in chiaro (embedding + nomi), chiave di valutazione, circuito |
| **fa** | PCA + quantizza + **cifra** (in chiaro); poi **decifra** e sceglie il più vicino | calcola i punteggi di distanza sul cifrato |

- **Sotto FHE (sul server, alla cieca):** solo il *matching*, cioè i punteggi di
  distanza `‖b‖² − 2·a·b` per ogni faccia della galleria. Sono tutte
  moltiplicazioni **cifrato×chiaro** (probe cifrato × galleria in chiaro), quindi
  **nessun PBS / bootstrapping**.
- **In chiaro sul client:** l'embedding PCA del volto, la quantizzazione, la
  cifratura e — ricevuti i punteggi cifrati — la decifratura e la scelta del più
  vicino.
- **In chiaro sul server (precalcolato, fuori dal circuito):** `‖b‖²` per ogni
  faccia (dipende solo dalla galleria, nessun cifrato coinvolto).
- **L'argmin lo fa il client, non il server.** Il server restituisce *tutti* i
  punteggi cifrati (un vettore di N, uno per persona iscritta); il client li
  decifra e prende il minimo. Così il server non impara mai l'esito e non serve
  alcun confronto cifrato (di nuovo niente bootstrapping). Il costo è di
  comunicazione (N punteggi cifrati) e di privacy (il client vede la similarità
  con tutta la galleria, non solo col match).

Modello di sicurezza: il probe è cifrato sotto la chiave del **client**; la
**galleria sta in chiaro sul server** (è il server a iscrivere le persone). Il
server è *honest-but-curious* sul volto, mentre resta aperto quanto considerare *trusted*
il client visto che cambierebbe le ottimizzazioni disponibili.

## I livelli delle tecniche (dal più semplice, che ~segue il costo FHE)

| Livello | Tecnica | Adatta a FHE? |
|---|---|---|
| Geometriche / lineari | **PCA** (eigenfaces) + distanza euclidea, LDA | Ottima — proiezione lineare + una quadratica |
| Descrittori locali | LBP (χ²), HOG | Più difficile — χ² ha una divisione |
| CNN | MobileNet/ShuffleNet (poco profonde) → ResNet/InsightFace (profonde) | Costose — le attivazioni non lineari richiedono bootstrapping |
| Transformer | — | Fuori scope? |

**Primo prototipo cifrato end-to-end = PCA + distanza euclidea al quadrato.**

## Setup

Gestito con [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                   # installa le dipendenze da pyproject.toml
uv run python experiments/00_hello_concrete.py
```

## Come si esegue

Esperimenti FHE, dal più semplice al matching (ognuno è eseguibile da solo):

```bash
uv run python experiments/00_hello_concrete.py     # hello-world: somma cifrata
uv run python experiments/01_op_con_pbs.py         # operazioni economiche vs care (PBS)
uv run python experiments/02_distanza_quadrata.py  # distanza ‖a−b‖² su vettori cifrati
uv run python experiments/03_galleria_in_chiaro.py # risparmio della formula espansa (conteggio PBS)
uv run python experiments/04_client_server.py      # separazione client/server (deploy + serializzazione)
```

Prototipo end-to-end (riconoscimento cifrato):

```bash
uv run python experiments/05_prototipo_e2e/demo.py [olivetti|lfw]
```

(default: `olivetti`; `lfw` è più grande e realistico, scarica ~200 MB.)

## Stato

Per ispezionare il progetto:
- **`experiments/05_prototipo_e2e/`** — il prototipo end-to-end; il suo README ha
  l'architettura (diagramma client/server) e il ruolo di ogni file.
- **`experiments/00`–`04`** — i concetti costruiti passo passo (hello world → PBS →
  distanza → galleria in chiaro → separazione client/server).
- **`findings.md`** — risultati e conclusioni distillate (F0–F5 + prossimi passi).
