# Tesi-FHE: riconoscimento facciale privacy-preserving con FHE

Studio di fattibilità e caratterizzazione del costo di un riconoscimento facciale 1:N in cui
il client cifra un volto, il server lo confronta con una galleria senza mai vedere il volto né
l'esito, e solo il client decifra il risultato. Costruito su
[Zama Concrete](https://docs.zama.ai/concrete) (TFHE, aritmetica intera, modello a circuito).

## Il setup (Mondo 1)

Il client estrae l'embedding del volto in chiaro, lo quantizza, lo cifra e lo manda al server.
Il server tiene la galleria in chiaro e calcola le distanze sul cifrato (`‖g‖² − 2·g·a`, cioè
cifrato×chiaro, quindi senza bootstrapping sul prodotto scalare); restituisce i punteggi
cifrati, oppure un solo bit se basta la soglia. Solo il client decifra. Il probe è cifrato
sotto la chiave del client; la galleria sta in chiaro sul server, che è honest-but-curious sul
volto. Cifrare anche la galleria (Mondo 2) è la versione più difficile, lasciata come lavoro
futuro.

## I due filoni

### Riconoscimento

Dalle tecniche geometriche (PCA, eigenfaces) ai descrittori hand-crafted (LBP, HOG) alle CNN
pre-addestrate (MobileFaceNet, ResNet50, ResNet100, AdaFace), confrontate prima in verifica
1:1 su benchmark via via più duri, poi in identificazione 1:N open-set (metrica DIR@FPIR). Le
tecniche semplici crollano al livello del caso sui volti difficili, le CNN reggono. A scala,
sui volti reali il sistema tiene circa il 95% fino a migliaia di iscritti; sul sintetico cala,
e il divario reale-vs-sintetico (circa 15 punti) conta più della scelta del modello.

### Costo FHE

Il collo di bottiglia è la sola selezione cifrata, cioè l'argmin o la soglia. Il prodotto
scalare è gratis (galleria in chiaro, 0 bootstrap) e il lavoro del client (embedding, cifra,
decifra) è classe-millisecondi. L'argmin cifrato sul server è classe-minuti (a 512 dimensioni
circa 455 s a N=8), la soglia circa 12 s. Il limite di velocità è l'API ad alto livello di
Concrete-python, che compila l'argmin in molti bootstrap: lo stesso argmin scritto a basso
livello in tfhe-rs è circa 100 volte più veloce, e per la scala CKKS col packing SIMD arriva a
milioni di template sotto il secondo (evitando o approssimando il confronto cifrato). Numeri e
ragionamenti in `findings.md`; lo stato dell'arte in `letteratura.md`.

## Struttura

- `core/`: il motore condiviso, con i circuiti FHE (`matching.py`), il plumbing client/server,
  la quantizzazione, il caricamento dataset e la metrica 1:N (`metriche.py`, DIR@FPIR): circuiti
  e metrica hanno un'unica definizione, così prototipo e benchmark non possono divergere.
- `experiments/NN_…/`: la scaletta numerata, dalle fondamenta FHE (00–04) ai gradini di
  riconoscimento (05 PCA, 06 argmin e soglia, 07 descrittori locali, 08 CNN) fino agli
  approfondimenti sul costo cifrato (09 GPU, 10 struttura dell'argmin, 11 MegaFace, 13
  head-to-head con tfhe-rs). Ogni gradino importa da `core/` e porta il suo `costo.py`.
- `benchmark/`: la valutazione trasversale sui dataset grandi, con la verifica 1:1
  (`verifica.py`), l'identificazione 1:N a scala (`scaling_*.py`, `identificazione_1n.py`), il
  varco a soglia su volti reali (`soglia_reale.py`) e il breakdown end-to-end di una query
  (`breakdown_query.py`).
- `datasets/`: i dati scaricati (gitignorato): i `.bin` dei benchmark, DigiFace-1M, VGGFace2.
  Rotte di download in `docs/benchmark_dataset.md`.
- `findings.md`: il diario dei risultati, F0–F33.
- `letteratura.md`: lo stato dell'arte del riconoscimento biometrico cifrato 1:N.
- `docs/`: note di riferimento su dataset e modelli di embedding.

## Setup ed esecuzione

Gestito con [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run python experiments/00_hello_concrete.py          # hello-world FHE: somma cifrata
uv run python experiments/05_pca/demo.py [olivetti|lfw]  # prototipo end-to-end cifrato
```

Ogni script è eseguibile da solo. Su macOS beta la compilazione di Concrete può richiedere un
piccolo wrapper di `ld` per il linker (vedi le note negli script che compilano circuiti).
