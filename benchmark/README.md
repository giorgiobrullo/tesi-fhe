# Benchmark duri -- tecniche già fatte su set più difficili di LFW

Cartella trasversale: misura come reggono le tecniche che
abbiamo già, cioè **PCA/eigenfaces** (gradino 05) e **descrittori locali LBP/HOG**
(gradino 07), su benchmark più duri di LFW, prima di salire alla CNN.

## I set

A buona risoluzione (112×112 allineati), formato InsightFace `.bin`, protocollo nativo
di **verifica 1:1** (6.000 coppie, 10-fold, soglia migliore):

| set | difficoltà |
|---|---|
| `lfw` | baseline (facile) |
| `cplfw` | **cross-posa** (il più duro dei pair-set) |
| `cfp_fp` | **frontale ↔ profilo** |

## Come procurare i dati

Download diretto dal bundle HuggingFace (pubblico, ~60-76 MB ciascuno) in
`datasets/bench/` (cartella gitignorata):

```bash
mkdir -p datasets/bench
for f in lfw cplfw cfp_fp; do
  curl -L -o "datasets/bench/$f.bin" \
    "https://huggingface.co/datasets/gaunernst/face-recognition-eval/resolve/main/$f.bin"
done
```

## Esecuzione

```bash
uv run python benchmark/verifica.py
```

Per ogni set e tecnica: accuratezza di verifica 1:1 (10-fold). Output in
`results/verifica_duri.csv`. (I risultati e la lettura sono in `findings.md`.)

## Due protocolli, due script

| script | protocollo | set | cosa misura |
|---|---|---|---|
| `verifica.py` | **verifica 1:1** (coppie) | LFW, CPLFW, CFP-FP (`.bin`) | degrado facile→duro su posa/profilo |
| `identificazione_1n.py` | **identificazione 1:N open-set** (il varco) | DigiFace, VGGFace2 | Rank-1 + DIR@FPIR (identifica i noti *e* rifiuta gli ignoti) |

`verifica.py` è il protocollo nativo dei benchmark `.bin` (confrontabile con la
letteratura). `identificazione_1n.py` è il protocollo del **nostro** sistema:
costruisce lo split open-set con `core.dataset.split_openset` e riporta il `DIR@FPIR`,
il numero che conta per il controllo-accessi (vedi `findings.md` F9, F10).
