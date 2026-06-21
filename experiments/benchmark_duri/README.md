# Benchmark duri — tecniche già fatte su set più difficili di LFW

Cartella **trasversale** (non un gradino nuovo): misura come reggono le tecniche che
abbiamo già — **PCA/eigenfaces** (gradino 05) e **descrittori locali LBP/HOG**
(gradino 07) — su benchmark più duri di LFW, prima di salire alla CNN.

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
uv run python experiments/benchmark_duri/verifica.py
```

Per ogni set e tecnica: accuratezza di verifica 1:1 (10-fold). Output in
`results/verifica_duri.csv`. (I risultati e la lettura sono in `findings.md`.)

## Nota

È **verifica 1:1** (stessa persona sì/no), non identificazione 1:N come i demo dei
gradini. Serve perché è il protocollo nativo di questi benchmark e dà il confronto
pulito del degrado LFW → set duri. L'1:N open-set vero verrà su VGGFace2/DigiFace con
`core.dataset.split_openset` (gradino 08).
