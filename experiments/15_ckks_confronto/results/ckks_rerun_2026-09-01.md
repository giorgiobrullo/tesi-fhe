# Rerun CKKS del 1 settembre 2026

Questo e' un controllo di riproducibilita' locale delle due implementazioni interne, non un
benchmark finale TFHE-vs-CKKS. La macchina non era quieta; per questo i tempi sotto sono
**engineering measurements** e non misure comparabili fra schemi.

## Stato riprodotto

- branch: `thesis-evidence-audit-2026-09`
- commit di base: `6611c185adc9a658a075519b4316386f0bb48656`
- host: Apple M4 Max, 16 CPU logiche, 64 GiB, macOS 27.0 build 26A5421a
- Python 3.12.11; TenSEAL 0.3.17 (`tenseal.sealapi`, Microsoft SEAL)
- `ckks_varco.py` SHA-256:
  `7215355ac03bb4372780cec4f2324713b837f5792e76cd1981f1f8c39fad29de`
- `ckks_packing_forte.py` SHA-256 dopo la correzione descritta sotto:
  `f0f8cd87768bc4fd11273b70e61243ae28149fa96ef7dfd29e60ae32bd6feaa4`
- scena baseline SHA-256:
  `b7814dfbb6df34361fe275870ffccb4e61d56053f63e64c622f7edbf00b0fe1d`
- scena packing SHA-256:
  `f20ddffc41aec984b3684a9006031547dd11e704288c0789e1b926338575bf5e`

## Baseline a blocchi, configurazione minima

Comando:

```sh
/usr/bin/time -l env CFG_FHE=0 Q_PROBE=7 \
  OUTPUT_CSV=experiments/15_ckks_confronto/results/ckks_varco_cfg0_n4_2026-09-01.csv \
  uv run python experiments/15_ckks_confronto/ckks_varco.py 4
```

Il run usa `poly=16384`, nove livelli, `g_1^2 f_1`, quattro probe di correttezza bilanciati
(due genuini e due impostori) e quattro probe per i tempi a ogni N. Il range analitico sul dominio
q=7 e' 16.764, contro 3.562 osservato nei probe della scena. Allargando il range, la banda ambigua
del segno diventa `d in [-1381, 1382]`.

| N | distanza media | soglia media | totale | errore max score |
|---:|---:|---:|---:|---:|
| 8 | 0,1159 s | 0,048 s | 0,1639 s | 0,0177 |
| 16 | 0,1166 s | 0,047 s | 0,1636 s | 0,1354 |
| 32 | 0,2365 s | 0,056 s | 0,2925 s | 0,1354 |
| 64 | 0,4718 s | 0,050 s | 0,5218 s | 0,1354 |
| 128 | 0,9969 s | 0,048 s | 1,0449 s | 0,1354 |

Evidenza di correttezza a N=128: 0 discrepanze CKKS/chiaro su 512 confronti; un genuino su due
ha un unico match corretto e nessuno dei due impostori e' accettato. Il dato `1/2` non e' un errore
del comparatore (che concorda col chiaro), ma mostra che questo minuscolo campione non misura una
DIR affidabile.

- keygen + Galois: 1,04 s (0,22 + 0,82 s nel log)
- processo completo: 14,56 s wall, 14,30 s user, 1,99 s system
- picco RSS: 716.128.256 byte (682,95 MiB); zero swap
- CSV SHA-256:
  `03d9e7fa71fc1f6a1c7ecd5680c9419b4eb88ce666df091af6648b79b84cebf1`

## Packing ibrido a N=128

Comando:

```sh
/usr/bin/time -l env Q_PROBE=3 \
  OUTPUT_CSV=experiments/15_ckks_confronto/results/ckks_packing_forte_n128_2026-09-01.csv \
  uv run python experiments/15_ckks_confronto/ckks_packing_forte.py \
  experiments/14_pipeline_tfhe_rs/results/scena_reale_1024_q3.txt 128
```

La scena ha N massimo 1.024, ma questo run valuta soltanto i primi 128 template. Il range analitico
q=3 e' 3.137, contro 770 osservato nei probe della scena.

| layout | rotazioni effettive | distanza media, 3 ripetizioni | Galois key set | errore max score |
|---|---:|---:|---:|---:|
| blocchi | 39 | 3,583 s | 1.937 MiB | 0,0011 |
| ibrido | 10 | 0,966 s | 1.615 MiB | 0,0011 |

Sul solo score di un probe il layout ibrido e' 3,71 volte piu' veloce del layout a blocchi.
Le dimensioni sono serializzazioni di key set separati, non dell'unione usata per eseguire le due
varianti nello stesso processo.

- processo completo, incluso setup e tre keygen Galois: 57,68 s wall, 52,56 s user, 8,41 s system
- picco RSS: 6.633.488.384 byte (6,178 GiB); zero swap
- load average prima: 7,65 / 11,42 / 16,64; dopo: 8,77 / 11,03 / 16,11
- CSV SHA-256:
  `d44a72d659e615d7126cbb7001283c18617b7d5afe0e4b74d903878c1de446b6`

## Errore riprodotto e correzione

Il primo tentativo del packing si e' fermato durante la misura del key set ibrido:

```text
ValueError: Galois element is not valid
```

TenSEAL 0.3.17 espone due overload indistinguibili come `list[int]`: elementi di Galois unsigned
e passi di rotazione signed. Una lista di soli Python `int` positivi sceglieva l'overload unsigned;
le liste legacy funzionavano accidentalmente perche' contenevano anche rotazioni negative. Un test
isolato ha riprodotto `[2]` fallito e `[np.int64(2)]` riuscito. La correzione minima converte i passi
in `np.int64` dentro `dimensione_galois`; non cambia le rotazioni o il percorso cronometrato.

Il tentativo fallito e' durato 24,91 s, ha raggiunto 6.521.552.896 byte RSS (6,074 GiB), non ha
usato swap e non ha prodotto CSV.

Prima del rerun finale entrambi gli script sono stati resi fail-fast sul dominio dichiarato:
`Q_PROBE` deve coprire il massimo coefficiente osservato nei probe. Il packing rifiuta inoltre N
non potenza di due, oltre la scena o incompatibile con `slots`, `dim`, `W` e `rho`. Sono stati
provati i fallimenti `Q_PROBE=2` sulle scene q=7/q=3 e `N=100`; tutti avvengono prima del keygen.

## Limiti

- I processi utente e una VM Docker erano attivi; il carico iniziale era elevato e variabile.
- La baseline copre solo la configurazione polinomiale meno profonda e quattro probe di
  correttezza; non sostituisce il protocollo held-out.
- Il packing ibrido misura un solo probe e tre ripetizioni, solo a N=128.
- `ckks_packing_forte.py` misura le distanze, non integra segno, decisione open-set, cifratura,
  trasferimenti o decrypt nel tempo online riportato.
- I due run usano scene e domini q diversi; i loro tempi non sono un confronto diretto.
- Sono misurate le rotation/Galois keys del packing. Public key, relinearization key e ciphertext
  non sono serializzati da questi script e quindi non hanno una misura di banda in questo rerun.
