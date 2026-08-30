# Esperimento 14 — il pipeline in tfhe-rs coi parametri standard: chiudere il design di luglio

Obiettivo (incontro di luglio, findings F35): selezione sul server a N = 64 e 128 sotto i 10 s,
scritta con le funzioni di tfhe-rs, uscita solo esito (mai la distanza). Tutto misurato su
Apple M4 Max (12P+4E, 16 thread rayon), tfhe-rs 0.11.3, `--release`, `target-cpu=native`,
parametri **standard a 128 bit** (`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`: n=879,
N=2048, k=1; multi-bit group 3 dove indicato). Findings F36–F38.

## 0. In chiaro prima: quanti bit del punteggio servono (`precisione_punteggio.py`, F36)

Embedding ResNet100 su VGGFace2, 4 bit, punteggio ⌊(s+C)/2^t⌋ troncato ai k bit alti, 20 scene.
La DIR@FPIR=1% non si muove fino a 4 bit; è la FPIR effettiva a degradare per i pareggi alla
soglia (8 bit: 1,1%; 5 bit: 2,4%; 4 bit: 8-54%). **Punto operativo: 8 bit** → `FheUint8`.

## 1. La selezione radix (`selezione.rs`, F38)

Punteggi casuali già in forma radix, argmin + soglia sul vincitore, 16 thread:

| param | N | seq-F32 (lt+min+select) | seq (lt+2 select) | **torneo** (livelli paralleli) | +soglia |
|---|---|---|---|---|---|
| def/u8 | 8 | 0,82 s | 0,61 s | **0,36 s** | 0,029 s |
| def/u8 | 64 | 7,36 s | 5,50 s | **2,32 s** | 0,028 s |
| def/u8 | 128 | 14,57 s | 10,81 s | **4,69 s** | 0,029 s |
| def/u16 | 8 | 1,12 s | 0,82 s | 0,57 s | 0,029 s |
| def/u16 | 64 | 10,23 s | 7,65 s | 4,55 s | 0,028 s |
| def/u16 | 128 | 20,78 s | 14,98 s | 9,07 s | 0,029 s |
| mb3/u8 | 128 | 8,27 s | 6,59 s | 4,84 s | 0,012 s |
| mb3/u16 | 128 | 14,88 s | 11,56 s | 9,86 s | 0,013 s |

(tabella completa in `results/selezione_16thread.txt`). Single-thread (`selezione_1thread.txt`):

| param | N | seq-F32 | seq | torneo | +soglia |
|---|---|---|---|---|---|
| def/u8 | 8 | 2,86 s | 2,43 s | 2,36 s | 0,041 s |
| def/u8 | 128 | 55,70 s | 48,20 s | 46,74 s | 0,040 s |
| def/u16 | 128 | 112,56 s | 94,18 s | 90,45 s | 0,070 s |
| mb3/u8 | 128 | 24,49 s | 21,09 s | 20,71 s | 0,018 s |
| mb3/u16 | 128 | 48,11 s | 40,04 s | 38,53 s | 0,030 s |

Su un thread il torneo non guadagna nulla (stesso lavoro, N−1 confronti) e il multi-bit vale
2,3× da solo; è la combinazione 16 thread + torneo a portare i 48 s della catena a 4,7 s (~10×).
Tutti gli esiti verificati contro il chiaro. Il torneo `FheUint8` sta nel target del prof (2,3 s
a N=64, 4,7 s a N=128), **ma presuppone i punteggi in forma radix**, cioè il ponte dal punteggio
leveled che coi parametri standard non c'è (F34).

## 2. Il varco senza ponte (`varco_leveled.rs`, F37)

Prodotto scalare leveled su LWE grezzi (0 PBS) + **un PBS di segno per iscritto** contro la
soglia, tutti in parallelo (profondità 1). Uscita: N bit (one-hot), oppure compatta: conteggio +
indice in binario (log N somme leveled). Scena reale (`esporta_dati.py`: ResNet100, VGGFace2,
4 bit, 128 iscritti, 64 probe genuini + 64 impostori, T al quantile 1% di 2000 impostori).

| N | dot (leveled) | KS+PBS ×N (16 thread) | **totale/query** | per PBS per thread |
|---|---|---|---|---|
| 8 | 0,001 s | 0,016 s | **0,017 s** | 32 ms |
| 16 | 0,002 s | 0,027 s | **0,029 s** | 27 ms |
| 32 | 0,002 s | 0,047 s | **0,049 s** | 23 ms |
| 64 | 0,005 s | 0,089 s | **0,094 s** | 22 ms |
| 128 | 0,007 s | 0,170 s | **0,177 s** | 21 ms |

Esattezza: **0 discrepanze su 31.744 confronti** cifrato/chiaro; esito per probe identico al
chiaro (58/64 genuini riconosciuti = 90,6%, 0/64 impostori accettati); uscita compatta corretta
128/128 a ogni N (0,2 ms).

Single-thread (`RAYON_NUM_THREADS=1`): il PBS costa 13,5-13,9 ms l'uno (meno che a 16 thread, dove
i thread si contendono cache e E-core), e il totale scala lineare in N:

| N | 8 | 16 | 32 | 64 | 128 |
|---|---|---|---|---|---|
| totale/query, 1 thread | 0,114 s | 0,225 s | 0,446 s | 0,887 s | **1,764 s** |
| totale/query, 16 thread | 0,017 s | 0,029 s | 0,049 s | 0,094 s | **0,177 s** |

Il parallelismo dei confronti indipendenti vale ~10× (12 P-core + 4 E-core).

Scala (`scena_reale_1024.txt`, `varco_leveled_16thread_1024.txt`, F43): N=256 0,34 s, 512 0,70 s,
**1024 1,41 s**, 0 discrepanze su 131.072 confronti, esito per probe come in chiaro (96,9%).
Uscita compatta **a blocchi di 64** (conteggio + indice locale): 128/128 a ogni N; con le somme su
tutti gli N sbagliava 8/128 a N=1024 (rumore ~√N). PBS multi-bit (`--multibit`, `--mb-threads K`):
0,198 s (7 thread interni) e 0,210 s (1) contro 0,177 s del classico: nessun guadagno
(`varco_leveled_16thread_multibit.txt`).

### La banda di sfocatura (`banda_soglia.rs`, `effetto_banda.py`)

Il PBS di segno decide dopo il modulus switch a 2N, che aggiunge un errore ~√(n/24)·q/2N =
2^54,6. Misurato a cavallo di T (400 prove per d = s−T ∈ [−48, 48]): P(match | d) è una sigmoide
con σ ≈ 12 unità di punteggio a Δ_s = 2^51 (quella della scena reale; 6,5 a 2^52, 25 a 2^50),
esattamente 2^54,6 / 2^51. Sui dati reali non scatta: nelle 20 scene le coppie (probe, iscritto)
entro ±24 unità da T sono lo 0,003-0,006%, e simulando la sfocatura su tutte le decisioni la DIR
resta identica (92,9 / 92,9 / 92,3% a N = 64 / 128 / 1000) con FPIR 0,97-0,99% contro 1,00%.

## 3. La CLI a tre ruoli (`varco.rs`, F41)

`varco keygen <dir>` · `varco encrypt <dir> probe.txt probe.ct` · `varco server <dir> galleria.txt
probe.ct esito.ct` · `varco decrypt <dir> esito.ct`. Probe come un solo GLWE (encoding
polinomiale): **32.800 byte** invece di 8,4 MB; esito 229 KB (a blocchi di 64); chiavi 23 KB (client) e 130 MB
(server). Server 0,18 s a N=128 (16 thread). Esempio in `results/e2e/` (galleria.txt = scena
reale con LOG_DELTA=50, cioè |s−T| < 2^13 dichiarato): genuino → `{"conteggio": 1, "indice": 104}`,
impostore → `{"conteggio": 0}`.

## 4. Cosa rivela il bit (`attacco_oracolo.py`, F40)

Oracolo di appartenenza simulato in chiaro: con la distanza l'embedding esce esatto in 513 query;
col solo bit servono ~30.000 query per coseno 0,999 (1.000 per un vettore accettato), e solo
partendo da un probe già accettato (una foto dell'iscritto); da impostori o vettori casuali
20.000 query non producono un'accettazione. Mettere ‖v‖² nel punteggio (palla invece di
semispazio) non aiuta: coseno 0,995 in 10.000 query, perché l'attaccante conosce la norma del
proprio vettore e il punteggio resta lineare nelle incognite. Contromisura: rate limiting.

## Riprodurre

```
uv run python precisione_punteggio.py      # F36, ~30 s
uv run python esporta_dati.py              # scena reale per i binari Rust
cargo run --release --bin selezione        # F38, ~4 min a 16 thread
cargo run --release --bin varco_leveled    # F37, ~1 min  (args: [scena] [N_min] [--multibit] [--mb-threads K])
uv run python esporta_dati.py 1024 && cargo run --release --bin varco_leveled -- results/scena_reale_1024.txt 256   # F43, ~6 min
cargo run --release --bin banda_soglia     # banda, ~3 min
uv run python effetto_banda.py             # effetto della banda, ~1 min
RAYON_NUM_THREADS=1 cargo run --release --bin <bin>   # versione seriale
uv run python attacco_oracolo.py                # F40, ~20 s
cargo run --release --bin varco -- keygen results/e2e/chiavi   # poi encrypt/server/decrypt (F41)
```

Su macOS beta, se il linker fallisce, anteporre il wrapper di `ld` (`PATH=/tmp/ldfix:$PATH`).
