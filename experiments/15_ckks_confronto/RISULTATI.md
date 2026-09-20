# Esperimento 15 - il varco in CKKS: quanto vale lo schema (F39)

Stesso varco di `experiments/14` (probe cifrato, galleria in chiaro, N iscritti a 512 dim, esito
"s_i ≤ T" per iscritto), riscritto in **CKKS** con Microsoft SEAL (via `tenseal.sealapi`),
parametri a 128 bit, single-thread. Scena reale di `experiments/14/results/scena_reale.txt`.

Packing: probe replicato R = slot/512 volte in un cifrato; per blocco di R iscritti 1 mult_plain +
9 rotazioni (rotate-and-sum) + 1 maschera + 1 rotazione di compattazione → tutti gli N punteggi
in un cifrato. Soglia: segno di (T+½−s)/RANGE come polinomio composto g_n^{d_g}∘f_n^{d_f}
(Cheon–Kim–Kim, ASIACRYPT 2020), una valutazione per tutti gli N.

| poly, livelli | segno | banda (unità) | N=8 | N=64 | N=128 | distanze N=128 | segno |
|---|---|---|---|---|---|---|---|
| 16384, 9 | g₁²f₁ | ±293 | 0,17 s | 0,53 s | 1,01 s | 0,96 s (8 blocchi) | 0,05 s |
| 32768, 13 | g₁⁴f₁ | ±67 | 0,71 s | 1,19 s | 2,14 s | 1,88 s (4 blocchi) | 0,26 s |
| 32768, 19 | g₁⁶f₁² | ±10 | 1,63 s | 2,51 s | 4,25 s | 3,54 s (4 blocchi) | 0,71 s |
| 32768, 19 | g₃³f₃ | ±9 | 1,83 s | 2,72 s | 4,44 s | 3,46 s | 0,98 s |

Esattezza: 0 discrepanze su 4096 confronti (32 probe, N=128) in ogni configurazione; errore CKKS
sui punteggi interi ≤ 0,03. Dettagli e letture in `findings.md` F39; output grezzo in
`results/ckks_varco.txt`, `results/ckks_varco.csv`.

Riprodurre: `uv run python ckks_varco.py [n_probe]` (~15 min con 32 probe).
