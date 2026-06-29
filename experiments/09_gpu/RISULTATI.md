# Risultati — argmin cifrato su GPU (Tesla T4, Google Colab)

Circuito: argmin 1:N cifrato, N=8, strategia CHUNKED, quantizzazione Q=±2.
GPU: **Tesla T4** (compute capability 7.5, 15 GB), `concrete-python` build GPU `2024.12.19`.

## GPU Tesla T4
| dim | bit | compile | **run** | esito |
|---|---|---|---|---|
| 64  | 8  | 7.1 s  | **629.05 s**  | corretto (pred=atteso) |
| 128 | 9  | 71.4 s | **1082.63 s** | corretto |
| 256 | 10 | 13.0 s | **1266.78 s** | corretto |

## Riferimento CPU
- M4 Max (findings F25, ~bit 11): dim 128 ≈ **123 s**.
- Stessa VM Colab, baseline CPU dim 128: **>17 min senza terminare** (2 vCPU shared).

## Verdetto
La T4 è ~9× più lenta della CPU M4 Max e non è manco più veloce rispetto alla CPU della
stessa VM. L'accelerazione GPU di TFHE è per il throughput in batch (tante bootstrap
indipendenti in parallelo), non per la latenza di una riduzione sequenziale su query
singola (il nostro argmin). Perciò la GPU non è la leva per i 2-3 s del singolo
riconoscimento. Dettagli in `findings.md` F26.

## Note d'installazione (per riprodurre)
1. `pip install --force-reinstall --no-deps --trusted-host pypi.zama.ai --index-url https://pypi.zama.ai/gpu concrete-python`
   (il `--trusted-host` aggira il **certificato SSL scaduto** dell'indice GPU di Zama).
2. `pip install --force-reinstall --no-deps "scipy==1.12.0"` + `pip install "numpy==1.26.4"`
   (il wheel GPU vuole numpy 1.26; allineare scipy all'ABI numpy 1.x), poi **riavviare il kernel**.
3. Verifica: `fhe.Configuration(use_gpu=True)` su un circuito minimo.
