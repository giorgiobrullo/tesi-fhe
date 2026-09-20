# Risultati - argmin cifrato su GPU (Tesla T4, Google Colab)

Circuito: argmin 1:N cifrato, N=8, strategia CHUNKED, quantizzazione Q=±2.
GPU: Tesla T4 (compute capability 7.5, 15 GB), `concrete-python` build GPU `2024.12.19`.

## GPU Tesla T4
| dim | bit | compile | run | esito |
|---|---|---|---|---|
| 64  | 8  | 7.1 s  | 629.05 s  | corretto (pred=atteso) |
| 128 | 9  | 71.4 s | 1082.63 s | corretto |
| 256 | 10 | 13.0 s | 1266.78 s | corretto |

## Riferimento CPU
- M4 Max (findings F25, ~bit 11): dim 128 ≈ 123 s.
- Stessa VM Colab, baseline CPU dim 128: >17 min senza terminare (2 vCPU shared).

## Interpretazione
A dimensione 128 la T4 impiega circa 9× il tempo del riferimento M4 Max.
Il confronto CPU nella VM si è interrotto senza completare dopo oltre 17 minuti:
non fornisce quindi un rapporto di prestazioni conclusivo.

L'esperimento misura la latenza di una riduzione sequenziale su una query,
non il throughput di bootstrap indipendenti in batch. In questa configurazione
non raggiunge l'obiettivo storico di 2–3 s per riconoscimento; il risultato
non esclude vantaggi GPU su altri circuiti o carichi. Dettagli in `findings.md`, F26.

## Installazione usata nella campagna storica
1. `pip install --force-reinstall --no-deps --trusted-host pypi.zama.ai --index-url https://pypi.zama.ai/gpu concrete-python`
   (nella campagna `--trusted-host` aggirava un errore di certificato SSL
   dell'indice GPU di Zama; il comando documenta quella configurazione).
2. `pip install --force-reinstall --no-deps "scipy==1.12.0"` + `pip install "numpy==1.26.4"`
   (il wheel GPU vuole numpy 1.26; allineare scipy all'ABI numpy 1.x), poi riavviare il kernel.
3. Verifica: `fhe.Configuration(use_gpu=True)` su un circuito minimo.
