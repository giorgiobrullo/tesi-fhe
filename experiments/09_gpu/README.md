# 09 — Il circuito Concrete sulla GPU

Il [passo 06](../06_argmin_soglia/README.md) aveva mostrato che confrontare
score cifrati in Concrete richiedeva molto tempo. Qui si è provato a eseguire
**lo stesso tipo di scelta del minimo** su una Tesla T4, senza cambiare la
struttura sequenziale della riduzione. La domanda era se la GPU bastasse a
ridurre la latenza di una singola query.

L'ingresso di questa prova è una piccola galleria di **8** candidati con
embedding di 64, 128 o 256 dimensioni, quantizzati a ±2. Il circuito sceglie
l'indice dello score minimo e lo confronta con l'atteso in chiaro. Non
comprende acquisizione della foto, client web né servizio 0/ID della demo.

| Dimensione | Valutazione su T4 | Esito |
|---:|---:|---|
| 64 | 629 s | indice corretto |
| 128 | 1083 s | indice corretto |
| 256 | 1267 s | indice corretto |

Sono i tempi della [campagna storica](RISULTATI.md), con build GPU Concrete
`2024.12.19` su Colab. Per 128 dimensioni, il riferimento di circa 123 s
proveniva da un **M4 Max**: è un confronto fra macchine e configurazioni
diverse, non un'accelerazione GPU/CPU controllata. La CPU della stessa VM
Colab non ha terminato entro 17 minuti, quindi non fornisce un rapporto
conclusivo. Il risultato dice soltanto che **questo circuito sequenziale su
questa T4** era ancora lento per la latenza cercata; non giudica i carichi
GPU in batch o altri circuiti.

Il [passo 10](../10_argmin_struttura/README.md) cambia quindi la struttura
dell'argmin. Il [notebook della prova](colab_argmin_gpu.ipynb) e il
[report](RISULTATI.md) conservano ambiente, comandi e misure originali.
