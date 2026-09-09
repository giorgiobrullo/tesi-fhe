# 20 — Normalizzatori derivati dal riporto e composizione classica

Una rotazione che produce il riporto può fornire anche la cifra bassa tramite
una trasformazione lineare dell'intero ciphertext. Questo esperimento raccoglie
il componente, il controllo esteso del rumore e la prima composizione veloce.

Il confronto isolato del carry dà **12,39% di riduzione**, 24/24 coppie su una
chiave. Lo sweep verifica 4096 valori, quattro modalità e tre chiavi:
49.152 estrazioni e 384 selezioni. I limiti calcolati dai vettori di errore
salvati sono condizionali; non sono una probabilità globale di fallimento.

La conferma dei comparatori classici paralleli dà **6,51%**, 56/56 coppie su
due nuove chiavi. La composizione notturna di carry, confronto parallelo e
soglie pubbliche dà **19,24% nella seconda famiglia**, 28/28 coppie; il primo
screening distinto dà 20,82%. Entrambi i riferimenti avevano già i tagli ID.
Il carry è incorporato nei risultati della composizione: le percentuali non
si sommano e non sono altri guadagni disponibili nel core selezionato.

| Sorgente | Ruolo effettivo |
|---|---|
| [carry-packed](sources/carry-packed/Cargo.toml) | Gate sul circuito completo e confronto dei tempi |
| [carry-sweep](sources/carry-sweep/Cargo.toml) | Wrapper dello sweep esteso |
| [carry-gate](sources/carry-gate/Cargo.toml) | Aspettativa corretta sulla LUT effettiva |
| [composite-classic](sources/composite-classic/Cargo.toml) | Composizione della notte, già incorporata nel successivo pacchetto 22 |

Le revisioni dei wrapper restano distinte: una correzione del gate non viene
attribuita retroattivamente al sorgente di un altro run. I negativi vicini
restano nel [riepilogo](RESULTS.json): mappe fuse circa 0,14% più lente e batch
classico del selettore circa 0,34% più lento nei rispettivi screening.

I [tempi isolati](evidence/normalizer-timing.json), le
[conferme classiche](evidence/classic-confirmation.json), la
[composizione](evidence/night-composition.json) e le
[mappe di errore](evidence/NORMALIZER_ERROR_MAPS.md) conservano gli estimatori
e i limiti. Le proiezioni JSON sono estrazioni delle prove concluse, senza
un nuovo replay dei cifrati. Carico esterno e chiavi limitate restano espliciti.

I workspace Rust includono lockfile, core locale e LUT pubblica incorporata;
i crate registry TFHE-rs 1.7.0 devono essere disponibili. **Le copie non sono
state compilate né eseguite in questa riorganizzazione.**
[COPY_ORIGINS.json](COPY_ORIGINS.json) verifica i byte copiati;
[EVIDENCE_ORIGINS.json](EVIDENCE_ORIGINS.json) identifica gli archivi originali.
Per il riuso del servizio partire dalla [composizione selezionata 22](../22_demo_composita/README.md).
