# Verifica aritmetica indipendente — valid1

Ricalcolo soltanto dai record pubblici, senza native, chiavi, fasi o modelli. Il raw contiene 38 record: start, 5 ammissioni, keys_ready, 10 correctness, 4 warmup, 16 timed, complete. Tutte le cinque ammissioni precedono keys_ready e riportano keys_generated=0. I metadati dichiarano una famiglia fresca per valid1, nessuna chiave serializzata, G4/profiling off e pool16.

Le 30 valutazioni riportano decoded=expected: **28 percorrono il circuito e 2 AllReject usano la scorciatoia pubblica**. Queste ultime hanno BR/KS/PFKS/marginals/initial_samples tutti zero. Per ogni coppia correctness, warmup e timed coincidono integralmente ledger, contatori classic e selector dei due bracci.

I 16 tempi formano 8 coppie: quattro per Uniform e quattro per Mixed. Per ciascun workload l'ordine è barrier/DAG, DAG/barrier, barrier/DAG, DAG/barrier. Ogni tempo è positivo. Ho ricavato ogni rapporto come DAG_ns/barrier_ns e poi la media geometrica dei rapporti, senza esclusioni:

| Workload | Coppie | Media geometrica | Variazione tempo |
|---|---:|---:|---:|
| Uniform | 4 | 1.0665163008731764 | +6.6516300873% |
| Mixed | 4 | 1.117333185647553 | +11.7333185648% |
| Complessivo | 8 | 1.091629083525934 | +9.1629083526% |

Tutti gli otto rapporti e i conteggi coincidono con SUMMARY.json. Il gate preregistrato, complessivo<0.97 e ciascun workload≤1.01, **non passa**. È un risultato di questa campagna sintetica N120/D512 con un'unica famiglia crittografica; non identifica la causa, una probabilità di errore o un'impossibilità generale del DAG.

Il primo tentativo rimane separato in root/INVALID_CAMPAIGN.json: una famiglia e una query cifrata, zero evaluate/controlli decifrati/timing; coordinata4 non ammessa. Non si conta come fallimento FHE. Valid1 termina con complete/all_correct e ricevuta exit0; non ho controllato processi o lanciato retry.

Pin diretti: root/NATIVE_VALID1.ndjson, 20893 byte, SHA256 `d1c0acb063aa4df7393f194953475558e601e234221bffed7b7b6f9754f54938`; root/SUMMARY.json, 2695 byte, SHA256 `f04a1d6ab53e6aed70a47faa130591b7ae9e708b6b2dd6ffa5e47dad47c13a2f`.
