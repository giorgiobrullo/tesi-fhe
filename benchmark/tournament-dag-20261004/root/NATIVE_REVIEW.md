# Torneo DAG: risultato della campagna valida

**PUBLIC_RESULT_PASS / RUNTIME_GATE_FAILED.** Verificati raw, summary, ricevute build/native e manifest sorgenti, senza eseguire helper, native, modelli o leggere materiale privato. Letta integralmente math/RUNTIME_CHECK: concorda con il ricalcolo indipendente seguente.

Il raw contiene38 record: start, cinque fixture_admitted con keys_generated0, keys_ready,10 correctness,4 warmup,16 timed e complete. La sequenza esatta e le cinque ammissioni antecedenti alla keygen corrispondono al main valido. Una sola famiglia/query cifrata entro questa campagna; nessuna chiave serializzata, pool16, G4/profileoff.

Tutti30 esiti coincidono con l'oracolo: Uniform/Mixed restituiscono76; rifiuti restituiscono0, incluso Mixed dove120 passerebbe ma il primo minimo76 fallisce. **28 chiamate percorrono il circuito; due AllReject hanno ledger nullo e sono shortcut pubblici.** Counts/classic/selector coincidono integralmente entro tutte15 coppie. Le ripetizioni riusano stessa chiave/query: non sono30 prove crittografiche indipendenti o una stima di p_fail.

Le16 misure sono quattro coppie AB/BA per workload. Ricomputati tutti rapporti DAG_ns/barrier_ns e media geometrica, senza esclusioni:

| Workload | Coppie | Rapporto | Variazione tempo |
|---|---:|---:|---:|
| Uniform |4|1.0665163008731764|+6.651630%|
| Mixed |4|1.117333185647553|+11.733319%|
| Totale |8|1.091629083525934|+9.162908%|

Tutte otto coppie hanno rapporto>1. Il gate preregistrato totale<0.97 e ciascuna famiglia≤1.01 fallisce. Chiudere questo candidato senza integrazione o retry: evidenza sul workload sintetico N120/D512 e questa esecuzione, non DAG universalmente più lento o causa interna identificata. Il timer comprende evaluate, esclude configurazione/oracolo/decode; non è latenza della demo.

Ricevute: buildexit0; native child54834/driver54833, exit0/complete. POSTCHECK riporta nessun processo riconosciuto nel proprio perimetro; non globalidle. I due test strutturali nuovi risultano PASS, non l'intera suite. Manifest SOURCE_CANDIDATE12 e VALID1_SOURCE4 verificati direttamente; binario/raw corrispondono alle ricevute.

Il primo tentativo resta INPUT_ADMISSION_FAILURE: una famiglia/query ma zero evaluate, decode o timing. SOURCE_PASS aveva mancato coordinate4/5. Correzione separata pre-keygen verificata; niente errore FHE, baselinefailure o selezione favorevole della chiave dedotti.

## Impronte principali

Percorsi relativi alla fase; byte/SHA256:

| File | B | SHA256 |
|---|---:|---|
| root/NATIVE_VALID1.ndjson |20893|d1c0acb063aa4df7393f194953475558e601e234221bffed7b7b6f9754f54938|
| target/release/current_tournament_dag_probe_valid1_20261004 |2078736|9627d1eb96cd813079ce56c4996f7c5b5f9fa56cbf03a368c8cc30dd0c00daf9|
| root/SUMMARY.json |2695|f04a1d6ab53e6aed70a47faa130591b7ae9e708b6b2dd6ffa5e47dad47c13a2f|
| root/SOURCE_CANDIDATE.json |1914|312107d186c461f43f91fdf95b7401294b507a9517327a95df98fe781347b63e|
| root/VALID1_SOURCE.json |688|e2c47c795736e00930acd5639b45103db682b4b17955bc7023b89556ed74c18e|
| root/NATIVE_VALID1_EXIT.json |1042|73f2014e38c75fed0a0dcce36d7eaa6a0883f00862d314262c0eac4435b635c5|
| math/RUNTIME_CHECK.md |2134|e1eefd6a2d20aa50bef4cbc960a4511bd4131b544cb5ae9108f78a399b877a7d|
