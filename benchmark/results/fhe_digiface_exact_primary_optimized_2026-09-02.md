# Suite primaria exact-ID ottimizzata: 632/632

> **Snapshot della revisione A25 da 5.600 PBS**, identificata dagli hash riportati sotto.
> Correttezza, conteggi e tempi valgono soltanto per questa revisione del circuito; non validano
> automaticamente gli hardening e le ottimizzazioni successive.

> **Evidenza funzionale completa della suite pianificata, non prova del `p-fail` composto né
> validazione biometrica esterna.** Il core a N=127 ha restituito per 632/632 query lo stesso codice
> exact-ID dell'oracolo clear, senza discrepanze o errori operativi. Questo prova equivalenza
> empirica FHE-clear sul campione eseguito, non un bound crittografico end-to-end.

Il run è iniziato il 2 settembre 2026 alle 03:06:44 e si è concluso alle 04:26:45 in ora locale
Europe/Rome. Il JSON registra gli equivalenti UTC `2026-09-02T01:06:44.408518+00:00` e
`2026-09-02T02:26:45.465880+00:00`, con durata wall di 4.801,047 s, cioè 1 h 20 min 1,047 s.

## Contratto e piano

Galleria DigiFace: 127 iscritti, embedding quantizzati a 512 dimensioni, soglia uniforme `T=4`.
Il contratto `exact-open-set-id-v2` restituisce un solo LWE cifrato:
`0=rifiuto`, `i+1=identita' piu' vicina accettata`. Il rifiuto non contiene l'indice del vicino.

```sh
RAYON_NUM_THREADS=16 uv run python benchmark/fhe_digiface_validation.py \
  --run \
  --primary-suite \
  --regression-repetitions 1 \
  --timeout 900 \
  --output-stem fhe_digiface_exact_primary_optimized_2026-09-02
```

La suite contiene una cifratura fresca per ciascuna delle 632 esecuzioni, sotto una singola coppia
di chiavi temporanee fresca. Gli indici di probe distinti sono 631, perche' il probe 758 compare
sia nella coorte di frontiera sia nel test impostori primario:

| coorte | query | autorizzate attese clear | autorizzate FHE | output FHE=clear |
|---|---:|---:|---:|---:|
| `historical_frontier` | 5 | 3 | 3 | 5/5 |
| `primary_genuine` | 127 | 127 | 127 | 127/127 |
| `primary_test_impostor` | 500 | 1 | 1 | 500/500 |
| **totale** | **632** | **131** | **131** | **632/632** |

## Risultato funzionale cifrato

- **632/632** codici exact-ID identici all'oracolo clear;
- **zero discrepanze** e **zero errori operativi**;
- **131 autorizzazioni attese e 131 osservate**;
- **632/632 probe ciphertext distinti per SHA-256**;
- **632/632 result ciphertext distinti per SHA-256**;
- **5.600 PBS per query** in tutte le righe, contro l'upper bound value-independent di 6.159 per
  soglie arbitrarie;
- probe cifrato da 32.840 byte e risultato a un solo LWE da 16.464 byte in ogni query;
- contratto, galleria, dominio, epoch, revisione, chiave e input registrati invariati durante il
  run.

La diversita' dei ciphertext esclude il riuso accidentale degli stessi byte cifrati; non dimostra
indipendenza statistica o qualita' del generatore casuale. La chiave temporanea e' stata rimossa a
fine esecuzione.

## Risultato biometrico clear, separato dall'equivalenza FHE

L'oracolo clear ha identificato correttamente 127/127 genuine al primo posto e sotto soglia. Fra i
500 impostori primari ne ha accettato uno: 1/500, cioe' FPIR empirica 0,2% su questo campione. FHE
ha riprodotto esattamente questi esiti.

I cinque probe `historical_frontier` sono casi preservati prossimi alla soglia, ma non provengono
tutti dal tuning: 265, 211 e 407 sono tuning; 758 appartiene anche al test primario; 1943 proviene
dall'holdout esteso. Gli score 2, 3 e 4 sono tre false-accept *execution*; score 5 e 7 sono rifiuti.
Le 131 autorizzazioni mescolano quindi 127 genuine corrette e quattro esecuzioni false accept,
perche' l'impostore 758 accettato compare due volte. I falsi accept impostore distinti sono tre.
Questi sono conteggi di protocollo, non una metrica biometrica aggregata.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server riportato | 7.251,7 ms | 7.512,15 ms | 7.581,231 ms | 8.127,4 ms | 8.689,6 ms |
| HTTP completo | 7.252,410 ms | 7.512,710 ms | 7.581,884 ms | 8.128,097 ms | 8.690,253 ms |
| cifratura, wall | 3,873 ms | 4,862 ms | 5,158 ms | 6,982 ms | 22,195 ms |
| decifratura, wall | 4,361 ms | 5,247 ms | 5,766 ms | 8,108 ms | 56,605 ms |

Il run completo precedente da 7.804 PBS, sulla stessa suite e macchina ma in una diversa finestra
di carico, aveva mediana server 15.882,65 ms. La revisione A25 riduce staticamente i PBS del 28,24%
(`7.804 -> 5.600`) e in questi due run la mediana osservata si riduce del 52,70%, rapporto 2,114x.
Il secondo numero non e' uno speedup controllato: i run non sono paired, la macchina non era
riservata, il JSON non registra modello CPU, load o `RAYON_NUM_THREADS`, e le modifiche cambiano
anche profondita' critica e parallelismo, non soltanto il numero di PBS. Il claim riproducibile
forte e' il conteggio; i tempi sono misure end-to-end locali dichiarate.

## Binding e provenienza

Il JSON registra `success=true`, il path esatto e lo SHA-256 del binario legato al PID del server,
e l'uguaglianza prima/dopo degli hash di tutti gli input inclusi dal validator. Il checkout era
dirty: gli hash, non il solo commit Git, identificano il materiale eseguito.

| input vincolato | SHA-256 |
|---|---|
| `benchmark/fhe_digiface_validation.py` | `d96ea46c6273938b0dc82f1b85c0e08983e8f01db2949f55b91ee6beb74e3171` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `6384d202ae7ca54fafed805d6eb01747e9a03b265a0737faeb9645c74851c2ba` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `457e0563f4e6cbc372159242781ffe99ec5dae75909329664cdfe4f50dc32e8a` |
| binario release `varco_demo` | `7a7fb6c19b027d716cdbc45ac2d28d1303349771b5259faa746cc3ee17991b36` |
| cache DigiFace `_q_demo_calibrazione_resnet100.npz` | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| `demo/config.json` | `8a381c871a9f4dd4cf2f8f59e9dd06ea6448259633d6435f3c8494934463121e` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `1175ef45ffefe5c4e99989bf115c5d2213eba36f18789fab1e411523695c97a8` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

La evaluation key temporanea aveva SHA-256
`152f996c1ee04016719589a66c106974074bbb5e01cb6d1468bdbbcfeb6fd547`. Scena e holdout
corrispondono rispettivamente a
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`. Il commit di base era
`6611c185adc9a658a075519b4316386f0bb48656` sul branch
`thesis-evidence-audit-2026-09`.

| artefatto | SHA-256 |
|---|---|
| `fhe_digiface_exact_primary_optimized_2026-09-02.csv` | `b5732c8e674d7e669eb4856fb399e1200492efe90b65c2eb6e18240be29adba2` |
| `fhe_digiface_exact_primary_optimized_2026-09-02.json` | `a322ee946b6f5f7a031d1f59f6e9a5ae26cc42b642333295526aa7b9a6e7a009` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON. Il validator di questa esecuzione non
includeva ancora `src/lib.rs` nella lista degli input sorgente: il binario eseguito resta vincolato
dal proprio hash, ma la completezza della provenienza sorgente e' inferiore a quella desiderata.
Il validator successivo deve includere esplicitamente anche quel file.

## Limiti della conclusione

La suite completa stabilisce correttezza funzionale empirica sui 632 casi e sulla singola coppia
di chiavi del run. Non stabilisce un bound del `p-fail` composto dei 5.600 PBS, non prova le code di
errore dei percorsi raw-LWE e non sostituisce una validazione biometrica esterna. Usa una galleria
DigiFace sintetica, una soglia uniforme e le coorti preservate della demo; i cinque casi di
frontiera provengono dal tuning.

La formulazione difendibile e' quindi: questa revisione implementa e riproduce sulla suite
pianificata il primo argmin, la soglia del solo vincitore e l'unico output cifrato `0`/ID. Gli
hardening successivi dell'estrazione e della scala d'uscita richiedono artefatti separati e non
possono ereditare il risultato 632/632.
