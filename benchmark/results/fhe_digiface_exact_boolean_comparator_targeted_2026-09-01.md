# Regressione mirata del comparatore booleano exact-ID (superata)

> **Storico: 40/40 valido per la revisione a 5.166 PBS, non per il core corrente.** Una suite ampia
> successiva ha osservato un rifiuto spurio e ha portato a ulteriori hardening del selettore, del
> bridge e dell'output. La regressione mirata del core post-fix e' in
> `fhe_digiface_exact_noise_bounded_targeted_2026-09-01.md`; lo stato canonico e' in
> `../../README.md` e `../../status.md`, e la cronologia in
> `exact_id_noise_hardening_2026-09-01.md`.

Data: 1 settembre 2026. Questa regressione verifica il circuito exact-ID dopo l'introduzione del
comparatore booleano della soglia del vincitore. Usa la galleria DigiFace fissata a 127 iscritti,
dimensione 512 e soglia uniforme `T=4`.

## Piano del run

Il validator ha eseguito otto cifrature per ciascuno dei cinque probe mirati `113`, `647`, `73`,
`37` e `41`, per un totale di 40 query:

Una sola coppia di chiavi temporanee fresca e' stata generata per l'intero run. Le 40 query usano
quindi cifrature nuovamente campionate sotto la stessa chiave, non 40 chiavi indipendenti. Lo
SHA-256 della evaluation key caricata e verificata dal server e':
`6ba93052a6a6bd97f28a011063124526ae9c2a99ff62f384cd9b67eae18794b4`.

## Risultato funzionale

| probe | coorte | minimo clear | risultato atteso e osservato | ripetizioni corrette |
|---:|---|---:|---|---:|
| 113 | genuine | -242 | indice 113, codice 114 | 8/8 |
| 647 | primary-test impostor | 216 | rifiuto, codice 0 e indice nullo | 8/8 |
| 73 | genuine | -223 | indice 73, codice 74 | 8/8 |
| 37 | genuine | -225 | indice 37, codice 38 | 8/8 |
| 41 | genuine | -256 | indice 41, codice 42 | 8/8 |

Risultato aggregato:

- **40/40** codici exact-ID uguali all'oracolo clear;
- **32 aperture e 8 rifiuti**, uguali ai conteggi attesi;
- **zero discrepanze** e **zero errori operativi**;
- **40/40 probe ciphertext distinti per SHA-256**; anche le otto ripetizioni di ogni probe hanno
  hash distinti;
- `exact-open-set-id-v2` in tutte le risposte;
- **5.166 PBS per query** in tutte le 40 righe;
- probe cifrato da 32.840 byte e risultato a un solo LWE da 16.464 byte in tutte le query;
- stato della galleria, epoch, revisione e fingerprint della evaluation key invariati tra
  enrollment e fine del run.

La diversita' dei 40 ciphertext dimostra che non sono stati riutilizzati gli stessi byte cifrati;
insieme all'invocazione separata della cifratura per ogni riga e' evidenza di cifrature fresche nel
run. Non e' un test statistico dell'indipendenza o della qualita' del generatore casuale.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server riportato | 9.343,4 ms | 11.812,85 ms | 11.900,808 ms | 15.104,4 ms | 15.301,8 ms |
| HTTP completo | 9.344,142 ms | 11.813,928 ms | 11.901,794 ms | 15.105,225 ms | 15.303,713 ms |
| cifratura, wall | 5,395 ms | 6,321 ms | 7,199 ms | 12,192 ms | 12,973 ms |
| decifratura, wall | 5,303 ms | 6,532 ms | 7,210 ms | 10,193 ms | 23,010 ms |

Il run completo e' durato 478,314 s. Questi tempi sono riportati per trasparenza, ma non provengono
da un benchmark prestazionale controllato: l'artefatto non registra un ambiente isolato, il carico
dell'host o un bound worst-case. Non autorizzano quindi un claim hard di latenza.

## Binding e provenienza

Il JSON registra `success=true`, lega il binario al PID del server e verifica che tutti gli input
registrati abbiano lo stesso SHA-256 prima e dopo il run. Il checkout era dirty; gli hash qui sotto,
non il solo commit Git, identificano percio' il materiale effettivamente eseguito.

| input | SHA-256 |
|---|---|
| `benchmark/fhe_digiface_validation.py` | `33c433f836ae6f8f420f306508418384f806529e3b0eced9e4c098985ff34eae` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `91d3470dc089f277000d4f78047a9a96d29351c0ed0025c9c177c2684b9e5862` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `af77fb006cda8e2b070cda28f1c3dab8d53860a531fd9be58d8e3df18ec6b95b` |
| binario release `varco_demo` | `3fa5547aa24a4f854e866cdd88c88e321afb07bc0d249700b16ab2d833b85ffe` |
| cache DigiFace `_q_demo_calibrazione_resnet100.npz` | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| `demo/config.json` | `8a381c871a9f4dd4cf2f8f59e9dd06ea6448259633d6435f3c8494934463121e` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `bdd7e63b67fbcd7a6326248bed09daf33e30f95a7873b44fff37b591261a634a` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Ulteriori identificatori registrati:

- scena quantizzata: `ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66`;
- holdout non-tuning: `0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`;
- host/toolchain: macOS arm64, Python 3.12.11, NumPy 1.26.4, Rust/Cargo 1.97.1.

Artefatti del run, ricontrollati dopo la scrittura:

| artefatto | SHA-256 |
|---|---|
| `fhe_digiface_exact_boolean_comparator_targeted_2026-09-01.csv` | `84b159c62aeaaa843a90c9887154cffc4ed2f3614462d16cc6a7d02398a4e93c` |
| `fhe_digiface_exact_boolean_comparator_targeted_2026-09-01.json` | `6aa8c9f55de4ff01b7cb234a48991b2f41a58aa98284b2380af2002801a4cec8` |

Lo SHA-256 del CSV coincide anche con quello incorporato nel JSON.

## Limiti della conclusione

Questa e' una regressione mirata sui probe scelti per coprire fallimenti noti e casi sensibili di
quella revisione; non e' un campione casuale e non sostituisce la suite primaria ampia. Dimostra
che, con questa singola chiave di run, 40 cifrature dei cinque casi produssero l'uscita exact-ID
corretta sul circuito a 5.166 PBS.

La galleria usa la stessa soglia `T=4` per tutti i 127 template. Il run non valida quindi da solo il
caso generale di soglie per-template diverse. Non stima DIR/FPIR di popolazione, non e' una
validazione biometrica esterna e non deriva una probabilita' di fallimento dell'intera query. In
particolare, il `log2_p_fail` nominale del parameter set standard non diventa automaticamente un
bound composto per i **5.166 PBS**, i fan-in custom, i riscalamenti e la decodifica finale.

I risultati si riferiscono alla revisione e agli input identificati in questo report.
Il clone non include il binario e tutti gli input del run storico; eseguire gli
script sul codice corrente non replica automaticamente queste misure.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
