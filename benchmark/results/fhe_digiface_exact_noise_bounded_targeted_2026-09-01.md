# Regressione mirata exact-ID dopo l'hardening bounded (superata)

> **Snapshot storico della revisione bounded da 7.804 PBS**, identificata dagli hash riportati
> nel report. Conteggi, correttezza e tempi valgono esclusivamente per quella revisione; non
> validano revisioni successive del circuito.

> **Evidenza funzionale mirata, distinta dalla suite completa.** Questo run misura il core
> post-audit a 7.804 PBS su N=127 e chiude 48/48 query selezionate senza discrepanze. La successiva
> suite canonica ha poi concluso **632/632** query senza discrepanze o errori; il puntatore e' nella
> sezione dedicata sotto. Nessuno dei due run deriva un bound del `p-fail` o stima da solo DIR/FPIR
> di popolazione. Lo stato canonico e' in `../../README.md` e `../../status.md`; la cronologia dei
> fallimenti e dei fix e' in `exact_id_noise_hardening_2026-09-01.md`.

Data del run mirato: 1 settembre 2026; aggiornamento della suite completa: 2 settembre 2026, ora
locale. Host macOS arm64, Python 3.12.11, Rust/Cargo 1.97.1. Galleria DigiFace: 127 iscritti,
embedding quantizzati a 512 dimensioni e soglia uniforme `T=4`.

## Piano del run

Il validator ha eseguito otto cifrature per ciascuno dei sei probe mirati `113`, `647`, `73`,
`37`, `41` e `87`, per 48 query:

```sh
benchmark/fhe_digiface_validation.py --run \
  --only-probe 113 --only-probe 647 --only-probe 73 \
  --only-probe 37 --only-probe 41 --only-probe 87 \
  --regression-repetitions 8 \
  --output-stem fhe_digiface_exact_noise_bounded_targeted_2026-09-01
```

Una sola coppia di chiavi temporanee fresca e' stata generata per l'intero run. Le 48 righe sono
quindi cifrature nuovamente campionate sotto la stessa chiave, non 48 chiavi indipendenti.

## Risultato funzionale

| probe | coorte | minimo clear | risultato atteso e osservato | ripetizioni corrette |
|---:|---|---:|---|---:|
| 113 | genuine | -242 | indice 113, codice 114 | 8/8 |
| 647 | primary-test impostor | 216 | rifiuto, codice 0, indice nullo | 8/8 |
| 73 | genuine | -223 | indice 73, codice 74 | 8/8 |
| 37 | genuine | -225 | indice 37, codice 38 | 8/8 |
| 41 | genuine | -256 | indice 41, codice 42 | 8/8 |
| 87 | genuine | -269 | indice 87, codice 88 | 8/8 |

Risultato aggregato:

- **48/48** codici exact-ID uguali all'oracolo clear;
- **40 aperture con identita' esatta e 8 rifiuti**, uguali ai conteggi attesi;
- **zero discrepanze** e **zero errori operativi**;
- **48/48 probe ciphertext distinti per SHA-256**;
- **7.804 PBS per query** e contratto `exact-open-set-id-v2` in tutte le righe;
- probe cifrato da 32.840 byte e risultato a un solo LWE da 16.464 byte in tutte le query;
- stato della galleria, epoch, revisione, chiave e input invariati durante il run.

La diversita' dei 48 ciphertext mostra che il validator non ha riutilizzato gli stessi byte
cifrati fra le query. Non e' un test statistico dell'indipendenza o della qualita' del generatore
casuale.

## Tempi osservati, non isolati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server riportato | 13.341,9 ms | 15.010,55 ms | 15.505,965 ms | 18.808,7 ms | 19.360,2 ms |
| HTTP completo | 13.342,680 ms | 15.011,461 ms | 15.506,818 ms | 18.809,798 ms | 19.360,929 ms |
| cifratura, wall | 5,234 ms | 5,825 ms | 6,020 ms | 7,702 ms | 8,962 ms |
| decifratura, wall | 5,108 ms | 6,021 ms | 6,440 ms | 9,163 ms | 12,186 ms |

Il run e' durato 746,998 s dal 19:00:50 al 19:13:17 UTC. Questi tempi sono osservazioni
evidence-grade del percorso locale, ma la macchina non era riservata a un benchmark isolato e il
report non registra un bound worst-case. Non autorizzano quindi un claim hard di latenza.

## Binding e provenienza

Il JSON registra `success=true`, verifica il path esatto e lo SHA-256 del binario legato al PID del
server, e conferma che gli hash degli otto input registrati sono invariati fra inizio e fine run.
Il checkout era dirty; gli hash, non il solo commit Git, identificano il materiale eseguito.

| input | SHA-256 |
|---|---|
| `benchmark/fhe_digiface_validation.py` | `072bf717f58232f91b7d120db93ce3b0c70198193c10562fe142b4a7fc707c5d` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `4bcc15c873cb0ccd81b5d07b639437d6856aa5b2b249270886fe1a73cf7912dc` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `af77fb006cda8e2b070cda28f1c3dab8d53860a531fd9be58d8e3df18ec6b95b` |
| binario release `varco_demo` | `170b5cf81a4365f357e31ce4ebfeae17ccc03368a4b5a9cacbc3cb7842766424` |
| cache DigiFace `_q_demo_calibrazione_resnet100.npz` | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| `demo/config.json` | `8a381c871a9f4dd4cf2f8f59e9dd06ea6448259633d6435f3c8494934463121e` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `bdd7e63b67fbcd7a6326248bed09daf33e30f95a7873b44fff37b591261a634a` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

La evaluation key temporanea aveva SHA-256
`3ef97df6bbc5b2f23e18aca9a4cd33f86e889efaeca091a1e02b6f18d187ca27`; la directory temporanea
contenente le chiavi e' stata rimossa al termine. Scena e holdout corrispondono agli hash fissati
nel config. Il commit di base era `6611c185adc9a658a075519b4316386f0bb48656`.

Artefatti del run:

| artefatto | SHA-256 |
|---|---|
| `fhe_digiface_exact_noise_bounded_targeted_2026-09-01.csv` | `eadca32e02728c96bbd529b09a6ccf0f9c1a3a6254f13c4323f657d42c37d0f9` |
| `fhe_digiface_exact_noise_bounded_targeted_2026-09-01.json` | `d75c3e7cf17a9680c433408b185ae6dc5c345e6a5b70699a2f0039e4ce6fb983` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON.

## Risultato successivo della suite canonica completa

Il gate separato `--primary-suite` e' terminato alle 00:06 del 2 settembre in ora italiana, pur
mantenendo nello stem la data di avvio `2026-09-01`. Ha registrato:

- **632/632 codici exact-ID uguali all'oracolo clear** sulle 5 frontiere storiche, 127 genuine e
  500 impostori primary-test;
- zero discrepanze e zero errori operativi;
- 131 aperture attese e osservate, 632 ciphertext del probe tutti distinti;
- 7.804 PBS/query e contratto `exact-open-set-id-v2` in tutte le righe.

Artefatti canonici separati:

| artefatto | SHA-256 |
|---|---|
| [`fhe_digiface_exact_primary_noise_bounded_2026-09-01.csv`](fhe_digiface_exact_primary_noise_bounded_2026-09-01.csv) | `804aa4390ad00deed08698905540e458176bfd91db0618bd826baa93edebb80b` |
| [`fhe_digiface_exact_primary_noise_bounded_2026-09-01.json`](fhe_digiface_exact_primary_noise_bounded_2026-09-01.json) | `b6e54b92bef8f53c0ce057f1e68e9b473487fdd423776962579661669d4fa512` |

Anche questa e' evidenza empirica: usa una sola coppia di chiavi temporanee, la stessa galleria a
soglia uniforme `T=4` e non fornisce un bound whole-circuit del `p-fail` dei 7.804 PBS.

## Limiti della conclusione

Questa e' una regressione mirata sui sei probe scelti per coprire tutti i fallimenti precedenti,
incluso il caso one-shot del probe 87. Non e' un campione casuale, usa una sola coppia di chiavi e
non sostituisce da sola la suite completa da 632 query, ora conclusa nell'artefatto separato sopra.
La galleria usa la stessa soglia `T=4` per tutti i 127 template, quindi ne' il run mirato ne' quello
completo validano da soli il caso generale di soglie per-template diverse.

Il risultato 48/48 e la trace interna senza divergenze sono evidenza funzionale del core post-audit;
non derivano una probabilita' di fallimento composta dai 7.804 PBS, non misurano DIR/FPIR di
popolazione e non costituiscono una validazione biometrica esterna. Il successivo 632/632 estende
la copertura empirica pianificata, ma non cambia questi limiti formali.
