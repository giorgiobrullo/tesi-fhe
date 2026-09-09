# Suite primaria exact-ID bounded DigiFace: 632/632

> **Snapshot storico della revisione bounded da 7.804 PBS**, identificata dagli hash riportati
> sotto. Conteggi, correttezza e tempi di questo file valgono esclusivamente per quella revisione;
> non validano revisioni successive del circuito, che richiedono artefatti separati.

> **Evidenza funzionale completa della suite pianificata, non prova di accuratezza biometrica o
> del `p-fail`.** Il core bounded a N=127 ha restituito per 632/632 query esattamente lo stesso
> codice dell'oracolo clear, senza discrepanze o errori operativi. Questo dimostra equivalenza
> empirica FHE-clear sul campione; non trasforma le accettazioni biometriche errate dell'oracolo in
> identificazioni corrette e non deriva un bound della probabilita' di fallimento composta.

Il run conserva lo stem `fhe_digiface_exact_primary_noise_bounded_2026-09-01` perche' e' stato
avviato il **1 settembre 2026**. In ora locale Europe/Rome e' iniziato alle 21:17:03 del 1 settembre
ed e' terminato alle 00:06:31 del **2 settembre 2026**, quindi dopo la mezzanotte. Il JSON registra
gli equivalenti UTC `2026-09-01T19:17:03.449560+00:00` e
`2026-09-01T22:06:31.867728+00:00`, con durata wall 10.168,399 s.

## Piano del run

Galleria DigiFace: 127 iscritti, embedding quantizzati a 512 dimensioni, soglia uniforme `T=4`.
Il contratto e' `exact-open-set-id-v2`: il server restituisce un solo LWE cifrato che decodifica
`0=rifiuto` oppure `i+1=identita' piu' vicina accettata`.

```sh
benchmark/fhe_digiface_validation.py --run \
  --primary-suite \
  --regression-repetitions 1 \
  --output-stem fhe_digiface_exact_primary_noise_bounded_2026-09-01
```

La suite pianificata e misurata contiene:

| coorte | query | autorizzate attese clear | autorizzate FHE | output FHE=clear |
|---|---:|---:|---:|---:|
| `historical_frontier` | 5 | 3 | 3 | 5/5 |
| `primary_genuine` | 127 | 127 | 127 | 127/127 |
| `primary_test_impostor` | 500 | 1 | 1 | 500/500 |
| **totale** | **632** | **131** | **131** | **632/632** |

Una sola coppia di chiavi temporanee fresca e' stata generata per l'intero run. Le 632 query sono
cifrature nuovamente campionate sotto la stessa chiave, non 632 chiavi indipendenti.

## Risultato crittografico funzionale

- **632/632** codici exact-ID identici all'oracolo clear;
- **zero discrepanze** e **zero errori operativi**;
- **131 autorizzazioni attese e 131 osservate**;
- **632/632 probe ciphertext distinti per SHA-256**;
- **7.804 PBS per query** e contratto `exact-open-set-id-v2` in tutte le righe;
- probe cifrato da 32.840 byte e risultato a un solo LWE da 16.464 byte in tutte le query;
- galleria, epoch, revisione, chiave e input registrati invariati durante il run.

La diversita' dei ciphertext dimostra che il validator non ha riutilizzato gli stessi byte
cifrati. Non e' un test statistico dell'indipendenza o della qualita' del generatore casuale.

## Risultato biometrico del clear, distinto dall'equivalenza FHE

L'oracolo clear ha identificato correttamente **127/127 genuine** al primo posto e sotto soglia.
Fra i 500 impostori della coorte primaria ne ha accettato uno: **1/500**, cioe' FPIR empirica 0,2%
su questo campione preservato. FHE ha riprodotto entrambi i risultati senza alterazioni.

I cinque probe `historical_frontier` sono invece impostori di tuning scelti vicino alla soglia:
quelli con score 2, 3 e 4 sono tre **false accept biometrici**, mentre quelli con score 5 e 7 sono
rifiuti. Il loro 3/5 non e' una stima primaria e non sono tre identificazioni corrette. Il totale
di 131 autorizzazioni mescola quindi 127 genuine corrette con quattro false accept biometrici
(uno primario e tre di frontiera); e' un conteggio di esecuzione del protocollo, non una metrica di
accuratezza aggregata.

## Tempi osservati, non isolati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server riportato | 10.793,5 ms | 15.882,65 ms | 16.068,894 ms | 19.546,6 ms | 22.263,4 ms |
| HTTP completo | 10.794,102 ms | 15.884,630 ms | 16.070,002 ms | 19.548,534 ms | 22.268,090 ms |
| cifratura, wall | 4,103 ms | 6,074 ms | 6,813 ms | 10,154 ms | 125,712 ms |
| decifratura, wall | 4,574 ms | 6,410 ms | 7,781 ms | 12,347 ms | 305,770 ms |

Il run completo e' durato 2 h 49 min 28,399 s. Questi sono tempi evidence-grade del percorso
locale, ma la macchina non era riservata a un benchmark isolato e l'artefatto non fornisce un
bound worst-case. Non autorizzano quindi un claim hard di latenza.

## Binding e provenienza

Il JSON registra `success=true`, verifica il path esatto e lo SHA-256 del binario legato al PID del
server, e conferma che gli hash degli otto input registrati sono identici prima e dopo il run. Il
checkout era dirty; gli hash, non il solo commit Git, identificano il materiale eseguito.

| input | SHA-256 |
|---|---|
| `benchmark/fhe_digiface_validation.py` | `072bf717f58232f91b7d120db93ce3b0c70198193c10562fe142b4a7fc707c5d` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `61200a3d97626d4617b50cdb3101909e634ae597788fe05bb4d73f422b8abc8b` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `457e0563f4e6cbc372159242781ffe99ec5dae75909329664cdfe4f50dc32e8a` |
| binario release `varco_demo` | `f016349d45b6c90243a858373ac339c249074c3e63a62abc5e0e2019cd5689f3` |
| cache DigiFace `_q_demo_calibrazione_resnet100.npz` | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| `demo/config.json` | `8a381c871a9f4dd4cf2f8f59e9dd06ea6448259633d6435f3c8494934463121e` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `1175ef45ffefe5c4e99989bf115c5d2213eba36f18789fab1e411523695c97a8` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

La evaluation key temporanea aveva SHA-256
`8abe4652d923d4ff63d663dd73c670da0578071c640028d1277c61689bb780ee`; la directory temporanea
contenente le chiavi e' stata rimossa al termine. Scena e holdout corrispondono rispettivamente a
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`. Il commit di base era
`6611c185adc9a658a075519b4316386f0bb48656`.

Artefatti del run:

| artefatto | SHA-256 |
|---|---|
| `fhe_digiface_exact_primary_noise_bounded_2026-09-01.csv` | `804aa4390ad00deed08698905540e458176bfd91db0618bd826baa93edebb80b` |
| `fhe_digiface_exact_primary_noise_bounded_2026-09-01.json` | `b6e54b92bef8f53c0ce057f1e68e9b473487fdd423776962579661669d4fa512` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON.

## Limiti della conclusione

La suite completa pianificata e' superata sul campione e sulla singola coppia di chiavi del run,
ma non costituisce una prova formale della probabilita' di fallimento composta dei 7.804 PBS. Non
e' una validazione biometrica esterna: usa una galleria DigiFace sintetica, una soglia uniforme e
le coorti preservate della demo. I cinque casi di frontiera provengono dal tuning e restano fuori
dalla stima primaria.

La correttezza 632/632 e' quindi un claim di equivalenza funzionale FHE-clear per questa suite. Le
metriche biometriche restano quelle dell'oracolo sul campione dichiarato; generalizzazione,
galleria mista, soglie per-template reali, coorti indipendenti e bound analitico del `p-fail`
restano separati.
