# Comparatore periodic-fold sperimentale - 1 settembre 2026

> **CHECKPOINT STORICO RITIRATO - F70 / periodic-fold / `any_match`.** Questo report documenta il
> comparatore standalone e la sua integrazione nel vecchio gate
> `OR_i[score_i <= T_i]`. Non documenta l'argmin cifrato, la soglia del solo vincitore o l'output
> exact-ID `0`/`indice+1`; i suoi 3 PBS/template, 400 PBS a N=127 e tempi sub-secondo non sono
> prestazioni del contratto finale. "Corrente" e "finale" nei nomi degli artefatti significano
> soltanto corrente/finale per questo checkpoint del 1 settembre 2026. Per lo stato exact-ID
> attuale vedere il [README principale](../../README.md#implementazione-selezionata) e
> i [risultati sperimentali](../../findings.md); la cronologia tecnica dell'hardening exact-ID e' in
> [`exact_id_noise_hardening_2026-09-01.md`](exact_id_noise_hardening_2026-09-01.md).

## Stato del checkpoint periodic-fold

Nel checkpoint qui preservato `varco_demo` integrava un comparatore di soglia a **3 PBS per
template**: due correzioni periodiche con `P=32` e `P=512`, seguite dal PBS di segno. Usava
soltanto KSK e BSK del set di parametri allora adottato dal prototipo,
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`; non aggiungeva chiavi WoP-PBS e non cambiava
il formato del probe o dell'esito.

Il predicato finito e' esatto in chiaro per ogni intero dichiarato
`d = score - T in [-4095, 4095]`. I test cifrati avversariali, multikey e di servizio sotto non
hanno osservato errori. Questi test documentano il comportamento osservato; non derivano
la probabilita' di fallimento del circuito composto. Il comparatore era quindi
marcato `periodic_fold_3pbs_sperimentale`, non production-ready.

- sorgente standalone del checkpoint:
  `experiments/14_pipeline_tfhe_rs/src/bin/exact_comparator_scratch.rs`;
- SHA-256 sorgente standalone: `334debda099cb10e7ffe59b908347e1785f020a0de46b127cf45123e047f27d3`;
- SHA-256 binario Release: `0d3b0b14d64cfc2e423545ddeed148555eada22d717af0531aaaa4dd40fd6621`;
- tfhe-rs `0.11.3`, Rust/Cargo `1.97.1`, Apple arm64;
- chiavi e ciphertext freschi da `new_seeder()`, senza seed deterministico.

Gli hash vanno ricalcolati se il sorgente cambia. Il binario non esegue keygen o benchmark senza
il flag esplicito `--run`.

## Costruzione

L'input resta quello del servizio precedente:

```text
x = (score - T - 1/2) * Delta,     Delta = 2^51.
```

In unita' di `Delta/2`, si pone `v0 = 2(score-T)-1`. Per ciascun periodo `P` il servizio:

1. conserva il ciphertext di stato;
2. ne moltiplica tutti i coefficienti toroidali per
   `2^(64-log2(Delta)-log2(P))`;
3. applica il KSK di produzione e un PBS con accumulatore costante `(P/4)*Delta`;
4. somma allo stato la correzione ottenuta.

La negaciclicita' dell'accumulatore rende la correzione `+P/2` o `-P/2` nelle unita' di `v`. Il
modello in chiaro applicato dal test e':

```text
r = v mod 2P
v <- v + P/2    se r < P
v <- v - P/2    altrimenti
```

dopo `P=32`, poi `P=512`. Il KSK e il PBS finali leggono il segno del residuo. Uno sweep
esaustivo dei 8.191 interi ammessi verifica contemporaneamente:

```text
v_finale < 0  <=>  score <= T
273 <= |v_finale| <= 7919 < 8192.
```

L'ultima disuguaglianza evita il wrap nel semitoro a `Delta=2^51`. Sui valori raggiungibili, i
margini minimi dei tre ingressi PBS sono rispettivamente 64, 68 e 68,25 rotazioni; nel
comparatore diretto ritirato il margine di frontiera era soltanto 0,25 rotazioni.

Questa e' una costruzione sperimentale specifica dell'istanza. E' concettualmente vicina alla
letteratura che amplia la precisione del segno tramite applicazioni iterative di floor/LUT, ma
non viene rivendicata come nuova primitiva crittografica ne' come istanza gia' coperta da quei
teoremi.

## Evidenza cifrata

### Harness preservato nel repository

I run seguenti sono stati eseguiti dopo una build esplicita del binario col primo hash riportato
sopra.

| prova | campioni corretti | dettaglio |
|---|---:|---|
| score sintetici 2..7, `T=4` | 150/150 | 25 GLWE freschi per score; 3-PBS 150/150, comparatore diretto 87/150 |
| template denso, score 3/5 | 200/200 | bound 4.061 su raggio 4.095; 100 freschi per lato; diretto 113/200 |
| discontinuita' periodiche selezionate | 147/147 | estremi, frontiera e punti adiacenti a multipli rappresentativi di 16 e 256 |
| galleria N=127, score 2..7 | 762/762 bit | una query per score, 127 confronti paralleli |

Il test Rust separato prova in chiaro **tutti** i `d in [-4095,4095]`; i 147 punti sono uno sweep
cifrato mirato, non una sostituzione della prova finita.

### Verifica avversariale indipendente

Un secondo harness temporaneo, scritto prima dell'integrazione e con implementazione separata
della stessa trasformazione, ha prodotto:

| prova | risultato |
|---|---:|
| `d=-2,-1,0,1`, 100 cifrati per valore | 400/400 |
| pipeline GLWE completa: due estremi negativi, negativo non banale `d=-4093`, positivi `d=4094/4095`, frontiera densa `d=-1/+1`, frontiera semplice `d=0/+1` | 800/800 |
| 20 chiavi fresche x 3 casi densi x 2 cifrati | 120/120 |
| 5 chiavi fresche x `d=0/+1` x 127 template | 1.270/1.270 bit |

I massimi errori di fase osservati al KSK erano circa 10,46 rotazioni nel run diretto e 9,91
rotazioni nei casi full-pipeline, sotto il guard empirico minimo di 64. Sono misure, non limiti
probabilistici.

Identificatori degli input della verifica indipendente:

| artefatto | SHA-256 |
|---|---|
| sorgente Rust del test indipendente (non incluso) | `5489fb709a65a198c90449ad9b02eef56731b0169dd10df3296523681c91be79` |
| manifest Cargo del test indipendente (non incluso) | `b440f79920239c8708cca799a3c8df6adb2097d4e0fd17d140d6192104612ef1` |
| `three_pbs_32_512_full_adversarial.log` | `bf1bf6f8ec703c1c009372c1f3df772d7c3b372afd0d1deb482c695273526eb2` |
| `three_pbs_32_512_multikey_20x2.log` | `a62ac7a601700f33cbc5305167bf547e37ae625b5b8dbc7f43297a55a191c29c` |
| `three_pbs_32_512_gallery_5keys.log` | `639c47287520d80f781b125959d4de54de6e0f0ce74821ce9b01f77283b10fd2` |

Il test indipendente e i suoi log non sono inclusi nel clone: gli hash identificano i
materiali usati, ma non consentono di rigenerarli. Il sorgente standalone incluso implementa
la costruzione e i test della prima tabella; non ricrea automaticamente le prove della seconda.

### Integrazione HTTP

La suite reale avvia `varco_demo`, genera chiavi, cifra il probe, attraversa HTTP e decifra il bit.
Nel checkpoint periodic-fold ha prodotto:

- 760/760 decisioni di frontiera/estremo in dieci invocazioni, quindi dieci chiavi fresche;
- **10/10 test** del modulo completo;
- galleria N=127 con hit agli indici interni 7, 8, 63, 64, 119 e 120, nell'ultimo slot, nessun
  hit e molti hit;
- `X-Pbs=3` a N=1, `400` a N=127 e `403` a N=128.

Il replay separato della cache DigiFace verificata ha poi rieseguito 16 volte ciascuna le cinque
probe che avevano esposto il difetto diretto, con score minimo 2, 3, 4, 5 e 7. Su una chiave
temporanea fresca ha prodotto **80/80 decisioni coerenti col chiaro**, 48 aperture e 32 rifiuti,
zero discrepanze, zero errori operativi e 80 ciphertext di probe unici. Ogni risposta riportava
`X-Pbs=400` e `experimental-periodic-fold-3pbs`; la latenza server aveva mediana 705,85 ms e p95
968,9 ms, quella HTTP mediana 706,566 ms e p95 970,086 ms sotto il carico registrato. Gli input
sono rimasti invariati durante il run e cache, scena e holdout sono stati verificati contro la
configurazione. Questo replay era successivo alla semplificazione conclusiva del sorgente del
checkpoint: registra
SHA-256 Rust `c89d5666c31c60254b2ac388169a7cc6ea6df91801de2900dbd5bf4a5940f16c`, binario release
`2b6cef1f027056ecf25ea36a671292358f70f24f4cd03a2fbe732048655b0467` e harness
`b16e11bffd7c9975edd491e10ff10752faac0537f08df58dfdc540d29ca9df69`.

Artefatti del replay:

- `fhe_digiface_periodic_fold_final_2026-09-01.csv`, SHA-256
  `07479865858b28bad361b532e622e20fd140f38032077b61879b9d6d1e791216`;
- `fhe_digiface_periodic_fold_final_2026-09-01.json`, SHA-256
  `687474237ff3eaf94e4b35d6ac49ee7eb5bfe0e6b2946206c1102281f40a17ee`.

Il replay chiude la regressione funzionale su quei cinque casi, ma non e' una valutazione
biometrica held-out completa.

### End-to-end applicativo del checkpoint periodic-fold

Una prova separata ha identificato il binario periodic-fold mediante il suo hash
e ha attraversato embedding, cifratura, server, decifratura ed endpoint client su 127 iscritti.
Ha dato **20/20 aperture e 20/20 rifiuti**, senza identita' restituite e sempre con 400 PBS:

| misura | mediana | p95 |
|---|---:|---:|
| server FHE | 647,55 ms | 1.189,6 ms |
| somma delle tappe strumentate | 828,5 ms | 1.669,4 ms |
| endpoint HTTP locale | 844,361 ms | 1.694,535 ms |

Le mediane delle singole tappe client erano 157,7 ms per embedding, 9,45 ms per cifratura e
8,3 ms per decifratura.

Il preload dei 127 template ha richiesto 19,9 s; probe ed esito erano 32.800 e 16.424 byte. Il JSON
conclusivo del checkpoint registra sorgente Rust SHA-256
`c89d5666c31c60254b2ac388169a7cc6ea6df91801de2900dbd5bf4a5940f16c`,
binario `2b6cef1f027056ecf25ea36a671292358f70f24f4cd03a2fbe732048655b0467`, client
`5a078989a45fa8df73accf36ac5963bce07312933c2fae09265fd98661904703`, harness benchmark
`70c7bcee0605311962598adae4ca0ea42c6303bf46092bc7b4f19e731befe33e`, configurazione
`eb060789a2018c9df50abbee4d1bdbf948fbcc2e5aac7e16512305a4c1f4c7db`, cache DigiFace
`1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` e manifest dei 374 file
selezionati `563bee6f660a30f05292287f1e348c7b151bf84d2fe47eb4a3c8c4a305d41408`.

Artefatti: `demo_e2e_periodic_fold_final_2026-09-01.csv`, SHA-256
`a79aba0151396ce45f6f2af28250f31b4ced63e39b5ef9379aca1a1b23c6a48c`, e
`demo_e2e_periodic_fold_final_2026-09-01.json`, SHA-256
`997140751a63d34998c924f18cc55dff6efed2a057dc94ef91cef80d9a8dbc18`. La coppia senza suffisso
`final` e' il run precedente alla semplificazione e non identifica il sorgente conclusivo del
checkpoint periodic-fold.

Questo chiudeva il gate di integrazione periodic-fold sui 40 casi scelti, non la stima statistica
di DIR/FPIR FHE, un bound di latenza, la certificazione del `p-fail` composto o il contratto
exact-ID.

## Tempo e costo strutturale

Nel log multikey, 120 confronti hanno richiesto 10,462 s incluse 20 generazioni di chiave. Nel
run standalone del checkpoint, il tempo medio sequenziale del solo comparatore era 40,97-41,79 ms
per template.

Cinque chiavi fresche, ciascuna con una galleria N=127 a `d=0` e `d=1`, hanno dato tempi
threshold-only fra 531,350 e 613,219 ms; la mediana combinata delle dieci query e' **544,447 ms**.
Questa misura comprende 381 PBS di soglia paralleli, ma **esclude** i 19 PBS dell'OR, la rete,
embedding, cifratura e decifratura. Non va presentata come latenza server o endpoint.

Il costo strutturale del servizio e':

| N | PBS di soglia | PBS OR | totale |
|---:|---:|---:|---:|
| 1 | 3 | 0 | 3 |
| 127 | 381 | 19 (`16+2+1`) | 400 |
| 128 | 384 | 19 (`16+2+1`) | 403 |

## Chiavi e traffico

Il percorso usa soltanto le chiavi gia' serializzate dal servizio:

| oggetto | byte |
|---|---:|
| evaluation key | 129.724.048 |
| client key | 23.580 |
| probe GLWE | 32.800 |
| esito globale LWE | 16.424 |
| chiavi addizionali del comparatore | 0 |

I 195.510.272 byte di chiavi WoP-PBS e il totale di circa 325,2 MB appartengono al candidato
14-PBS ritirato, non al servizio periodic-fold.

## Limite formale

Il parametro tfhe-rs dichiara sicurezza stimata 132 bit e `log2_p_fail=-71.625` per la primitiva
nominale del set. Quel numero non si trasferisce automaticamente alla catena custom: l'uscita di
un PBS viene sommata a un suo antenato, riscalata, riusata con lo stesso KSK/BSK e sottoposta ai
PBS successivi. La versione 0.11.3 non espone una certificazione della coda con queste dipendenze.
Una union bound sarebbe lecita soltanto dopo avere limiti validi per ogni stato intermedio.

Il limite e' visibile anche nel contratto interno della libreria: il set dichiara
`max_noise_level=5`; le API shortint controllano che moltiplicazione scalare e somma non superino
quel livello. Qui le primitive core bypassano il tracker e, a `log_delta=51`, il contributo fresco
del primo PBS viene moltiplicato per 16 prima del secondo fold. Il guard custom puo' compensare
questa crescita, come suggeriscono i test, ma il `log2_p_fail` nominale non certifica quello stato.

Un modello engineering condizionato a errori gaussiani/indipendenti stima un ordine per
comparatore vicino a `2^-71`, ma **non e' un bound** per questa distribuzione TUniform composta e
non viene usato per rivendicare affidabilita' di access-control. Sotto il modello di input onesto e il bound dichiarato, il rumore del prodotto GLWE
e' trascurabile rispetto alle 64 rotazioni; resta da formalizzare la catena KSK/PBS.

Condizioni indispensabili: ciphertext ben formato sotto la chiave corrispondente e chiave con la
geometria/decomposizioni PARAMS; coefficienti di
probe e template in `[-3,3]`; `||g||_1<=600`; `score_bound<=4095` a `Delta=2^51`; dimensione 512
senza alias negaciclico; periodi 32/512; esito corretto di ogni fold precedente. Il server valida
il template e rifiuta evaluation key di altri parameter set, ma non autentica il binding fra una
chiave PARAMS della stessa geometria e la secret key del client; non puo' neppure provare da solo
che un client arbitrario abbia cifrato un probe valido.

## Percorso delle alternative

1. Il PBS di segno diretto a 1 PBS/template e' stato invalidato vicino alla soglia (F68).
2. Un percorso WoP-PBS a 14 PBS/template ha funzionato nei campioni iniziali, ma era molto piu'
   lento e aggiungeva 195,5 MB di chiavi: e' preservato come tentativo ritirato.
3. La rimozione iterativa di otto bit con le sole chiavi di produzione ha ridotto il costo a
   9 PBS/template e ha superato 400/400 casi bound-near; resta il fallback conservativo, con circa
   1,93-2,43 s threshold-only a N=127 e p-fail composto ancora aperto.
4. Una fold a soli 2 PBS con `P=128` ha fallito 11/1.000 frontiere ed e' stata scartata. Due
   varianti a 4 PBS hanno superato i casi provati, ma erano piu' lente e con rapporto
   errore/margine peggiore.
5. La coppia `P=32,512` piu' segno finale ha dato il miglior compromesso osservato ed e' stata
   promossa nel servizio sperimentale.

## Comandi

Dal crate:

```bash
cd experiments/14_pipeline_tfhe_rs
cargo build --release --bin exact_comparator_scratch
cargo test --release --bin exact_comparator_scratch
shasum -a 256 src/bin/exact_comparator_scratch.rs target/release/exact_comparator_scratch

./target/release/exact_comparator_scratch --run --trials 25
./target/release/exact_comparator_scratch --run --trials 100 --bound-near
./target/release/exact_comparator_scratch --run --trials 1 --gallery
./target/release/exact_comparator_scratch --run --trials 1 --domain-sweep
```

Il secondo test avversariale richiede il proprio harness non incluso; i comandi sopra
riguardano esclusivamente il comparatore standalone disponibile nel repository.

Al termine del checkpoint, il comparatore periodic-fold era integrato nella baseline
`any_match`, con aritmetica finita corretta e replay/run applicativi positivi per quella funzione;
non era giustificato come affidabile o production-ready senza un bound p-fail composto e una
valutazione biometrica held-out attraverso FHE. Non validava l'identificazione exact-ID ed e'
stato ritirato dal percorso finale. Il binding fra evaluation key e secret key e l'onesta' del
plaintext del probe non erano imposti crittograficamente.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
