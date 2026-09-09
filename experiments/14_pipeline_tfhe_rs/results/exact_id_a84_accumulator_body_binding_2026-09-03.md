# A84 — binding dei body degli accumulatori A53/A62

Data: 2026-09-03  
Ambito: analisi statica/source-only; nessuna compilazione Cargo, generazione di
chiavi o operazione FHE.

## Domanda

A79 vincola tramite digest il manifest, la trace e gli artefatti dichiarati, ma
il suo `accumulator_spec` descrive ancora soltanto metadati: non dimostra che il
polinomio usato dal bootstrap implementi davvero la LUT dichiarata. A84 verifica
se questo ponte può essere reso meccanico per gli accumulatori A53 usati dalla
pipeline A62/A66 a `N=127`.

## Esito

**GO strutturale/source-level. NO-GO come attestazione runtime o chiusura del
bound end-to-end.**

Il prototipo costruisce deterministicamente i body previsti dai sorgenti Rust
pin-nati, li serializza come coefficienti `u64` little-endian, li lega a truth
table congiunte input→output e li rivaluta su tutto il plateau robusto. Il
verificatore richiede inoltre il digest del manifest come input indipendente.

Risultato riproducibile:

| Controllo | Risultato |
|---|---:|
| Source pin verificati | 9 |
| Body/spec distinti a N=127 | 35 |
| Polinomi condivisi OR/local-first/identity | 3 |
| Selettori dual-sample | 32 |
| Coefficienti body verificati | 71.680 |
| Byte canonici del bundle | 573.440 |
| Confronti torus esatti sul plateau | 78.105 |
| Record confrontati col modello Python A53 indipendente | 35/35 |
| Contratti/campioni accettati e confrontati dal parser A79 reale | 35/67 |
| Test avversariali | 23/23 PASS |
| Ruff | PASS |

Status emesso dal verificatore:

```text
PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES
```

### Correzioni emerse dall'audit

La prima bozza A84 non superava il parser A79 reale: dichiarava il modulus con
l'alias `native`, mentre il contratto A44 richiede esattamente `native_u64`.
Inoltre il self-verifier controllava che la reachable overapproximation
contenesse le fasi necessarie, ma non ne rifiutava valori extra fuori periodo.
Entrambi sono stati trattati come blocker, non come dettagli documentali: il
manifest precedente è stato rigenerato, il range è ora fail-closed e ogni
verifica A84 invoca anche il parser A79 pin-nato. I digest riportati qui sotto
identificano soltanto la versione corretta.

## Cosa viene vincolato

Per ogni record il manifest A84 contiene:

- `body_id` content-addressed, offset, lunghezza e SHA-256 dei 2.048
  coefficienti;
- codec esplicito `u64-le-v1`, così endianness e rappresentazione non dipendono
  dalla piattaforma;
- `contract_id` separato dal body e valutatore
  `a53-raw-negacyclic-no-half-box-v1`;
- digest dell'intero GLWE pre-rotazione atteso, cioè una maschera di 2.048 zeri
  seguita dal body, coerente con `glwe_size=2` e con la costruzione tramite
  `allocate_and_trivially_encrypt_new_glwe_ciphertext`;
- una truth table congiunta per fase di input. Ogni riga mantiene assieme i due
  output del selettore, il grado di estrazione (`0`/`1024`) e l'offset pubblico
  applicato dopo l'estrazione;
- una proiezione compatibile con i campi dell'accumulatore
  `a79.manifest.v3`, inclusi dominio small-LWE A44, encoding, margine e reachable
  overapproximation. La proiezione completa viene inoltre passata al vero
  `_manifest_accumulators` A79 pin-nato e i 35 contratti/67 campioni risultanti
  vengono confrontati post-parse su modulus, input reachable, numero e gradi
  dei campioni, output reachable ed etichetta dell'encoding. Gli altri campi
  sono controllati dal self-verifier A84 e devono comunque essere accettati dal
  parser A79.

Il confronto semantico usa i word torus a 64 bit esatti. Non è sufficiente che
il coefficiente decodifichi nello stesso residuo: anche un bias di un singolo bit
viene rifiutato. Le fasi negative dei selettori, il wrap negaciclico e gli
offset distinti dei gruppi sono inclusi.

## Provenienza

Sono pin-nati per SHA-256:

1. la logica A53 delle copie A62 e A66, che è byte-identica;
2. il modello Python A53 precedente usato come secondo oracolo;
3. gli adapter A62 raw e A66 prepared;
4. i backend A62 e A66 che trasformano `torus_body` nel GLWE e fanno blind
   rotation/sample extraction;
5. il parser manifest A79 v3 e il suo modello tipizzato del crypto domain.

Questo rende rilevabile sia un drift della logica sia un cambio del collegamento
tra body e backend. A66 cambia preparazione/riuso e scheduling, non la semantica
dei body rispetto ad A62.

## Test avversariali

La suite rifiuta, fra gli altri:

- flip di un bit, truncation, append, offset sovrapposti e inversione endianness;
- una sostituzione coerentemente ri-hashata ma diversa dal costruttore pin-nato;
- modifica di una riga della truth table o di un offset pubblico;
- sostituzione di `body_id` o `contract_id`;
- esclusione di un input/output reale dalla reachable overapproximation A79;
- alias errato `ciphertext_modulus="native"` invece dell'esatto `native_u64`;
- reachable input fuori periodo (ad esempio `999`), sia nel self-verifier A84
  sia chiamando direttamente il parser A79 reale;
- modalità PBS, unità/raggio del margine o gradi di estrazione errati;
- maschera GLWE non zero o digest dell'intero GLWE errato;
- modifica del manifest mantenendo il vecchio digest atteso;
- drift del file sorgente o scomparsa di un frammento pin-nato.

La suite esercita esplicitamente le fasi `-4..4`, entrambi i campioni e tutti i
127 errori interi del plateau `[-63,+63]`. Non certifica `±64`.

## Limite della prova

I byte sono quelli **attesi e ricostruiti dai sorgenti pin-nati**, non byte
catturati da un processo reale. Il digest del GLWE atteso non dimostra che il
binario compilato abbia istanziato o usato quell'oggetto. Inoltre A84 non prova:

- che una trace sia stata emessa dal binario pin-nato;
- che ogni chiamata runtime passi dal wrapper auditato;
- che tutti i 3.390 blind rotation A62 compaiano nella trace completa;
- che gli input runtime restino nei domini certificati delle LUT;
- la probabilità che lo spostamento dopo modulus switching resti entro ±63;
- un `p_fail` end-to-end non banale.

Di conseguenza A84 non autorizza a cambiare il confine corretto di A79:
`execution_attested=false`, obblighi runtime aperti e bound incondizionato
`P_fail <= 1`.

## Gate successivo

La prosecuzione concreta è strumentare il wrapper Rust tipizzato: immediatamente
prima di ogni blind rotation deve calcolare lo SHA-256 dell'intero GLWE reale
pre-rotazione (`mask || body`), emettere il relativo `contract_id` e collegare
l'evento a manifest, binario e input domain. Un gate statico deve inoltre
rifiutare chiamate raw dirette che aggirino il wrapper. Questo chiuderebbe il
ponte source→runtime; copertura completa della topologia e premessa probabilistica
del margine resterebbero obblighi separati.

## Artefatti e digest

- Directory: `tmp/a84-accumulator-body-binding/`
- Bundle SHA-256:
  `836f783ea806758bc0a4cb553e1870f58934260ec3ddfb5b1acbcb119305730e`
- Manifest canonical-JSON SHA-256 richiesto dal verificatore:
  `4b9eca2418fa17c4aed1009cf6ea8c5d8777d082f8eb280bc33177967fdbb12b`
- SHA-256 del file JSON pretty-printed:
  `a11bed233e1fe9afe113b93386aaebb5c4e2d9512903a0ac0245f5414ec4fb22`
- Tutti gli hash dei file principali sono in `SHA256SUMS`.

Comando di verifica:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  tmp/a84-accumulator-body-binding/a84_accumulator_binding.py verify \
  --manifest tmp/a84-accumulator-body-binding/artifacts/a84_a53_n127_manifest.json \
  --bundle tmp/a84-accumulator-body-binding/artifacts/a84_a53_n127_accumulator_bodies.bin \
  --expected-manifest-sha256 4b9eca2418fa17c4aed1009cf6ea8c5d8777d082f8eb280bc33177967fdbb12b
```
