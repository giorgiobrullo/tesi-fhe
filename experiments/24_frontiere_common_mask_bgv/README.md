# 24 - Common-mask Joint4 e BGV

Questi prototipi esplorano due costruzioni alternative al core Head/PFKS.
Entrambe partono da query cifrate e cercano un esito 0/ID, ma usano
rappresentazioni, parametri e gallerie di prova propri. Non sono componenti
intercambiabili della demo.

## Common-mask: cambiare la preparazione degli ingressi

Query cifrata → score → **correzioni e bit per il selettore common-mask**
→ selezione dei candidati → ID cifrato o zero.

*Common-mask* indica il riuso della stessa parte di maschera del ciphertext
fra controlli correlati, per condividerne il lavoro. Joint4 cambia il
produttore degli ingressi di quel selettore: ricava insieme correzioni e
bit da una stessa tabella cifrata. La blind rotation è l'operazione che
ruota la tabella in base all'ingresso cifrato, senza decifrarlo.

| Passaggio | Prima | Proposta Joint4 |
|---|---|---|
| Preparazione degli score per il common-mask | Il produttore precedente estrae i bit in successione, correggendo il residuo tra i passaggi. | Le estrazioni congiunte riuniscono correzioni e bit, riducendo le rotazioni del produttore. |
| Selezione e uscita | Selettore common-mask seguito dalla scansione degli indicatori dei candidati. | Lo stesso percorso restituisce due cifre ID cifrate in base 15. |

Il [produttore Joint4](sources/common-mask-timing/src/joint_untraced.rs)
e gli [endpoint confrontati](sources/common-mask-timing/src/endpoint.rs)
mostrano quale parte cambia. Il miglioramento rispetto al precedente
common-mask non basta: nel pilot Joint4 resta più lento di R3, il riferimento
TFHE che estrae cifre e restringe i candidati. Non viene scelto come percorso
più veloce.

## BGV: provare il grafo completo con un altro schema

Query cifrata → score → confronti e selezione in BGV → codici terminali.

BGV esegue aritmetica modulare su interi e può disporre molti valori nelle
posizioni, o *slot*, di un cifrato. Il [prototipo](sources/bgv/src/main.cpp)
include sia il calcolo degli score sia il loro utilizzo nella selezione;
non parte da score già forniti in chiaro. L'uscita verificata è un insieme
di valori negli slot, non il formato a tre LWE del servizio TFHE.

La costruzione precedente esauriva il margine di rumore ammesso dalla
libreria. La prova qui conservata usa un anello più grande, con parametri
e disposizione dei dati differenti, per verificare se il calcolo completo
rimane ammissibile. `phi(m)` indica la dimensione dell'anello; la capacità
in bit è un indicatore del margine residuo riportato da HElib, non un tempo
di esecuzione. Il nuovo grafo passa i controlli descritti sotto, ma non è
stato misurato un vantaggio di latenza rispetto a TFHE.

## Risultati

**Common-mask Joint4:** il circuito completo passa quattro scene N16,
compresi pareggi e rifiuto. Un pilot distinto usa una scena N16, una chiave
e quattro coppie misurate. La mediana delle riduzioni entro coppia è
**17,774834% rispetto al precedente common-mask**; Joint4 resta però
**24,567076% più lento di R3**. Non viene selezionato come percorso più veloce
né estrapolato a N127.

<a id="misure-salvate-integrazione-del-6-ottobre-2026"></a>

Le [osservazioni del pilot common-mask](evidence/common-mask-timing.json)
conservano il confronto Joint4/common-mask/R3.

**BGV:** il grafo con phi(m)=65536 passa 210 stadi ammessi e tutti i 32.768
valori terminali, su una chiave e scene N8/8/8/4. La capacità finale è
**575,184 bit**; HElib riporta **135,336 bit di sicurezza**. La chiave pubblica
serializzata misura 3.150.947.064 byte, che non sono RSS.

La decifratura BGV osservata riguarda una copia diagnostica con `noiseBound`
impostato a zero. L'intervento non è necessario per l'ammissione: il ciphertext
originale era già `isCorrect=true` e tutti i suoi stadi avevano capacità
positiva. Il grafo precedente con anello più piccolo fallisce invece
l'ammissione, con capacità finale **−6,537 bit**, pur producendo valori
terminali diagnostici corretti. I risultati sotto contesti differenti non
costituiscono una sottrazione causale delle capacità.

Nessuno di questi test misura il vantaggio di BGV sulla latenza TFHE,
la correttezza a N127 o una probabilità globale di errore.
[Dati riepilogativi](RESULTS.json) e [rapporto BGV](evidence/BGV_FINAL_REVIEW.md).

## Codice e dipendenze

Sono disponibili il [worker common-mask](sources/common-mask-timing/Cargo.toml),
il [prefisso](sources/common-mask-prefix/Cargo.toml) e il
[grafo BGV](sources/bgv/src/main.cpp). Il pacchetto comprende il
[riferimento R3](sources/r3/candidate/Cargo.toml), gli input deterministici,
il piano del confronto e le tabelle pubbliche incluse dai sorgenti.
La baseline è riusata dal [pacchetto 17](../17_head_pfks_tfhe17/source/baseline-20260905-tfhe17/candidate/Cargo.toml):
i sette file di sorgente e input richiesti coincidono con quelli originali
e sono condivisi fra i due pacchetti.

Dalla radice della repository, con Rust 1.98.1:

```sh
rustup run 1.98.1 cargo build --release --locked \
  --manifest-path experiments/24_frontiere_common_mask_bgv/sources/common-mask-timing/Cargo.toml \
  --target-dir .local/target-common-mask
```

Il worker genera nuove chiavi e richiede un percorso assoluto nuovo per il
log, dentro una directory con permessi `0700`. Prima dell'esecuzione richiede
`RAYON_NUM_THREADS=8`, `CM_NIBBLE_N16_TIMING_ACK=ROOT_EXCLUSIVE_CM_NIBBLE_N16_TIMING`,
`CM_NIBBLE_N16_TIMING_SOURCE` uguale al contenuto di
[SOURCE_DIGEST.txt](sources/common-mask-timing/SOURCE_DIGEST.txt) e
`CM_NIBBLE_N16_TIMING_BINARY` uguale allo SHA-256 del binario appena compilato.
L'invocazione è `BINARIO --run PERCORSO_ASSOLUTO_NUOVO.jsonl`.
Il digest sorgente incorporato identifica la revisione sperimentale; le
impronte della distribuzione attuale sono nel manifest di provenienza.

BGV richiede HElib 2.2.0, l'header esterno `json.hpp` e CommonCrypto su macOS.
CMake cerca l'header installato; per una posizione non standard usare
`-DNLOHMANN_JSON_INCLUDE_DIR=/directory/che/contiene/json.hpp`. Dalla radice del repository:

```sh
cmake -S experiments/24_frontiere_common_mask_bgv/sources/bgv \
  -B .local/build-bgv -DCMAKE_BUILD_TYPE=Release
cmake --build .local/build-bgv
```

Il file [PUBLIC_SLOTS.json](sources/bgv/PUBLIC_SLOTS.json), necessario anche
durante l'esecuzione BGV, è incluso e coincide con l'impronta incorporata
nel programma. `BGV_LR_N8_SOURCE_DIR` deve indicare la directory assoluta
`sources/bgv`; il programma documenta e verifica gli altri vincoli
nell'[ingresso](sources/bgv/src/main.cpp).

Il [manifest dei sorgenti e degli input](PROVENANCE.json) identifica
anche i file condivisi e quelli richiesti tramite inclusione. I percorsi
Cargo e gli input dei quattro crate sono stati verificati con i metadati
Cargo offline; questa verifica della distribuzione non è una nuova build FHE.
Per un servizio interattivo consultare il [runtime](../../runtime/README.md).
Il [primo PoC common-mask](../16_common_mask_poc/README.md) introduce il filone.

## Provenienza

La [provenienza dei sorgenti e delle misure](PROVENANCE.json) lega i file
alle fonti originali e dichiara le selezioni dei dati. Le impronte delle
copie pubbliche sono distinte da quelle degli originali.
