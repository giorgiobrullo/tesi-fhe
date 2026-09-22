# 20 - Normalizzatori derivati dal riporto e composizione classica

Qui si riduce il lavoro per separare una cifra dal suo riporto, durante
l'estrazione dei punteggi. L'[esempio con due candidati](../../docs/come-funziona-il-confronto.md)
mostra come queste cifre arrivano al risultato finale.

## Passaggio modificato

Score cifrati → **estrazione e normalizzazione delle cifre** → torneo
(confronto e selezione) → controllo della soglia → esito cifrato 0/ID.

Interveniamo sui due normalizzatori usati da [Head](../17_head_pfks_tfhe17/README.md),
prima che le cifre degli score entrino nei confronti. Ciascuno separa un
intermedio in una cifra bassa e un riporto alla posizione successiva.
La *blind rotation* citata sotto è una rotazione di tabella controllata
dall'ingresso cifrato, senza rivelarlo.

## Prima e dopo

| Operazione | Prima: normalizzatori separati | Dopo: normalizzatori condivisi |
|---|---|---|
| Una coppia cifra/riporto | Una blind rotation per la cifra bassa e una per il riporto. | Una blind rotation per il riporto; dalla stessa tabella cifrata si ricava anche la cifra bassa con trasformazioni lineari. |
| Le due coppie di uno score | Quattro blind rotation. | Due blind rotation più le trasformazioni lineari. |
| Uscita verso il torneo | Cifre normalizzate dello score, ancora cifrate. | Stessi valori e stessa rappresentazione attesa dal confronto. |

Il risparmio riguarda due di queste operazioni per score nella modalità `both`;
le trasformazioni lineari aggiunte hanno un costo, incluso nelle misure.
Il lavoro viene riutilizzato fra le due uscite dello stesso intermedio.

### Esempio

Il normalizzatore separa `r` fra 0 e 31 in `r % 16` e `r / 16`, con
divisione intera. Per `r = 21`, le uscite rappresentano cifra 5 e riporto 1,
perché `21 = 5 + 16 × 1`. Prima si valutavano due tabelle separatamente;
dopo si usa la rotazione della tabella del riporto per ottenere entrambe
le uscite cifrate. La trasformazione agisce su tutte le componenti
dell'accumulatore GLWE (un polinomio cifrato), prima di estrarre le due
uscite LWE (qui una cifra cifrata ciascuna).

Le [mappe del componente](evidence/NORMALIZER_ERROR_MAPS.md) descrivono
la trasformazione e il rumore osservato. Il confronto completo combina
questo intervento con comparatori paralleli e soglie pubbliche: sotto
sono separati il costo del componente e quello della composizione.

I sorgenti e i risultati qui conservati usano TFHE-rs 1.7. Per il percorso
mantenuto: [runtime](../../runtime/README.md),
[implementazione dei normalizzatori](../../runtime/core/src/shared_normalizers.rs)
e [punti di utilizzo in Head](../../runtime/core/src/split.rs).

## Metodo e risultati

Il confronto isolato del carry misura **12,39% di riduzione**, 24/24 coppie
favorevoli su una chiave. Lo sweep copre 4096 valori, quattro modalità e tre
chiavi: **49.152 estrazioni e 384 selezioni**. I limiti derivati dai vettori
di errore osservati sono condizionali, non probabilità globali di fallimento.

La conferma dei comparatori classici paralleli dà **6,51%**, 56/56 coppie su
due nuove chiavi. La composizione di carry, confronto parallelo e soglie
pubbliche dà **19,24% nella seconda famiglia**, 28/28 coppie; lo screening
precedente distinto dà 20,82%. Entrambi i riferimenti avevano già i tagli ID.
Il carry è incorporato nella composizione: i guadagni non si sommano.

Le mappe fuse sono circa **0,14% più lente** e il batch classico del selettore
circa **0,34% più lento** nei rispettivi screening. Un primo controllo della
LUT è risultato troppo restrittivo per una rappresentazione equivalente;
la sua correzione è distinta dalle modifiche al circuito.

| Dati | Contenuto |
|---|---|
| [Risultati](RESULTS.json) | Confronti e limiti |
| [Tempi del normalizzatore](evidence/normalizer-timing.json) | Confronto isolato |
| [Sweep su tre chiavi](evidence/THREE_FAMILY_RESULT.json) | Correttezza e rumore osservato |
| [Conferma classica](evidence/classic-confirmation.json) | Confronto del parallelismo |
| [Composizione](evidence/night-composition.json) | Risultato della combinazione |
| [Mappe di errore](evidence/NORMALIZER_ERROR_MAPS.md) | Trasformazioni lineari e limiti condizionali |

Le misure conservano carico esterno e un numero limitato di chiavi. Una
mappa esatta dei coefficienti non dimostra indipendenza degli errori né
una probabilità di fallimento per il circuito composto.

## Sorgenti e compilazione

| Workspace | Funzione |
|---|---|
| [carry-packed](sources/carry-packed/Cargo.toml) | Circuito completo e confronto dei tempi |
| [carry-sweep](sources/carry-sweep/Cargo.toml) | Sweep esteso |
| [carry-gate](sources/carry-gate/Cargo.toml) | Controllo della LUT effettiva |
| [composite-classic](sources/composite-classic/Cargo.toml) | Composizione del normalizzatore e del parallelismo |

Servono Rust e le dipendenze del lockfile, fra cui TFHE-rs 1.7.0.
Da questa cartella, per compilare il circuito completo:

```sh
cargo build --release --locked --manifest-path sources/carry-packed/Cargo.toml \
  --target-dir .local/target-carry
```

La [demo 22](../22_demo_composita/README.md) integra questa linea di lavoro
con le successive ottimizzazioni.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
