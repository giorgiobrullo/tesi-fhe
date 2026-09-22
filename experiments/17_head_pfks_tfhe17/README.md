# 17 - Head/PFKS exact 0/ID su TFHE-rs 1.7

Questo esperimento estrae le cifre dei punteggi cifrati e seleziona il
candidato con il punteggio più basso. Restituisce il suo ID se passa la
propria soglia, altrimenti 0. I pareggi favoriscono il primo candidato.
Per seguire tutti i passaggi, vedere l'[esempio con due candidati](../../docs/come-funziona-il-confronto.md).

Head Start estrae le cifre; la selezione PFKS (*private functional key
switching*) le prepara in una rappresentazione che consente di raggrupparle.
La variante M usa cinque cifre da trasferire, divise in gruppi di tre e due
(split 3+2), con parametri PFKS 22 × 1. Con 127 candidati, l'esito è
codificato in due cifre cifrate in base 15.

## Passaggi modificati

Score cifrati → **estrazione delle cifre → selezione del minimo** →
controllo della soglia → esito cifrato 0/ID.

Il servizio parte da uno score cifrato per candidato. Deve trovare il
primo minimo, applicare la soglia del vincitore e restituire soltanto
l'esito. Per esempio, a parità fra ID 2 e ID 5 conserva ID 2; restituisce
2 se il controllo di soglia passa, altrimenti 0.

## Prima e dopo

Questa cartella confronta tre versioni, R3, H e M. Ci sono due passaggi
successivi: R3 → H cambia estrazione e selezione; H → M modifica il nodo
del torneo mantenendo lo stesso ingresso Head.

Un PBS (*programmable bootstrapping*) valuta una funzione sull'ingresso
cifrato; la blind rotation, cioè la rotazione controllata da quell'ingresso,
ne è una delle operazioni principali. La tabella distingue i conteggi.

| Passaggio | Prima | Dopo |
|---|---|---|
| Estrazione, R3 → H | R3 estrae prima la cifra bassa, poi la media dal residuo, producendo già correzione e cifra per i passaggi successivi del circuito. | H usa Head dalla cifra più significativa alla meno significativa, corregge il residuo e normalizza le uscite. |
| Ricerca del minimo, R3 → H | R3 restringe i candidati in ordine di significatività e ricava l'ID con una scansione finale degli indicatori cifrati dei candidati rimasti. | Un torneo confronta due candidati e trasferisce direttamente tre cifre dello score e due cifre dell'ID del vincitore tramite PFKS. |
| Controllo e selezione, H → M | H usa quattro PBS di confronto/controllo e un gruppo di cinque cifre, con PFKS 24 × 1. | M usa tre confronti fra cifre, ciascuno con esito minore/uguale/maggiore, e una correzione pubblica dell'errore medio del controllo, poi due gruppi 3+2, con PFKS 22 × 1. |

Il confronto R3/H misura insieme il cambiamento dell'estrazione e della
ricerca del minimo. H/M ha invece lo stesso ingresso Head. Nel nodo storico
H → M restano cinque rotazioni:
si passa da quattro più una a tre più due. Cambiano il key switching e le
estrazioni, non si elimina una rotazione netta. I guadagni misurati sotto
si riferiscono alle composizioni complete.

L'[estrazione locale](source/wrapup-head-service-20260906/core/src/split.rs)
adatta **Head Start**, di D'Anvers, Pottier, de Ruijter e Verbauwhede:
[articolo](https://eprint.iacr.org/2025/2012) e
[codice degli autori](https://github.com/KULeuven-COSIC/Head_Start).
La [selezione M](source/wrapup-head-service-20260906/core/src/m_untraced.rs)
usa PFKS per trasferire le differenze fra candidati da LWE (qui una cifra
cifrata) a GLWE (un polinomio cifrato che permette di raggruppare le cifre).
Il [nodo H](source/wrapup-head-service-20260906/core/src/h_untraced.rs)
mostra il controllo precedente; il [controllo R3](../18_scaling_soglie_miste/source/wrapup-head-mean-finalist-timing-20260906/r3-control/src/parallel.rs)
conserva il percorso di estrazione e selezione anteriore al torneo Head/PFKS.

## Metodo e risultati

Il confronto M/H/R3 usa una famiglia di chiavi nuova, due terne di
riscaldamento escluse e sei terne misurate con tutti gli ordini possibili.
Le mediane M/H/R3 sono **3,048836 / 3,071472 / 4,615544 secondi**.
La mediana della riduzione entro coppia per M è **0,7963% rispetto a H**
e **34,0848% rispetto a R3**, con 6/6 coppie favorevoli in entrambi i casi.

La verifica aritmetica distinta copre tre chiavi. Il servizio N127 supera
separatamente 15 uscite cifrate e 39 controlli negativi, con sei nuove
cifrature della query sotto una nuova famiglia. Il [riepilogo numerico](RESULTS.json)
separa questi controlli dal confronto dei tempi.

Split, base e correzione media cambiano insieme: il contributo dei singoli
interventi non è isolato. Le riduzioni entro coppia non sono rapporti delle
mediane e non si sommano agli esperimenti successivi. Il confronto usa input
full51 adattati per R3; non equivale al suo servizio con input nativi full52.
Le prove non stabiliscono la probabilità globale di fallimento del circuito.

## Codice e compilazione

La [libreria Rust](source/wrapup-head-service-20260906/core/src/lib.rs) espone
il core; il [servizio](source/wrapup-head-service-20260906/candidate/Cargo.toml)
lo integra. Il controllo A126 è in una cartella sorella richiesta dai path
Cargo. Il core M richiede input nativi full51/low60; le codifiche non si
cambiano rinominando o dimezzando ciphertext già prodotti.

Con Rust e le dipendenze TFHE-rs 1.7.0 del lockfile, da questa cartella:

```sh
cargo build --release --locked \
  --manifest-path source/wrapup-head-service-20260906/candidate/Cargo.toml \
  --target-dir .local/target-service
```

La generalizzazione a taglie e soglie diverse è nell'[esperimento 18](../18_scaling_soglie_miste/README.md).
Per l'applicazione client/server usare la [demo 22](../22_demo_composita/README.md).
Questa cartella conserva l'esperimento su TFHE-rs 1.7; la versione e le
successive modifiche adottate sono descritte nel [runtime mantenuto](../../runtime/README.md).

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
