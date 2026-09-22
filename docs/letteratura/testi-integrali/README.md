# Approfondimento sui testi integrali

[Indice della rassegna](../../../letteratura.md) · [Metodo](../metodo-ricerca.md) · [Bibliografia](../aggiornamento-20260919.bib)

**19 settembre 2026.** Questo passaggio approfondisce 23 articoli, ora tutti
disponibili in PDF, incluse le edizioni pubblicate HEArgmax con appendice
e Akbari. Sono state lette le sezioni pertinenti ad algoritmi, ipotesi,
protocollo e risultati; formule e tabelle decisive dei PDF sono state anche
controllate visivamente. Non si dichiara una verifica completa di tutte le
prove né una replica sperimentale. La rassegna resta narrativa e ampliabile.

**Aggiornamento del 22 settembre:** verificati frontespizio, abstract e
tabelle 5–6 dell'edizione finale TCHES della compensazione della media,
distinta dal preprint nella [scheda TFHE](tfhe.md#compensazione-della-media).
Per FDFB ricorsivo sono verificati metadati e abstract dell'edizione Springer;
la lettura tecnica rimane sul preproceedings. Il numero di articoli resta 23.

## Letture e copertura

| Scheda | Articoli | Accesso e profondità |
|---|---:|---|
| [Primitive TFHE](tfhe.md) | 8 | PDF Head, Tetris, mean compensation, Sharing the Mask, Chen, RevHomTrace, FDFB e RevoLUT; costruzioni, rumore e misure |
| [CKKS e confronti](ckks.md) | 7 | Cinque PDF sul CKKS discreto, Lee minimax e Mazzone USENIX con appendice; rappresentazioni, margini e costi |
| [Privacy e indicizzazione](privacy-e-indicizzazione.md) | 4 | PDF Kluczniak, Ducas corretto, Rahimi e Drozdowski; modelli, ipotesi e risultati |
| [Sistemi biometrici](sistemi.md) | 4 | PDF HEFT, SCiFI, Akbari editoriale e HEArgmax completo di appendice |

Versioni multiple e supplementi non sono conteggiati come articoli diversi.
Le schede indicano pagine e fonti; gli hash e i tentativi d'accesso sono
conservati nel registro locale della ricerca. I PDF sono copie di consultazione,
non redistribuiti dentro questa versione del repository.

## Correzioni che incidono sul racconto della tesi

- Tetris include confronti specializzati cifrato/cifrato a 32 bit: la
  precedente lettura del limite delle LUT generali era troppo restrittiva.
- Head assume indipendenza nel modello del rumore; le cifre intermedie
  DirtyMSB non sono automaticamente canoniche. Il port e il consumatore
  locale richiedono condizioni proprie.
- I tempi CKKS distinguono batch, costo ammortizzato e canonicalizzazione.
  Mazzone tratta i pareggi stabili, pur con una valutazione approssimata
  i cui margini vanno qualificati.
- La sanitizzazione di Ducas–Stehlé va citata con la correzione del 2025;
  Kluczniak distingue il campionatore della prova da una variante euristica.
- Rahimi non misura la decisione binaria cifrata completa nel tempo
  dell'attacco. Drozdowski mostra un compromesso fra lavoro e accuratezza.
- HEFT/Akbari restituiscono gli score al client; i loro tempi riassuntivi
  non sono internamente uniformi. SCiFI distingue funzionalità proposta
  e implementazione effettivamente misurata.

Per una tesi sperimentale, queste letture motivano le scelte e gli obblighi
rimasti aperti: non trasformano la sola presenza di una tecnica in un
miglioramento misurato. Le letture del 19 settembre sono integrate dai
controlli di versione del 22 settembre descritti sopra; anche il raccordo
con il progetto è aggiornato. Il caso storico
della variante Head generale è stato [diagnosticato nel selettore](../../selector-repair-20260920.md),
con le estrazioni Head corrette in quella istanza. Il [runtime mantenuto](../../../runtime/README.md)
usa ora la correzione e pack4, le cui prove sono indipendenti dai paper.
Le letture non modificano i dati delle campagne locali.

## Due nuovi PDF verificati

- [HEArgmax, edizione pubblicata](heargmax-edizione-pubblicata.md):
  11 pagine, incluse le sezioni A.1–A.3 e le prove in A.3. L’audit identifica controesempi
  nel modello aritmetico ideale alla garanzia di sola uscita argmax e
  problemi nella giustificazione del mascheramento. Specifica, margini
  CKKS, pareggi e contabilità richiedono chiarimenti prima di adottarne
  le garanzie o i numeri. Nessun attacco software eseguito.
- [Akbari, edizione pubblicata](akbari-edizione-pubblicata.md):
  15 pagine, pp. 573–587. Le tabelle confermano il costo per-match e
  la discrepanza del tempo complessivo dichiarato in conclusione.
  Le metriche principali e quelle delle ablation sono distinte.

**È disponibile un PDF per ciascuno dei 23 articoli nelle versioni indicate.**
Questo non equivale ad avere confrontato tutte le edizioni finali: per FDFB
ricorsivo il controllo editoriale resta limitato a metadati e abstract.
Disponibilità e lettura
mirata non equivalgono alla chiusura delle questioni scientifiche o alla
completezza universale della rassegna. I precedenti tentativi falliti sono
conservati nel registro storico; non descrivono più lo stato d’accesso attuale.

L'eventuale versione estesa SCiFI citata nell'appendice sarebbe utile solo
per approfondire la costruzione con soglie individuali. Il PDF conferenza
con appendice è già disponibile. Altre famiglie adiacenti, elencate nel
[metodo](../metodo-ricerca.md), restano possibili estensioni del corpus,
non lavori implicitamente verificati da questo approfondimento.
