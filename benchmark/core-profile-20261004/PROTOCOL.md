# Profilazione TFHE-rs 1.8.1 — 4 ottobre 2026

Una copia del runtime corrente espone i timer esistenti di punteggi, Head,
torneo, controllo finale e livelli. Cambia soltanto il servizio HTTP;
il core cifrato è identico e il runtime mantenuto non viene modificato.
La copia ha un proprio binding e una nuova famiglia di chiavi.

M4 Max, 16 thread, Rust 1.98.1, N120/D512, soglia comune 273. Tre query
intere già calcolate da foto di iscrizione: Einstein, Curie e Turing.
Ogni query è cifrata una volta; entrambe le condizioni usano esattamente
lo stesso binario, chiave e input cifrato.

Quattro blocchi off/on, on/off, off/on, on/off, con un nuovo processo per
condizione/blocco. Ogni processo esegue un warmup e due misure per scena:
24 warmup e 48 misure, 72 risposte totali. Tutte sono decifrate e confrontate
con il primo minimo intero e la soglia inclusiva del solo vincitore.
I test offline del driver precedono la campagna. Nessun campione è scartato.

Nel CSV, filtrare `phase=measured`; per le fasi aggiungere `arm=on`.
Per ogni scena/blocco: mediana delle due richieste on e delle due off,
rapporto on/off, poi mediana dei quattro rapporti. Un rapporto maggiore
di uno indica più tempo con il flag on nella copia.
Il riepilogo conserva separatamente il tempo HTTP.

Le durate di fase e dei livelli sono tempi wall del coordinatore, con i
worker completati prima della chiusura del timer. I livelli sono compresi
nel torneo. La percentuale di una fase è la mediana del suo rapporto con
evaluate in ciascuna delle 24 richieste on; le mediane marginali dei tempi
non vanno sommate per ricostruire la mediana totale.

Il timer del servizio esclude avvio, iscrizione, cifratura e decifratura.
La serializzazione dell'header di profilo avviene dopo X-Tempo-Ms e compare
nel timer HTTP. Si confronta il flag nella stessa copia, non il costo
complessivo della patch rispetto al runtime mantenuto.

Una famiglia, tre query fisse e carico desktop non controllato: nessun
intervallo di confidenza, garanzia sul costo della profilazione, miglioramento
del runtime o probabilità di errore raro. Nessun tempo di foto/browser/webcam.

SUMMARY.json contiene configurazione, conteggi, hash del CSV e delle fonti.
Le 72 righe conservano warmup, esiti, tempi e livelli. I record HTTP,
cifrati e chiavi sono conservati nell'archivio locale di ricerca.
