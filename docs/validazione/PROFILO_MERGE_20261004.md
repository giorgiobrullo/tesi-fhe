# Dentro un confronto cifrato — 4 ottobre 2026

Nel primo confronto della galleria N120, il costo osservato si concentra
nel **confronto delle cifre, nel refresh del controllo e nella rotazione
di selezione**. Le quattro query della diagnosi, incluso un warmup,
restituiscono gli ID corretti. Non è stata introdotta un'ottimizzazione.

| Passaggio del nodo | Einstein | Curie | Turing | Quota osservata del nodo |
|---|---:|---:|---:|---:|
| Confronto delle tre cifre | 42,85 ms | 51,49 ms | 43,16 ms | 44,67–55,83% |
| Refresh e preparazione del controllo | 16,57 ms | 16,72 ms | 30,29 ms | 16,52–31,34% |
| Differenze, allocazioni e quattro PFKS | 4,33 ms | 5,78 ms | 4,65 ms | 4,81–5,72% |
| Packing e blind rotation del gruppo | 12,99 ms | 27,19 ms | 18,51 ms | 16,93–26,87% |
| Estrazione delle quattro cifre e addback | 0,009 ms | 0,010 ms | 0,009 ms | 0,009–0,011% |
| **Nodo completo** | **76,75 ms** | **101,19 ms** | **96,62 ms** | |

Sono tre osservazioni, una per query dopo il warmup. Le quote sono
calcolate sul nodo della singola richiesta, non sul tempo dell'intero
motore. Il residuo non assegnato alle cinque fasi è circa 0,009 ms:
setup, ripristino delle cifre pubbliche e intervalli fra i timer.

Il confronto esegue tre PBS sulle cifre; la preparazione rigenera il
controllo e lo porta nella chiave usata per la selezione. PFKS prepara
le differenze cifrate del payload. Il gruppo raggruppa le tre cifre
score e la cifra bassa dell'ID e viene selezionato con una blind rotation.
Le due cifre alte dell'ID sono entrambe zero per ID1/ID2 e restano pubbliche.
La voce packing include quindi un'operazione cifrata costosa: non è
una misura isolata delle copie o dell'impacchettamento in memoria.

Questa diagnosi orienta la ricerca verso il confronto e le rotazioni.
Nel nodo osservato PFKS è circa il 5%, mentre estrazione e ripristino
occupano una frazione molto piccola. Questo non stabilisce una quota
universale per tutti i merge o una previsione di risparmio complessivo.

## Quale nodo e quale misura

Una nuova copia locale TFHE-rs 1.8.1, compilata con Rust 1.98.1, aggiunge
soltanto timer opzionali alle operazioni esistenti. Non cambia operazioni,
ordine delle cifre o contatori FHE. Il runtime mantenuto resta invariato.
La copia usa una nuova identità di circuito e una nuova famiglia di chiavi;
il servizio espone il record del nodo nell'header del profilo.

M4 Max, 16 thread, galleria N120/D512 e soglia comune 273. Il servizio
esegue warmup Einstein, poi una misura per Einstein, Curie e Turing.
Tutte le quattro risposte sono decifrate e verificate contro l'oracolo
intero. Modalità Both, narrow-ID attivo, parallelismo richiesto e
conteggi 1.111 BR, 509 PFKS, 1.080 KS, 1.709 marginali e 120 campioni iniziali.

Si misura soltanto **il merge indice 0 del livello 0**, con 120 candidati
e 60 confronti pronti: il nodo fra ID1 e ID2, anche quando il vincitore
finale della query è Turing. Le sue operazioni interne sono sequenziali
sullo stesso worker; gli altri merge del livello procedono in parallelo.
La guardia cancella il record locale al ritorno o su errore. Ogni profilo
osservato è completo, con quattro payload in un gruppo, cinque timer
positivi, somma entro il tempo del nodo e residuo coerente.

Il nodo è già incluso nel livello e nel torneo della
[profilazione delle fasi](PROFILO_RUNTIME_20261004.md).
**Non si moltiplica questo tempo per60 e non lo si aggiunge al torneo.**
I timer sono wall time e comprendono i ritardi dello scheduling sul worker.
Non descrivono la distribuzione dei tempi degli altri59merge.

Il servizio completo osserva qui 1,617/1,646/1,700 s, con una sola misura
per scena. I valori sono conservati nei dati, ma nuova chiave, copia
strumentata e condizioni del desktop rendono questa una campagna diversa.
Non è un confronto appaiato con i tempi precedenti e non dimostra che
il runtime sia diventato più veloce. Il carico non è controllato e non
si escludono campioni. Foto, browser, cifratura e decifratura sono fuori
dal timer del servizio; i casi di iscrizione non valutano nuova biometria.

[Quattro campioni](../../benchmark/merge-profile-20261004/samples.csv),
[riepilogo e hash](../../benchmark/merge-profile-20261004/SUMMARY.json),
[protocollo](../../benchmark/merge-profile-20261004/PROTOCOL.md).
Header originali, cifrati, esiti decifrati e chiavi restano nell'archivio
locale `tmp/current-merge-profile-20261004` del workspace di ricerca.
