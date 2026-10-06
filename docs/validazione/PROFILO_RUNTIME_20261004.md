# Dove il runtime impiega il tempo — 4 ottobre 2026

Nel motore TFHE-rs 1.8.1 con galleria di 120 persone, **torneo e Head
occupano quasi tutto il calcolo**. Le 72 richieste della profilazione
restituiscono gli ID corretti. Questa misura individua i passaggi da
ottimizzare; non introduce ancora un'accelerazione.

| Passaggio | Cosa fa | Tempo mediano | Quota mediana per richiesta |
|---|---|---:|---:|
| Punteggi | Combina la query cifrata con i template pubblici | 6,3 ms | 0,32% |
| Head | Estrae le cifre dei 120 punteggi | 805,4 ms | 41,44% |
| Torneo | Confronta i candidati e trasferisce score e ID del vincitore | 1.087,3 ms | 55,90% |
| Finale | Confronta il minimo con la soglia e seleziona ID oppure 0 | 44,3 ms | 2,28% |

Le colonne usano le **24 richieste misurate con profiling attivo**.
Le percentuali sono mediane dei rapporti fase/evaluate di ogni richiesta.
Le mediane marginali non sono additive: non ricostruiscono esattamente il
totale mediano di evaluate, 1.928,0 ms. Il residuo non assegnato alle quattro
fasi ha mediana 0,49 ms. Sono tempi wall del coordinatore, non somme dei worker.

Il torneo comprende sette livelli, osservati in tutti i 24 profili:

| Candidati prima del livello | Confronti | Tempo mediano del livello |
|---:|---:|---:|
| 120 | 60 | 464,7 ms |
| 60 | 30 | 250,6 ms |
| 30 | 15 | 131,4 ms |
| 15 | 7, più un candidato riportato | 95,9 ms |
| 8 | 4 | 53,3 ms |
| 4 | 2 | 45,3 ms |
| 2 | 1 | 44,3 ms |

Questi intervalli sono **già inclusi nel torneo**. Le loro mediane non si
aggiungono alla tabella delle fasi. I primi livelli offrono più confronti
indipendenti; il finale ha un solo confronto. Il profilo misura i livelli,
non separa ancora il costo di ogni blind rotation, PFKS, key switch o copia.
La [diagnosi di un singolo confronto](PROFILO_MERGE_20261004.md) separa
i passaggi di un nodo, con un campione e un timer diversi.

## Misura e controllo della strumentazione

Una copia del runtime espone nell'header HTTP gli hook di profilazione già
presenti. Il core cifrato non cambia; il runtime mantenuto resta invariato.
La copia usa una nuova identità di circuito e una nuova famiglia di chiavi.

Su M4 Max/16 thread, Rust 1.98.1, N120/D512/T273, si alternano quattro
blocchi off/on, on/off, off/on, on/off. Binario, chiave e tre ciphertext
Einstein/Curie/Turing sono identici fra le condizioni. Otto nuovi processi
eseguono 24 warmup e 48 misure. Tutte le 72 risposte, warmup compresi,
sono decifrate e concordano con l'oracolo intero del primo minimo e della
soglia inclusiva del vincitore. I conteggi restano 1.111 BR, 509 PFKS,
1.080 KS, 1.709 estrazioni marginali e 120 campioni iniziali.

La mediana dei quattro rapporti on/off delle mediane di blocco è:

| Query | Tempo del servizio con profiling / senza profiling |
|---|---:|
| Einstein | 1,0167 (+1,67%) |
| Curie | 0,9957 (−0,43%) |
| Turing | 1,0407 (+4,07%) |

Questi valori comprendono la variabilità fra processi e del desktop.
Il blocco Curie finale osserva +12,71%, mentre altri rapporti sono sotto
uno; nessuna osservazione viene eliminata. **Non sono una stima precisa
dell'overhead universale dei timer.** Si confronta il flag nella stessa
copia, non tutta la patch rispetto al runtime mantenuto.

Il timer principale è X-Tempo-Ms, con il confine del servizio già esistente.
Avvio, iscrizione, cifratura e decifratura sono esclusi. L'header JSON del
profilo viene serializzato dopo quel timer; il tempo HTTP è conservato
separatamente per includere anche questa parte. La misura non comprende
l'elaborazione della foto né il browser; per questi intervalli vedere il
[rapporto della demo](DEMO_SSE_20261004.md).

Una sola famiglia di chiavi, tre query fisse di iscrizione e un host:
il risultato descrive questi casi e non un limite sugli errori rari,
una nuova verifica biometrica o un'accelerazione dimostrata. Il carico
del desktop non è controllato. La prossima modifica va verificata sui
passaggi Head/torneo prima di attribuirle un risparmio.

[72 campioni](../../benchmark/core-profile-20261004/samples.csv),
[riepilogo e hash](../../benchmark/core-profile-20261004/SUMMARY.json),
[protocollo di ricalcolo](../../benchmark/core-profile-20261004/PROTOCOL.md).
Header HTTP, cifrati, esiti decifrati e ricevute rimangono nell'archivio
locale `tmp/current-core-profile-20261004` del workspace di ricerca.

## Quante operazioni richiede la query — 5 ottobre 2026

La lettura dei callsite attivi permette di separare i totali già registrati
nel profilo. Per N120/D512, soglia comune 273 e configurazione corrente:

| Passaggio | Blind rotation | Key switch | PFKS | Estrazioni |
|---|---:|---:|---:|---:|
| Head, compresi i normalizzatori | 480 | 480 | 0 | 720 |
| Torneo | 626 | 595 | 507 | 983 |
| Controllo della soglia e uscita 0/ID | 5 | 5 | 2 | 6 |
| Totale | 1.111 | 1.080 | 509 | 1.709 |

Una **blind rotation** valuta la LUT cifrata; un **key switch** cambia la
chiave con cui è rappresentato il dato. La **PFKS** prepara una cifra per
il selettore; l'**estrazione** ricava un ciphertext LWE da un GLWE.
Il calcolo dei punteggi produce inoltre **120 estrazioni iniziali**, contate
a parte come `initial_samples`. Le 1.709 della tabella sono `marginals`.
Head restituisce tre cifre per score, ma usa sei estrazioni interne:
i due numeri descrivono passaggi diversi.

Il torneo esegue 119 confronti. Ogni nodo confronta le tre cifre dello
score, rigenera il controllo e trasferisce le cifre necessarie del vincitore.
Con gli ID da 1 a 120, la cifra alta è già nota e quella media resta nota
in 88 nodi: conservarle evita di selezionarle. Il packing delle cifre
rimanenti richiede 150 rotazioni di payload nel torneo. Nel finale basta
trasferire le due cifre variabili dell'ID oppure restituire zero.

Questi sono **conteggi strutturali**, riconciliati con l'aggregato del
profilo: alcuni contatori sono inizializzati da formule, altri dalle
metriche dei selettori. Non sono una nuova misura indipendente di ogni
chiamata. Non contano gli external product effettivamente eseguiti dentro
le blind rotation, né copie, allocazioni e operazioni lineari.
La ripartizione vale per normalizzatori Both, tagli ID Both e cifre pubbliche
Repack; altre configurazioni richiedono il loro piano.

I conteggi descrivono il lavoro del circuito, ma non fissano un tempo
indipendente dalla CPU: parametri, tipo di primitiva e parallelismo restano
necessari per confrontare implementazioni. Non è stato eseguito un nuovo
benchmark né modificata la baseline.
