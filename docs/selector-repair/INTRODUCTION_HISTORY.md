# Dal selettore compatto alla verifica dei margini

Ricostruzione per il percorso sperimentale della tesi, aggiornata al 19 settembre
2026. Tutti gli orari riportati sono UTC. Questa sezione spiega l'origine del
problema, la sua diagnosi e la scelta del candidato di correzione. La
qualificazione del nuovo candidato, l'eventuale adozione e il costo misurato
appartengono al rapporto conclusivo della campagna separata.

## Una semplificazione con un nuovo obbligo sul rumore

Il passaggio decisivo della linea di ricerca avviene il 6 settembre 2026.
Il confronto delle tre cifre dello score produce tre segni ternari, combinati
con pesi 4:2:1. Nel predecessore, un quarto programmable bootstrap rigenerava
questa combinazione in un controllo a due valori, 4 e 12, prima della selezione
dei payload. La successiva variante compatta usa direttamente la combinazione
ternaria, dopo una conversione di chiave, come controllo delle rotazioni del
selettore PFKS. La ponderazione 4:2:1 era quindi già presente: la novità locale
del passaggio consiste nell'omettere la rigenerazione del controllo. [S1, S12]

La geometria adottata divide i cinque payload in tre cifre score e due cifre ID.
Ogni gruppo viene selezionato da una rotazione dinamica. Le tre cifre score
sono collocate agli offset 0,41 e 82, le cifre ID agli offset 0 e 41. La funzione
PFKS contiene sette bande di 41 coefficienti, per 287 coefficienti non nulli.
La verifica finita dimostra che il mux è corretto per tutti i segni ternari
quando lo scarto dell'indirizzo effettivo resta entro ±20 gradi. Un controesempio
è già presente a raggio 21. Questa è una prova della geometria condizionata
all'indirizzo, non una prova che ogni ciphertext rumoroso rispetti quel
vincolo. [S1:3–43]

L'interesse iniziale è concreto ma circoscritto. Il passaggio dal controllo
rinfrescato al layout 3+2 mantiene cinque blind rotation per fusione: tre
rotazioni dei ternari e due del selettore sostituiscono tre ternari, un refresh
e una selezione. Il risparmio effettivo è una KS e un campione estratto per
fusione; non diminuisce il numero totale di BR o di livelli gadget. Un erratum
del 6 settembre corregge esplicitamente la precedente etichetta di costo.
Questo dettaglio permette di raccontare anche la revisione dei conteggi come
parte del metodo sperimentale. [S11:3–18]

## I primi risultati e il segnale che il margine è stretto

Il primo componente rumoroso della geometria 3+2 si conclude il 6 settembre alle
06:20:17.340703. Passano tutte le 27 combinazioni di segni e tutti i 135 payload;
gli scarti osservati sono compresi fra −16 e +12. Il successivo torneo completo
Head, concluso alle 07:15:42.657612, passa quattro scene N127 e 508 fusioni,
restituendo gli ID attesi 127,126, 63 e 0. Tuttavia, alcuni controlli raggiungono
già entrambi i bordi della finestra,−20 e+20. I successi dimostrano la
fattibilità dei casi osservati e rendono visibile l'assenza di margine
aggiuntivo in quelle osservazioni. [S2:1910–1923,2124–2146]

Alle 08:42:44.456357 emerge il primo superamento rumoroso del supporto
rintracciato in questa successione. La variante PFKS 22×1 ancora priva di
correzione della media raggiunge l'indirizzo 4009 anziché il centro 4032,
quindi uno scarto −23. La prima scena è completa e corretta; la seconda si
ferma al quinto merge eseguito, nel nodo 4 del primo livello. I cinque payload
del nodo sono ancora corretti e non viene emesso un ID finale per la seconda
scena. Si tratta precisamente di un fallimento del requisito sul supporto.
Attribuirgli già un ID errato, oppure attribuire causalmente lo scarto al
passaggio PFKS 24→22 fra chiavi diverse, allargherebbe la conclusione oltre
l'evidenza disponibile. [S2:2521–2543]

La correzione pubblica della media era già allo studio: il disegno viene
accettato alle 08:27:15.387438, prima della conclusione di quel run negativo.
Il suo componente separato termina alle 08:55:31.566993 con 27 fixture e 135
payload corretti, scarti fra −10 e +9. La correzione modifica il body del
controllo per compensare una componente media pubblica dei residui di
arrotondamento. Conserva sia la finestra ±20 sia gli offset 41. Non annulla
il residuo legato alla specifica chiave e ai singoli coefficienti, e quindi
non certifica da sola il supporto del selettore. [S3:2–6; S2:2601–2614;
S8:98–116]

La variante con mean-centering viene poi integrata nella baseline M,
promossa il 6 settembre alle 12:35:20.742025. L'estensione M3, attestata
entro le 17:08:58.206694 dello stesso giorno, porta anche l'ID a tre cifre
e introduce il layout 3+3. La finestra stretta era già presente in M:
l'estensione dell'ID ne eredita la geometria e la correzione della media.
La ricostruzione dei sorgenti lega questa linea alla variante generale
congelata il9 settembre e alle baseline del 18 e 19 settembre. I percorsi
più recenti omettono alcune cifre pubblicamente note, conservando il gruppo
score 0/41/82 e il medesimo limite geometrico. [S4:2–14; S2:3832–3845;
S5:476–765; S12:80–108]

## Dal risultato ID75 alla causa nel selettore

Il primo output errato rintracciato nella linea con mean-centering è il caso
del 9 settembre alle 02:19:11.283842: famiglia 1, blocco 26, scena `tie_first_last`,
ripetizione 2. La variante generale restituisce ID75 mentre è atteso ID1.
Questa osservazione è distinta dal superamento del supporto senza mean del
6 settembre, che aveva ancora payload corretti. La data del 9 settembre
identifica quando viene osservato quel risultato; l'introduzione strutturale
della finestra stretta risale al6 settembre. [S5:843–861]

La diagnosi del 19 settembre riproduce il risultato storico e ne localizza
il primo errore in `merge/0/37`, fra ID75 e ID76. Gli ingressi e i tre
confronti ternari sono corretti; deve essere selezionato ID76. Anche tutte
le 127 estrazioni Head della capsula risultano corrette. Il controllo della
selezione ha centro nominale 320, supporto 300…340 e indirizzo effettivo 341.
Con gli offset 0/41/82, la matrice delle letture diventa
`[[0,1,0],[0,0,1],[0,0,0]]`: mescola le cifre anziché applicare il mux richiesto.
Questa matrice predice tutte le sei cifre osservate. Il valore 26 fra le cifre
score è già fuori dalla rappresentazione canonica base 16, perciò l'ID75 finale
non descrive una normale vittoria di quel template. [S6:3–10,32–76]

Il controfattuale rende la diagnosi causale per questa istanza. Nel medesimo
binario, intervenire su una sola parola del controllo porta l'indirizzo
da 341 a 340 e il torneo restituisce ID1, con gli altri ingressi e i nodi
estranei al suo percorso preservati. Questo consente di sostituire la
generica descrizione «fallimento della variante Head» con una formulazione
più precisa: fallimento della selezione PFKS impacchettata per uscita dalla
finestra, con estrazione Head corretta nell'istanza diagnosticata. Lo
spostamento locale di un grado resta uno strumento diagnostico; applicarlo
indiscriminatamente ridurrebbe il margine sul lato opposto. [S6:19–29,78–104]

## Il replay attuale precisa la portata della diagnosi

La baseline del 19 settembre, prima della correzione B, viene quindi provata
sulla stessa famiglia storica e sullo stesso input. Il suo percorso corrente
`public_parallel` restituisce **ID1**. Le esecuzioni fedele, con traccia spenta
e con traccia accesa producono gli stessi ciphertext finali. L'audit di 4.318
eventi verifica 127 selettori senza matrici errate o mismatch semantici globali.
Nello stesso nodo `merge/0/37`, il controllo attuale ha indirizzo effettivo
**318**, scarto −2 dal centro 320, e le matrici dei gruppi score 3 e IDlow1 sono
corrette. [S7:6100–29485,29496–29497,30008–30023]

La propagazione della geometria non impone l'identità dei ciphertext
intermedi fra versioni. Nel percorso corrente cambiano anche i normalizzatori
e alcune selezioni delle lane; il replay misura il loro effetto complessivo
sulla capsula, senza attribuire il cambiamento 341→318 a una singola
ottimizzazione. Il risultato corretto attuale delimita la conclusione:
questa prova non mostra un errore della baseline corrente. Rimane una
geometria con margine ±20, accompagnata da un controesempio rumoroso
riproducibile nella linea da cui deriva. La decisione di cercare una
correzione più robusta va motivata con queste due evidenze insieme.
[S7:12740–12895; S8:141–156; S12:93–108]

L'audit attuale osserva i ciphertext ai confini dei componenti: non contiene
una traccia interna di tutte le BR ternarie o Head e non separa i residui
PFKS e BR della selezione. Questi limiti sono diversi dalla diagnosi più
profonda della capsula storica e devono restare espliciti nel confronto.
[S7:30015–30021]

## La scelta del candidato B e il costo da misurare

Il candidato scelto ripristina un refresh del controllo verso 4/12. Conserva
la prima KS e la correzione della media sul combined originale; esegue una
BR ordinaria con corpo costante 4*Delta59, estrae il coefficiente 0 e aggiunge
8*Delta59. Una seconda KS e una seconda correzione della media preparano
il controllo condiviso dei gruppi payload. La nuova funzione PFKS contiene
una banda centrata in 1536 di raggio 127; i gruppi mantengono al massimo tre
lane con offset 0/256/512. Richiede una nuova chiave per la nuova funzione.
[S10:18–26]

Il modello dimostra una composizione condizionale: i ternari devono essere
corretti; il controllo del refresh deve restare entro ±63 dal proprio centro;
quello della selezione deve restare entro ±127 da 512 o 1536; i residui dei
payload devono mantenere la corretta cella di decodifica. Il refresh
interrompe la propagazione analogica della somma 4:2:1 al controllo finale,
quando la sua decisione è corretta. Questi margini non costituiscono un
bound sulla probabilità di fallimento del circuito completo. [S9:89–128,
179–210; S10:28–32]

Il costo strutturale rispetto al selettore corrente è **una BR, una KS e un
campione estratto in più per selezione effettivamente eseguita**. Il numero
di gruppi payload e delle PFKS resta quello del piano corrente; la BR del
refresh deve essere conteggiata separatamente. Il costo temporale richiede
misure appaiate del nuovo circuito dopo la qualificazione di correttezza.
In questa fase B è un candidato con obblighi espliciti, non una correzione
già adottata. Il rapporto della root deve completare il percorso con esiti,
eventuali nuovi fallimenti e costo misurato, conservando tutte le evidenze
precedenti. [S9:130–145; S10:35–66]

La lezione metodologica di questa sequenza è la distinzione fra correttezza
della geometria, correttezza rumorosa dei casi provati e affidabilità generale.
La ricostruzione spiega perché un'ottimizzazione plausibile viene conservata,
interrogata con osservatori più precisi e infine affiancata da un candidato
che esplicita margini e costo. È un capitolo del percorso sperimentale del
selettore; non stabilisce completezza dello stato dell'arte, un primato
prestazionale o una certificazione crittografica. [S1:38–43; S10:69–77]

## Provenienza verificabile

Le righe sono one-based nei file letti per questa stesura. Gli SHA256 sotto
identificano i file delle fonti; i digest di intere campagne citati al loro
interno restano identificatori dichiarati dalle rispettive ricevute. Il
conteggio 127 di S7 è il numero di elementi dell'array `selectors`, tutti con
`all_matrices_match_observed_combined=true`; il nodo 0/37 è alle righe 12740–12970.
Nessuna nuova esecuzione FHE o lettura di chiavi è stata effettuata per questa
stesura. “Primo” indica il primo artefatto o fallimento rintracciato nella
catena locale esaminata, non un primato storico assoluto. Per l'introduzione
del modello si dispone della data e dell'ordine del diario, non di un minuto
di creazione certificato o di un commit introduttivo. [S12:163–177]

| Fonte | Percorso esatto relativo alla radice del repository | SHA256 del file |
|---|---|---|
| S1 | `tmp/pfks-fused-split32-geometry-20260906/README.md` | `8f5c698564123b187de92b83af0eaf7028da183056d657a5c4e44764278c1543` |
| S2 | `docs/research-state/2026-09-06/continuation/STATUS.md` | `bb8badfc3420949186d45ce74efbeeb550b9c70b0e5bdb4f6830f322e32afaa8` |
| S3 | `docs/research-state/2026-09-06/continuation/PFKS_MEAN_CENTER_ROOT_ACCEPTANCE.json` | `f2488616ee860924b8c2a6cd5f948cd94055e4766cb5cccf35ae5ce45e9b1db1` |
| S4 | `docs/research-state/2026-09-06/wrap-up/BASELINE_PROMOTION.json` | `e7a11c5f697cff2a985b282e38ee896748d44a8acacc0102e56fb08db6edc78a` |
| S5 | `tmp/selector-repair-20260919/lineage/SOURCE_PINS.json` | `0e965353173f14db361ad6f7aea5ee8f004ff4a91af8d303ed67ac1b11333b79` |
| S6 | `tmp/head-failure-investigation-20260919/RESULT.md` | `df2a78913c1862d5169eaa5d62a275d2c23e41afec8466b6e81321a641fcc818` |
| S7 | `tmp/selector-repair-20260919/current-trace-audit/CURRENT_TRACE_RESULT.json` | `3abd6ec40bfd2f07109605eb70b1f515e4b69deae66eb735f938527ed47dedc0` |
| S8 | `tmp/head-failure-investigation-20260919/source-lineage/CURRENT_RISK.md` | `fe7406f4cb264ff4c25bcd4d58488c1e7c2e2e3f424845fb0564ca693b516020` |
| S9 | `tmp/selector-repair-20260919/design/DECISION.md` | `293ae0bcbc4314d8ee3036ac45fdc2b417fcb014b88404459f5fd15ab34f67a9` |
| S10 | `tmp/selector-repair-20260919/PROTOCOL.md` | `6d0e4b1b38ef58755a2787ab6510012c419285cf3e67bf780c1040d7d3e4fca8` |
| S11 | `docs/research-state/2026-09-06/continuation/split32-counter-erratum.md` | `608b50b6e511fb44336dce4ad618e7fdd4d887ba7df91986a210dc37fede1807` |
| S12 | `tmp/selector-repair-20260919/lineage/README.md` | `cdd28682e2481fbc4710587a9fcda9a48af67ebc37cb014aa7029fc39c3731fb` |

S8 è citata per formula, geometria e differenze dei percorsi. La sua precedente
frase sul replay ancora da effettuare è superata da S7; quella sui residui
storici ancora da separare è superata da S6. I record congelati restano
conservati e non vengono retroattivamente riscritti.
