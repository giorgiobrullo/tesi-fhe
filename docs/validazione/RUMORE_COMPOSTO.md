# Rumore della pipeline: cosa è dimostrato e cosa manca

## Nuove dimostrazioni e correzione — 5 ottobre 2026

Questa mappa distingue i risultati condizionati sui singoli passaggi
dagli obblighi ancora aperti della composizione. Non presenta una
probabilità numerica di fallimento dell'intero runtime mantenuto.

**Correzione del conto Head.** Il resto `2^33` è per componente del
ciphertext. Nella fase compare invece `r_body − r_mask · S`. Se ogni
coefficiente dei due resti ha modulo al più `2^33` e il segreto binario
ha peso H, il maggiorante triangolare per ciascun coefficiente della
fase è `(H + 1) · 2^33`, al più `2049 · 2^33` quando H ≤ 2048.
Il precedente conto scalare ometteva questa convoluzione e non va usato
come certificato della fase. La sezione sulla prima uscita Head sotto
riporta la correzione senza attribuirle un budget composto già chiuso.

2 ottobre 2026. La [validazione pack4](PACK4_VALIDATION.md) documenta le
query corrette osservate; la [migrazione a TFHE-rs 1.8.1](TFHE_181_MIGRATION.md)
documenta compilazione e controlli funzionali della versione mantenuta.
Nessuna delle due fornisce una probabilità di fallimento del circuito completo.
Il bilancio condizionato del selettore, sviluppato il 22 settembre, delimita
una parte di questa prova. Qui si precisano anche gli obblighi dei passaggi
precedenti e del decoder, senza introdurre nuove misure.


## Raccordo con la query corrente — 5 ottobre 2026

I [conteggi del runtime](PROFILO_RUNTIME_20261004.md) consentono di
localizzare gli obblighi per N120/D512, soglia comune 273 e configurazione
Both/Repack. I numeri indicano quante operazioni richiede il circuito;
non sono probabilità di errore.

| Passaggio | Operazioni | Cosa deve ancora essere giustificato |
|---|---:|---|
| Punteggi | 120 estrazioni iniziali | Budget della fase dello score dall'ingresso cifrato. |
| Head | 240 BR | Indirizzi ed errori dei due intermedi per punteggio. |
| Normalizzatori | 240 BR, con due uscite ciascuna | Errore polinomiale, filtri, riporti e feedback che formano le cifre. |
| Confronti ternari | 360 BR | Finestra ±63 e rumore del controllo pesato 4/2/1. |
| Refresh | 120 BR e 240 KS | Prima finestra ±63, poi seconda KS e finestra ±127. |
| Selezione dei payload | 151 BR e 509 PFKS | Resti PFKS, errore ereditato e rumore dei gruppi selezionati. |
| Decoder | Due cifre ID variabili; terza pubblica zero | Budget finale strettamente inferiore a 2^58 per cifra. |

Le BR sommano a 1.111. I normalizzatori producono due uscite dalla stessa
rotazione; i 120 controlli di selezione sono riutilizzati nei 151 gruppi.
Queste condivisioni non rendono le uscite o gli errori indipendenti.

Il punto numerico ancora aperto è il bilancio completo della chiave
ordinaria dei normalizzatori. Il suo contratto pointwise contiene due
prodotti Fourier, ma mancano limiti uniformi sulle loro ampiezze effettive,
con storia della chiave e condizioni aritmetiche giustificate. I limiti di
Head non si trasferiscono automaticamente: la decomposizione è diversa.
Risolto questo requisito, resterebbero comunque conversioni, rumore
crittografico, indirizzi e feedback da raccordare.

Per comporre il circuito servono limiti validi sul primo errore, sotto il
prefisso precedente corretto, oppure limiti uniformi equivalenti. Il
criterio della sezione 5 non assume indipendenza; non autorizza a usare
`1.111 × p_fail` del parametro di catalogo per questa pipeline.
La calibrazione biometrica all'1% riguarda il riconoscimento, ed è distinta
dalla probabilità che il calcolo cifrato restituisca un esito aritmetico errato.
Questa mappa non introduce nuove misure o una garanzia numerica.

Un probe pubblico separato del 5 ottobre ha controllato FPCR e sette casi
IEEE nel thread principale, prima e dopo il pool, e in ciascuno dei 16 worker
Rayon. I 252 risultati in bit coincidono con quelli attesi: arrotondamento
al più vicino con parità, subnormali e differenza fra FMA e prodotto seguito
da somma. FPCR è rimasto zero nei 18 contesti. Il codice da intrinseci NEON
compila in parte a istruzioni scalari; si verifica solo la prima lane.
È un'osservazione del nuovo probe e del suo pool sul Mac, non del servizio
o di tutti gli input. Non fornisce i limiti B0/B1 mancanti né chiude il
bilancio crittografico. Evidenza locale: `current-fp-environment-pool-20261005`,
`root/NATIVE.ndjson`, `root/CODEGEN.txt` e `root/RESULT.json`.

## Valore ideale, rumore e indirizzo

Un ciphertext contiene una **fase**: il messaggio ideale codificato, più
un errore, modulo `q = 2^64`. L'errore non è un'altra cifra del punteggio:
è lo scostamento introdotto da cifratura e operazioni cifrate.
La blind rotation (BR) usa un **indirizzo intero** per leggere una tabella
negaciclica. Questo indirizzo dipende dalla fase, dal key switching (KS)
e dall'arrotondamento del modulus switch.

Servono quindi due controlli distinti: arrivare nella zona giusta della
tabella e conservare un errore sufficientemente piccolo nel valore restituito.
Un indirizzo corretto non garantisce da solo il secondo controllo.
I budget sotto usano distanze centrate sul toro, nelle unità della fase;
le finestre di indirizzo sono invece espresse in gradi su un ciclo di 4096.
Si assumono input ammessi e chiavi coerenti con il contratto del runtime.

## 1. Head e normalizzatori

Lo [split](../../runtime/core/src/split.rs) parte dal punteggio a scala
`2^51`. Head produce due intermedi cifrati `d0`, `d1`; i normalizzatori
ricavano le tre cifre canoniche da confrontare. L'identità del residual è:

```text
residual = 128 input51 - 256 d0 - 16 d1              (mod q)
B_residual ≤ 128 B_score + 256 B_d0 + 16 B_d1
```

La seconda riga è un maggiorante triangolare, condizionato alla corretta
semantica di Head; non stima il rumore tipico. Occorre ancora giustificare
i budget dello score, del KS e dell'estrazione Head con le scale reali.

I [normalizzatori condivisi](../../runtime/core/src/shared_normalizers.rs)
ricavano due uscite dalla stessa BR. Sul suo errore polinomiale `E` applicano:

```text
K0 = X^64 + X^128 + … + X^960 - 15 X^1024
K_middle = K0,       ||K0||₁ = 30
K_residual_low = 2 K0,       ||2 K0||₁ = 60
```

Se la BR ha l'indirizzo pertinente e `||E||∞,T ≤ B`, il contributo del
kernel è al più `30 B` o `60 B`; l'uscita carry non trasformata resta
entro `B`. Le operazioni polinomiali intere trasformano esattamente la fase
modulo `q`, senza aggiungere un ulteriore errore di arrotondamento.
Resta da maggiorare `E`, inclusi BR e FFT. Vanno inoltre contabilizzate
le somme `v1 = d1 + residual_carry` e `top = 2 d0 + carry_top`.
I fattori 30/60 sono maggioranti conservativi condizionati, non amplificazioni
osservate, nuovi fallimenti o ragioni sufficienti per cambiare il circuito.

## 2. Confronti ternari

Il [comparatore](../../runtime/core/src/comparator.rs) confronta le cifre
con tre risultati in `{-1, 0, 1}`. Per ogni differenza di cifre in `[-15,15]`,
uno scostamento di indirizzo entro `±63` dal centro `128(d_left-d_right)`
è una condizione sufficiente per il segno corretto. Questa finestra precede
quella del refresh: non è coperta dalla prova del selettore.

Occorre trattare errori delle due cifre, KS, modulus switch e rumore BR.
Poi il controllo combina i risultati con pesi `4,2,1`: l'errore è
`4 E0 + 2 E1 + E2`. Un budget valido è `4 B0 + 2 B1 + B2`.
Le cifre e le chiavi sono condivise: non si possono sommare soltanto le
varianze pesate assumendo covarianze nulle senza una giustificazione.

## 3. Refresh e indirizzo di selezione

Il [refresh](../../runtime/core/src/selector_refresh.rs) richiede una prima
finestra `±63`. Produce il controllo ideale `4Δ` o `12Δ`, con `Δ = 2^59`.
Dopo BR, seconda KS e [correzione della media](../../runtime/core/src/mean_center.rs),
l'indirizzo deve rientrare entro `±127` da 512 o 1536.
Il successo della prima finestra non implica quello della seconda.
Servono code valide per entrambe, includendo rumore e residui di
arrotondamento effettivi; la correzione algebrica della media non fornisce
da sola queste code.

## 4. Trasferimento dei dati del vincitore

La [selezione pack4](../../runtime/core/src/selector_parallel.rs) prepara
ogni differenza `right-left` con PFKS, raggruppa fino a quattro cifre,
ruota ed aggiunge il payload sinistro. Condizionatamente a decisione e
finestre corrette, per ciascuna cifra vale:

```text
E_out = E_chosen + b r + ν                         (mod q)
```

`b` vale 1 quando si sceglie destra; `r` è il resto scalare della
decomposizione PFKS della differenza effettiva. `ν` comprende il rumore
polinomiale delle chiavi PFKS del gruppo e il difetto della BR implementata,
FFT inclusa. L'errore ereditato del candidato non scelto si cancella:
lungo il percorso vincente l'accumulo è additivo. I nuovi termini restano
da maggiorare. Non si assume linearità della decomposizione PFKS né
indipendenza fra lane, nodi o query. Il controllo della soglia del vincitore
deve rientrare nello stesso bilancio.

## 5. Decoder e probabilità composta

Il [decoder corrente](../../runtime/candidate/src/client_commands.rs)
legge tre cifre ID a scala `2^59`. Un raggio sufficiente per ciascuna
cifra è **strettamente minore di `2^58`**. Un errore può produrre un altro
ID valido: il controllo del formato non lo rileva.

Si possono ordinare gli eventi di prima violazione: ingresso/Head,
normalizzatori, ciascun ternario, primo indirizzo, secondo indirizzo,
budget dei payload e decodifica finale. Per ogni evento serve un `ε_j`
valido sotto il prefisso precedente corretto, oppure un maggiorante
uniforme equivalente sulla distribuzione reale di chiavi e cifrature.
Allora `P(uscita errata) ≤ Σ ε_j`. Questo union bound non richiede
indipendenza; non produce gli `ε_j` mancanti. Numero di BR e `p_fail`
di un parametro del catalogo non certificano questa composizione custom.
I [limiti generali](../limiti.md) distinguono questi obblighi dalla sicurezza
del protocollo e dall'accuratezza biometrica.

## Ricalcolo di un record Head conservato

Il 2 ottobre un lettore indipendente ricostruisce il primo Head di una
foglia della traccia storica TFHE-rs 1.7, senza avviare FHE né leggere
chiavi segrete. Passano 2.156 controlli di provenienza, decomposizione,
LUT e identità lineari. Il record distingue errore dello score,
incremento KS aggregato, correzione A98, indirizzo e difetto raw della BR;
il ramo Head osservato è ammesso. Il caso non cambia la diagnosi del
guasto nel selettore a valle.

Quel primo lettore non separava due quantità necessarie:

```text
R = Σ δ_i S_i − floor((Σ δ_i)/2)
K = Σ digit_il η_il
incremento KS corretto = R − K
```

Un secondo lettore calcola ora R dai residui e dal segreto grande, e K
dalle 10.240 righe effettive della KSK e dai segreti coerenti con la
famiglia. Calcola entrambi prima di confrontare la differenza delle fasi:
non ricava K da R e dall'incremento osservato. Ricostruisce tutte le 860
parole del ciphertext piccolo, identiche alla traccia, e verifica R−K
sia modulo q sia nel lift centrato; nel record non serve aggiungere un
multiplo di q. Passano 70.678 controlli, inclusi casi sintetici di tie,
wrap e metà di somme negative dispari. Il segreto piccolo è legato alla
famiglia dalla precedente ricevuta di recupero, verificata qui; la sola
identità algebrica non proverebbe quel legame.

Questa verifica chiude l'accounting deterministico della KS del record.
Il residuo centrato di ciascuna riga non è, da solo, una prova del campione
originario non avvolto o della sua distribuzione. Il massimo errore GLWE
salvato limita quella realizzazione, non il supporto di un sampler
gaussiano. Ricevuta del secondo lettore SHA256
`ec77710a9953a13fc5541898964900f7d0034e0f70cb62ad93efdde11bb32829`.

È un ricalcolo di un record 1.7; lo split corrente differisce, benché
gli adapter A98/A112 coincidano. Non certifica la prima Head della
pipeline 1.8.1 o i passaggi successivi. Ricevuta del lettore SHA256
`ee79066c5a8409b0ab1aa00ef7d16c78ca76c51d478ec999ade07671c05daea5`;
record, cifrati e diagnostica restano nell'archivio locale. Nessun nuovo
`p_fail` numerico viene attribuito alla composizione.

## Correzione centrata della prima Head

La prima Head corrente usa una KS corretta e una correzione della media
prima del modulus switch. Un modello di modulus switch senza questa
correzione non fornisce automaticamente la sua legge d'errore.
Con `U = 2^52`, sia `ρ(a)` il grado arrotondato e sia
`u_j = lift_q(a_j − U ρ(a_j))` il residuo della maschera piccola.
Il lift sceglie il rappresentante centrato modulo q, anche quando il
grado arrotondato torna a zero attraversando il limite del toro.
La correzione pubblica e il termine dipendente dal segreto piccolo sono:

```text
C_MS = −floor((Σ u_j)/2)
T_MS = Σ s_j u_j + C_MS
     = Σ (s_j − 1/2) u_j + parity(Σ u_j)/2
```

Il bit di parità conserva l'effetto delle somme dispari, anche negative.
T_MS precede l'arrotondamento del body: non coincide con tutto lo
scostamento dell'indirizzo. Per il punteggio normalizzato m, ponendo
`d = floor((m−128)/2)`, `θ = (m−128)2^51 − Ud` ed
`e = E_score + R − K`, l'indirizzo soddisfa:

```text
address = d + floor((θ + e + T_MS + U/2)/U)         (mod 4096)
```

Il lettore verifica questa identità sul record storico e ritrova
l'indirizzo 275. Per ottenere una probabilità sulla prima Head corrente
resta da maggiorare congiuntamente `E_score + R − K + T_MS`, dichiarando
quali maschere o storie si condizionano e giustificando la legge del
sampler finito implementato. Le righe e le chiavi riusate non diventano
rumori gaussiani indipendenti per effetto di questo ricalcolo. Seguono
ancora la zona ammessa della LUT, il difetto raw BR e i passaggi della
composizione descritti sopra.

## Margine della prima Head e candidata in studio

Ponendo `Z = E_score + R − K + T_MS`, un'enumerazione della LUT su tutti
i 4096 punteggi normalizzati trova il seguente intervallo sufficiente
comune. U corrisponde a un grado prima dell'arrotondamento del body.
L'estremo sinistro è incluso, quello destro escluso.

| Variante | Intervallo di Z/U valido per tutti i punteggi |
|---|---|
| Prima Head attuale | [−96,5; 32) |
| Prima Head candidata | [−64,5; 64) |

Sono le componenti valide che contengono zero; altri intervalli periodici
possono ancora portare a un indirizzo ammesso. Per m=255, Z=32U raggiunge
il primo indirizzo non ammesso della tabella attuale. Una simulazione con
input invariato e passaggi successivi ideali restituisce allora [17,17,0]
invece delle cifre [15,15,0]. Il controllo riguarda una perturbazione
costruita dell'indirizzo: non è un nuovo fallimento FHE osservato.

La candidata sposta soltanto la tabella Head4 di 32 gradi. È equivalente,
per LUT e indirizzo, a conservare la tabella attuale e sottrarre `3Δ/2`
anziché `Δ` alla copia `shifted` del primo giro. La sottrazione aggiuntiva
agisce sulla copia; lo `state` prima dell'estrazione rimane invariato.
Le operazioni della seconda Head e dei normalizzatori restano identiche.
La maschera e i digit KS non cambiano per una traslazione pubblica del
body; la correzione A98 dipende dalla stessa maschera. Il numero strutturale
di BR e KS resta uguale. Tutti i punteggi nominali e tutte le prime cifre
ammesse producono le cifre canoniche nella continuazione ideale.

Il minimo margine simmetrico sufficiente raddoppia da 32U a 64U, mentre
quello negativo si restringe. La geometria da sola non prova una minore
probabilità d'errore. La candidata resta un prototipo separato: il runtime
mantenuto conserva la prima sottrazione attuale. La modifica riguarda
l'estrazione iniziale dello score; non sostituisce il refresh e la finestra
corretta del selettore a valle.

### Primo confronto con cifrature reali

Il 2 ottobre un pilot isolato TFHE-rs 1.8.1 confronta le due sottrazioni
con la stessa famiglia di chiavi e lo stesso ciphertext per ogni coppia.
Entrambi i bracci passano 321 ingressi LWE diretti, scelti attorno ai bordi
dei 16 blocchi della cifra alta, e 1.079 score prodotti dal prefisso
packed reale di 14 query. I primi sono cifrati direttamente con la
distribuzione di rumore parametrizzata per GLWE; i secondi includono il
rumore pesato dal template. Sono due gruppi
distinti, non 1.400 ricerche indipendenti.

Le 14 query complete usano gallerie di 1, 2, 120, 127, 128, 225 e 226 voci:
minimo unico,
primo minimo a pari punteggio, soglia inclusiva e rifiuto del vincitore
anche quando un'altra voce avrebbe una soglia più permissiva. In entrambi
i bracci le cifre score sono canoniche base16 e l'esito base15 ricostruisce
lo stesso 0/ID dell'oracolo in chiaro. Coincidono anche i contatori BR,
KS, PFKS e campioni dell'endpoint. La prima cifra intermedia cambia in
103 coppie dirette e 223 score del prefisso: la candidata è stata
esercitata e la normalizzazione conserva il risultato corretto.

Un lettore scalare separato ricontrolla i ciphertext salvati: 43.305
controlli PASS su hash, fasi, raggi stretti, relazione delle cifre Head,
cifre canoniche e ID. Usa il segreto grande esportato dal worker locale,
legato alla provenienza congelata; non deserializza nuovamente la chiave
client e non riesegue FHE. Il controllo osservato/non
osservato del pilot confronta le parole soltanto sul primo ingresso
diretto di ciascun braccio; non è una verifica su tutto il dominio.
I dettagli KS/MS e i target interni dei normalizzatori sono controllati
nel worker, non nuovamente decifrati dal lettore. Il lettore verifica
anche l'offset comune degli score rispetto all'oracolo, senza
reimplementare il planner o decifrare il GLWE packed.

Il caso chiamato `uniform-public-reject` nel piano congelato è un rifiuto
con soglia comune valutato dal circuito cifrato: esegue 18 BR, 18 KS e
2 estrazioni iniziali per braccio. Non attiva la scorciatoia pubblica
AllReject; il nome non estende la copertura del test a quel ramo.

È correttezza osservata su una sola famiglia già esistente, non una
probabilità di fallimento o una misura di velocità. La compilazione usa
Rust 1.98.1, il piano FFT e le feature della baseline; la candidata non
è installata nel servizio. Ricevuta della verifica scalare SHA256
`eae30f1a8bb2d6e7a336d1e43102c9279000fb7396bc661b810b239862f85442`.

Nel modello esplicito di nastri ideali indipendenti, con query e template
fissati indipendentemente dalle chiavi, il lemma condizionato sulle due
maschere `H=(x,a)` conserva l'indipendenza di segreti ed errori. Per il
limite più stretto della MS si condiziona però soltanto su `x` e si media
anche sulla maschera piccola `a`, usando parole delle maschere KSK iid uniformi:
per digit non tutti zero, `g = gcd(q, digit)` vale 1, 2 o 4 e il
proxy della MS, prima della parità, è `859 (U² + 2g²)/48`. Il caso di
digit tutti zero ha maschera piccola e termine MS nulli. La parità non
va sostituita con un bit indipendente dai residui.
Quel proxy non vale identico per ogni `a` fissata: il maggiorante uniforme
in quel condizionamento è `859 U²/16`. Il limite più stretto descrive
la media sull'esperimento di generazione dichiarato, non ogni chiave salvata.

Questa legge e un modello di errori gaussiani ideali arrotondati permettono
un confronto probabilistico dichiaratamente ideale delle due finestre.
Non danno un nuovo p_fail del runtime. Il sampler usa byte finiti e
operazioni f64; seed derivati e stream disgiunti non dimostrano nastri
statisticamente indipendenti. Restano da giustificare il trasferimento
al sampler/PRG effettivo e gli eventi BR/FFT e degli stadi successivi.

### Seconda famiglia e rami pubblici

Un secondo confronto usa una famiglia esistente del 22 settembre, diversa
da quella del primo pilot: differiscono anche i segreti grandi esportati
dai due worker. Questo controllo di provenienza non dimostra indipendenza
statistica. Le chiavi erano state generate nel contesto Rust 1.98.0;
il nuovo producer viene compilato con Rust 1.98.1 e TFHE-rs 1.8.1.

Entrambi i bracci passano 129 ingressi diretti, 595 score del prefisso
packed e 16 valutazioni complete dell'endpoint. La prima cifra intermedia
cambia in 44 ingressi diretti e 103 score del prefisso; cifre canoniche
e 0/ID concordano con l'oracolo. Le gallerie comprendono N120, N225 e N226,
oltre a casi di una o due voci. La scena N120 riusa la fixture precedente:
non è un nuovo test biometrico o una misura HTTP della demo.

Il piano osservato copre **tre AllReject, quattro AllAccept, sei confronti
con sentinel e tre casi a soglie diverse**. Per i template di norma 1 e 4,
il dominio pubblico è [−124,132]. T=−2940 conserva l'allineamento e una
larghezza inclusiva di 4096; T=−2941 attiva AllReject. T=899 conserva
l'allineamento; T=900 attiva AllAccept. Sono transizioni del piano di
esecuzione, non cambi dell'ID corretto nelle rispettive coppie di casi.
La soglia −100 resta invece un confronto cifrato, come nel primo pilot.

Ogni braccio rispetta i contatori congelati e quelli dell'altro braccio.
Gli endpoint AllReject hanno zero BR, KS, PFKS ed estrazioni. I cinque
score di quei casi vengono comunque valutati nella diagnostica separata:
i 595 prefix controllati non sono i 590 score raggiunti dagli endpoint.
AllAccept evita il controllo terminale della soglia, conservando il
torneo quando ci sono più candidati; il caso N225 restituisce ID225.

Il lettore scalare separato passa 23.350 controlli sulle uscite salvate.
Ricalcola ora anche i 16 piani pubblici, con aritmetica intera e larghezze
inclusive, e confronta ogni score normalizzato con il suo offset atteso.
Verifica i 32 ledger dei bracci contro le aspettative derivate dai sorgenti;
sono contatori software, non una traccia delle istruzioni della CPU.
Restano le qualifiche sull'esportazione del segreto, sul plaintext GLWE
non decifrato separatamente e sulla diagnostica interna KS/MS/normalizzatori.
Ricevuta scalare SHA256
`f911c21ad9406c24f558a5dd05e041574c95824c1bc3824f1fcc1cbaddfbaf60`.

Questo confronto amplia la correttezza osservata a una seconda famiglia
e ai rami espliciti del planner. Non misura latenza o probabilità d'errore
e non installa la candidata nel servizio mantenuto. Il refresh e la
correzione del selettore restano invariati.

## Generazione del rumore: il modello a byte finiti

Il sampler polar non estrae una gaussiana continua esatta: legge due parole
di 64 bit per tentativo, le converte in `f64`, scarta i punti fuori dal
disco e applica logaritmo e radice quadrata. Una nuova prova confronta
**tutte le celle dei possibili input**, conservando anche le molteplicità
della conversione e il denominatore della probabilità di accettazione.
Non stima una coda contando errori in un campione.

Nel surrogato con quelle parole finite ma trasformazione reale esatta,
il primo valore normalizzato G0 soddisfa:

```text
E exp(t G0) ≤ exp((1 + 2^-42) t²/2),       |t| ≤ 1/8
```

È un limite diretto della funzione generatrice, senza un addendo di
probabilità per le celle ai bordi. Il ponte verso il raggio arrotondato
gestisce anche la diversa regola di accettazione. Per il valore `f64`
effettivo rimangono invece condizioni esplicite: operazioni con
arrotondamento al più vicino, logaritmo deterministico, finito e nonpositivo,
intermedi normali o zero, e un errore assoluto del logaritmo limitato su
**tutti** i raggi accettati. I parametri σ sono i valori esatti dei bit
`f64`, non le frazioni ottenute dalle sole stringhe decimali.

La lettura statica del binario del secondo pilot verifica la conversione
a scala `2^-63`, le moltiplicazioni per i quadrati e la conversione torus
a scala `2^64`. Non certifica lo stato di arrotondamento dei thread.
Il logaritmo è importato dal sistema. La prova sui byte della libreria
presente oggi è descritta sotto; manca il legame con la libreria caricata
e con lo stato aritmetico delle esecuzioni conservate. La KSK riusata era
stata generata nel contesto Rust 1.98.0: il binario del pilot compilato
con 1.98.1 non certifica retroattivamente quell'aritmetica.

Sotto il contratto numerico dichiarato, persino un limite assoluto
`L_log ≤ 1/16` è sufficiente per un proxy del rumore normalizzato minore
di `3/2`. Il raccordo razionale con il modello della prima Head verifica
sia il dominio dei parametri di Chernoff sia l'arrotondamento torus,
contato una sola volta nella traslazione precedente. Con parole iid uniformi
per ogni tentativo, nastri maschera/segreto/rumore indipendenti e la media
sulle maschere KSK prevista sopra, il modello della **candidata** conserva
un maggiorante strettamente minore di `2^-64` per l'unione di 120 uscite
dall'intervallo sufficiente di indirizzo.

Quest'ultima è un'implicazione condizionale sull'**ingresso nella zona valida**
della prima Head. Non è il p_fail del runtime o di una chiave fissata;
non include budget esauriti del generatore, trasferimento PRG, difetto raw
BR/FFT, rumore d'uscita o stadi successivi. Non giustifica l'installazione
della candidata né modifica i tempi misurati. La candidata resta separata
dal runtime mantenuto.

La prova ha una revisione matematica indipendente; i checker esatti passano
5.178 controlli sulle costanti, 29 sul contratto aritmetico, 55 sul modello
delle code e 24 sul raccordo. I checker supportano la prova analitica e
non certificano la funzione logaritmo importata. Artefatti congelati
nell'archivio locale `tmp/finite-gaussian-mgf-20261002/`; ricevuta del raccordo
SHA256 `8b3af3dc84eaf0c2358ede4f213d9e1edd4d228039de14ad994e4b8a787d466f`.
Le sezioni successive distinguono il controllo del logaritmo e il
trasferimento a una permutazione ideale dal legame con il generatore
effettivo e dalla composizione a valle, che restano da chiudere.

## Logaritmo di sistema: proprietà numeriche della routine attuale

Per trasformare il raggio in rumore, il sampler chiama il logaritmo del
sistema. Abbiamo identificato il codice e le tabelle della libreria oggi
presente sul Mac, quindi ricostruito i due rami della routine. La prova
copre tutte le 129 celle della tabella e tutti i valori `f64` nell'intervallo
`[2^-127, 1)`, che contiene tutti i raggi accettati dal modello precedente.
Con arrotondamento al più vicino e istruzioni IEEE senza trap, la routine
restituisce un valore negativo normale con errore assoluto `<1/4096`.
Questo soddisfa il contratto `L_log ≤ 1/16`; la routine conserva il modo
di arrotondamento con cui entra, senza dimostrare quale sia quel modo.

La revisione indipendente e 1.879 controlli razionali passano. È una prova
sugli esatti byte identificati, senza campionare raggi o eseguire il logaritmo.
L'identità della libreria caricata e lo stato aritmetico dei thread nelle
vecchie generazioni di chiavi restano da documentare. Il risultato riguarda
la precisione numerica: non dimostra la sicurezza della distribuzione del
rumore né la probabilità d'errore dell'intero circuito. Nessuna routine o
chiave è stata sostituita. Prova, byte e ricevute sono congelati nell'archivio
locale `tmp/system-log-certificate-20261002/`; l'immagine della libreria
ha UUID `8CDB307B-E40C-3879-B8F1-32DE2F85D068`, versione `3326.40.2`.

## Generatore AES: cosa copre il modello di permutazione ideale

La prova precedente assume parole casuali indipendenti. Il programma le
produce invece con AES applicato a contatori: a parità di chiave, contatori
distinti producono blocchi completi distinti. Abbiamo quindi ricostruito gli intervalli letti
per segreti, maschere e rumore della KSK ordinaria e della query, insieme
alla derivazione dei seed. Il conteggio tiene conto delle metà di blocco
condivise fra righe adiacenti e dei tentativi scartati dal sampler.
Gli altri valori prodotti durante la preparazione vengono marginalizzati:
non fissiamo il loro contenuto né condizioniamo sul successo della BSK.
Il risultato riguarda soltanto gli input del primo indirizzo Head.

**Nel modello con cinque permutazioni ideali indipendenti**, una per
ciascun flusso rilevante, la probabilità di un evento su questi blocchi
è al massimo quella del modello indipendente moltiplicata per un fattore
prossimo a uno. Il contributo delle collisioni entra così nel fattore
moltiplicativo, anziché come probabilità da sommare al limite. Per includere
il rigetto del sampler il confronto usa 58 tentativi per valore:
il modello assume questo budget nativo per ogni riga della KSK;
per la query il limite è solo virtuale e non modifica il programma.
La determinazione effettiva del budget nativo, che usa `log2` e
arrotondamento, resta una premessa da verificare. Nel modello ideal-cipher,
che include la derivazione dei seed dalla radice, si aggiunge un termine
`12/2^128` per le possibili coincidenze fra chiavi; il margine sotto
riportato vale anche con questo termine.

Con il contratto numerico precedente e input onesti fissati prima dei
sorteggi, il limite resta `<2^-66` per l'uscita dall'intervallo sufficiente
di almeno uno dei 120 primi indirizzi della **candidata**, includendo
l'esaurimento dei tentativi rilevanti nel modello limitato. Si tratta
di una query confrontata con 120 candidati: il suo rumore e quello delle
chiavi sono condivisi, non sono 120 query indipendenti. Il risultato è
una media sui sorteggi del modello, non una garanzia per una chiave salvata.

**AES reale richiede un passaggio ulteriore.** La riduzione esplicita
passa dalla radice ai cinque flussi rilevanti e aggiunge i vantaggi di
distinzione fra AES e una permutazione ideale; questi contributi non sono
stati quantificati. Aggiunge inoltre `<3/2^128` per sostituire i tre seed
distinti della radice con seed indipendenti. È un percorso di riduzione
separato dal modello ideal-cipher appena descritto. Anche le ipotesi sui seed
del sistema operativo e il legame con l'ambiente numerico effettivo
restano aperti. La riduzione riguarda l'evento marginale studiato, non
un'interfaccia che esponga i seed. Non dimostra il p_fail del runtime,
la sicurezza della distribuzione del rumore o la correttezza di blind
rotation, FFT e stadi successivi.

La prova ha una revisione indipendente e 51.019 controlli esatti passati,
senza eseguire AES o campionare rumore. Prova, conteggi e ricevute sono
congelati nell'archivio locale `tmp/finite-prp-transfer-20261002/`.
La candidata e il cap virtuale restano separati dal runtime mantenuto;
i tempi misurati non cambiano.

## Budget di tentativi: indirizzi prodotti e interruzioni

Il risultato precedente includeva l'esaurimento dei tentativi e assumeva
un budget nativo di 58. La prova successiva considera un evento diverso:
**un primo indirizzo viene prodotto e si trova fuori dall'intervallo
sufficiente della candidata**. Le esecuzioni fermate prima di quel passaggio
non appartengono a questo evento. Un'uscita dall'intervallo, inoltre, non
dimostra da sola che una cifra o l'ID finale siano errati.

Per il confronto guardiamo al massimo i primi 58 tentativi di ogni campione,
conservando le posizioni riservate dal programma. Se il budget nativo è più
piccolo, un campione completato usa già quel prefisso; un esaurimento ferma
la generazione. Se è più grande, il caso di 58 tentativi scartati entra nel
limite di probabilità. Per la query il limite rimane soltanto virtuale.

Sotto le precedenti ipotesi numeriche e di permutazione ideale, il limite
`<2^-66` vale per questo evento congiunto anche senza fissare il budget
nativo a 58. Le quote effettive e gli intervalli riservati devono essere
validi, allineati e deterministici, indipendenti dai valori casuali.
Il risultato resta una media sui sorteggi: non è una garanzia per chiavi
salvate né una probabilità condizionata al completamento.
Non stabilisce quanto spesso il programma riesca a completare la generazione.
Le qualifiche su AES reale, ambiente numerico e stadi successivi restano
quelle della sezione precedente.

La revisione indipendente e 218.594 controlli esatti passano; 45.022
assegnamenti completi di piccoli esempi finiti supportano le identità della
prova, senza campionare il generatore reale. Artefatti congelati nell'archivio
locale `tmp/budget-agnostic-address-20261003/`. La candidata resta sperimentale;
questa fase non cambia il runtime o i tempi misurati.

## Nota sui nomi storici

Gli header di [A98](../../runtime/core/src/a98.rs) e
[A112](../../runtime/core/src/a112.rs) descrivono ancora il momento in cui
erano proposte non compilate. Oggi entrambi sono moduli del crate mantenuto,
compilato nei gate della migrazione: lo split usa i loro adattatori Head.
Quelle frasi sono uno stato storico, non lo stato attuale. Questa nota
non modifica i sorgenti, che partecipano ai binding del circuito.

## Prima uscita Head: limite condizionale e obbligo FFT

3 ottobre 2026. Il primo passaggio dello [split](../../runtime/core/src/split.rs)
restituisce un valore cifrato interno, `d0`, che viene subito usato per
correggere il punteggio. La sua spaziatura è `Δ_H = 2^58`, diversa da quella
`2^59` delle cifre ID finali. Un errore strettamente minore di `2^57`
lo mantiene nella cella della cifra ideale; qui il programma non decifra
né arrotonda `d0`, quindi questo margine non basta a validare il seguito.
L'indirizzo deve comunque identificare la cifra pertinente della LUT.

È stata ricostruita la ricorrenza dell'errore della prima BR. Ogni CMUX
ruota l'errore precedente senza amplificarne il massimo per coefficiente;
aggiunge il rumore delle righe della chiave, il residuo della decomposizione
e il difetto della FFT. Il residuo dipende dal ciphertext corrente:
non viene trattato come un rumore indipendente o di media zero.

Per una chiave Head generata onestamente con segreti binari, sotto il
contratto numerico e di conversione del sampler descritto sopra,
ogni errore di riga ha modulo minore di `14 q σ_G + 1/2`. Con la chiave
Head a base `2^15`, due livelli e polinomi da 2048 coefficienti, il limite
delle cifre di decomposizione è `|d| ≤ 2^14`, inclusi entrambi gli estremi.
Il resto per coefficiente del ciphertext è entro `2^33`. Questo limite
non è il resto della fase: occorre sottrarre il prodotto della maschera
per il segreto. Per un segreto binario di peso H si ottiene, con la
maggiorazione triangolare:

```text
B_resto_fase ≤ (H + 1) · 2^33 ≤ 2049 · 2^33
```

Il precedente conto dei 859 passaggi usava il solo `2^33` per questo
termine: quella disuguaglianza non certifica il budget `2^57` della fase.
Occorre ricomporre i contributi delle righe, il resto corretto e il
difetto FFT effettivo. Il cap FFT locale `2^44`, usato come obiettivo nei
modelli successivi, resta da giustificare e non chiude da solo il conto.
Deve comprendere la trasformazione della chiave salvata, quelle delle
cifre, i prodotti, le somme, la trasformata inversa e la conversione sul toro.

L'analisi dei soli cast, con tutte le altre operazioni assunte esatte,
produce un maggiorante troppo largo quando viene sommato al limite di
supporto. Non dimostra un errore della demo e non è un certificato FFT.
Il piano fisso Dif4 della demo e il riordino canonico durante il salvataggio
della chiave non forniscono quel certificato. Le routine trigonometriche
usate dalla FFT restano distinte dal logaritmo verificato sopra.

Il controllo del modello iniziale riporta 18.258 verifiche, con 8.192
casi CMUX in un piccolo anello esaustivo, oltre alla geometria e alle
disuguaglianze del modello. Questo esito non convalida il precedente
termine scalare errato nel conto della fase. Sono esempi algebrici e
controlli esatti, senza nuova FHE. Codice runtime e tempi sono invariati.
Restano il limite FFT, la provenienza aritmetica della chiave e il passaggio
dall'errore di `d0` al feedback, ai normalizzatori e all'ID finale.
La prova della candidata per l'indirizzo non viene attribuita alla baseline.

## Margini dopo la prima estrazione

3 ottobre 2026. La prima Head dello [split](../../runtime/core/src/split.rs)
produce una cifra cifrata. Il server la usa subito per sottrarre la parte
alta del punteggio e preparare l'estrazione seguente. In questo calcolo l'errore
della prima cifra viene moltiplicato per 16, poi per 256 nel residuo finale.
Per questo il limite che mantiene la prima cifra nella sua cella non basta
a verificare il seguito.

La propagazione è stata ricostruita nel percorso attuale. Indicando con
`e_score` l'errore iniziale e con `e_H4`, `e_H5` quelli delle due uscite
Head, l'errore del residuo prima della normalizzazione è:

```text
128 e_score − 256 e_H4 − 16 e_H5
```

Ogni nuova estrazione aggiunge inoltre il proprio contributo di key switch
e modulus switch all'indirizzo della LUT. Questi termini dipendono dai
ciphertext e dalle chiavi riusate; non si assumono indipendenti.

La demo usa entrambi i normalizzatori condivisi: ciascuno ottiene due
uscite dalla stessa blind rotation, trasformando l'intero polinomio
cifrato. Un limite sull'errore della sola cifra del riporto non controlla
anche la cifra bassa. Un limite uniforme su tutti i coefficienti del
polinomio di errore della fase comune permette di maggiorare quell'errore
con fattori 60 per il residuo e 30 per
la cifra intermedia. Il limite della prima Head, con chiave 15×2, non si
attribuisce a questi normalizzatori, che usano la chiave ordinaria 23×1.

È stato ricavato un contratto sufficiente che combina i margini degli
indirizzi e delle ampiezze lungo tutto l'ingresso. La sua conclusione è
ristretta alle tre cifre del punteggio: i limiti richiesti restano da
dimostrare per l'implementazione, e il torneo richiede ancora i propri
margini. Fra i limiti ancora da dimostrare rientra il difetto complessivo
delle FFT. Il server continua a usare quelle cifre cifrate senza decifrarle.

Un esempio algebrico ai bordi mostra perché il solo limite della prima
cella non è sufficiente: la prima cifra resta nella sua cella, mentre il
residuo passa alla cifra successiva. Gli errori sono scelti nel modello;
l'esempio non è una nuova esecuzione FHE o un errore osservato della demo.
Il controllo nuovo passa 87.291 verifiche delle identità, dei margini e
di questo esempio con aritmetica esatta. Il codice runtime non è stato
modificato e non sono state ripetute misure di tempo.

## Parametri Head: cosa possiamo concludere dal limite conservativo

3 ottobre 2026. È stato controllato se cambiare la decomposizione della
[chiave Head](../../runtime/core/src/head_key.rs) possa soddisfare i margini del feedback descritti sopra.
La configurazione attuale è 15×2: due livelli di cifre da 15 bit.
Aumentare i bit rappresentati riduce l'errore di decomposizione, ma cifre
più grandi o più livelli aumentano il contributo del rumore delle righe.
Quindi «più precisione» non equivale automaticamente a «meno errore».

Il controllo considera tutte le 273 configurazioni positive con meno di
64 bit complessivi, mantenendo dimensioni e rumore delle righe attuali.
Sotto le premesse di generazione e aritmetica della prova di supporto
precedente, usa un limite uniforme valido per ogni segreto binario e
suppone prodotti torus esatti. Per isolare il contributo delle Head pone
a zero l'errore iniziale dello score, i nuovi errori di key switch e
modulus switch, quelli dei normalizzatori ordinari e i difetti FFT.
Le due Head continuano a usare la stessa chiave Head.

Fra queste configurazioni, 64 passano il criterio sufficiente del modello.
Il numero minimo di livelli è otto, con cifre da cinque bit. È un minimo
per questo particolare maggiorante: non un costo minimo dell'algoritmo,
né una misura del rumore effettivo. La configurazione attuale 15×2 e
le alternative 18×2 e 12×3 non vengono certificate da questo criterio;
il risultato non dimostra un errore nella demo.

La chiave Head a otto livelli occuperebbe quattro volte il payload
attuale. Supera da sola il limite di 320 MiB del bundle; inoltre il
caricatore attuale ammette soltanto 15×2. Nessuna configurazione che passa
questo modello può quindi sostituire direttamente quella della demo.
I conteggi sono strutturali, senza nuove misure di tempo o affermazioni
di sicurezza per i parametri ipotetici.

Il risultato orienta il lavoro successivo verso limiti meno grossolani
o un diverso percorso di estrazione. Restano da verificare le FFT reali,
gli altri contributi al feedback e la composizione fino al risultato 0/ID.
Il codice runtime e i risultati sperimentali precedenti restano invariati.

## Un limite sulle righe della chiave, valido anche quando viene riusata

3 ottobre 2026. Il controllo precedente usava il peggior errore ammesso
per ogni coefficiente. Qui si limita invece la **somma dei valori assoluti
degli errori di una riga** della chiave Head, prima della conversione
Fourier, detta norma L1. Quando
questa somma rispetta il limite, possiamo controllare il contributo
della riga per qualunque input del calcolo, anche se dipende da passaggi
precedenti che hanno usato la stessa chiave. Non serve assumere che
le due uscite Head siano indipendenti.

La parte probabilistica resta condizionale al modello di generazione:
parole casuali uniformi indipendenti e ipotesi aritmetiche dichiarate
per il sampler finito. Il percorso effettivo genera 2.048 coefficienti
con 2.048 chiamate scalari accettate: ciascuna conserva una sola
coordinata polare. Non si contano 1.024 chiamate che restituiscono coppie.

Nel modello, la probabilità congiunta di produrre una riga e superare
il limite scelto è inferiore a `2^-102`. Per una singola generazione
di chiave Head con geometria fissata, l'unione sulle sue righe resta
inferiore a `2^-85`. Non è una probabilità di errore della demo, né
una legge condizionata alla riuscita della generazione. Il trasferimento
al generatore AES effettivo e la provenienza delle chiavi restano aperti.

Il nuovo controllo esatto passa 5.075 verifiche. Delle stesse 273
configurazioni, 79 soddisfano il criterio sufficiente che considera
soltanto le due Head, con prodotti torus esatti e gli altri errori
posti a zero come nella sezione precedente. Il minimo per questo
limite più stretto scende da otto a cinque livelli, con cifre da otto
o nove bit. Non è un minimo di costo dell'algoritmo.

Anche queste configurazioni richiedono modifiche al caricatore, che
ammette soltanto 15×2. A cinque livelli la sola chiave Head occuperebbe
281.477.120 byte; il bundle complessivo arriverebbe a 475.365.376 byte,
superando il limite attuale di 320 MiB. La configurazione attuale
non viene certificata da questo criterio: ciò non dimostra un errore
nelle esecuzioni. Restano le FFT reali, gli altri contributi al feedback
e la composizione fino a 0/ID. Nessun parametro o codice runtime è stato modificato
e non sono state ripetute misure di tempo.

## Dalle parole indipendenti al modello di permutazione

3 ottobre 2026. Il limite sulla norma delle righe Head è stato trasferito
a un modello con una sola permutazione uniforme su blocchi da 128 bit.
Questo modello produce risposte diverse a contatori diversi; non tratta
i blocchi come nuove estrazioni indipendenti. La prova confronta la legge
del suo evento finito con quella delle parole indipendenti usata sopra.

Si seguono soltanto i blocchi di rumore necessari alle righe Head,
mantenendo le loro posizioni effettive. Il [generatore del bundle](../../runtime/core/src/service.rs)
usa prima lo stesso flusso per PFKS: quelle riserve precedenti rimangono
nel conto delle posizioni, anche se i loro valori non servono al nuovo
evento. Il seme di questo flusso viene richiesto direttamente al seeder
del bundle; non viene identificato con il seme del precedente calcolo
dell'indirizzo.

Per rendere il confronto finito, la prova osserva un prefisso di ogni
riserva. Le righe che richiedono più tentativi vengono coperte da un
limite separato sul tempo di attesa del sampler. Un'interruzione che
non produce una chiave non diventa un superamento della norma di una
chiave prodotta. Il limite del prefisso è soltanto matematico: nessun
cap è stato aggiunto al programma e le riserve native restano intere.

Sotto le ipotesi aritmetiche precedenti, con riserve valide e fissate
indipendentemente dal rumore, la probabilità dell'evento congiunto
resta inferiore a `2^-85`: una generazione produce una chiave Head
onesta e qualche sua riga supera la norma ammessa. Non si divide per la
probabilità che la generazione riesca. Quando la norma è rispettata,
il certificato precedente continua a valere per input che riusano
la chiave, senza assumere nuove uscite Head indipendenti.

Il nuovo controllo esatto passa 5.014 verifiche, sui budget di 63
numeri di livelli e su piccoli esempi esaustivi. Non sono esecuzioni
AES o FHE. Il passaggio ad AES reale resta condizionale alle ipotesi sul seme
e sulla provenienza; il vantaggio di distinzione non è quantificato. Restano
le FFT e la composizione completa: il limite non è una probabilità
di errore dell'ID finale. Non sono stati modificati parametri
o codice runtime e non sono state ripetute misure di tempo.


## Errore della conversione iniziale della chiave

3 ottobre 2026. Quando la chiave standard viene convertita in Fourier,
i coefficienti interi a 64 bit passano a numeri in virgola mobile.
I valori più grandi non sono tutti rappresentabili. Sotto l'ipotesi
di arrotondamento IEEE al più vicino (ties-to-even), lo spostamento
di un coefficiente è al massimo di 512 unità torus. Questa analisi
isola quel passaggio e considera ideale ed esatta ogni altra parte
della FFT, comprese le sue costanti matematiche.

Per una riga della chiave, l'errore della fase è quello della parte body
meno il prodotto degli errori della maschera per il segreto. Body e
maschera sono correlati: il calcolo conserva questa dipendenza, usando
un limite deterministico per il body e la legge finita dei coefficienti
originali della maschera. Il segreto binario deve essere scelto prima
della maschera, con la legge casuale condizionale dichiarata nella prova.

Il nuovo limite per l'errore di conversione della fase è di 147.968
unità torus per coefficiente. Nel modello di una permutazione uniforme
su blocchi da 128 bit, la probabilità dell'evento congiunto è inferiore
a `2^-93`, per una geometria fissata: la generazione produce una chiave
Head completa onesta e il limite viene superato in almeno una riga. Si seguono i blocchi delle maschere Head nelle loro
posizioni effettive: le riserve PFKS precedenti nella
[generazione del bundle](../../runtime/core/src/service.rs) rimangono.
Il limite vale poi per input che riusano la stessa chiave, anche adattivi.
Non è una probabilità di errore dell'ID finale; il trasferimento ad AES
reale e alla legge del seme resta condizionale e non quantificato.

Aggiungendo questo contributo al limite sul rumore delle righe, nel
controllo teorico delle sole due Head con gli altri errori posti a zero,
il minimo per questo maggiorante è sei livelli, con cifre da sei o
sette bit. Nessuna configurazione che passa è ammessa dal programma:
a sei livelli la sola chiave Head occuperebbe 337.772.544 byte e il
bundle completo 531.660.800 byte, oltre il limite attuale di 320 MiB.
Il criterio non certifica la configurazione 15×2 attuale; questo non
dimostra un errore nelle sue esecuzioni.

Il nuovo controllo esatto passa 15.047 verifiche della legge finita,
dei limiti e di piccoli esempi esaustivi. Non sono esecuzioni FHE.
Restano le altre approssimazioni FFT, la provenienza delle chiavi
caricate e la composizione completa. Nessun parametro o codice runtime
è stato modificato e non sono state ripetute misure di tempo.


## Arrotondamento finale dalla FFT agli interi torus

3 ottobre 2026. Dopo la FFT inversa, ciascun coefficiente in virgola mobile
viene convertito di nuovo in un intero torus a 64 bit. Nel convertitore scalare
di TFHE-rs 1.8.1, il controllo isola
questa conversione scalare sulla **stessa rappresentazione binary64 finita**
che arriva al convertitore. Non confronta input prodotti da FFT diverse.

La conversione sottrae l'intero più vicino, moltiplica il resto per `2^64`,
arrotonda e passa attraverso un intero con segno prima di tornare a quello
senza segno. Nel modello dichiarato, i valori a metà sono arrotondati lontano da zero.
I passaggi sono esatti salvo l'arrotondamento finale e un caso di saturazione.
Per esempio,
`-0,5` lascia un resto di `+0,5`: scalato diventa `2^63`, oltre il massimo
intero con segno. La saturazione restituisce `2^63-1`, una unità sotto il
valore torus atteso. L'esempio è calcolato nel modello dyadico: non è
un'esecuzione nativa del convertitore né un fallimento FHE/ID osservato.
Il caso riguarda esattamente i valori binary64 negativi
che sono a metà tra due interi. Fuori da quel gruppo, la conversione coincide
con l'arrotondamento torus matematico della stessa rappresentazione.

La distanza complessiva dal valore reale scalato è al massimo una unità
intera torus (`2^-64` in unità normalizzate), e al massimo mezza unità fuori
dal caso di saturazione. Non si sommano i due massimi: nel caso di saturazione
il valore scalato è già intero. Il nuovo controllo esatto passa 17.680 verifiche: usa una classificazione
di tutte le classi binary64 finite, accompagnata da 83 casi di confine e
piccoli formati esaustivi. Non esegue la FFT nativa né prova un errore dell'ID finale.

Nel percorso scalare, la conversione avviene una volta per coefficiente dopo
aver accumulato tutti i livelli del prodotto esterno. Con un segreto GLWE
binario di lunghezza 2.048, come nel [profilo Head](../../runtime/core/src/head_key.rs), il solo contributo di conversione alla fase è
quindi al massimo 2.049 unità per prodotto esterno; il numero di livelli non
moltiplica questo termine. Il limite è deterministico e vale anche per
input adattivi e riuso della chiave, purché ogni input soddisfi le ipotesi.

Restano esplicite le ipotesi su input finiti, semantiche dell'eseguibile,
gestione dei subnormali e risultato esatto della scala `2^64`: la documentazione
generale di `powi` non garantisce da sola quest'ultimo punto. Il percorso
vettoriale x86 richiede una verifica distinta. Restano inoltre le altre
approssimazioni FFT e la corrispondenza fra chiave standard e Fourier caricata.
Questo termine è già compreso in un eventuale limite numerico totale: non
va aggiunto una seconda volta. Non sono stati modificati codice runtime,
parametri o risultati dei benchmark.


## Costanti trigonometriche interne della FFT

3 ottobre 2026. La FFT moltiplica alcuni risultati intermedi per costanti
complesse che rappresentano rotazioni. Prima occorre controllare le costanti;
poi occorrerà seguire gli errori delle moltiplicazioni e delle somme fino
all'uscita. Questo controllo riguarda il primo passaggio, per il piano
scalare Dif4 a 1.024 valori complessi del percorso attuale.

Il codice `sincospi64` genera le costanti interne con polinomi e operazioni
in virgola mobile. Abbiamo ricostruito i suoi coefficienti, l'ordine delle
operazioni e l'arrotondamento, confrontando il risultato con intervalli
razionali rigorosi per seno e coseno matematici. Il riferimento usa un limite
indipendente per pi greco: non assume esatte le funzioni trigonometriche
della piattaforma.

Il nuovo controllo esatto passa 59.132 verifiche e copre **tutti i 768 punti
di generazione**, corrispondenti a 511 argomenti distinti. L'errore di ogni
costante complessa, misurato come somma degli errori delle due coordinate,
è al massimo `2^-52`, circa `2,2 × 10^-16`; lo stesso limite vale per la
norma usuale dell’errore complesso e per la deviazione dal modulo unitario. Le costanti
dell'inversa sono coniugate delle stesse uscite, quindi conservano il limite
senza richiedere errori indipendenti. Si tratta di un maggiorante certificato
nel modello, non di una misura dell'errore delle tabelle native caricate.

Abbiamo anche controllato la tabella: entrambe le direzioni usano tutte le
768 celle del secondo layout che sono state inizializzate. Le celle lasciate
inutilizzate non vengono lette. In ogni trasformazione le costanti vengono
caricate 1.020 volte e usate in 3.072 moltiplicazioni, perché alcuni valori
caricati sono riutilizzati. Questi conteggi non sono altrettanti errori
indipendenti, né basta moltiplicarli per il limite di una costante per
ottenere l'errore totale: serve anche l'ampiezza dei risultati intermedi.

Il risultato assume la conversione corretta dei letterali, le operazioni
IEEE binary64 con arrotondamento al più vicino e pareggi al pari, FMA con
un solo arrotondamento, segno degli zeri, sottoflusso graduale, ordine del
codice e corrispondenza fra tabelle generate e usate. Non
attesta l'eseguibile storico o le chiavi salvate. Le rotazioni esterne
`Twisties`, che chiamano `sin_cos` della piattaforma, richiedono un limite
separato; restano inoltre gli arrotondamenti della FFT completa. Nessuna
probabilità di errore dell'ID finale, modifica di parametri o variazione
dei tempi deriva da questo controllo.


## Dal limite sulle costanti al calcolo della FFT

3 ottobre 2026. Dopo le costanti interne, abbiamo controllato le somme e le
moltiplicazioni della FFT scalare a 1.024 valori complessi. Il percorso ha
quattro stadi con rotazioni e uno finale senza rotazioni. Ogni stadio
combina gruppi di quattro valori; i risultati passano alternativamente fra
il buffer originale e quello di lavoro. Il primo stadio scrive tutte le
celle del buffer di lavoro prima che vengano lette.

La prima verifica riguarda il significato del calcolo. Abbiamo ricostruito
dagli indici del codice quali input contribuiscono a ciascuna uscita e con
quale rotazione. Una prova algebrica mostra che, sostituendo operazioni e
costanti con quelle matematiche esatte, il percorso calcola la trasformata
discreta di Fourier nell'ordine naturale. Il nuovo controllo esatto verifica
tutte le 1.048.576 coppie ingresso–uscita, con entrambi i segni: negativo
per la diretta, positivo per l'inversa. Sono coefficienti formali del
calcolo, non esecuzioni FFT su foto o ciphertext.

La seconda verifica riguarda l'arrotondamento. Abbiamo seguito i due livelli di
somme e le moltiplicazioni complesse nella loro forma effettiva: due
prodotti ordinari e due FMA. Il limite sulle costanti dello stadio precedente
si moltiplica per l'ampiezza del ramo; il riuso non lo rende rumore
indipendente. Nel modello dichiarato, indicando con `R` il massimo modulo
complesso degli elementi effettivamente in ingresso, l'errore massimo
della FFT rispetto alla trasformata esatta degli stessi input è al più

    2^-38 R + 2^-1063.

È un limite assoluto rispetto all'ampiezza degli input, non una percentuale
del valore in uscita. Se l'ingresso ha già una discrepanza massima `e`
rispetto a un riferimento, si aggiunge `1.024 e` una sola volta. Il piccolo
termine costante conserva il contributo dei subnormali: il risultato non
assume che ogni intermedio sia un numero normale.

Il limite vale per input binary64 finiti con `R <= 2^1000`, operazioni IEEE
con arrotondamento al più vicino e pareggi al pari, FMA con un solo
arrotondamento, sottoflusso graduale, segno degli zeri e ordine del codice
preservati. La prova usa quel dominio per escludere l'overflow di ogni
operazione. Richiede inoltre il percorso scalare e la corrispondenza fra
costanti generate e usate, con buffer validi e distinti; non attesta l'eseguibile o le chiavi salvate.

Entrambe le trasformate sono grezze, senza normalizzazione: l'inversa
matematica composta con la diretta restituisce 1.024 volte l'ingresso.
Dopo l’inversa grezza, il percorso TFHE applica il fattore `1/1.024`,
le rotazioni esterne `Twisties` e la conversione agli interi torus. Prima
della diretta compaiono altre conversioni e rotazioni esterne; restano da
collegare anche i prodotti fra gli elementi Fourier. Questo risultato chiude il contributo della FFT scalare interna
nel modello, senza fornire ancora il limite del prodotto esterno completo
o una probabilità di errore dell'ID finale. Codice runtime, parametri e
misure di tempo restano invariati.


## Conversioni di ingresso e uscita della FFT

3 ottobre 2026. Il controllo precedente copriva la FFT scalare interna.
Abbiamo ora collegato il suo modello alle conversioni che la precedono e
la seguono, mantenendo lo stesso input di riferimento e distinguendo gli
arrotondamenti di ciascun passaggio.

Il polinomio ha 2.048 coefficienti. La conversione li divide in due metà:
il coefficiente `j` diventa la parte reale del valore complesso `j`, quello
`j+1024` la parte immaginaria. Per esempio, il primo valore contiene i
coefficienti 0 e 1.024. Prima della FFT si applica una rotazione esterna;
dopo l'inversa si ricostruiscono le stesse due metà. La prova delle radici
mostra che, con operazioni e costanti matematiche esatte, questa forma
rappresenta il prodotto polinomiale negaciclico previsto da TFHE.
Il nuovo controllo esatto verifica tutte le 2.097.152 relazioni fra
coefficienti e radici, usando l'identità FFT già verificata.
Non sono prove su altrettanti ciphertext.

Gli arrotondamenti delle conversioni richiedono un limite proprio. Il
prodotto complesso generico esegue quattro prodotti ordinari e due somme;
la moltiplicazione interna alla FFT usa due prodotti e due FMA. Abbiamo
derivato limiti sull'errore dei primi, inclusi i termini assoluti che
coprono i subnormali. Richiedono operazioni al più vicino con pareggi al
pari, sottoflusso graduale, ordine del codice preservato, valori finiti
e domini di ampiezza dichiarati per escludere l'overflow di ogni operazione.
Il percorso scalare, i buffer e la corrispondenza dell'eseguibile restano
premesse, senza essere attestati da questo controllo.

All'uscita il codice coniuga la rotazione, la scala con `1/1024` e poi la
moltiplica per il risultato dell'inversa. Il modello conserva quest'ordine:
spostare la scala dopo il prodotto cambierebbe gli arrotondamenti. L'errore
dell'inversa grezza si divide matematicamente per 1.024, mentre il calcolo
della rotazione scalata e il prodotto hanno contributi separati. Se la
scala di ingresso è esattamente `2^-64`, i valori interi già convertiti
si normalizzano senza un ulteriore errore di arrotondamento; questa condizione non
si deduce dalla sola notazione `powi` nel sorgente. La scala di uscita
può invece produrre subnormali e conserva il relativo termine assoluto.

L'accuratezza delle rotazioni esterne resta indicata con un parametro
`tau`. Deve includere sia la costruzione dell'angolo sia l'errore di
`sin_cos` rispetto alla radice matematica: la documentazione della
funzione non fornisce un piccolo limite portabile. Generazione della
chiave e uso successivo possono richiedere limiti e corrispondenze
distinti. Riutilizzare o coniugare la stessa tabella conserva errori
deterministici, senza renderli indipendenti.

Le formule trasportano quindi l'errore di ingresso con il guadagno 1.024
e quello dell'inversa con il fattore `1/1024`, usando sempre le ampiezze
effettive. Il cast iniziale e la conversione finale agli interi torus
rimangono contributi contati una volta, sugli stessi valori di riferimento.
Il risultato non assegna ancora un valore numerico a `tau`, non copre
i prodotti e gli accumuli nello spettro e non certifica la provenienza
delle chiavi salvate. Restano il limite del prodotto esterno completo e
la composizione fino all'esito `0/ID`. Runtime, parametri e tempi misurati
restano invariati.


## Prodotti e accumuli tra la FFT diretta e l’inversa

Dopo la trasformazione diretta, il prodotto esterno combina lo spettro della
chiave con quello delle cifre ottenute dalla decomposizione. Nel profilo Head
a due livelli e due righe, ogni posizione dello spettro riceve quattro
prodotti. Il primo scrive l’accumulatore; gli altri tre aggiungono il loro
contributo al valore già calcolato. Seguono la FFT inversa, la conversione
agli interi e l’aggiunta al ciphertext di uscita.

Le sezioni precedenti coprono le trasformazioni e le conversioni. Questo
controllo aggiunge il limite per la moltiplicazione e la somma dei quattro
contributi. Il codice usa operazioni fuse: ogni FMA calcola un prodotto più
una somma con un solo arrotondamento. Il primo prodotto usa due prodotti
ordinari e due FMA; gli aggiornamenti usano quattro FMA. Sono grafi diversi
dal prodotto complesso ordinario impiegato nelle conversioni.

Il confronto parte dagli stessi spettri effettivi: quale errore introduce
il codice rispetto alla loro somma esatta? Il limite conserva l’errore
dei passaggi precedenti mentre si aggiungono gli altri termini. Non assume
errori indipendenti quando vengono riusate la chiave o le sue rotazioni.
Solo dopo si aggiunge, separatamente, la differenza tra gli spettri effettivi
e quelli del riferimento corrispondente. Il riferimento della chiave è già
dopo il cast iniziale; quel cast non va contato una seconda volta.

Con `u=2^-53`, `beta=2^-1074`, `h=2u+u²` e `kappa=(2+u)beta`,
la prova condizionale dà `hP+kappa` per il primo prodotto e
`h(P+C)+kappa` per ciascun aggiornamento. Qui P maggiora il prodotto dei
moduli degli operandi effettivi, e C il modulo dell’accumulatore effettivo
precedente. Il termine assoluto beta copre anche cancellazioni, zeri e
risultati subnormali. Il limite complessivo dei quattro passaggi si ottiene
conservando questi contributi nella ricorrenza; non contando ogni errore
come una nuova variabile casuale.

La condizione sufficiente della prova su prodotto e accumulatore esclude
overflow nei singoli passaggi. Il vincolo della prova sull’ingresso
dell’inversa serve invece a soddisfare il dominio del limite FFT precedente. Sono condizioni diverse: restare
finiti non significa automaticamente rispettare il dominio dell’inversa.
Per collegare il risultato a quest’ultima si usano il massimo del raggio
e dell’errore su **entrambi i polinomi e tutte le 1.024 frequenze**. Il
limite di una singola posizione non basta per una trasformazione completa.

Il nuovo controllo esatto è passato: formule del prodotto e degli accumuli,
ricorrenza a quattro termini, domini sufficienti, indici e inizializzazione
sono coerenti con il contratto dichiarato. Copre tutte le 2.048 posizioni
di uscita e gli 8.192 indirizzi di chiave coinvolti. Scalar e Neon hanno
ordine e segni diversi nelle operazioni; la prova copre entrambi con lo
stesso maggiorante senza affermare che tutti i bit, compreso il segno dello
zero, coincidano.

Nearest-even, FMA a un arrotondamento, gestione graduale dei subnormali,
layout valido, piano FFT e corrispondenza delle chiavi restano ipotesi
esplicite. Il collegamento fra le sorgenti verificate, l’eseguibile e il
suo ambiente FP resta da attestare. L’accuratezza delle rotazioni esterne
resta simbolica. Il
trasporto all’uscita usa la scala della rotazione prima del prodotto e
conta una volta il limite totale della mappa agli interi. Questo è un
limite del canale numerico sotto tali condizioni: non fornisce da solo
una probabilità di errore del risultato `0/ID`, una verifica nativa della
pipeline o una misura dei tempi.

## Rotazioni esterne: un candidato con errore delimitato

Prima della FFT, il codice moltiplica i coefficienti per una rotazione
complessa. All’uscita usa la rotazione coniugata, scalata prima del prodotto.
Queste rotazioni sono diverse dalle costanti usate nei passaggi interni
della FFT. La prova precedente lasciava simbolico il loro errore.

Il generatore attuale di TFHE-rs calcola gli angoli usando il valore
approssimato di pi e chiama `sin_cos`. La sua documentazione non offre
un limite di precisione portabile. Abbiamo quindi verificato un candidato
che usa `sincospi64`, la routine già presente in tfhe-fft, con gli argomenti
esatti `j/2048`, per `j=0,...,1023`. Il riferimento matematico è
`exp(i*pi*j/2048)`. La funzione restituisce seno e coseno: per formare il
numero complesso il coseno va nella parte reale e il seno in quella immaginaria.

Il nuovo controllo copre tutti i 1.024 argomenti. La precedente verifica
delle costanti interne copriva una griglia diversa e non bastava a giustificare
questa sostituzione. Il modello segue le operazioni originali, comprese
la rappresentazione delle costanti, ogni prodotto arrotondato separatamente,
le FMA con un solo arrotondamento e i segni degli zeri. Il confronto usa
intervalli razionali per pi, seno e coseno, senza una funzione trigonometrica
numerica come riferimento. Include anche l’argomento sul bordo della riduzione.

La verifica esatta è passata. Sotto il contratto aritmetico dichiarato,
ogni fattore candidato ha errore assoluto complesso al massimo `2^-52`
rispetto alla rotazione matematica, e modulo compreso fra `1-2^-52` e
`1+2^-52`. Il limite deriva da un maggiorante della somma degli errori
delle due componenti; non è una misura dell’errore nativo né il massimo
esatto dell’errore trascendentale. La coniugazione conserva lo stesso limite.

Il candidato **non è installato nel servizio**. La funzione originale si
trova in un modulo privato, quindi serve un’integrazione mantenuta e verificata.
Occorre poi collegare sorgenti, eseguibile, ambiente aritmetico e tutti i valori
effettivamente generati e usati al contratto del controllo. Il risultato non
certifica la precisione dell’attuale `sin_cos` e non attesta retroattivamente
la conversione delle chiavi Fourier salvate. Generazione e uso mantengono
errori distinti finché la loro corrispondenza non è verificata.

L’integrazione proposta cambierebbe tutti gli usi della FFT di questa taglia,
quindi richiederebbe una provenienza verificata per ogni oggetto Fourier
coinvolto: rigenerare soltanto Head non basta per gli altri oggetti salvati.
I percorsi conservati con il generatore precedente e le altre taglie restano
fuori da questo certificato. Il nuovo limite riguarda una parte del canale
numerico; la composizione fino all’esito `0/ID`, le ipotesi native e i tempi
richiedono ancora verifiche separate. In questa fase non è cambiato il runtime.


## Rotazioni esterne: verifica del prototipo compilato

La verifica precedente delimitava l’errore del candidato `sincospi64(j/2048)`
nel modello numerico. Abbiamo ora compilato una copia integrale della funzione
con Rust 1.98.1 per Apple M4 ed eseguito il prototipo una volta. Tutti i 1.024
fattori, le 15 costanti e gli argomenti effettivi sono stati acquisiti. La
tabella nativa ha la stessa impronta SHA256 della tabella certificata:
`c8d51378277799c27d11871e626dc338b54f78c7dba34bd072e5a050abc46de2`.

Il confronto usa l’impronta registrata, senza rigenerare il vecchio modello
e senza una seconda tabella attesa disponibile. Sotto l’assunzione di identità
dell’impronta, il limite complesso `2^-52` si applica ai valori registrati di
questa esecuzione. Sono stati controllati sorgente, programma compilato e
formato completo dell’output; le letture FPCR restano osservazioni grezze.
Il risultato non prova la correttezza generale del compilatore o dell’ambiente
FP. Il candidato non è installato nella pipeline TFHE: tabelle del servizio,
conversione delle chiavi e composizione fino a `0/ID` restano da verificare.
Non è una misura di velocità né della probabilità di fallimento FHE.

## Composizione di un external product: domini ammessi, limite insufficiente

Un external product è il passaggio che combina i digit dell'ingresso con
le righe della chiave cifrata. Nel percorso Head qui considerato accumula
quattro termini, poi converte due polinomi dal dominio Fourier agli interi.
Prima avevamo limiti separati per conversioni, FFT, prodotti e arrotondamento
finale. Mancava verificare se, composti sugli stessi dati, bastassero a
giustificare il margine numerico assunto dalla prova della blind rotation.

Abbiamo ricavato le ampiezze dai coefficienti legalmente ammessi, senza
leggere una chiave salvata: raggio complesso packed al massimo 1 per la chiave
dopo cast e scala, e `2^15` per i digit. La nuova verifica razionale ha passato
256 controlli. Queste ampiezze rispettano i domini dei limiti delle singole
operazioni, sotto le rispettive ipotesi di sorgente e aritmetica. La copertura
è uniforme sui quattro termini, entrambi gli output e tutte le 1.024 frequenze;
non dipende dalla freschezza o dall'indipendenza dei digit.

La composizione, però, **non certifica il budget di fase `2^44`**. La fase è
la quantità da cui dipende il messaggio in decifratura. Il maggiorante
ottenuto per il canale restante, dopo avere separato il cast iniziale, è
compreso fra `2^65` e `2^66`. Anche le due alternative per reinserire il cast
restano in questo intervallo. Sono maggioranti dell'errore: il loro valore
elevato non dimostra un errore effettivo elevato né un fallimento FHE.

Il confronto conserva la stessa chiave standard, gli stessi digit e lo stesso
riferimento dopo cast. Conta una sola volta la mappa finale agli interi; le
due stime del cast sono alternative e non vengono sommate fra loro. I nuovi
contributi propongono di delimitare il difetto totale, senza aggiungersi a
un difetto totale che li includa già.

Questo risultato assume anche il limite `2^-52` delle rotazioni candidate,
che **non sono integrate nel servizio**: non certifica le tabelle correnti
o la provenienza delle chiavi salvate. Mostra che migliorare soltanto quelle
rotazioni non chiude questa specifica prova. Il prossimo punto da studiare
è un limite congiunto per mask e body prima di applicare le disuguaglianze
triangolari: la cancellazione della relazione cifrata esatta non si trasferisce
automaticamente ai calcoli arrotondati. Runtime, parametri e risultati
sperimentali precedenti restano invariati.


## Difetto congiunto di fase: riferimento e contributi da delimitare

Il controllo precedente applicava limiti separati a mask e body e poi li
trasportava in fase. Abbiamo ora definito un riferimento per studiare insieme
le due uscite dello stesso external product, senza cambiare il runtime.

Fissiamo le cifre intere effettive dell'ingresso e il loro spettro Fourier
già calcolato. Il riferimento conserva le costanti di generazione delle
chiavi e di uso, ma interpreta in aritmetica esatta le operazioni sui valori
dopo il cast iniziale. È quindi lineare nella riga della chiave, a cifre e
costanti fissate. Questo non rende lineare il programma cifrato completo
e non suppone che il riferimento coincida con la convoluzione esatta.

La differenza di fase rispetto all'external product esatto si separa in:

- il contributo del cast iniziale;
- il commutatore: quanto cambia il risultato applicando il riferimento prima
  o dopo la moltiplicazione per il segreto;
- l'azione dell'errore dell'operatore sul messaggio della riga e sul suo rumore;
- l'azione sui multipli di `q` dovuti ai rappresentanti interi scelti;
- l'azione aggiuntiva dell'operatore approssimato sugli errori di cast;
- il residuo dei calcoli effettivi di conversione, accumulo, inversa e uscita,
  con la mappa finale agli interi contata una volta.

I multipli di `q` scompaiono nel calcolo intero esatto modulo `q`, ma non
possono essere eliminati prima di un operatore approssimato senza provarne
la compatibilità. Anche usare lo stesso operatore per mask e body non basta
a dimostrare che il commutatore sia nullo. La relazione esatta fra le due
parti della chiave non elimina automaticamente questi contributi numerici.

Un altro riferimento lecito può togliere anche gli arrotondamenti della trasformata Fourier
delle stesse cifre intere. In quel caso il loro effetto deve spostarsi nel residuo. Le due
decomposizioni restituiscono la stessa differenza totale: cambiare il modo
di dividerla non è un miglioramento del limite.

La derivazione e il collegamento ai passaggi del codice sono stati revisionati
indipendentemente. È un risultato algebrico e statico; non abbiamo eseguito
un nuovo test FHE o misurato una riduzione dell'errore. Restano da delimitare
questi contributi sul calcolo effettivo, con una provenienza coerente
delle chiavi e delle tabelle. Il budget di fase e la garanzia generale `0/ID`
rimangono aperti; non sono cambiati parametri, tempi o risultati precedenti.

## Costanti Fourier: un limite strutturale condizionale

Il controllo del 3 ottobre distingue le **costanti approssimate della FFT**
dagli arrotondamenti che avvengono mentre si elaborano i dati. La nuova prova
riguarda le prime: mantiene le costanti effettive e considera esatti soltanto
i calcoli sui dati. Non sostituisce il precedente limite della FFT eseguita
in binary64.

Per il percorso scalare su 1024 valori complessi, indicando con `alpha_j`
il massimo errore delle costanti nello strato `j`, la differenza dalla
trasformata ideale ha il limite operatoriale Euclideo

    ||T_costanti - T_ideale||_2 <= 32 * (prod_j(1 + alpha_j) - 1).

I quattro fattori corrispondono ai quattro strati con costanti di rotazione
(twiddle); l'ultimo
strato non ne aggiunge uno. Il limite vale separatamente per generazione e
uso: non presuppone che le loro tabelle o costanti coincidano. Le sorgenti
del piano configurato selezionano questa FFT scalare su ARM; la selezione
Neon dei prodotti spettrali è un passaggio distinto.

Questo riferimento permette di isolare il contributo che rompe la
cancellazione con il segreto. Con trasformate ideali, anche lo spettro
effettivo delle cifre, mantenuto identico, produce un operatore che commuta
con la moltiplicazione per il segreto. Nel confronto con le trasformate
effettive, il termine che combina i due difetti viene contato una volta.
Gli errori delle cifre restano invece nel contributo che determina il
valore del risultato, insieme alle eventuali differenze di normalizzazione.

La prova è **condizionale e parziale**: non abbiamo istanziato un nuovo
limite numerico per la fase completa. Restano gli arrotondamenti effettivi,
i contributi del cast e del wrapping, e la provenienza di chiavi/tabelle.
Il candidato di costanti esterne verificato in precedenza è ancora separato
dal runtime. Non segue un nuovo tempo, una riduzione dell'errore osservato o
una garanzia generale di `0/ID`.

## Cast: un limite più stretto per il vettore degli errori

Questo controllo riguarda la preparazione della chiave Head: le righe
cifrate vengono convertite da interi a 64 bit a numeri floating point
prima di trasformarle in Fourier.
Alcuni interi non sono rappresentabili esattamente: la conversione può
spostarli di una piccola quantità. Nel calcolo cifrato conta l'errore di
fase, che combina l'errore del body con quello della maschera moltiplicato
per il segreto. Non basta quindi guardare l'arrotondamento di un solo valore.

Prima avevamo limitato ciascun coefficiente separatamente e sommato i
limiti: il maggiorante della norma L1, cioè la somma dei valori assoluti
degli errori di cast di una riga, era
303.038.464. La nuova dimostrazione considera l'intero vettore della
maschera e usa la struttura del segreto binario. Ottiene il maggiorante
**225.443.840** per la stessa quantità, circa il **25,6% in meno**.
È una riduzione del limite matematico; codice e tempi restano invariati.

La prova usa tre proprietà della conversione già dimostrate nel modello
iid degli interi originali: errore simmetrico, valore assoluto al più 512
e varianza inferiore a 50.000. Da queste deriva un limite globale della
funzione generatrice dei momenti, con proxy 65.536. La disuguaglianza
[quadratica di Hsu, Kakade e Zhang](https://doi.org/10.1214/ECP.v17-2079) permette poi di controllare il vettore
dopo la moltiplicazione negaciclica. La dimostrazione locale verifica le
ipotesi e mantiene il body, che può dipendere dalla maschera, sotto un
limite deterministico. Il testo integrale primario è conservato localmente.

Il passaggio al modello con un'unica permutazione ideale per il ruolo
delle maschere usa lo stesso denominatore di non-collisione già verificato.
Nel modello ideale, fissati prima delle maschere il segreto binario e i
parametri ammissibili, la probabilità che la generazione produca almeno
una riga oltre il nuovo limite è inferiore a 2^-98. Le uscite della
permutazione non vengono trattate come indipendenti. Il limite riguarda
le righe conservate una volta sola: se l'evento buono vale, lo stesso
limite resta disponibile anche con cifre successive scelte in modo
adattivo. Non è una probabilità di errore per ogni richiesta. Il passaggio
dalla permutazione ideale all'AES e ai seed effettivi resta aperto.

Per i quattro termini con cifre limitate da 2^14, il contributo ideale
del cast è ora al più 215·2^36, inferiore al target 2^44 del bilancio in
costruzione. Lascia 41·2^36 per gli altri contributi; non dimostra che
questi vi rientrino. Restano da chiudere il residuo degli arrotondamenti
effettivi, il rapporto con il digit ideale, i lift e la composizione
completa fino all'esito 0/ID. La prova non modifica chiavi, parametri,
prestazioni o garanzie biometriche e di sicurezza.

## Maschera e body: sommare gli effetti prima di maggiorarli

Questo passaggio riguarda la **prova degli errori numerici**, nella preparazione e nell'uso delle righe Fourier di Head. Non modifica il circuito o i suoi tempi. Consuma le identità e i limiti strutturali delle sezioni precedenti.

Ogni riga della chiave cifrata ha una maschera e un body, la parte che contiene il messaggio mescolato alla maschera. Nella prova, `a` e `b` sono i vettori reali ottenuti dal cast signed64→f64 di quelle due parti della stessa riga standard. Nella rappresentazione reale usata dalla prova, la loro relazione comprende il messaggio, il rumore, l'errore di conversione e il cambio di rappresentante modulo `q`. Prima maggioravamo separatamente gli effetti di questa relazione e il difetto di commutazione dell'operatore Fourier. Così la disuguaglianza poteva perdere cancellazioni che esistono nell'espressione completa.

Ora raggruppiamo quei termini **prima** di prendere le norme, mantenendo gli stessi operandi e lo stesso riferimento. Se `M` è la moltiplicazione esatta per il segreto, `D` quella per le cifre effettive e `K` l'operatore Fourier con costanti conservate e aritmetica dei dati esatta, il gruppo è esattamente:

```text
(K − D)b − M(K − D)a.
```

Il cambio di rappresentante resta dentro `b − Ma`; non viene posto a zero. Il residuo dell'aritmetica effettiva, compresa la conversione finale in torus, resta nel bilancio una sola volta.

Per stringere il limite usiamo anche il riferimento ideale `K0` con lo stesso spettro delle cifre effettivamente calcolato. Questo riferimento commuta con `M`. Indichiamo con `L` il limite di `K − K0` e con `chi` il limite di `K0 − D`: sono difetti distinti. Ponendo `A = ||a||₂`, `B = ||b||₂`, `Q = ||b − Ma||₂` e `sigma ≥ ||M||₂`, il nuovo maggiorante per una riga è:

```text
L(B + sigma A) + chi Q.
```

Sugli stessi valori, è sempre minore o uguale al precedente maggiorante coerente `2 sigma L A + (L + chi)Q`. La differenza è `L(sigma A + Q − B) ≥ 0`, per la disuguaglianza triangolare. Può essere zero: non abbiamo dimostrato una riduzione stretta per la chiave in uso, né un miglioramento dell'errore effettivo. La sola norma di `K − D` non darebbe questo confronto in generale.

Resta da giustificare numericamente `L`, `chi` e il residuo completo per la generazione e l'uso effettivi delle chiavi. Il limite condizionale del cast della sezione precedente lascia `41·2³⁶` entro il target locale `2⁴⁴`; questa nuova identità definisce quali contributi devono starci, senza dimostrare che ci stiano già. Correttezza generale `0/ID`, probabilità effettiva di fallimento e provenienza delle chiavi rimangono aperte. Nessuna nuova misura o modifica del runtime.

## Arrotondamento effettivo: usare lo stesso riferimento della prova

Questo controllo riguarda la preparazione della chiave Head e l'uso delle sue righe Fourier durante il bootstrap. Il residuo del bilancio precedente confronta l'esecuzione effettiva con un calcolo che esegue le operazioni sui dati in aritmetica esatta, **conservando le costanti FFT effettive**. Il limite della FFT già disponibile confrontava invece il risultato con la trasformata matematica, che usa le radici ideali. Sono due confronti diversi: non possiamo chiamare il vecchio limite direttamente «residuo».

Il nuovo passaggio usa la trasformata matematica come riferimento comune. Sullo **stesso input effettivo**, la distanza fra esecuzione e calcolo con costanti conservate è maggiorata dalla somma delle loro distanze dalla trasformata ideale. Questo rende utilizzabili insieme i due limiti già dimostrati, con norme e fattori di scala espliciti. La somma può perdere cancellazioni e risultare larga; non dimostra che l'errore effettivo sia altrettanto grande.

Nella preparazione della chiave si conserva il cast iniziale e si separa l'arrotondamento della normalizzazione e del prodotto con il twist prima della FFT. Nel bootstrap, l'accumulazione riguarda gli stessi spettri effettivi e l'intero primo prodotto più tre aggiornamenti; l'inversa parte dallo stesso accumulatore effettivo. All'uscita, si mantiene l'ordine del codice: scalare il twist coniugato, moltiplicare, poi convertire in torus. La conversione finale entra una sola volta nel residuo della fase.

I limiti delle costanti restano nel riferimento e nei maggioranti operatoriali; non diventano un altro termine fisico aggiunto al bilancio. Le disuguaglianze usate per cambiare riferimento possono comunque sovrastimare il loro effetto. Una chiave caricata richiede inoltre una corrispondenza giustificata con la sua generazione: forma e finitezza del file non bastano a porre a zero un errore di storia o di riferimento.

Il risultato è un limite **simbolico e condizionale** per il residuo completo. Restano da giustificare e inserire i valori delle costanti, i domini effettivi, l'ambiente di arrotondamento e la storia di generazione/uso. Non abbiamo verificato che il totale rientri nel margine della sezione precedente. Circuito, parametri, chiavi, misure e grafici rimangono invariati; la garanzia generale `0/ID` è ancora aperta.

## Arrotondamento sui dati: un limite diretto in norma euclidea

Il passaggio precedente confrontava l'esecuzione effettiva e il calcolo con costanti FFT conservate attraverso una trasformata ideale comune. La somma dei due limiti è valida, ma può perdere cancellazioni. Qui il confronto resta direttamente fra l'esecuzione e il calcolo esatto con **le stesse costanti**: si stimano soltanto gli arrotondamenti delle operazioni sui dati.

Il controllo riguarda due parti di ogni blocco Scalar. Nel butterfly, le somme e differenze sono organizzate in due livelli; i cambi di segno e gli scambi delle coordinate sono esatti. Nel prodotto con il twiddle, il codice usa due prodotti ordinari e due operazioni fuse. Le norme dei blocchi già dimostrate permettono di propagare i nuovi errori locali attraverso i quattro livelli con twiddle e il livello terminale senza twiddle. L'inversa rimane non normalizzata: il fattore di uscita viene applicato dopo, come nel codice.

La norma euclidea conserva il contributo dell'intero vettore durante questa propagazione. Il limite include anche un termine assoluto per arrotondamenti subnormali e valori molto piccoli. Le costanti conservate influenzano le norme e il trasporto degli errori; la loro differenza dalle radici ideali non viene aggiunta come un altro arrotondamento locale.

Nelle stesse condizioni del controllo precedente, il nuovo maggiorante del core è dimostrato non superiore a quello ottenuto passando dal riferimento ideale. Sostituendolo nel bilancio, e mantenendo identici l'errore all'ingresso della FFT, la storia della chiave, l'accumulazione completa, l'uscita e la conversione finale, anche il maggiorante del residuo completo non cresce. Non abbiamo ancora verificato che il totale rientri nel margine disponibile.

Questa è una prova condizionale sull'aritmetica: richiede il percorso Scalar fissato, arrotondamento e operazioni fuse conformi, underflow graduale e intermedi finiti. Non certifica queste condizioni per una chiave caricata o per un eseguibile soltanto dalla forma dei dati. Non cambia circuito, chiavi, parametri o tempi misurati; la garanzia numerica completa `0/ID` resta da chiudere.

## Stime degli intermedi e fattibilità della prova

Il limite che evita overflow e il limite che serve a chiudere il budget d’errore hanno scopi diversi. Il primo ammette valori molto grandi; il secondo deve garantire che tutti i contributi restino entro il margine del selettore. L’analisi seguente riguarda la stima sufficiente usata nella prova, senza modificare il circuito.

L’input della FFT inversa è un vettore complesso di 1024 elementi: l’accumulatore dei prodotti in frequenza. Indichiamo con `X_body` e `X_mask` due limiti certificati sulla sua norma euclidea, per i due output. Sono stime sugli intermedi della moltiplicazione cifrata, non punteggi facciali. Ogni limite deve valere sullo stesso input effettivo e per tutti gli input ammessi; non basta misurarlo in qualche esecuzione.

Il limite diretto dell’arrotondamento della FFT inversa contiene un termine almeno pari a `576·2^-53·X`. Questa è una proprietà della formula del maggiorante. Non è un limite inferiore sull’errore reale, che può essere molto più piccolo o anche nullo. Gli altri contributi di chiavi, conversioni, accumulazione e uscita restano nel budget completo.

Consideriamo una configurazione esplicita della prova: scala d’uscita esattamente `2^-10` come premessa separata, limite scelto per i fattori esterni almeno uno, guadagno uniforme della maschera pari a 1408 e maggiorante della conversione finale pari a 2049. Con il margine residuo già fissato, una condizione necessaria per questa stima sufficiente è:

```text
1152 · (X_body + 1408 · X_mask) + 2049 ≤ 41 · 2^36.
```

Se si dispone soltanto di un raggio massimo complesso comune `R` e si sceglie la conversione conservativa `X_body = X_mask = 32R`, qualsiasi `R ≥ 2^16` rende impossibile soddisfare questo budget con quella scelta. È un risultato sulla prova: non dimostra che gli intermedi raggiungano quel raggio, che la demo fallisca o che ogni altra stima sia insufficiente. Un limite euclideo indipendente più stretto può cambiare il risultato; deve però essere giustificato.

Il filtro più ottimistico lascia spazio a `R = 2^15`, ma questo non certifica il caso: mancano ancora tutti gli altri contributi positivi e le ipotesi sulla versione effettivamente eseguita. Il prossimo passo è quindi ottenere limiti uniformi più stretti sugli accumulatori reali, oppure una prova congiunta che sfrutti la relazione tra gli errori di body e mask. Questa analisi non modifica parametri, tempi misurati o risultati sperimentali.

## Un limite per l’accumulatore che usa più informazioni

Il passaggio studiato è quello prima della FFT inversa. Per ogni output, il server ha accumulato quattro prodotti fra righe cifrate della chiave e vettori di cifre trasformati. Se si dispone soltanto di un limite sul massimo complesso `R` dell’accumulatore, con 1024 elementi si ottiene il limite euclideo `32R`. È una scelta conservativa, come se tutti gli elementi raggiungessero quel massimo.

La nuova derivazione costruisce un altro limite sulla grandezza complessiva dell’accumulatore. Per ciascun prodotto si combina la norma euclidea di una riga con il massimo dell’altro vettore, oppure si scambiano i ruoli. Una terza possibilità usa le norme di quarto ordine. Si prende il minimo fra queste stime e la conversione conservativa dal massimo; ogni stima inclusa deve essere certificata sugli stessi operandi effettivi.

Si sommano i quattro limiti dei prodotti e si aggiunge `32·ε_acc`, dove `ε_acc` è il limite già dimostrato sull’errore dell’overwrite iniziale e dei tre accumuli successivi. Questo termine serve perché la FFT inversa riceve l’accumulatore arrotondato, non la somma esatta dei prodotti. Il nuovo limite si interseca con quello già disponibile: così il valore del maggiorante non aumenta, a parità di tutti gli altri contributi e domini.

Ci sono due limiti precisi a questa proposta. Se le norme aggiuntive vengono ricavate soltanto dai massimi, la formula torna alla stima ottenuta sommando i massimi dei prodotti e l’errore di accumulazione: non c’è un miglioramento rispetto a quella scelta. Anche interpolare la norma di quarto ordine dal massimo e dalla norma euclidea non migliora il loro minimo; occorre una certificazione più informativa di quella norma per ottenere un vantaggio ulteriore.

La derivazione quindi indica quali informazioni servono, senza dimostrare un guadagno numerico attuale. Le norme devono valere uniformemente per le righe usate e per tutte le cifre ammesse, anche con query adattive e riuso della chiave. Il raggio che ammette la FFT inversa e i limiti delle conversioni restano da conservare separatamente. La discrepanza di generazione o memorizzazione della chiave non può essere posta a zero perché il file è finito e ha la dimensione attesa.

Questo risultato cambia la prova del limite, senza modificare il circuito o i tempi misurati. Il prossimo confronto richiede norme degli operandi certificate più strette, oppure una prova separata della fase su ciascun coefficiente richiesto dal selettore.

## Un limite diretto per ogni coefficiente della fase

Il selettore usa la fase del ciphertext GLWE: il polinomio del body meno il prodotto fra maschera e segreto. Dopo le rotazioni, l’estrazione prende la fase nella posizione richiesta. Occorre controllare tutte le posizioni, perché i controlli cifrati e il packing possono scegliere coefficienti diversi.

Il limite precedente era già riferito a ogni coefficiente. Per stimare il contributo della maschera, passava però attraverso un limite euclideo sull’intero polinomio. La nuova derivazione usa direttamente la riga del prodotto che determina ciascun coefficiente. Con un segreto binario di peso `H`, quella riga ha norma `√H`: cambia l’ordine e il segno dei termini, ma la loro grandezza complessiva resta la stessa in ogni posizione.

Questo dà un limite uniforme per tutti i coefficienti. Non richiede di osservare il segreto o di assumere che gli errori si compensino. Se non conosciamo un limite più stretto sul peso, usiamo `H ≤ 2048`. Il guadagno per questo trasporto è quindi `√2048`; il precedente guadagno globale `1408` resta disponibile per i passaggi che richiedono una norma euclidea dell’intero vettore.

La prova conserva il contributo del body e tutti gli errori della maschera: generazione e storia della chiave, ingresso, accumuli, FFT inversa e conversione finale. Il difetto della conversione al toro resta un contributo distinto, già nelle unità native. Anche il valore cifrato atteso, il rumore, il cast e i lift della fase restano nel confronto completo. Le nuove formule sono confrontate con le precedenti a parità di queste condizioni.

La revisione della sorgente conferma il requisito locale per coefficiente e distingue i passaggi successivi. Una rotazione conserva questo limite; somme, moltiplicazioni pubbliche, normalizzatori e feedback possono amplificarlo. L’estrazione e le rotazioni identificano la fase modulo `q`: i confronti reali devono mantenere lift coerenti e i loro multipli di `q`.

Il risultato restringe un maggiorante condizionale, senza cambiare il circuito o i tempi. Non è ancora un bilancio numerico passato con i parametri attuali, né una prova completa di `0/ID`. Restano da comporre i margini di indirizzamento e le trasformazioni dei normalizzatori con tutti gli altri contributi.

## Errore dopo i normalizzatori: conservare i limiti sui componenti

3 ottobre 2026. La prova precedente dei normalizzatori resta valida: la
trasformazione del ramo basso può amplificare un errore uniforme di fase
fino a 60 volte nel residuo e 30 nel riporto. Non sono tempi di esecuzione.
La nuova verifica studia lo stesso risultato mantenendo separati, fino
alla trasformazione finale, i limiti sull’errore del corpo e della maschera, i due componenti
dell’oggetto cifrato.

Con limiti completi in norma2 per questi due componenti, la trasformazione
pubblica può essere trattata direttamente come un funzionale. Il suo
fattore sul corpo è la norma2 della riga, invece della somma dei valori
assoluti usata dal limite precedente. Si conservano anche il contributo
della maschera, gli errori di conversione e il riferimento completo. Il
minimo fra limiti validi per lo stesso errore permette di conservare la
stima precedente quando è migliore. La conclusione è uniforme su tutti
i coefficienti; non dipende da quale candidato verrà scelto. Nel ramo
di riporto, il fattore del solo errore del corpo può passare da 30 a
√240; nel residuo da 60 a 2√240, con gli stessi limiti completi
sui componenti. I fattori 60/30 della prova precedente restano validi
quando si conosce soltanto un limite uniforme sulla fase.

Questo restringe una stima condizionale dell’errore. Non modifica il
circuito, i tempi o gli errori realmente osservati. Per applicarla ai
normalizzatori attuali servono ancora limiti completi per la loro rotazione
cifrata e il raccordo al rumore totale rispetto alla LUT ideale allo stesso
indirizzo effettivo. La chiave
ordinaria dei normalizzatori ha una configurazione diversa dalla chiave
custom di Head: i limiti numerici e l’evento sulle righe dimostrati per
Head non vengono trasferiti automaticamente. Il miglioramento riguarda i rami basso e medio: il riporto che alimenta
il passaggio successivo e il ramo alto richiedono ancora i propri limiti
non filtrati. Feedback, margini degli indirizzi, torneo e decoder restano
obblighi distinti.

## Dalle singole operazioni alla rotazione completa

Il limite precedente richiede un bilancio completo dell'errore all'uscita del normalizzatore. Una stima di una sola operazione interna non basta: la rotazione cifrata ne esegue una sequenza, e ciascuna usa l'accumulatore prodotto dai passaggi precedenti.

Il nuovo risultato spiega come raccogliere i contributi lungo quella stessa esecuzione. Nella fase crittografica ogni errore locale viene trasportato dai passaggi successivi con una rotazione esatta dei coefficienti, che ne conserva la norma. Si possono quindi conservare separatamente i contributi numerici del corpo e della maschera, le conversioni in valori nativi e tutti gli altri termini. I limiti locali si sommano; non si presume che gli errori siano indipendenti o si cancellino. Questa coppia è un registro dei contributi all'errore di fase, non una differenza fra due interi programmi eseguiti con cifre intermedie identiche.

Dopo il filtro pubblico si può anche scegliere, per ogni termine restante, il migliore fra i limiti validi disponibili e poi sommare. Questo limite non supera quello ottenuto scegliendo un solo limite alla fine, a parità di ipotesi e contributi inclusi.

La prova è condizionale. Per applicarla alla versione attuale manca ancora il bilancio completo di ciascuna operazione con la chiave ordinaria: due termini locali, con condizioni verificate su arrotondamenti, dati intermedi e storia della chiave. I limiti della chiave usata da Head, che ha quattro termini, non si trasferiscono automaticamente. Il confronto riguarda l'uscita alla stessa posizione effettivamente selezionata; la correttezza di quella posizione e il feedback restano condizioni separate. Il risultato non certifica ancora l'intero esito 0/ID e non cambia codice, parametri o tempi misurati.
