# Lettura dei testi integrali: primitive TFHE

Letture originarie del **19 settembre 2026**. Gli otto PDF di quel passaggio sono stati ottenuti
da ePrint; per Head Start e Tetris il download coincide byte per byte
con le copie pubbliche già conservate. I PDF sono fonti di consultazione,
non file redistribuiti nel repository.

Il controllo selettivo dell'edizione finale della compensazione della media
del 22 settembre è descritto separatamente sotto, con fonte e hash propri.

È una lettura mirata di algoritmi, premesse sul rumore, parametri e valutazioni,
con controllo visivo delle pagine indicate. Disponibilità integrale non significa
verifica indipendente di tutte le dimostrazioni: nessuna prova completa è qui
certificata, nessuna implementazione è stata eseguita. Le applicazioni alla tesi
sono segnalate come inferenze. Le letture sono del 19 settembre; il raccordo
con il [runtime mantenuto](../../../runtime/README.md), dotato di selettore
corretto e pack4, è aggiornato al 22 settembre. Questa integrazione
bibliografica non modifica gli esperimenti o le loro misure.

## Head Start

D'Anvers, Pottier, de Ruijter e Verbauwhede,
[Head Start: Digit Extraction in TFHE from MSB to LSB](https://eprint.iacr.org/2025/2012.pdf).
ePrint ricevuto il 28 ottobre 2025; 24 pagine. Letti §2.3, pp. 4-5;
§4, pp. 8-14; §6, pp. 18-20; appendice A, p. 21.
Algoritmo 1, p. 11, controllato anche visivamente.

L'estrazione DirtyMSB introduce una correzione di cifra `delta` compensata
nel residuo. Le cifre intermedie possono quindi differire dalla decomposizione
canonica, pur ricostruendo il messaggio. La LUT deve anche trattare
l'underflow dello zero (§4.2). La condizione critica sul rumore riguarda
l'ultimo bootstrap esatto (§4.4), con amplificazione delle correzioni precedenti.

**Precisazione:** rumore rinfrescato all'uscita non significa cifre canoniche
o indipendenza dimostrata. Il §2.3 assume esplicitamente indipendenza fra
cifrati bootstrappati; i parametri analizzati mirano a sicurezza 128 bit e
fallimento al massimo `2^-64`. Il §6 assume già avvenuta la conversione
degli input al formato esteso; i tempi riguardano somme e moltiplicazioni
scalari, non argmin.

**Inferenza per la tesi:** normalizzazione delle cifre, riuso delle uscite e
consumo nel torneo richiedono una verifica propria. Il caso locale storico
della variante Head generale è stato [localizzato nel selettore](../../selector-repair-20260920.md),
con le 127 estrazioni Head corrette in quella istanza. Questa diagnosi e la
correzione successiva non sono risultati del paper.

## Tetris

Wang et al., [Tetris: Versatile TFHE LUT and Its Application to FHE Instruction Set Architecture](https://eprint.iacr.org/2025/1623.pdf).
ePrint ricevuto il 9 settembre 2025; 46 pagine. Letti §§4-6,
pp. 9-25, ed enunciato/analisi del rumore dell'appendice B, pp. 38-41.
Tabelle 3 e 6, pp. 19 e 25, controllate visivamente.

Il refresh produce bit trasformati mediante XOR cumulativo; conversione
RevHomTrace e scheme switching alimentano un albero CMux la cui LUT deve
rispettare tale trasformazione (§4). Il supporto generale a LUT univariate
32 bit non esaurisce il risultato: §6.2 descrive confronti bivariati 32 bit
specializzati mediante potatura; tabella 6 riporta GTE cifrato/cifrato in
2,27 s.

**Precisazioni:** §5.1 dichiara sicurezza 128 bit e fallimento inferiore a
`2^-40`. Tabella 3 distingue stime per PBS-tree 12/16 bit, misura PBS di
11 bit e variante Server-op a otto thread. Il rapporto 2916× sul Sign
32 bit (§6.3) usa una baseline CKKS stimata tramite normalizzazione,
non una replica misurata dello stesso compito. Il testo cita anche 915×
per la potatura, ma tale numero non compare in tabella 6.

**Inferenza:** includere la variante specializzata fra i precedenti; evitare
rapporti con la tesi senza parità di parametri, conversioni e contratto.

## Compensazione della media

de Ruijter, D'Anvers e Verbauwhede,
[Don't be mean: Reducing Approximation Noise in TFHE through Mean Compensation](https://eprint.iacr.org/2025/809.pdf).
**Preprint letto il 19 settembre:** ePrint ricevuto il 6 maggio 2025;
23 pagine. Letti §§3.1-3.3,
pp. 6-11, e §§6-7, pp. 17-20. Tabella 6, p. 20, controllata visivamente.

La correzione pubblica del corpo usa gli errori di arrotondamento della
maschera e la media della distribuzione del segreto. Nel modello sostituisce
il termine dipendente da `Var(s)+E(s)^2` con quello dipendente da `Var(s)`;
il dimezzamento riguarda le componenti di approssimazione per segreti binari,
non automaticamente tutto il rumore.

**Precisazioni:** tabella 5 usa il preset TFHE-rs 0.10.0 e distingue MS,
KS e BR: la compensazione BR costa circa il 29,5% in più in quella prova.
Tabella 6 attribuisce il massimo 2,14× alla configurazione con sicurezza
almeno 80 bit. A 128 bit e `p_fail <= 2^-64`, le righe 4/5 bit danno
1,02×/1,05×; il massimo 128 bit nella tabella è 2,06× con `2^-128`.

**Inferenza:** specificare quali compensazioni implementa il core e separare
riduzione del rumore, cambio dei parametri e tempo osservato.

**Edizione finale verificata il 22 settembre:**
[TCHES 2026(1), pp. 82–104](https://doi.org/10.46586/tches.v2026.i1.82-104),
[PDF DNB](https://d-nb.info/1387577298/34). Controllati frontespizio, abstract
e tabelle 5–6, pp. 100–101 (PDF pp. 19–20).
SHA-256 del PDF finale: `c82b504cc99ada4766ee26521bfd6d8400084c84449bde44dd022513396ee0b6`;
del preprint conservato: `3d108a46b6ad5c3342551de289f48bcfd5e96a93c37d13ebbb39a3db3f280118`.
La tabella 6 conserva le sei
righe con sicurezza almeno 128 bit del preprint: massimo **2,06×**, per
4 bit e `p_fail ≤ 2^-128` (434→210 ms). I tempi riguardano due funzioni su
64 ciphertext, otto core Ryzen 7 Pro 8840HS; i bit escludono il padding.
La riga da **2,14×** apparteneva
al gruppo almeno 80 bit, assente nel finale. Non è un guadagno perso dal
runtime locale: è un diverso perimetro della tabella esterna.

Cambia anche il parametro di riferimento (PS1, appendice A, tabella 7,
p. 104 / PDF p. 23): dimensione LWE 834→866 e
deviazione del rumore LWE `3,554·10^-6`→`2,046·10^-6`. La tabella 5 finale
riporta `2^-73.77`→`2^-130.21` con compensazione MS+KS e tempo relativo
0,998; includere anche BR porta a `2^-130.81` e 1,295. Questi valori
appartengono ai parametri del paper; non sostituiscono una probabilità di
fallimento del circuito locale. Il confronto fra versioni è mirato a
queste tabelle, non una nuova verifica integrale delle dimostrazioni.

## Sharing the Mask

Bergerat, Bonte, Curtis, Orfila, Paillier e Tap,
[Sharing the Mask: TFHE Bootstrapping on Packed Messages](https://eprint.iacr.org/2025/2112.pdf).
ePrint ricevuto il 17 novembre 2025; TCHES 2025(4),
[DOI](https://doi.org/10.46586/tches.v2025.i4.925-971); 47 pagine.
Letti §§3-5, pp. 9-16, §§7-8, pp. 18-21, e l'impostazione
dell'argomento ibrido in appendice A.1, p. 28.
Tabelle 3-4, p. 21, controllate visivamente.

Ogni corpo usa una colonna diversa del segreto matriciale. Lemma 1 riduce
la sicurezza CPA a GLWE con perdita dipendente da `w`; non è riuso della
stessa maschera sotto un unico segreto. Algoritmo 10 richiede `n*w` blocchi
di chiave per impacchettare LWE inizialmente distinti.

**Precisazioni:** §8 confronta KS+PBS common-mask con PBS sequenziali;
il fallimento è definito per singolo PBS. I parametri dichiarano almeno
132 bit stimati. Più corpi non garantiscono accelerazione: tabella 3,
precisione 4 bit e otto corpi, misura 126,5 ms contro 115,2 ms.
La pressione sulla cache è una spiegazione proposta, non accertata.

**Inferenza:** il vantaggio dipende anche da formato iniziale, packing,
chiavi e batch. Non trasferire i guadagni booleani al torneo locale.

## Conversioni di Chen et al.

Chen, Dai, Kim e Song,
[Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts](https://eprint.iacr.org/2020/015.pdf).
ePrint, revisione 4 dicembre 2020; ACNS 2021; 19 pagine.
Letti §2.5, p. 7; §3.4, pp. 10-13; §4.1, pp. 13-14;
appendice A, pp. 18-19. P. 12 controllata visivamente.

PackLWEs aggrega `n` cifrati tramite automorfismi e applica una traccia
per azzerare i coefficienti residui. L'uscita impacchetta nei coefficienti,
non automaticamente negli slot SIMD. La fase viene moltiplicata per `N`:
la rimozione tramite `N^-1 mod q` richiede `gcd(N,q)=1` (§3.4).
Il paper separa anche la conversione coefficienti/slot, dipendente dallo schema.

**Precisazioni:** §2.5 esplicita l'assunzione di sicurezza circolare per
le chiavi di automorfismo. L'appendice A modella euristicamente il rumore
KS con coefficienti gaussiani indipendenti. Le misure usano SEAL 3.5.1,
moduli prodotti di primi, segreti ternari e un thread; non sono misure
del packing TFHE-rs del progetto.

**Inferenza:** con `q=2^64` e `N` potenza di due, quell'inverso non
esiste. Serve un adattamento esplicito, come la linea modulus-switch/trace,
con analisi del rumore; non una trasposizione letterale del pre-processing.

## RevHomTrace e MS-PackLWEs

Kang Hoon Lee e Ji Won Yoon,
[Homomorphic Field Trace Revisited: Breaking the Cubic Noise Barrier](https://eprint.iacr.org/2025/1088.pdf).
ePrint, revisione 16 ottobre 2025; TCHES 2026; 30 pagine.
Letti §4, pp. 10-14, e §5, pp. 14-20.
Algoritmo 5 e teorema 4, p. 11, controllati visivamente.

RevHomTrace alterna divisione/modulus switching per due e automorfismi
in ordine inverso rispetto alla traccia precedente. Tale ordine elimina
anche i termini introdotti dal cambio di modulo. Il teorema 4 limita
la **varianza** aggiunta con `4 log(N) V_MS + log(N) V_Auto`:
il passaggio da `O(N^3)` a `O(N log N)` non riguarda direttamente
deviazione standard o probabilità di fallimento.

MS-PackLWEs modifica l'aggregazione dei cifrati (§5.3, algoritmo 6).
Tabella 6 confronta cinque metodi; il PackLWEs precedente rimane il più
veloce nelle configurazioni riportate, mentre MS-PackLWEs riduce il rumore
con un costo temporale aggiuntivo. I test della traccia usano cifrature
dello zero e 1000 iterazioni (§5.1); le misure di profondità CMux hanno
un criterio `2^-40` (tabella 4).

**Inferenza:** è un precedente diretto per conversioni meno rumorose,
non una prova del torneo PFKS né un'accelerazione garantita del core.

## FDFB

Kluczniak e Schild,
[FDFB: Full Domain Functional Bootstrapping Towards Practical Fully Homomorphic Encryption](https://eprint.iacr.org/2021/1135.pdf).
ePrint, revisione 3 gennaio 2023; TCHES 2023; 38 pagine.
Letti §3, pp. 13-17, e §4, pp. 17-20; tabella 4, p. 19,
controllata visivamente. Data interna PDF: 14 dicembre 2022;
non va confusa con la revisione dell'archivio.

Il bootstrap identifica la metà del dominio, costruisce l'accumulatore
appropriato, esegue un'ulteriore blind rotation e le conversioni finali
(figura 4). «Una FDFB» non equivale quindi a «un PBS TFHE ordinario».
Il §3.4 ricava anche `max(x,y)=max(x-y,0)+y`, entro una rappresentazione
compatibile del dominio: il solo valore massimo non trasporta l'identità.

**Precisazioni:** i parametri sperimentali dichiarano sicurezza 80/100 bit,
non 128. Tabella 4 distingue fallimento dopo bootstrap e dopo composizione
con una funzione affine di 784 termini. Ampliare il dominio può introdurre
errori frequenti: il paper distingue esplicitamente modalità esatta e
approssimata. Le misure derivano da PALISADE modificato, su macchina virtuale,
con media di cinque esecuzioni.

**Inferenza:** full-domain elimina il vincolo negaciclico sulla funzione,
ma non elimina vincoli di dominio, rumore, costo del payload o composizione.

## RevoLUT

Azogagh, Birba, Gambs, Killijian e Larose-Gervais,
[RevoLUT: Rust Efficient Versatile Oblivious Look-Up-Tables](https://eprint.iacr.org/2024/1935.pdf).
ePrint, revisione 20 aprile 2025; 7 pagine. Letti §§2-5,
pp. 1-6; p. 5 controllata visivamente. L'ordine degli autori qui segue
il PDF, diverso da quello nei metadati ePrint. L'intestazione
«Conference'17» del template non stabilisce una pubblicazione nel 2017.

La libreria tratta LUT cifrate come array e compone letture, scritture,
permutazioni e sorting. PFKS significa qui *Public Functional Key Switch*
(§2.2.2). Le scritture con blind rotation possono disallineare i blocchi
ridondanti; §3.4 prescrive estrazione e repacking prima che i centri
diventino corrotti, con un costo PFKS esplicito.

**Precisazioni:** BCS e radix sort conservano l'ordine nei pareggi (§3.3.2).
I benchmark distinguono array LWE da LUT già impacchettate e, per le
scritture, escludono eventuali prefetch/carry (tabelle 2-3). Il PDF non
riporta una tabella completa di parametri crittografici o un limite composto
di fallimento per queste applicazioni.

**Inferenza:** la stabilità interessa il first-index, ma accessi, margini
delle LUT e refresh devono essere qualificati nel consumatore concreto.

## Identità dei documenti e limiti residui

Gli SHA-256 identificano esattamente le versioni lette. Le date di ricezione
o revisione sono quelle delle pagine ePrint consultate; non sono dedotte dalla
data interna del PDF. Le pagine citate sopra sono le pagine PDF, numerate da 1.

| ePrint | Pagine | SHA-256 PDF |
|---|---:|---|
| 2025/2012 | 24 | `3086cc63916d5ef5385df49021888b3dcb6be30132f1733be07fceffba0eeb6d` |
| 2025/1623 | 46 | `0cc318ca6c4cdef753942da1b86f57f17ee9841cb9beb876a7dcd188cc48775f` |
| 2025/809 | 23 | `3d108a46b6ad5c3342551de289f48bcfd5e96a93c37d13ebbb39a3db3f280118` |
| 2025/2112 | 47 | `d21f350cdab374e3b9fa44b9b3b11c74233daaada629d7fff350d0821fbd0af4` |
| 2020/015 | 19 | `0be9a67249237d47572fa09be491fea1f6aba8e4be9a633cd7a1ea4b22fe1622` |
| 2025/1088 | 30 | `4f1033580542c56baa8a493aab178681082df768cd3446cc4470bc75b49589a9` |
| 2021/1135 | 38 | `3cce4320d36f270c795bf6be0778f48f2df9ce182047dc3aaf00e94e1511702f` |
| 2024/1935 | 7 | `de374d727d85a8c7e5925a878b5d2345e59b9a96d26bb7181638c664f954d795` |

Non restano blocchi di accesso per questo insieme. Restano da svolgere,
se richiesti per una specifica affermazione della tesi, la verifica indipendente
delle dimostrazioni pertinenti e il collegamento puntuale fra formule,
parametri e sorgenti della relativa implementazione. Questi PDF non
trasformano i risultati locali in una prova generale o in un confronto SOTA
omogeneo.
