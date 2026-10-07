# Tentativi, risultati negativi e correzioni

<a id="tetris-torneo-dag-e-filoni-alternativi"></a>

[Indice dei risultati](../../findings.md) · [Repository](../../README.md) · [Percorso sperimentale](../percorso-sperimentale.md) · [Catalogo dei tentativi A](catalogo-tentativi-a.md)

Il percorso verso l'uscita cifrata **0 oppure ID del primo minimo, accettato
solo se soddisfa la propria soglia**, comprende anche costruzioni
sbagliate, corrette ma troppo costose, e proposte fermate prima della FHE.
Questa pagina spiega quei passaggi dall'inizio dei prototipi alle campagne
del 4–5 ottobre. I successi dei loro successori non cancellano i negativi:
cambiano il circuito, i parametri o il requisito verificato.

La distinzione decisiva è fra cinque esiti. Un **negativo funzionale** contiene
un output diverso dall'oracolo; un **negativo di costo** contiene output corretti
ma non supera il confronto temporale; un **limite statico** esclude una specifica
geometria o interfaccia senza eseguire FHE. Una **build fallita, un'interruzione
o un record invalido** non misurano la correttezza del circuito. Un **controllo
intenzionalmente errato** deve essere rilevato: se il verificatore lo accetta,
fallisce il gate di verifica, anche quando i rami positivi sono corretti.

Scegliere un filone:

- **Riconoscimento e decisione:** [rappresentazioni](#rappresentazioni),
  [dominio e contratto](#dominio-e-contratto), [biometria e garanzie](#biometria-e-garanzie).
- **Sistemi e costruzioni alternative:** [Concrete e GPU](#concrete-e-gpu),
  [CKKS](#ckks-e-switching), [compatibilità delle interfacce](#alternative-di-interfaccia),
  [common-mask e BGV](#common-mask-bgv).
- **Cifre e selezione del vincitore:** [selezione e scansione](#selezione-scan),
  [PFKS](#pfks), [riuso delle cifre basse](#estrazione-low),
  [precisione Head/nibble](#precisione-nibble).
- **Correzioni del circuito composto:** [selettore stretto](#selettore-stretto),
  [compressioni del 4 ottobre](#precisione-compressa).
- **Attendibilità delle prove:** [controlli e rumore](#checked-e-rumore),
  [servizio e strumenti di misura](#servizio-e-strumentazione).
- **Costi e riuso:** [CPU e composizione](#cpu-e-composizione),
  [Tetris e DAG](#f91---tetris-e-torneo-dag-esiti-negativi-circoscritti),
  [profili e microkernel](#profili-e-microkernel), [ultimo stadio e riuso](#ottimizzazioni-terminali).

Le percentuali appartengono ai rispettivi confronti e non si sommano.
I casi cifrati corretti non stabiliscono un limite alla probabilità di
fallimento; le ripetizioni sotto la stessa chiave non sono chiavi indipendenti.
La [mappa finale](#mappa) collega tutte le sigle del catalogo alle sezioni,
compresi modelli, controlli e successori positivi che spiegano le decisioni.

<a id="rappresentazioni"></a>

## Rappresentazioni: un calcolo cifrato esatto può riconoscere male

I [gradini 00–04](../../experiments/README-00-04.md) verificano la costruzione
progressiva del calcolo. Il primo problema scientifico emerge passando dai
volti controllati a immagini variabili: la correttezza aritmetica della
[PCA cifrata](../../experiments/05_pca/README.md) non rende la rappresentazione
adeguata al riconoscimento. Nei confronti dei [descrittori](../../experiments/07_descrittori_locali/README.md)
PCA+Euclidea passa dal 98,8% su Olivetti al 32,4% su LFW; LBP e HOG migliorano
LFW, ma non chiudono il problema del varco.

La prova discriminante è l'identificazione open-set con 50 iscritti e
50 sconosciuti, non soltanto il riconoscimento di una persona già nota.
Su VGGFace2, al punto di lavoro empirico FPIR=1%, la DIR è 0,6% per PCA,
0,4% per LDA, 1,8% per LBP e 2,2% per HOG. In verifica 1:1, invece,
CPLFW dà 49,5–53,3% per PCA, le due metriche LBP e HOG. Sono protocolli diversi:
non si confrontano direttamente quei valori e non si estende il verdetto
a ogni possibile descrittore. Le prove motivano il passaggio agli embedding
CNN, lasciando leggibili le configurazioni escluse. [F9–F10](diario/f00-f14.md#f9),
[dati 1:1](../../benchmark/results/verifica_duri.csv),
[dati 1:N](../../benchmark/results/identificazione_1n.csv) e
[programma 1:N](../../benchmark/identificazione_1n.py).

Anche ridurre le dimensioni o la quantizzazione non è gratuito. Nella curva
DigiFace/ResNet50 riportata in F31, tre bit conservano quasi la DIR del float
(86,2% contro 86,7%), mentre due bit scendono al 61%. La prova Concrete di
A11 ha un solo caso per dimensione e un output errato a 64 dimensioni:
non basta per dichiarare inutile ogni compressione. La successiva griglia
[A136](catalogo-tentativi-a.md#a136) restringe davvero il dominio a valori
ternari: 308 righe, 28 celle, 168 configurazioni distinte. La DIR media peggiora
e la FPIR non migliora uniformemente; gli split sovrapposti non costituiscono
repliche di popolazione indipendenti. Il [risultato della griglia](../../experiments/attempts-a/a136/results/full-grid-existing-tests-20260905/result.public.json)
conserva il confronto, distinto dalle calibrazioni successive.

Le CNN non eliminano i limiti di dominio: a 48.000 iscritti DigiFace, ResNet50,
ResNet100 e AdaFace restano circa al 67% nel protocollo provato. Non è un tetto
universale del modello. CoreML viene scartato in quella campagna perché non
accelera e modifica gli embedding di circa il 2%; batching e algebra a blocchi
sono verifiche diverse. I vecchi richiami a 10 o 20 fotografie per identità
sono corretti dal conteggio effettivo di sei nel sottoinsieme VGGFace2.
[A07](catalogo-tentativi-a.md#a07) mostra inoltre che T=4 calibrata su DigiFace
non si trasferisce automaticamente alla scala reale con mediana T=273.
[F29–F31](diario/f29-f42.md#f29) e [correzioni dei prototipi](prototipi-e-correzioni.md)
precisano dataset, metriche e denominatori. Il loader
[MegaFace 11](../../experiments/11_megaface/README.md) incompleto resta una
preparazione non eseguita, senza un risultato da aggiungere allo scaling.

<a id="concrete-e-gpu"></a>

## Concrete, struttura dell'argmin e GPU: localizzare il costo

Il calcolo dei soli score era relativamente economico; restituirli al client
spostava però fuori dal server l'argmin e mostrava tutti i punteggi. Il
[gradino 06](../../experiments/06_argmin_soglia/README.md) e il successivo
[esperimento 10](../../experiments/10_argmin_struttura/RISULTATI.md) spostano
la selezione sul server. Su Linux, N4 passa da 78,3 s sequenziale a 36,1 s
a torneo, e N8 da 180,4 a 69,1 s: un miglioramento reale della costruzione,
ancora costoso. Il parallelismo dataflow non migliora sempre; torneo+dataflow
N8 si ferma a un'asserzione del compilatore sulle conversioni MLIR.
Le proiezioni N16/N32/N64 riportate nel rapporto non sono misure.

Ridurre il problema al conteggio sotto soglia costa 31,2 s a N8 e 347,6 s
a N64 nel test Concrete di F28, ma cambia l'uscita. Anche le strategie
alternative di confronto e il rounding di F31 risultano più lenti o incontrano
errori del compilatore. Il caso 128 dimensioni a 237,9 s contro 158,7 s a 512
mostra che il numero di coordinate da solo non predice il circuito compilato;
sono casi limitati, non una legge generale di Concrete o TFHE.
[Misure e limiti F27–F28](diario/f15-f28.md#f27), [F31](diario/f29-f42.md#f31).

Il [test GPU 09](../../experiments/09_gpu/RISULTATI.md) usa Tesla T4 e
Concrete GPU 2024.12.19. Le tre valutazioni corrette a N8, con 64/128/256
dimensioni, richiedono 629,05/1082,63/1266,78 s. Il richiamo a circa 9×
rispetto al Mac è descrittivo: parametri e macchina non sono un confronto
appaiato. Il controllo CPU sulla stessa VM si interrompe senza completamento
dopo oltre 17 minuti; non fornisce una latenza da usare come denominatore.
La prova riguarda latenza della singola query, non throughput di grandi batch.
Non dimostra che una GPU sia inadatta a ogni circuito FHE.

Il [passaggio a TFHE-rs 13](../../experiments/13_tfhe_rs_headtohead/README.md)
risolve una parte diversa del costo. Il vecchio «100×» confronta l'argmin
Rust con tempi Concrete il cui timer include anche gli score, con generatori
di input e attribuzioni hardware differenti nei rapporti. L'intera valutazione
Rust ad alto livello impiega 24,24/49,86 s a N4/N8, contro 0,45/1,05 s del
solo argmin: le somme con riporti dominano il percorso ingenuo. È la motivazione
per il calcolo lineare LWE a basso livello, non una misura causale di uno
speedup 100× dell'applicazione. [Correzione F32](prototipi-e-correzioni.md)
e [tempi Rust originali](../../experiments/13_tfhe_rs_headtohead/results/argmin_tfhe_rs.txt).

<a id="dominio-e-contratto"></a>

## Dominio, risoluzione e decisione: tre problemi distinti

A01–A03 correggono tre bound insufficienti. Il range dei probe osservati non
copre tutti gli input ammessi; il guard di enrollment ometteva la norma
quadratica del template e accettava bound 5.423 oltre il raggio 4.095; il bound
rispetto a T sottostimava i confronti a coppie, 3.646 contro 4.262 nella scena
q3. L'inputset Concrete di F11 aveva già mostrato lo stesso rischio pratico:
l'argmin poteva essere corretto mentre la soglia andava in overflow e accettava
sempre. Dieci casi corretti dopo l'ampliamento dell'inputset provano la
riparazione su quel campione, non la copertura dell'intero dominio.
[F11](diario/f00-f14.md#f11), [A01–A03](catalogo-tentativi-a.md#a01).

Eliminare il wrap non basta. Il comparatore diretto pre-fold A17 usa
Npoly=2048 e Delta=2^51: un'unità di score equivale a mezza rotazione.
Nello score 5 si osservano 48 falsi accessi su 100 cifrature. A10 trova che
Delta=2^58 corregge i due score provati, ma restringe il raggio a 31 contro
il bound di galleria 3.690. La ritaratura non risolve quindi il contratto.
A04 registra inoltre errori di decisione del torneo CBS anche dopo un Delta
compatibile con il bound a coppie. Sono negativi delle costruzioni provate.
[A17](catalogo-tentativi-a.md#a17), [F68](diario/f57-f70.md#f68) e
[rapporto del comparatore](../../benchmark/results/exact_comparator_scratch_2026-09-01.md).

Le vie A18–A20 cambiano il comparatore: WoP-PBS passa i casi provati ma costa
14 PBS/template e 195.510.272 byte di chiavi aggiuntive; il fold periodico
scende a tre PBS/template e passa 20 aperture più 20 rifiuti end-to-end.
La fallback a nove PBS è distinta. Queste prove implementano membership,
non ancora la selezione dell'identità richiesta. Conservare tutti i bit
(A05) espone un oracolo più ricco; `count == 1` (A06) rifiuta più template
validi; `count > 0` (A16) non identifica il primo minimo. Con soglie diverse
può accettare grazie a un candidato più lontano mentre il vero vincitore
va rifiutato. Sono revisioni del contratto, non falsificazioni di ogni risultato
membership precedente. [A05–A20](catalogo-tentativi-a.md#a05),
[confine di protocollo](../../benchmark/results/protocol_boundary_audit_2026-09-01.md).

Infine A15 distingue il dominio numerico dall'origine del dato. Un limite
alla norma impedisce il wrap ma non dimostra che il vettore derivi da una
cattura autorizzata. La scelta di terminale fidato e il rischio di interrogazioni
adattive rimangono parte del modello di sistema; non si risolvono scegliendo
soltanto una LUT o una soglia diversa.

<a id="ckks-e-switching"></a>

## CKKS e conversioni: confrontare l'intero lavoro richiesto

Le prove CKKS rispondono a domande progressivamente più ampie. A08 corregge
prima un `NameError` e il range in-sample: il nuovo test ha 0/512 discrepanze
su quattro probe, 0,9969 s per gli score e 0,048 s per la soglia. La banda
analitica e l'assenza del confronto integrato held-out impediscono di assumerlo
come baseline finale. A09 porta gli score packed da 3,583 a 0,966 s con meno
rotazioni, ma su un solo probe, tre ripetizioni e 6,178 GiB di picco nel keygen.
Il risultato score-only non comprende una decisione discreta esatta 0/ID.
[A08–A09](catalogo-tentativi-a.md#a08), [esperimento CKKS 15](../../experiments/15_ckks_confronto/README.md).

A13 esegue realmente lo switching CKKS→FHEW in OpenFHE 1.5.1 a 16 slot:
compare e min funzionano, ma richiedono 44,4 e 69,2 s, oltre alle chiavi.
Manca l'adattatore dagli score della tesi e resta l'approssimazione CKKS.
A21 restituisce soltanto l'output finale ma costa 30,4695–35,280 s, con
35,794 s di keygen e 6,603 GB RSS. A22 misura 3,57–3,86 s e 4,55 GB RSS
su un prefisso aggregate-first: non è il costo di un 1:N completato.
Questi sono negativi di costo o limiti della parte eseguita, non impossibilità
di usare CKKS per riconoscimento. [A13](catalogo-tentativi-a.md#a13),
[A21–A22](catalogo-tentativi-a.md#a21) e [sistemi confrontati](../letteratura/sistemi.md).

A14 va letto fino alla correzione: il negativo iniziale CPU del packing BSGS
è seguito da riparazioni di padding e riuso della cache. Passano poi zero-match
N64/N128, genuine/reject N64 e genuine N128 su vettori sintetici. Sono prove
CPU circoscritte; non sono una replica GPU o un confronto biometrico matched.
[Rapporto del percorso privato](../../benchmark/results/fasthe_private_bsgs_2026-09-01.md).

La successiva [ottimizzazione CKKS 23](../../experiments/23_ckks_ottimizzazioni/README.md)
con riduzioni condivise e preparazione delle rotazioni ottiene **8,098%**,
18/18 coppie favorevoli su tre nuove chiavi, 66 risultati e 69 uguaglianze
fra checkpoint e uscite. Il riferimento ha già la stessa cache pubblica e
la preparazione dipendente dalla query è inclusa. È un successo di quella
costruzione, senza incremento da sommare alla demo TFHE.
[Rapporto combinato](../../experiments/23_ckks_ottimizzazioni/evidence/ORIGINAL_COMBINED_RESULTS.md).

<a id="alternative-di-interfaccia"></a>

## Alternative dalla letteratura fermate all'interfaccia

Una primitiva può essere valida e veloce nel proprio sistema senza essere
sostituibile direttamente nel nostro. Gli audit seguenti conservano proprio
questa informazione: non sono tentativi FHE eseguiti e falliti.

| Pista | Verifica svolta e limite circoscritto | Seguito |
|---|---|---|
| A12 BatchBoot | Gli ingressi richiesti sono messaggi già packed in RLWE a segreto sparso, non i nostri LWE indipendenti. | Serve pagare e validare un bridge; il beneficio pubblicato non è un confronto locale. |
| A32/A106 LFBS | La LUT diretta di due score a 12 bit ha dominio 24 bit e almeno 16 GiB di soli polinomi plaintext. La lookup unaria presuppone già le cifre. | Piccoli chunk e riuso restano costruzioni diverse. |
| A46 Blind Top-k | Dominio Z16, classi in uscita e ordine dei chunk non forniscono direttamente score esatti a 12 bit, primo tie e soglia del vincitore. | A49/A52 provano il bridge locale, con negativo della high lane. |
| A81–A83 BOLT/priority encoder | L'encoder è semanticamente equivalente con rimappatura pubblica; il modello dei percorsi fissati non implementa sintesi o ricerca automatica. | Confronto strutturale, non nuovo speedup né prova di novità universale. |
| A91 lookup larga | Il dominio non entra nel ring N2048 corrente; N4096 richiede switching e ritorno alla chiave del consumer. | La linea Head decompone lo score, senza eseguire retroattivamente A91. |
| A105 ANN GPU | Uscita, approssimazione e fiducia differiscono dal contratto esatto 0/ID. | Sistema adiacente, non baseline temporale trasferibile. |
| A110 `first_index` | Confronto, one-hot e codifica aggiungono lavoro rispetto alla scansione specializzata. | Riferimento semantico, senza nuovo benchmark FHE. |
| A114 automorfismi | Nel modello a parametri fissati restano n prodotti esterni e si aggiungono key switch. | Non esclusa una riparametrizzazione con altre distribuzioni di chiave. |

Le [singole schede](catalogo-tentativi-a.md#a12) collegano audit e sorgenti;
la [rassegna delle primitive](../letteratura/primitive-e-codesign.md) mantiene il contratto
di ciascun lavoro. Il passaggio successivo è ammesso solo quando il costo
della conversione e l'uscita richiesta sono effettivamente inclusi.

<a id="selezione-scan"></a>

## Stato candidato, packing e scansione: i controesempi che cambiano il grafo

La famiglia A23–A62 costruisce l'uscita exact-ID. I successi A23/A25/A28
su 632 query, A29/A33/A38 nei rispettivi confronti e A62 su 142 valutazioni
non rendono intercambiabili i loro encoding. A24 scarta centrature implicite
errate dei bit bassi e introduce il canale indipendente modulo 16. A26 trova
un errore concreto nella LUT: trattare −Delta come il messaggio positivo 15
ignora il segno negaciclico −f(15). Tutti gli accept falliscono su cinque
chiavi; porre f(15)=−1 fa passare gli stessi key-run e i replay.
[A24–A26](catalogo-tentativi-a.md#a24), [prove split4](../../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.md).

A35 raccoglie tre proposte diverse. Il [classificatore fuso](../../benchmark/a35_fused_group_classifier_model.py)
usa pesi (2,4,8), norma L1=14; anche il minimo separante L1=7 supera il
limite conservativo max-5. Il [decoder di etichette per blocco](../../benchmark/a35_block_label_scan_output_model.py)
è corretto nel modello clear, ma il doppio output da una sola BR non entra
nell'accumulatore: 13 stati su 16 orbite impongono almeno dieci sovrapposizioni,
mentre solo una è compatibile. La fallback a due BR è valida nel modello,
ma a N127 non riduce le BR rispetto ad A34. La [riduzione radix-5](../../benchmark/a35_radix5_reduction_model.py)
è invece favorevole: raggiunge il bound locale cinque senza superarlo.
A38 integra le riduzioni selettive nel proprio circuito. I log del 2 ottobre conservano **29 test unitari statici passati**
(nove block-label, dieci fused-group, dieci radix-5), con sorgenti identici
alle copie distribuite: [risultati e binding](../../experiments/attempts-a/a35/results/RESULTS.public.json).
Non sono tre campagne FHE; l'evidenza cifrata è quella separata del successore.

Anche sotto la sigla A36 coesistono proposte diverse. Il
[modello group-4 dello scan](../../benchmark/a36_group4_scan_output_model.py)
esclude il packing scalare diretto di quattro Booleani: richiede L1 almeno
15 contro max-5. La variante a due stadi rispetta quel bound, ma nessuno
dei 2.048 gradi provati dal modello consente di estrarre insieme codice
locale e flag con raggio 63. A N127 i due nibble condividono un accumulatore
soltanto nei gruppi 3 e 31; negli altri servono due BR. Questo limite statico
riguarda quel layout, non la selezione chunked A36 che passa il proprio
gate né il diverso scan group-4 A53.

A37 esclude la compressione diretta di tre flag signed in un solo Booleano
p16 e costruisce una rete a due stadi, rimasta un modello. A45/A49 hanno
geometria clear favorevole ma A52 fallisce la high lane: con x=0 restituisce
17 invece di 0, dopo sette test clear corretti. La diagnosi osserva già dopo
KS la cella sbagliata, peggiorata dal modulus switch; il PBS restituisce
correttamente il contenuto di quella cella. Cambiare il decoder non ripara
questo ingresso. [Trace diagnostico A52](../../experiments/attempts-a/a52/results/linked-evidence/docs/research-state/2026-09-05/remaining-code-baseline/actions/a52-diagnostic/stdout.public.json).

I conti sono anch'essi parte del risultato. A50 assume stato canonico e
max-15; A51 proietta 3.432 BR, A53 sceglie group-4 e arriva a 3.390 soltanto
insieme ad A50. Il piano A61 che sostituiva il solo scan avrebbe dato 3.590.
A62 materializza la composizione e osserva 3.390 BR/3.009 KS a N127, con
142/142 esiti su otto key-block. A39/A41 cambiano il terminale da somma larga
a due LWE, rimuovendo un obbligo di decoder ma quasi raddoppiando la risposta:
non eliminano il rumore degli stadi precedenti. A40 radix-7 completa poi
39 fixture proprie; un vecchio stato «solo modello» non deve oscurarle.
[A34–A62](catalogo-tentativi-a.md#a34) e [costruzione della pipeline](tentativi-a.md#costruzione).

Una proposta successiva di eliminare il refresh finale fallisce già nel
modello: candidati morti possono valere −1, mentre A53 richiede 0/1.
Con due candidati, una somma di gruppo nulla può quindi mascherare uno vivo.
Spostare un refresh e cancellarlo sono trasformazioni diverse; A126 costruisce
una fusione con un consumer compatibile. La correzione è descritta nella
[sintesi dei prototipi](prototipi-e-correzioni.md) e nella linea seguente.

<a id="pfks"></a>

## PFKS: dal negativo convolutivo alle finestre dirette

A30/A86/A87 motivano un torneo che trasferisce più payload con la stessa
rotazione; i primi conti non sono un'implementazione validata. A108 esegue
il selettore convolutivo D2 con quattro payload e fallisce tutti e cinque
i punti di decomposizione provati. Le durate dei bracci sbagliati non sono
speedup. La precedente spiegazione «errore dentro il supporto certificato»
viene ritirata: la fase scalare non ricostruisce l'indirizzo ottenuto dal
modulus switch coefficiente per coefficiente.

La replica del 5 ottobre conserva sorgente e lockfile TFHE-rs 0.11.3, con
Rust 1.98.1 e chiavi nuove. Su otto fixture per punto, 23×1/24×1/16×2/12×3/10×4
falliscono rispettivamente 4/3/4/5/6 casi; i riferimenti scalari passano.
Sono 40 casi e 295 record completi. La replica conferma il negativo delle
cinque configurazioni, non ricrea le chiavi originarie né prova la vecchia
localizzazione del rumore. [A108](catalogo-tentativi-a.md#a108),
[pacchetto della replica](../../experiments/14_pipeline_tfhe_rs/results/a108_rerun_2026-10-05/)
e [sorgenti del tentativo](../../experiments/attempts-a/a108/).

L'audit [A123](catalogo-tentativi-a.md#a123) trova kernel e generatore
PFPKS byte-identici fra TFHE-rs 0.11.3 e 1.7. L'aggiornamento della libreria
non costituisce quindi una riparazione di A108; l'identità di quei sorgenti
non promette tempi identici per il programma completo.

Il seguito cambia domande e costruzioni. A120 sposta gli offset verso
l'interno e passa 24 casi, ma l'osservatore non identifica tutte le chiavi
o l'indirizzo BR effettivo. A121/A122 fanno generare la finestra direttamente
alla chiave funzionale; D1 seleziona right−left e riaggiunge left.
Dimezzare da otto a quattro PFKS non dimostra un dimezzamento della varianza:
A134 contiene un controesempio. A127/A137/A167 aggiungono gli osservatori
necessari e passano 24 casi per braccio su tre processi; A171/A174 completano
D1 con 24 fixture e 966 record. A147/A151 chiudono separatamente l'identità
delle righe a un payload. A191 consuma finalmente un controllo prodotto
dal comparatore; l'integrazione successiva passa quattro casi N2 da score
a 0/ID. È il seguito che porta all'[esperimento 17](../../experiments/17_head_pfks_tfhe17/README.md),
non la promozione del vecchio A108. [Catena PFKS](tentativi-a.md#pfks).

A92–A104 esplorano l'alternativa Chen. L'inverso modulare di N non esiste
sul toro 2^64, quindi divisione e normalizzazione vanno trattate esplicitamente.
A95 lega geometricamente spaziatura e raggio, senza dimostrare un raggio
più piccolo. EvalAuto, pseudo-GGSW e packing hanno poi PASS reali: A97
verifica 6.553.600 coefficienti; A99 nove casi; A104 sessanta casi e
60.960 parole. Mancano in questi gate il confronto cifrato, la rotazione
di scelta e il torneo completo. Il kernel A103 riduce staticamente gli
aggiornamenti di parole da 520.192 a 8.442, ma il rapporto 61,62× non è un
tempo misurato. [Schede e componenti Chen](catalogo-tentativi-a.md#a92).

<a id="estrazione-low"></a>

## Riuso delle correzioni low-bit: il produttore passa, il consumer fallisce

A125 tenta di evitare un canale cifrato riusando correzioni del canale alto
moltiplicate per 256. Il rumore iniziale piccolo non risolve il problema:
la moltiplicazione amplifica anche l'errore delle correzioni prodotte da PBS.
A130 chiude il programma diagnostico ma fallisce due requisiti del consumer
scalare, mentre le decodifiche native passano. L'exit 0 del diagnostico
non è un PASS del candidato. A165 aggiunge b1 e fallisce ancora; A169
ripara b0+b1 e passa lo smoke del consumer scalare.

Il test decisivo successivo usa il consumer cifrato reale. A175 prima non
compila per la ricorsione JSON; A184 supera quel problema e si ferma su
un helper privato; A185 ripara l'import e compila. La prima esecuzione,
A182, produce 17.703 record ed exit 1: il produttore decodifica correttamente,
ma il consumer b2=0 del caso `dense_nonzero/x17` fallisce. Il riferimento
passa. La diagnosi e A173 distinguono le regioni del bit zero da quelle
del bit uno; il successo di decodifica non implica l'appartenenza alla
regione richiesta dalla PBS successiva. [Linea e spiegazione](tentativi-a.md#estrazione),
[diagnosi A182](../../experiments/attempts-a/a182/results/a182-a175-first-runtime-envelope/artifacts/failure-diagnosis-first-key1/RESULT.public.json),
[sorgenti A185](../../experiments/attempts-a/a185/).

Questo negativo non si estende alla fusione A126. A131/A133 ne seguono
coefficienti e indirizzi: 27 casi, tre chiavi, 1.050 witness corretti; il
pilot A168 favorisce la fusione in quattro coppie, ma con una chiave e
guardia OS non qualificata. La fusione entra poi in una baseline distinta.
A194 propone un'altra uscita low-bit fusa: dodici test del modello e
controesempi, senza implementazione Rust/FHE in quel manufatto. È una
proposta, non un esperimento cifrato mancante. [A126](catalogo-tentativi-a.md#a126),
[A168](catalogo-tentativi-a.md#a168), [A194](catalogo-tentativi-a.md#a194).

<a id="precisione-nibble"></a>

## Head e nibble: precisione, padding e validità dei record

A88 esclude l'uso diretto di Head sul vecchio Delta52; Delta51 rende
rappresentabile il dominio 0…4095. A89 costruisce un adattatore di switching
per i casi di frontiera. A94 corregge una conclusione troppo forte:
1.820 differenze nei digit su 32.768 stati non cambiano la ricomposizione
modulo q né le norme assolute. Non provano né rumore peggiore né uguaglianza
della legge del rumore senza ulteriori ipotesi.

A98 passa quattordici vere BR, ma con input LWE costruiti senza rumore.
Il primo A112 si arresta prima delle chiavi per una diversa serializzazione
dello stream da sottoporre a hash; la copia corretta passa sedici casi di
KS→switch→BR. Nella ricorrenza originale resta il successivo errore
513→514. Il test di componente iniziale non aveva quindi certificato
l'intera estrazione. [A88–A112](catalogo-tentativi-a.md#a88),
[record A112 originale e corretto](../../experiments/attempts-a/a112/results/artifacts/).

A135/A138 progettano un minimo stabile che consuma nibble. A142–A145
rendono esplicite le regioni del consumer e gli osservatori; A149, eseguito
tramite A179, compila ma fallisce **tutti e quattro i rami positivi richiesti**.
I 355 record includono 346 osservazioni dei coefficienti, tutte aritmeticamente
coerenti. La chiusura del replay non ripara digit e consumer: il negativo è
funzionale. [Validazione del primo gate](../../experiments/attempts-a/a179/results/artifacts/first-validation.public.json)
e [diagnosi affine](../../experiments/attempts-a/a179/results/artifacts/first-affine-diagnosis.public.json).

A183 cambia la premessa di precisione, verificandola prima nel modello;
A187 passa il nuovo gate cifrato con 211 record. È una costruzione modificata,
non un nuovo nome del vecchio negativo. A192 poi termina con exit 0 ma
l'osservatore attribuisce una label di keyset incoerente: il replay rigido
rifiuta il record, e il full non viene promosso. A195 corregge il sorgente
separatamente e passa 16 fixture N4 su tre chiavi, 48 componenti e 10.130
record. Seguono R2/R3, 63 casi su sei chiavi e servizio N127. Il fallimento
della prima precisione e l'invalidità della label rimangono distinti.
[A192 invalido](../../experiments/attempts-a/a192/results/runs/n4-smoke/validation.public.json),
[A195 corretto](../../experiments/attempts-a/a195/results/runs/n4-full/validation.public.json),
[percorso padding](tentativi-a.md#padding).

<a id="common-mask-bgv"></a>
<a id="f92---ckks-common-mask-bgv-e-gpu"></a>

## F92 - CKKS, common-mask, BGV e GPU

Il primo [PoC common-mask 16](../../experiments/16_common_mask_poc/README.md)
e A27 non giustificavano il vecchio claim di circa 2×: parametri diversi,
loop separati e output non consumati impedivano il trasferimento alla
pipeline. A78 compie un passo più preciso: OR4 passa 64 output, il controllo
ordinary sedici, e la mappa volutamente errata sbaglia 45/64. Il cambio di
chiave PMK passa separatamente quindici casi su tre chiavi. Nessuno di questi
risultati è ancora la misura della loro composizione.

A107 sposta l'obiettivo agli otto livelli bassi del selettore; A132/A176
materializzano e provano singoli round fino a N127. Il negativo A150 riguarda
un altro requisito: i rami positivi stock/N4 passano, ma `witness-key2` non
rileva il controllo con lane errata. Il gate resta fallito. A155 adotta un
criterio di margine diverso e passa il replay di 381 record, dichiarando
il cambio di criterio; non trasforma A150 in un PASS. A146, inoltre,
mostra che l'aggiunta di uno zero comune non equivale a CMNR ordinary e
che superare uno stimatore non garantisce deterministicamente tutte le lane.
[Diagnosi A150](../../experiments/attempts-a/a150/results/diagnosis-witness-key2/RESULT.public.json),
[linea common-mask](tentativi-a.md#common-mask).

A188/A190 mantengono poi lo stato fra otto round: N4 passa 1.820 controlli
semantici e 336 di supporto; l'integrazione con estrazione reale, A34 e A53
passa tre scene per due politiche, 3.120 controlli semantici e 576 di supporto.
Il [Joint4 dell'esperimento 24](../../experiments/24_frontiere_common_mask_bgv/README.md)
cambia il produttore e arriva a quattro scene complete N16. Nel pilot
separato, una chiave e quattro coppie, è **17,77% più veloce** del precedente
common-mask ma **24,57% più lento** di R3. La correttezza del campione è
positiva, la scelta prestazionale negativa; nessuna estrapolazione a N127.
[Misure del pilot](../../experiments/24_frontiere_common_mask_bgv/evidence/common-mask-timing.json).

Il percorso BGV A109–A118 è un'altra costruzione. A115 misura contesti,
non ancora chiavi o FHE. A116 esclude il bridge lineare universale compatto
verso cifre modulo 131, senza escludere conversioni non lineari o p8191.
A117 incontra prima warning bloccanti e un crash; lo stesso binario con
GMP 6.3 caricato localmente passa poi 16.384 confronti con capacità finale
91. La copia privata preparata del backend non è quella usata per il PASS.
A118 preferisce staticamente il layout duplicato D, senza misurarne il tempo.
[A115–A118](catalogo-tentativi-a.md#a115).

Nel grafo completo il contesto più piccolo arriva a capacità **−6,537 bit**:
i valori diagnostici corretti non bastano ad ammettere il ciphertext originale.
Con anello più grande, phi(m)=65536, passano **210 stadi e 32.768 valori
terminali** su una chiave e scene N8/8/8/4, con capacità finale **575,184 bit**.
Si decifrano copie diagnostiche con `noiseBound=0`; in questo secondo grafo
l'originale era già `isCorrect=true` e la capacità di ogni stadio positiva.
Il cambiamento di contesto non permette una sottrazione causale dei margini.
La chiave pubblica serializzata è **3.150.947.064 byte**, non RSS; i
**20,6 minuti dell'azione** non sono latenza di query. Non è un confronto
di velocità con TFHE. [Rapporto BGV](../../experiments/24_frontiere_common_mask_bgv/evidence/BGV_FINAL_REVIEW.md),
[dati](../../experiments/24_frontiere_common_mask_bgv/RESULTS.json),
[codice](../../experiments/24_frontiere_common_mask_bgv/sources/bgv/src/main.cpp).

Il risultato CKKS associato a F92 rimane il confronto distinto **−8,098%**,
18/18 coppie su tre nuove chiavi, descritto [sopra](#ckks-e-switching).
La pista GPU custom Head/PFKS resta un prototipo con controlli preliminari
CPU: non sono osservati compilazione CUDA, correttezza FHE GPU o tempi
comprensivi dei trasferimenti. Il suo stato non eredita né il negativo
Concrete/T4 né il successo dei componenti CPU.

<a id="checked-e-rumore"></a>

## API checked, osservatori e rumore: cosa un PASS non certifica

A56/A59/A60 rilevano che un parametro nominale per PBS non si trasferisce
automaticamente alle LUT raw composte, al decoder finale o agli errori
correlati. A41 rimuove il decoder stretto e A44 cambia il preset, ma nessuno
dei due atti chiude da solo il prefisso raw. A139 individua un preset p128
compatibile e i successori superano i propri gate: il target del catalogo
rimane distinto dalla probabilità dell'intera pipeline. Anche KS32 A144
ha un PASS reale di primitiva, non un bound completo.

A64/A68 costruiscono un riferimento con API checked-shortint e abort distinto
da ID. Il primo run A75 è interrotto esternamente dopo 483,12 s, senza ID
o conteggio delle chiamate: non è un risultato algoritmico negativo.
A76 termina intenzionalmente dopo 1.024 chiamate del prefisso diagnostico.
Successivamente lo stesso binario qualificato da A72 completa N1 e N2,
con ID1/ID2, 43.013/61.995 chiamate e circa 514/1.000 s. Sono due fixture
costose, non un conteggio PBS o un completamento N127.
[A64–A76](catalogo-tentativi-a.md#a64).

A79 verifica un modello tipizzato del circuito ma conserva P_fail≤1 come
solo limite incondizionato; gli hash di tracce dichiarative non attestano
l'esecuzione. A84 lega 35 accumulatori, 71.680 coefficienti e 78.105 confronti
alla sorgente. A90 scopre però che 55/67 campioni consegnano valori dopo
l'offset dove A79 richiede valori grezzi. A93 corregge la proiezione:
è un difetto dell'interfaccia fra verificatori, non una LUT errata né
una FHE fallita. [A79/A84/A90/A93](catalogo-tentativi-a.md#a79),
[mappa del rumore composto](../validazione/RUMORE_COMPOSTO.md).

A131/A141/A148/A152–A163 distinguono identità esatte, formule di libreria,
leggi di maschere fresche, distribuzione del segreto e sampler finito.
I controesempi vietano di trasferire una legge di maschere fresche a cifrati
valutati o riusati, e una garanzia media sul segreto a ogni chiave fissata.
Il supporto ideale della trasformazione gaussiana polare non è l'enclosure
dell'implementazione f64/log/sqrt. A141 prima fallisce un import, poi esegue
il modello Rust coerente con Python senza FHE. A160 fallisce un helper;
A164 ripara il prefisso P0, A166 esegue il consumer P1. A158/A163 verificano
record e coefficienti reali nel modello dichiarato, senza certificare
sampler, CSPRNG o pipeline completa. [Schede dei modelli e prefissi](catalogo-tentativi-a.md#a148)
e [obblighi del rumore composto](../validazione/RUMORE_COMPOSTO.md).

<a id="servizio-e-strumentazione"></a>

## Servizio e misuratori: fallimenti del protocollo di prova

A55/A57/A63/A69/A74 sono gate diversi: Docker, fixture FHE e replay di
risultati salvati. Rileggere un log non aggiunge query al campione. A65
compila il servizio base-16; A67 usa base-15 e richiede un decoder compatibile.
Il primo A71 riusa dal target condiviso un artefatto di un altro clone e
fallisce sui simboli A62. La build isolata passa 23 test di libreria, dodici
del binario e release; A74 restituisce ID16 e 0 a N16 e rifiuta 31 formati
incompatibili. Questi ultimi sono controlli negativi **riusciti**, non 31
guasti del servizio. [A55–A74](catalogo-tentativi-a.md#a55).

A129 corregge la persistenza del controller dopo A124: piano, eventi,
stdout/stderr ed esiti vengono salvati progressivamente. Quattordici test
di guasti passano; non viene così ricreata una guardia CPU storica mai
registrata. A157 definisce un protocollo appaiato con tredici test statici,
ma non ha un esecutore di workload: non aggiunge benchmark alla ricerca.
[A129](catalogo-tentativi-a.md#a129), [A157](catalogo-tentativi-a.md#a157).

La linea dei contatori Darwin deve conservare tutti i passaggi. A170 compila
la CLI. A172 fallisce su parsing del primo snapshot e lettura BSD dello
zombie; A177 separa le due cause. A178 passa l'ordine 1→2, ma il replay
rifiuta la cronologia terminale 2→1 nonostante exit 0. A180 progetta due
barriere; A181 esegue entrambi gli ordini e i controlli di identità/reap,
riconoscendo il discendente non supportato. A193 completa anche il clock
del worker, 84 record nei due ordini. Sono progressi reali di ciclo di vita.
A189 confronta ipotesi sulle unità, ma unità, settlement e occupazione CPU
normalizzata restano non qualificati. [A172 rifiutato](../../experiments/attempts-a/a172/results/runs/order-12/validation-rejected.public.json),
[A178 secondo ordine rifiutato](../../experiments/attempts-a/a178/results/runs/order-21/validation-rejected.public.json),
[A181](../../experiments/attempts-a/a181/results/artifacts/independent-review/RESULT.public.json),
[A193](catalogo-tentativi-a.md#a193).

<a id="cpu-e-composizione"></a>

## CPU, normalizzatori e composizione: non sommare i guadagni

A66 conserva il grafo A62, cambiando preparazione e parallelismo dello scan.
A73 verifica output byte-identici in 240 coppie misurate più 48 warmup:
a sedici thread migliora del **22,2018%**, a un thread peggiora del **2,2628%**.
A77 elimina allocazioni riusando piano FFT e scratch, ma i due microbenchmark
ammessi restano sotto l'1% di differenza; il primo run contaminato da A73
è escluso e conservato. A85 è il protocollo successivo a quattro bracci,
senza misura del proprio adattatore parallelo. [A73](catalogo-tentativi-a.md#a73),
[A77/A85](catalogo-tentativi-a.md#a77).

A124 completa 21 celle, tre taglie per sette livelli di thread, con 294
query corrette e 210 tempi. A128 supera lo snapshot iniziale incompleto,
ma le guardie rimangono limitate: otto celle accettate pre/post, dodici
letture post elevate e una senza metadata; nessun monitor continuo.
I profili A80/A140 indicano dove cade il tempo, non core fisici occupati
o guadagni già disponibili. Dodici thread non dimostrano affinità ai dodici
P-core. [Risultato A124](../../experiments/attempts-a/a124/results/standalone/linked-evidence/experiments/14_pipeline_tfhe_rs/results/a124_thread_sweep_2026-09-04.public.json).

L'[esperimento 19](../../experiments/19_runtime_cpu/README.md) seleziona
opt3/CGU1, sedici thread e FFT Dif4 fissa. Native e CGU1/8 non confermano
un vantaggio; PGO è **1,53% più lento** nello screening separato e le opzioni
copie/cache non vengono selezionate. Le conferme positive usano due medie
per chiave, non 48 chiavi indipendenti, con carico segnalato e contabilità
parzialmente incerta. I piani adattivi precedenti non erano registrati:
non si attribuisce ogni differenza alla FFT.
[PGO](../../experiments/19_runtime_cpu/evidence/pgo-heldout.json),
[screening runtime](../../experiments/19_runtime_cpu/evidence/runtime-screen.json).

Nell'[esperimento 20](../../experiments/20_normalizzatori_carry/README.md),
condividere il normalizzatore porta riduzioni confermate, ma le mappe fuse
sono **0,14% più lente** e il selettore classic-batch **0,34% più lento**.
Il primo checker della LUT era troppo restrittivo verso una rappresentazione
equivalente: la sua correzione non cambia il circuito. L'esito positivo
isolato non obbliga quindi ad adottare ogni fusione successiva.
Nell'[esperimento 21](../../experiments/21_costanti_pubbliche_parallelismo/README.md)
l'attraversamento PFKS condiviso perde **0,991443%**, con 11/28 coppie
favorevoli, e non attiva altre famiglie. G4 guadagna **2,323432%** contro
il proprio riferimento, ma perde nella combinazione rispetto alla migliore
variante pubblica/parallela: la [demo 22](../../experiments/22_demo_composita/README.md)
lo esclude. I due risultati sono compatibili perché il riferimento cambia.
[Negativo PFKS](../../experiments/21_costanti_pubbliche_parallelismo/evidence/pfks-negative.json),
[conferma G4](../../experiments/21_costanti_pubbliche_parallelismo/evidence/g4-confirmation.json).

## F91 - Tetris e torneo DAG: esiti negativi circoscritti

Il primo [controllo aritmetico Tetris](../../experiments/25_tetris/failed-first/RESULT.json)
trova, al nibble 5/prefix bit 3, il valore 3 invece di −1. Non esegue FHE;
il [sorgente fallito](../../experiments/25_tetris/failed-first/tetris.rs)
resta distinto dalla successiva costruzione rumorosa.

Il produttore Tetris ibrido include sei circuit bootstrap freschi ed è
**66,401451% più lento** in 18 coppie, senza vittorie, su una famiglia e tre
scene. Passano **54 uscite complete del consumatore e 2091 controlli di fase
LWE**, oltre ai controlli di componente. La misura comprende le conversioni
del produttore, ma non è una misura della query intera. Questa costruzione
è esclusa dalla demo; l'esito non dimostra l'impossibilità di altri produttori.
[Esperimento 25 e codice](../../experiments/25_tetris/README.md),
[dati del produttore](../../experiments/25_tetris/evidence/producer-timing.json).

Il primo torneo senza attesa globale di livello è **3,060286% più lento**
del core qualificato P in 48 terne, con 2/48 vittorie. La successiva diagnosi
prova nuove politiche in una campagna distinta: una nuova famiglia, cinque
scene e 50 gruppi appaiati di cinque versioni.

| Politica della diagnosi successiva | Aumento del tempo rispetto a P | Vittorie |
|---|---:|---:|
| D: accodare il padre pronto | 0,897554% | 17/50 |
| I: proseguire direttamente nel padre pronto | 1,691943% | 19/50 |
| W: limitare il parallelismo interno finché resta lavoro iniziale largo | 2,619876% | 13/50 |

Il nuovo controllo con barriera B è **0,010341% più lento** di P. Tutti i
risultati aggregati per scena dei candidati/P sono sfavorevoli. Passano
560 uscite, 1680 fasi e 455 uguaglianze complete. I meccanismi sono effettivamente
esercitati: 1909 partenze anticipate per D/I/W nel gate, 2089 prosecuzioni I
e 103 soppressioni interne W. Tutte le 300 finestre di timing conservano
carico alto; in 220 l'attribuzione ai processi è parzialmente incerta.
Fra le 250 misurate, 177 hanno attribuzione incerta.
La copertura temporale campionata è completa in entrambe le campagne DAG.

Nessun candidato supera il criterio di selezione prefissato, quindi non
vengono generate le famiglie aggiuntive. La differenza fra i risultati delle
due campagne non permette di attribuire un guadagno a una singola modifica.
I profili di prontezza e il rapporto CPU/tempo trascorso non misurano core
liberi né un limite al risparmio ottenibile. Il fallimento iniziale di un
controllo sull'ordine fra due orologi diversi, la correzione verificata e
il gate completo successivo sono preservati. [Esperimento 26](../../experiments/26_torneo_dag/README.md),
[riepilogo](../../experiments/26_torneo_dag/RESULTS.json),
[coppie](../../experiments/26_torneo_dag/timing-pairs.csv),
[limiti dell'interpretazione](../../experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md).

La [nuova prova DAG del 4 ottobre](../../benchmark/tournament-dag-20261004/README.md)
riguarda il core N120/D512. Il primo lancio fallisce l'ammissione di una
coordinata sintetica, dopo keygen ma prima di qualsiasi valutazione del
circuito: non ha tempi da includere. La correzione controlla tutte le fixture
prima delle chiavi. La campagna valida registra 30 esiti, di cui 28 chiamate
del circuito e due rifiuti pubblici anticipati; il DAG perde tutte le otto
coppie, **+9,16% aggregato**. Una famiglia/query riusata non rende questi
esiti trenta prove crittografiche indipendenti. Il candidato non è integrato.
[Primo lancio](../../benchmark/tournament-dag-20261004/root/INVALID_CAMPAIGN.json),
[record validi](../../benchmark/tournament-dag-20261004/root/NATIVE_VALID1.ndjson),
[verifica temporale](../../benchmark/tournament-dag-20261004/math/RUNTIME_CHECK.md).

<a id="selettore-stretto"></a>

## Il selettore stretto: un guasto reale e il costo della riparazione

La finestra stretta con offset 0/41/82 e margine ±20 sostituisce un refresh
nella linea del 6 settembre. Un primo scarto −23 senza correzione della
media esce dal supporto pur restituendo payload corretti; non è ancora
l'errore ID75. Il primo output errato rintracciato nella linea con correzione
della media è invece **ID75 al posto di ID1**, il 9 settembre.

La diagnosi della capsula storica verifica tutte le 127 estrazioni Head
e i ternari. Nel nodo ID75/ID76 il controllo arriva a **341**, fuori
300…340; spostare solo quell'indirizzo a 340 ripristina ID1 nell'intero
torneo. Il replay della baseline pre-fix più recente sulla stessa capsula
produce ID1 e indirizzo 318: il rischio resta nel sorgente, ma non viene
osservato quel guasto nella versione più recente. Non si attribuisce il
cambiamento degli intermedi a una singola ottimizzazione.
[Cronologia e diagnosi](../selector-repair-20260920.md),
[fonti della prima introduzione](../selector-repair/INTRODUCTION_HISTORY.md).

La correzione B rigenera il controllo e amplia le finestre; pack4 conserva
il refresh e raggruppa fino a quattro payload. Il quinto consecutivo non
è ammesso. Passano 432 chiamate su tre famiglie nuove e 1.296 LWE finali
verificate; i casi storici restano regressioni, non nuove chiavi indipendenti.
Il costo va misurato: pack4 contro originale è **+6,8737456%** nel confronto
diretto, intervallo 95% condizionato **[+6,21%; +7,52%]**, differenza mediana
appaiata **0,1207 s/query**. Le percentuali +13,17% della prima correzione
e −4,7438% di pack4 appartengono a campioni diversi e non si moltiplicano.
[Validazione pack4](../validazione/PACK4_VALIDATION.md),
[confronto diretto](../selector-direct-cost-20260920.md).

Le scorciatoie successive non recuperano gratuitamente quel costo. Non
viene trovato un refresh duplicato. La guardia pubblica provata non passa
127+127 controlli, anche assumendo errore precedente nullo: fallisce una
condizione sufficiente, senza provare impossibilità generale. Sovrapporre
refresh e PFKS conserva 96 query, ma perde **0,49%** nei cinque scenari
primari e non supera il criterio temporale. Il campione usa una famiglia
riusata con carico esterno. La baseline mantiene il refresh corretto.
[Approfondimenti e relativi limiti](../selector-repair-20260920.md#approfondimenti-conclusi-e-limiti-aperti).

<a id="precisione-compressa"></a>

## Tre compressioni del 4 ottobre, tre negativi diversi

Il [comparatore compresso](../validazione/COMPARATORE_COMPRESSO_20261004.md)
cerca due PBS invece di tre, combinando due cifre basse. Alla scala Delta59
esistono collisioni ideali; Delta55 le elimina nel modello, ma restringe
il margine uniforme da ±63 a ±3 gradi. Con una chiave TFHE-rs 1.8.1,
la correzione della sola media supera alcuni casi che il ramo non centrato
sbaglia, poi **255 contro 0 restituisce uguaglianza** invece di maggiore.
Il test si ferma al sesto caso, lasciandone 26 pianificati ineseguiti;
i diciotto ternari di riferimento controllati sono corretti. Le uscite
finali non localizzano da sole il componente responsabile; niente latenza
adottabile o tasso di errore stimato. [Campioni](../../benchmark/comparator-encoding-20261004/samples.csv),
[record](../../benchmark/comparator-encoding-20261004/rows.jsonl),
[geometria](../../benchmark/comparator-encoding-20261004/GEOMETRY.md).

Il [comparatore binario isolato](../../benchmark/binary-comparator-20261004/README.md)
passa otto coppie con cifre fresche. La [pipeline binaria](../validazione/PIPELINE_BINARIA_20261004.md)
che le produce via Head passa quattro scene N2 e fallisce la quinta: due
score uguali a −1, primo candidato con soglia −2 e secondo con soglia −1.
Il contratto richiede scegliere il primo e rifiutare, **0**; il circuito
restituisce **ID2**. La sesta scena non viene eseguita. Il programma Rust
termina 101; l'exit 0 del launcher indica soltanto che il diagnostico ha
raccolto il risultato. Il tempo totale del processo non è una latenza
utile del candidato corretto. [Record della pipeline](../../benchmark/binary-pipeline-20261004/rows.jsonl),
[review](../../benchmark/binary-pipeline-20261004/RESULT_REVIEW.md).

La diagnosi successiva usa **un'altra famiglia**: già il produttore devia
su score normalizzato 62, atteso [0,3,14], osservato [0,3,13] oppure [0,3,15].
Si ferma prima dei confronti. Localizza il guasto di quel test nel produttore,
non dimostra quale stadio interno abbia causato il precedente errore su
un'altra chiave. Le verifiche statiche escludono inoltre un singolo encoding
lineare alla scala Delta59 per tutte le due cifre, ma non ogni algoritmo
a due PBS. Il bound pubblico di galleria non certifica una cifra alta
costante per tutte le foglie. [Diagnosi degli stadi](../../benchmark/binary-pipeline-20261004/stages/RESULT_REVIEW.md),
[collisioni affini](../../benchmark/binary-pipeline-20261004/encoding/affine-aliases.json),
[bound pubblici](../../benchmark/binary-pipeline-20261004/encoding/public-bounds.json).

Il [produttore base64](../validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md)
vuole due blocchi da sei bit invece di tre da quattro: una Head e due
normalizzatori, tre rotazioni anziché quattro. Tutti i 4.096 centri ideali
passano, con margine ±7 invece di ±31, ma il preset non certifica una
LUT a 128 stati. In FHE passano 63, 64 e 0; **4095 esce come 4094**,
[63,62] al posto di [63,63]. Il test si ferma al quarto caso; cinque passi
pianificati restano ineseguiti, compreso il prefisso con score reali.
Le decodifiche finali non identificano l'esatta causa interna. Non sono
stati misurati né un torneo corretto né una sua accelerazione.
[Campioni](../../benchmark/base64-producer-20261004/samples.csv),
[obblighi di errore](../../benchmark/base64-producer-20261004/ERROR_OBLIGATIONS.md),
[review](../../benchmark/base64-producer-20261004/RESULT_REVIEW.md).

<a id="profili-e-microkernel"></a>

## Versioni, profili e microkernel: evitare guadagni trasferiti

L'aggiornamento a TFHE-rs 1.8.1 supera i controlli funzionali ma non porta
l'accelerazione sperata. Il [pilot del 22 settembre](../validazione/TFHE_181_MIGRATION.md)
ha 31 valutazioni cifrate corrette complessive; nel confronto breve la 1.8.1
richiede circa 3–6% in più. La [campagna del 4 ottobre](../../benchmark/tfhe-181-20261004/README.md)
usa Rust 1.98.1 uguale nei due bracci, tre famiglie per versione e 144 misure:
216 risposte corrette con warmup, **0,88–2,09%** di tempo in più per la 1.8.1
nelle tre scene. Sono nuovi campioni, non la correzione retroattiva del pilot.
Carico, famiglie separate per versione e assenza di intervallo di confidenza
impediscono una legge generale o una causa certa del rallentamento.
Il primo lancio Python 3.9 fallisce prima delle query per `hashlib.file_digest`;
la [ricevuta](../../benchmark/tfhe-181-20261004/receipts/FIRST_LAUNCH_FAILURE.md)
è un problema del driver, distinto dall'esito prestazionale.

La profilazione del [core](../../benchmark/core-profile-20261004/README.md)
e dei [nodi merge](../../benchmark/merge-profile-20261004/README.md) orienta
le prove: nel primo campione torneo ed estrazione rappresentano medianamente
55,90% e 41,44% della query; nel secondo il confronto pesa 44,67–55,83%
del tempo del nodo e PFKS 4,81–5,72%. Il profilo non è una variante accelerata.
I tempi dei nodi non si moltiplicano per sessanta, perché si sovrappongono.

Il [test pubblico dei buffer BR](../../benchmark/br-scratch-cost-20261004/PROTOCOL.md)
esegue allocazione/azzeramento/liberazione e riuso, senza chiavi o FHE.
Confronta cicli densi diversi dal lavoro di una vera BR; il riuso non riscrive
l'intero buffer, e non c'è verifica del codice generato. Il risultato riduce
la priorità del prototipo, ma non consente di moltiplicare nanosecondi per
numero di BR per prevedere il guadagno della query.
[Dati e limiti](../../benchmark/br-scratch-cost-20261004/SUMMARY.json).

FCMA supera invece un [gate di codice generato](../../benchmark/fcma-codegen-20261004/README.md)
e un [test aritmetico/temporale pubblico](../../benchmark/fcma-public-gate-20261004/README.md):
65.536 confronti razionali senza discrepanze, 32 osservazioni in otto blocchi,
rapporto FCMA/NEON **0,7180**. Il 28,20% in meno riguarda un aggiornamento
complesso isolato, un thread e buffer caldi; gli zeri con segno sono equivalenti
numericamente, non promessi identici bit per bit. È una pista con evidenza
positiva di componente, ancora senza integrazione FHE o garanzia sugli
errori rari. Non viene presentata come un altro negativo né come un 28%
disponibile sull'intera applicazione.

<a id="ottimizzazioni-terminali"></a>

## Ultimo stadio, PFKS pubbliche e riuso del vincitore

La [variante raw9](../../benchmark/raw9-20261005/README.md) rende più economico
il terminale del 5 ottobre. Passano 54 esiti controllati; lo stadio finale
migliora in 18/18 coppie, circa **15–16%**. Il totale è però favorevole solo
in 5/6, 4/6 e 3/6 coppie per i tre input, con variazioni di segno in ogni
scena e mediane appaiate **−0,8135%, −0,2297%, −0,0069%**. Una famiglia,
sei coppie per scena e timer diagnostico non stabiliscono un vantaggio
stabile della query. La variante non è adottata; il progresso del terminale
rimane documentato. [Tabella completa](selettore-e-generalizzazione.md#raw9),
[risultato](../../benchmark/raw9-20261005/results/RESULT.md).

La cache delle PFKS degli ID pubblici si ferma dopo una
[profilazione effettiva](../../benchmark/public-id-pfks-20261005/README.md).
Le dodici query sono corrette; nelle nove profilate si osservano 244 PFKS
al primo livello, 180 score, sessanta ID basso e quattro ID intermedio.
Gli ID hanno maschera nulla: buona parte del lavoro che la cache avrebbe
evitato è già assente. La quota **0,1471–0,1556%** riguarda la somma dei
tempi dei worker al primo livello, non la latenza della richiesta e non
un limite matematico al risparmio. Nessun prototipo cache viene eseguito.
[Risultato e chiusura del ramo](../../benchmark/public-id-pfks-20261005/results/RESULT.md).

L'idea di riusare direttamente il GLWE interno incontra invece un limite
di interfaccia: il polinomio corrente contiene una **correzione**, e solo
dopo l'estrazione si riaggiunge il candidato sinistro. La disposizione dopo
la rotazione dipende dal controllo cifrato, mentre la PFKS successiva
richiede finestre fisse. Non è già il vincitore canonico riutilizzabile.
[Analisi GLWE](../evidence/repo-coverage-20261005/glwe-interface.md).

CBS potrebbe selezionare due polinomi completi, ma richiede di costruire
quei carrier, chiavi dedicate, parametri e un budget per le selezioni
ripetute. Il test di libreria esaminato usa parametri dichiaratamente
insicuri per testing, non direttamente adottabili. Le revisioni statiche
passano; **nessun prototipo CBS di questa proposta viene eseguito o fallisce**.
Il negativo Tetris riguarda un produttore diverso. È escluso l'innesto diretto,
resta condizionata la riprogettazione. [Interfaccia CBS](../evidence/repo-coverage-20261005/cbs-review.md),
[parametri](../evidence/repo-coverage-20261005/cbs-parameters.md).

<a id="biometria-e-garanzie"></a>

## Biometria e probabilità FHE: due verifiche non sostituibili

La [prima galleria VGGFace2 del 2 ottobre](../validazione/BIOMETRIA_VGGFACE2_20261002.md)
si ferma a 119 template: il detector non trova un volto fra le 120 foto
d'iscrizione. Nessuna query è eseguita e non viene presentata come N120.
Il successore aggiunge uniformemente due foto a tutti gli iscritti prima
di vedere risultati query. La galleria completa produce 110/120 iscritti
riconosciuti con una foto e 119/120 con tre foto diverse; gli sconosciuti
accettati sono uno e due. Tre tentativi della prima condizione non producono
un vettore ammissibile e rimangono nei denominatori pertinenti. La differenza
fra condizioni non isola il solo effetto della fusione. Il codec browser
non era incluso e la separazione della coorte dallo sviluppo è condizionata.
Non è una prova FHE o una garanzia FPIR=1%.

La [campagna Georgia Tech del 5 ottobre](../../benchmark/biometrics-gt-20261005/README.md)
include invece il passaggio di codifica dell'interfaccia. Galleria 120:
cento preset e venti nuovi iscritti; trenta sconosciuti. In ciascuna delle
due condizioni passano 20/20 iscritti e viene accettato **1/30 sconosciuti**,
la stessa coppia persona/iscritto. Score 219 e 273, quest'ultimo accettato
per soglia inclusiva. Tutte le cento decisioni concordano con l'oracolo
intero; il falso accesso esiste già in chiaro, non è un guasto del selettore
FHE. Il limite superiore unilaterale 95% è **14,86%**, condizionato al modello
binomiale e alla galleria. Le due condizioni sulle stesse persone non
raddoppiano gli sconosciuti indipendenti. Nessuna garanzia dell'1% viene
confermata, e la soglia non viene ritoccata per far sparire l'errore.
[Risultato e review](../../benchmark/biometrics-gt-20261005/results/RESULT.md).

La derivazione della probabilità FHE risponde a un'altra domanda. Il
limite sul primo indirizzo e un budget insufficiente non sono una
frequenza di ID errati. La [mappa del rumore](../validazione/RUMORE_COMPOSTO.md)
distingue premesse e budget ancora da giustificare per la baseline composta;
i pacchetti sperimentali documentano gli esiti osservati. Questi esiti non
certificano una probabilità di fallimento della pipeline e non sostituiscono
la validazione biometrica.

<a id="mappa"></a>

## Mappa del percorso e riproduzione dei risultati

Le sezioni precedenti raggruppano le domande scientifiche; il
[catalogo](catalogo-tentativi-a.md) mantiene la scheda di ogni sigla, compresi
auditori, launcher, modelli, controlli positivi e successori. Una sigla A
non equivale a una campagna FHE indipendente. La mappa seguente assegna
ciascuna voce a una sezione di lettura, senza copiare tutte le schede.



| Lettura ragionata | Sigle del catalogo |
|---|---|
| [Rappresentazioni, dominio e accuratezza](#rappresentazioni) | [A07](catalogo-tentativi-a.md#a07), [A11](catalogo-tentativi-a.md#a11), [A136](catalogo-tentativi-a.md#a136) |
| [Dominio e contratto della decisione](#dominio-e-contratto) | [A01–A06](catalogo-tentativi-a.md#a01), [A10](catalogo-tentativi-a.md#a10), [A15–A20](catalogo-tentativi-a.md#a15) |
| [CKKS e conversioni](#ckks-e-switching) | [A08–A09](catalogo-tentativi-a.md#a08), [A13–A14](catalogo-tentativi-a.md#a13), [A21–A22](catalogo-tentativi-a.md#a21) |
| [Compatibilità delle alternative](#alternative-di-interfaccia) | [A12](catalogo-tentativi-a.md#a12), [A32](catalogo-tentativi-a.md#a32), [A46](catalogo-tentativi-a.md#a46), [A81–A83](catalogo-tentativi-a.md#a81), [A91](catalogo-tentativi-a.md#a91), [A105–A106](catalogo-tentativi-a.md#a105), [A110](catalogo-tentativi-a.md#a110), [A114](catalogo-tentativi-a.md#a114) |
| [Stato candidato, packing e scan](#selezione-scan) | [A23–A26](catalogo-tentativi-a.md#a23), [A28–A29](catalogo-tentativi-a.md#a28), [A31](catalogo-tentativi-a.md#a31), [A33–A41](catalogo-tentativi-a.md#a33), [A44–A45](catalogo-tentativi-a.md#a44), [A49–A53](catalogo-tentativi-a.md#a49), [A58–A59](catalogo-tentativi-a.md#a58), [A61–A62](catalogo-tentativi-a.md#a61), [A70](catalogo-tentativi-a.md#a70) |
| [PFKS, finestre dirette e Chen](#pfks) | [A30](catalogo-tentativi-a.md#a30), [A86–A87](catalogo-tentativi-a.md#a86), [A92](catalogo-tentativi-a.md#a92), [A95–A97](catalogo-tentativi-a.md#a95), [A99](catalogo-tentativi-a.md#a99), [A101–A104](catalogo-tentativi-a.md#a101), [A108](catalogo-tentativi-a.md#a108), [A120–A123](catalogo-tentativi-a.md#a120), [A127](catalogo-tentativi-a.md#a127), [A134](catalogo-tentativi-a.md#a134), [A137](catalogo-tentativi-a.md#a137), [A147](catalogo-tentativi-a.md#a147), [A151](catalogo-tentativi-a.md#a151), [A167](catalogo-tentativi-a.md#a167), [A171](catalogo-tentativi-a.md#a171), [A174](catalogo-tentativi-a.md#a174), [A186](catalogo-tentativi-a.md#a186), [A191](catalogo-tentativi-a.md#a191) |
| [Riuso low-bit e refresh fuso](#estrazione-low) | [A125–A126](catalogo-tentativi-a.md#a125), [A130–A131](catalogo-tentativi-a.md#a130), [A133](catalogo-tentativi-a.md#a133), [A162](catalogo-tentativi-a.md#a162), [A165](catalogo-tentativi-a.md#a165), [A168–A169](catalogo-tentativi-a.md#a168), [A173](catalogo-tentativi-a.md#a173), [A175](catalogo-tentativi-a.md#a175), [A182](catalogo-tentativi-a.md#a182), [A184–A185](catalogo-tentativi-a.md#a184), [A194](catalogo-tentativi-a.md#a194) |
| [Head, precisione e padding](#precisione-nibble) | [A88–A89](catalogo-tentativi-a.md#a88), [A94](catalogo-tentativi-a.md#a94), [A98](catalogo-tentativi-a.md#a98), [A111–A112](catalogo-tentativi-a.md#a111), [A135](catalogo-tentativi-a.md#a135), [A138](catalogo-tentativi-a.md#a138), [A142–A143](catalogo-tentativi-a.md#a142), [A145](catalogo-tentativi-a.md#a145), [A149](catalogo-tentativi-a.md#a149), [A179](catalogo-tentativi-a.md#a179), [A183](catalogo-tentativi-a.md#a183), [A187](catalogo-tentativi-a.md#a187), [A192](catalogo-tentativi-a.md#a192), [A195](catalogo-tentativi-a.md#a195) |
| [Common-mask e BGV](#common-mask-bgv) | [A27](catalogo-tentativi-a.md#a27), [A78](catalogo-tentativi-a.md#a78), [A107](catalogo-tentativi-a.md#a107), [A109](catalogo-tentativi-a.md#a109), [A115–A118](catalogo-tentativi-a.md#a115), [A132](catalogo-tentativi-a.md#a132), [A146](catalogo-tentativi-a.md#a146), [A150](catalogo-tentativi-a.md#a150), [A155](catalogo-tentativi-a.md#a155), [A176](catalogo-tentativi-a.md#a176), [A188](catalogo-tentativi-a.md#a188), [A190](catalogo-tentativi-a.md#a190) |
| [Checked, modelli del rumore e prefissi](#checked-e-rumore) | [A56](catalogo-tentativi-a.md#a56), [A60](catalogo-tentativi-a.md#a60), [A64](catalogo-tentativi-a.md#a64), [A68](catalogo-tentativi-a.md#a68), [A72](catalogo-tentativi-a.md#a72), [A75–A76](catalogo-tentativi-a.md#a75), [A79](catalogo-tentativi-a.md#a79), [A84](catalogo-tentativi-a.md#a84), [A90](catalogo-tentativi-a.md#a90), [A93](catalogo-tentativi-a.md#a93), [A139](catalogo-tentativi-a.md#a139), [A141](catalogo-tentativi-a.md#a141), [A144](catalogo-tentativi-a.md#a144), [A148](catalogo-tentativi-a.md#a148), [A152–A154](catalogo-tentativi-a.md#a152), [A156](catalogo-tentativi-a.md#a156), [A158–A161](catalogo-tentativi-a.md#a158), [A163–A164](catalogo-tentativi-a.md#a163), [A166](catalogo-tentativi-a.md#a166) |
| [Servizio, record e contatori](#servizio-e-strumentazione) | [A55](catalogo-tentativi-a.md#a55), [A57](catalogo-tentativi-a.md#a57), [A63](catalogo-tentativi-a.md#a63), [A65](catalogo-tentativi-a.md#a65), [A67](catalogo-tentativi-a.md#a67), [A69](catalogo-tentativi-a.md#a69), [A71](catalogo-tentativi-a.md#a71), [A74](catalogo-tentativi-a.md#a74), [A129](catalogo-tentativi-a.md#a129), [A157](catalogo-tentativi-a.md#a157), [A170](catalogo-tentativi-a.md#a170), [A172](catalogo-tentativi-a.md#a172), [A177–A178](catalogo-tentativi-a.md#a177), [A180–A181](catalogo-tentativi-a.md#a180), [A189](catalogo-tentativi-a.md#a189), [A193](catalogo-tentativi-a.md#a193) |
| [Thread, buffer e profili](#cpu-e-composizione) | [A66](catalogo-tentativi-a.md#a66), [A73](catalogo-tentativi-a.md#a73), [A77](catalogo-tentativi-a.md#a77), [A80](catalogo-tentativi-a.md#a80), [A85](catalogo-tentativi-a.md#a85), [A124](catalogo-tentativi-a.md#a124), [A128](catalogo-tentativi-a.md#a128), [A140](catalogo-tentativi-a.md#a140) |

Per gli esperimenti numerati e i successori senza sigla A:

| Materiale | Sezione e limite principale |
|---|---|
| 00–08, 11 | [Rappresentazioni](#rappresentazioni), [Concrete](#concrete-e-gpu): accuratezza, score-only e preparazioni non eseguite. |
| 09–10, 13–14 | [Concrete/GPU](#concrete-e-gpu), [contratto](#dominio-e-contratto), [scan](#selezione-scan): costi, build e domini. |
| 15–16, 23–24 | [CKKS](#ckks-e-switching), [common-mask/BGV](#common-mask-bgv): conversioni, controlli e costo del grafo completo. |
| 17–18 | [PFKS](#pfks), [precisione](#precisione-nibble), [selettore stretto](#selettore-stretto): composizione, scaling e successiva riparazione. |
| 19–22 | [CPU e composizione](#cpu-e-composizione): varianti escluse, normalizzatori e G4. |
| 25–26 e DAG del 4 ottobre | [Tetris e DAG](#f91---tetris-e-torneo-dag-esiti-negativi-circoscritti): errori preliminari distinti dai negativi di costo. |
| Riparazione selettore, pack4 e sovrapposizione | [Selettore stretto](#selettore-stretto): ID errato, riparazione e costo misurato. |
| Comparatore compresso, binario e base64 del 4 ottobre | [Compressioni](#precisione-compressa): tre gate distinti e successive diagnosi. |
| TFHE 1.8.1, profili core/merge, scratch e FCMA | [Profili e microkernel](#profili-e-microkernel): migrazione, misure locali e limiti di trasferimento. |
| raw9, PFKS ID, GLWE e CBS del 5 ottobre | [Ultimo stadio e riuso](#ottimizzazioni-terminali): vantaggio inconclusivo, priorità ridotta e incompatibilità dirette. |
| VGGFace2, Georgia Tech e prova C | [Biometria e garanzie](#biometria-e-garanzie): preparazione fallita, falsi accessi in chiaro e prova condizionale distinta. |

Per riprodurre un risultato si parte dal protocollo e dal manifesto del suo
pacchetto: versione, parametri, input, formato del consumer, keyset e confini
del timer fanno parte della prova. I [programmi della famiglia A](../../experiments/attempts-a/README.md)
e i [pacchetti di benchmark](../../benchmark/README.md) distinguono sorgenti
condivisi, risultati, estratti pubblici e ricette degli input. Un nuovo run
deve conservare anche i casi falliti e quelli pianificati ma non eseguiti,
senza sovrascrivere le osservazioni qui discusse. La disponibilità del codice
e il ricalcolo di un riepilogo non sono una nuova replica crittografica.
