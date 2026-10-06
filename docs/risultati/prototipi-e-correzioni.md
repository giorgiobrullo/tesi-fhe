# Dai prototipi al contratto 0/ID

<a id="prime-campagne-e-correzioni"></a>
<a id="risultati-storici-e-correzioni"></a>

[Indice dei risultati](../../findings.md) · [Percorso sperimentale](../percorso-sperimentale.md) · [Diario completo](diario/README.md)

Le schede F0–F83 seguono quattro passaggi: rappresentare il volto,
scegliere sul dato cifrato, precisare il protocollo e costruire la risposta
esatta `0/ID`. Questa sintesi integra nelle rispettive fasi le correzioni
emerse dal controllo di programmi e risultati. Il diario conserva i
ragionamenti originali e ogni tentativo, con rimandi alle conclusioni corrette.

Ogni misura appartiene al proprio programma, campione e timer. Le percentuali
di confronti diversi non si sommano; prove biometriche, test cifrati e
probabilità di fallimento del circuito rimangono verifiche distinte.

<a id="f0f83---risultati-storici-e-correzioni-consolidate"></a>

## F0–F19: dalla foto a una rappresentazione utile

| Identificatori | Risultato e condizioni |
|---|---|
| F0–F3 | Concrete è stato eseguito nativamente su macOS arm64. La galleria pubblica consente prodotti cifrato×chiaro e richiede la corretta espansione del punteggio; non elimina da sola i problemi del modello di minaccia. |
| F4–F10 | PCA e descrittori locali hanno prototipi e benchmark conservati. I risultati sui dataset semplici non si trasferiscono ai benchmark difficili o al riconoscimento open-set 1:N. |
| F11–F14 | Argmin+soglia è implementabile; un inputset di compilazione non è un dominio di sicurezza. Gli embedding CNN migliorano le prove biometriche rispetto ai descrittori precedenti; quantizzazione e protocollo vanno valutati separatamente. |
| F15–F19 | Profondità, taglia della galleria e dominio dei volti cambiano l'accuratezza osservata. I primi numeri con un solo seed sono circoscritti e rinviano alle successive verifiche multi-seed; nessun tetto universale di accuratezza è dimostrato. |

<a id="precisazioni-del-2-ottobre-2026"></a>

Il [protocollo biometrico della baseline](../validazione/PROTOCOLLO_BIOMETRICO.md)
richiede dati separati per configurazione e valutazione. I dettagli seguenti
precisano quali separazioni erano effettivamente presenti nelle prime prove.

### F18: foto separate non significano una valutazione interamente indipendente

La nota di [F18](diario/f15-f28.md#f18) diceva che la separazione train/test
era già garantita. Sono effettivamente separate le foto d'iscrizione dai
probe, cioè le richieste da riconoscere, e le identità iscritte dagli
sconosciuti. Questo però non separa tutti i calcoli usati per scegliere la
configurazione dai dati su cui se ne misura l'accuratezza.

La [metrica 1:N delle prime campagne](../../core/metriche.py) sceglie la soglia sugli stessi
sconosciuti del campione valutato. Nelle prove di
[compressione](../../benchmark/compressione.py) e
[dimensione](../../benchmark/scaling_dimensione.py), la PCA è stimata sul
pool completo prima della valutazione; la LDA in `compressione.py` usa
invece la galleria. La
[calibrazione successiva della demo](../../demo/calibra.py) separa gli
sconosciuti per tarare e verificare la soglia all'interno di ogni split,
ma stima prima la scala di quantizzazione sull'intero cache reale.

Le percentuali di queste campagne restano confronti esplorativi nelle condizioni
dichiarate. Non dimostrano lo stesso tasso di falsi accessi su nuove
acquisizioni. Usare una CNN congelata non risolve inoltre la possibile
sovrapposizione tra identità del benchmark e addestramento originale del
modello: quel controllo resta distinto dalla separazione locale delle foto.

### Verifica 1:1: dieci fold con una suddivisione personalizzata

[verifica.py](../../benchmark/verifica.py) assegna le coppie ai dieci gruppi
con `indice % 10`. Il
[valutatore di riferimento InsightFace](https://github.com/deepinsight/insightface/blob/master/recognition/arcface_torch/eval/verification.py)
usa invece KFold senza mescolamento, con blocchi contigui. Entrambi
scelgono la soglia usando i fold di training, ma non valutano gli stessi
fold. La PCA locale è anche stimata su tutte le immagini; il riferimento
la stima dentro ciascun fold sui soli dati di training. Quest'ultimo
limite non riguarda le colonne CNN, che non stimano la PCA.

I valori conservati descrivono quindi una verifica interna a dieci fold,
non una riproduzione del protocollo ufficiale di ciascun benchmark. Anche
[verifica_resnet100.py](../../benchmark/verifica_resnet100.py) riusa quella
suddivisione. Non vanno confrontati al decimo di punto con risultati
ufficiali senza prima applicare lo stesso protocollo. La verifica a coppie
1:1 resta inoltre diversa dalla ricerca open-set 1:N della baseline.

La [galleria web](../../demo/web/gallery/README.md) conserva 120 ritratti
illustrativi, con un template per persona. Riutilizzare la foto
d'iscrizione controlla il servizio e i suoi tempi. La verifica biometrica
su altre foto ha invece risultati propri: [VGGFace2 del 2 ottobre](../validazione/BIOMETRIA_VGGFACE2_20261002.md),
[preparazione UI](../validazione/BIOMETRIA_UI_20261002.md) e
[Georgia Tech del 5 ottobre](selettore-e-generalizzazione.md#georgia-tech).
Questi risultati in chiaro non qualificano sessioni webcam o un tasso
generale di falsi accessi; i [limiti ancora aperti](../limiti.md) sono distinti.

## F20–F39: quantizzazione e decisione sul dato cifrato

| Identificatori | Risultato e condizioni |
|---|---|
| F20–F24 | Sono state confrontate compressione degli embedding, argmin server e strategie a blocchi in Concrete. Funzione restituita, interazione e minaccia determinano se un confronto preserva il contratto. |
| F25–F28 | Il test Concrete su Tesla T4 e i tornei/controlli a soglia hanno risultati propri. Non qualificano il successivo circuito custom GPU né dimostrano limiti generali di GPU o TFHE. Le conclusioni bibliografiche di F26 vanno lette con le correzioni della rassegna. |
| F29–F34 | Scaling DigiFace, divario di dominio e prodotto scalare leveled hanno misure nelle rispettive prove. F32 contiene una serie attribuita al Mac distinta dalla tabella del report 13. I rapporti di circa 100× confrontano input e perimetri temporali diversi: non sono un confronto appaiato né un'accelerazione dell'intera applicazione. Vedere la precisazione sotto. |
| F35–F39 | Il protocollo distingue identificazione e decisione di accesso. Gli otto bit sono una verifica in chiaro della quantizzazione; il torneo radix e la prima CKKS hanno benchmark separati. Il comparatore diretto a un PBS di F37 è invalidato vicino alla soglia da F68. |

### F30: persone, template e numero effettivo di foto

Nelle curve biometriche N indica le **persone iscritte** (`N_id`); nei
circuiti FHE indica i **template confrontati** (`N_template`). Un template
è il vettore registrato in una voce della galleria. Le due quantità
coincidono soltanto se ogni persona ha una sola voce.

In [F30](diario/f29-f42.md#f30), il
[driver multi-seed](../../benchmark/rimisura_1n.py) richiede al massimo M
foto per persona, ma il cache reale ne contiene sei. I campi M10 e M20 del
[CSV originale](../../benchmark/results/rimisura_1n.csv) usano quindi
entrambi sei foto; la sensibilità effettiva è fra cinque e sei, non fra
cinque, dieci e venti. Lo
[split a metà](../../core/dataset.py) produce questi carichi:

| Foto usate per persona | Template in galleria per persona | Foto usate come probe |
|---|---:|---:|
| 6, per M10 e M20 nominali | 3 | 3 |
| 5, per M5 | 2, per l'arrotondamento `round(2,5)` | 3 |

Il punto a 4.300 iscritti usa dunque 12.900 template in chiaro: non misura
una query FHE da 4.300 voci. La calibrazione multi-frame della demo usa
invece un solo template fuso per persona. I futuri risultati dovranno
indicare separatamente `N_id`, `N_template`, foto richieste e foto usate.

### F31: cosa misura il risultato sulla quantizzazione

Il piccolo calo riportato in [F31](diario/f29-f42.md#f31) viene dalla
[figura sulla quantizzazione](../../benchmark/figura_quant_accuratezza.py):
ResNet50, DigiFace sintetico, un solo split, scala e, per le curve compresse,
PCA stimate sul pool valutato. La metrica usa la distanza quadratica completa
`||q||² + ||g||² − 2<g,q>`.

La baseline della demo usa lo score `||g||² − 2<g,q>` e una soglia in quel
dominio. Togliere `||q||²` mantiene il minimo per una data query, ma una
soglia fissa sullo score non equivale a una soglia fissa sulla distanza
quando la norma della query varia dopo quantizzazione. La calibrazione
della demo usa intenzionalmente lo score: questa distinzione non introduce
un errore aritmetico nel circuito. Il risultato di F31 non misura però la
perdita biometrica della baseline della demo; serve una valutazione in chiaro
con la sua regola, preparazione dei volti e parametri congelati.

<a id="precisazioni-del-22-settembre-2026"></a>

### F32: due serie e perimetri temporali differenti

La tabella del [diario F32](diario/f29-f42.md#f32) usa Concrete
**47,35/98,29 s** a N4/N8, presenti nel
[CSV Mac](../../experiments/10_argmin_struttura/risultati_mac.csv), e argmin
TFHE-rs **0,45/1,05 s**, presenti nel
[log Rust](../../experiments/13_tfhe_rs_headtohead/results/argmin_tfhe_rs.txt).
È la serie attribuita al Mac dal diario e dai commenti del sorgente; il CSV
riporta anche gli errori del dataflow non disponibile su macOS. Il solo log
Rust non costituisce una verifica indipendente della macchina usata.
La tabella del [report 13](../../experiments/13_tfhe_rs_headtohead/RISULTATI.md)
usa invece **78/180 s contro 0,68/1,78 s**: i suoi valori Concrete coincidono
con quelli arrotondati del [report Linux](../../experiments/10_argmin_struttura/RISULTATI.md).
La riserva sull'hardware di questa seconda tabella non va estesa alla prima
confondendo le due serie.

Restano limiti sostanziali anche per la serie Mac. I sorgenti conservati
generano galleria e query differenti: [Concrete](../../experiments/10_argmin_struttura/bench_struttura.py)
usa NumPy RandomState con seed 0/123; [Rust](../../experiments/13_tfhe_rs_headtohead/src/main.rs)
usa un altro generatore, LCG con seed 12345/999. Inoltre il timer Concrete
include formazione degli score e argmin, mentre la colonna Rust citata misura
solo l'argmin. Il log Rust riporta separatamente 24,24/49,86 s per score+argmin.
Il costo dello score Concrete non è isolato da queste osservazioni.

I rapporti arrotondati **105×/94×** restano descrittivi dei numeri riportati,
ma non misurano due argmin isolati sugli stessi input. Rappresentazioni,
API e parallelismo differiscono a loro volta. Non dimostrano un confronto
appaiato, una causa attribuibile al solo compilatore o un guadagno di 100×
dell'applicazione completa.

## F40–F70: protocollo, frontiere e rumore

| Identificatori | Risultato e condizioni |
|---|---|
| F40–F43 | Ridurre l'output riduce l'informazione esposta, ma conserva un oracolo applicativo. Query compatta, prototipo a tre ruoli e scaling fino a N1024 di quella revisione non validano il comparatore invalido né il contratto exact-ID corrente. |
| F44–F49 | GhostFaceNet e fusione multi-frame hanno verifiche biometriche specifiche. Parametri, ponti e codifiche hanno prove distinte. Le latenze F49 appartengono al servizio pre-fold: i suoi casi facili non provano la frontiera riparata successivamente. |
| F50–F55 | Rumore PBS, codifica dell'uscita e rumore composto sono obblighi diversi. La primitiva a galleria GGSW cifrata riesce senza validare la decisione completa; il torneo con circuit bootstrapping provato non è un argmin esatto. Z-norm ha effetti biometrici circoscritti. |
| F56–F61 | Il bound e i controlli della galleria risolvono l'overflow nel dominio verificato, non l'origine biometrica di un probe arbitrario. Cascata, packing e multi-bit hanno esiti propri; l'output minimale non chiude gli attacchi applicativi. |
| F62–F67 | Confronti di sicurezza e prestazioni richiedono parametri e funzioni comparabili. Il contributo del progetto è implementazione, integrazione e valutazione, senza pretesa di priorità. Le negative di ammortizzazione/scaling sono circoscritte; CKKS deve includere i rifiuti open-set. |
| F68–F70 | L'audit invalida la soglia diretta, ritira il percorso residuale da 14 PBS e conserva il fallback da 9. Periodic-fold ripara empiricamente la frontiera con tre PBS/template; è ancora distinto dal successivo exact-ID e da una prova di probabilità globale. |

## F71–F83: selezione esatta e riduzione del costo

| Identificatori | Risultato e condizioni |
|---|---|
| F71–F73 | F71 stabilisce primo minimo+soglia del vincitore+0/ID. A28 elimina 508 KS a N127; A29 riduce il tempo dell'8,876% nel suo confronto appaiato. La singola LWE e la specifica del servizio di allora non sono il formato attuale a tre cifre. |
| F74–F76 | A33 viene integrato e poi promosso con 13,734% nel confronto A29/A33; A38 dà 13,828% nel proprio confronto. Le suite precedenti da 632 casi appartengono alle revisioni indicate nelle fonti, senza trasferimento alle altre revisioni. |
| F77–F80 | A41 passa 29/29 casi con due LWE p16; A44 passa 120/120 ma conserva il bound raw condizionale. A62 materializza A50+A53 con 3390 BR e 142/142 casi di componente. A64 è un progetto statico checked, non un circuito compilato o misurato. |
| F81 | A73 confronta A62/A66, non A23/A66: 22,2018% di miglioramento a 16 thread e 2,2628% di peggioramento a un thread. Il conteggio A23→A66 e le suite 632 sono fatti separati. I successivi Head/PFKS, BGV e common-mask proseguono i rispettivi rami senza rendere valide le costruzioni fallite. |
| F82 | Domini A124 eseguiti: N64 `[-1019,2317]`, N127/128 `[-1019,2329]`. BR di estrazione/selezione/scan a N128: 1664+1615+136=3415; a N127: 1651+1603+136=3390. Conteggi e tagli sovrapposti non sono risparmi sommabili. Il margine nominale p128 non prova la coda del circuito raw. B8.1/B9 richiedono una verifica del rumore delle correzioni; B5.1 deve preservare l'ingresso booleano dello scan, come precisato sotto. |
| F83 | A124 termina 21 celle, 294 uscite corrette e 210 misure. L'audit successivo classifica 8 celle valide ai controlli pre/post, 12 con attività post elevata e una senza metadati driver. Il PASS originario non richiedeva quel successivo criterio post. Nessun monitor interno alla cella prova isolamento continuo; thread, carico e rapporti di stadio non identificano causalmente contributi degli E-core, copie, KS o un tetto allo scheduler. |

### F82: rumore delle correzioni e ingresso dello scan

Le proposte B8.1/B9 del [diario F82](diario/f71-f83.md#f82) devono distinguere
il piccolo errore della cifratura iniziale dall'errore delle **correzioni
prodotte dai PBS**, poi amplificate di un fattore 256. Il
[rapporto sullo split](../../experiments/14_pipeline_tfhe_rs/results/argmin_bucket_bits_exact_split_2026-09-01.md)
documenta fallimenti anche con input non centrati: il doppio canale non
rispondeva soltanto a un problema di centratura. Quei fallimenti non
confutano ogni variante con parametri o costruzione diversi; richiedono
una verifica separata del rumore delle correzioni prima di parlare di
rimozione sicura del canale basso.

B5.1 propone un solo refresh dopo il livello 6, invece dei livelli 3 e 7.
Questo cambiamento, applicato al consumatore A53 invariato, può perdere la
canonicalizzazione booleana finale. Un controesempio statico usa due
candidati con la stessa categoria alta e byte bassi **[2,0]**: dopo il
refresh sul bit 1 gli stati sono **[0,1]**; sul bit 0 la ricorrenza
`stato + candidato_zero - esiste_zero` dà **[-1,1]**. La somma del gruppo
è quindi 0 e l'OR dello scan indica erroneamente che non c'è un candidato.
Il refresh finale ripristina **[0,1]**, con somma 1.

La proposta deve conservare quella canonicalizzazione o dimostrare un
consumatore diverso. Il limite L1≤15 e il parametro nominale p128 non provano
che l'ingresso sia booleano. Questo è un limite semantico della proposta
B5.1; non è un errore osservato nel runtime mantenuto né una prova FHE.
Tagli e tempi proposti vanno ricalcolati solo dopo aver verificato la
composizione; i conteggi «PBS equivalenti» fra articoli restano modelli di
costo, non prestazioni appaiate o una frontiera di velocità dimostrata.
