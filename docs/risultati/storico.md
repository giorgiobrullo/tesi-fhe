# Risultati storici e correzioni

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati storici al 9 settembre 2026, con precisazioni editoriali del
22 settembre. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F0–F83 - Risultati storici e correzioni consolidate

Le [84 schede complete](diario/README.md) conservano tabelle, ragionamenti
e dettagli delle prove, con le correzioni successive indicate nel testo.
La tabella seguente riassume i principali risultati dei primi esperimenti, includendo
le correzioni emerse nelle prove successive. I formati e le prestazioni delle
versioni iniziali non descrivono automaticamente l'implementazione attuale.

| Identificatori | Risultato che rimane, con le correzioni successive |
|---|---|
| F0–F3 | Concrete è stato eseguito nativamente su macOS arm64. La galleria pubblica consente prodotti cifrato×chiaro e richiede la corretta espansione del punteggio; non elimina da sola i problemi del modello di minaccia. |
| F4–F10 | PCA e descrittori locali hanno prototipi e benchmark conservati. I risultati sui dataset semplici non si trasferiscono ai benchmark difficili o al riconoscimento open-set 1:N. |
| F11–F14 | Argmin+soglia è implementabile; un inputset di compilazione non è un dominio di sicurezza. Gli embedding CNN migliorano le prove biometriche rispetto ai descrittori precedenti; quantizzazione e protocollo vanno valutati separatamente. |
| F15–F19 | Profondità, taglia della galleria e dominio dei volti cambiano l'accuratezza osservata. I primi numeri con un solo seed sono circoscritti e rinviano alle successive verifiche multi-seed; nessun tetto universale di accuratezza è dimostrato. |
| F20–F24 | Sono state confrontate compressione degli embedding, argmin server e strategie a blocchi in Concrete. Funzione restituita, interazione e minaccia determinano se un confronto preserva il contratto. |
| F25–F28 | Il test Concrete su Tesla T4 e i tornei/controlli a soglia hanno risultati propri. Non qualificano il successivo circuito custom GPU né dimostrano limiti generali di GPU o TFHE. La lettura della letteratura F26 è storica e corretta dagli audit successivi. |
| F29–F34 | Scaling DigiFace, divario di dominio e prodotto scalare leveled hanno misure nelle rispettive prove. F32 contiene una serie attribuita al Mac distinta dalla tabella del report 13. I rapporti storici di circa 100× confrontano input e perimetri temporali diversi: non sono un confronto appaiato né un'accelerazione dell'intera applicazione. Vedere la precisazione sotto. |
| F35–F39 | Il protocollo distingue identificazione e decisione di accesso. Gli otto bit sono una verifica in chiaro della quantizzazione; il torneo radix e la prima CKKS hanno benchmark separati. Il comparatore diretto a un PBS di F37 è invalidato vicino alla soglia da F68. |
| F40–F43 | Ridurre l'output riduce l'informazione esposta, ma conserva un oracolo applicativo. Query compatta, prototipo a tre ruoli e scaling storico fino a N1024 non validano il comparatore invalido né il contratto exact-ID corrente. |
| F44–F49 | GhostFaceNet e fusione multi-frame hanno verifiche biometriche specifiche. Parametri, ponti e codifiche hanno prove distinte. Le latenze del servizio pre-fold F49 restano storiche: i suoi casi facili non provano la frontiera riparata successivamente. |
| F50–F55 | Rumore PBS, codifica dell'uscita e rumore composto sono obblighi diversi. La primitiva a galleria GGSW cifrata riesce senza validare la decisione completa; il torneo con circuit bootstrapping provato non è un argmin esatto. Z-norm ha effetti biometrici circoscritti. |
| F56–F61 | Il bound e i controlli della galleria risolvono l'overflow nel dominio verificato, non l'origine biometrica di un probe arbitrario. Cascata, packing e multi-bit hanno esiti propri; l'output minimale non chiude gli attacchi applicativi. |
| F62–F67 | Confronti di sicurezza e prestazioni richiedono parametri e funzioni comparabili. Il contributo del progetto è implementazione, integrazione e valutazione, senza pretesa di priorità. Le negative di ammortizzazione/scaling sono circoscritte; CKKS deve includere i rifiuti open-set. |
| F68–F70 | L'audit invalida la soglia diretta, ritira il percorso residuale da 14 PBS e conserva il fallback da 9. Periodic-fold ripara empiricamente la frontiera con tre PBS/template; è ancora distinto dal successivo exact-ID e da una prova di probabilità globale. |
| F71–F73 | F71 stabilisce primo minimo+soglia del vincitore+0/ID. A28 elimina 508 KS a N127; A29 riduce il tempo dell'8,876% nel suo confronto appaiato. La singola LWE e la specifica del servizio di allora non sono il formato attuale a tre cifre. |
| F74–F76 | A33 viene integrato e poi promosso con 13,734% nel confronto A29/A33; A38 dà 13,828% nel proprio confronto. Le suite precedenti da 632 casi appartengono alle revisioni indicate nelle fonti, senza trasferimento alle revisioni nuove. |
| F77–F80 | A41 passa 29/29 casi con due LWE p16; A44 passa 120/120 ma conserva il bound raw condizionale. A62 materializza A50+A53 con 3390 BR e 142/142 casi di componente. A64 è un progetto statico checked, non un circuito compilato o misurato. |
| F81 | A73 confronta A62/A66, non A23/A66: 22,2018% di miglioramento a 16 thread e 2,2628% di peggioramento a un thread. Il conteggio A23→A66 e le suite 632 sono fatti separati. I successivi Head/PFKS, BGV e common-mask superano le vecchie descrizioni di stato senza rendere valide le vecchie costruzioni fallite. |
| F82 | Domini A124 eseguiti: N64 `[-1019,2317]`, N127/128 `[-1019,2329]`. BR di estrazione/selezione/scan a N128: 1664+1615+136=3415; a N127: 1651+1603+136=3390. Conteggi e tagli sovrapposti non sono risparmi sommabili. Il margine nominale p128 non prova la coda del circuito raw. B8.1/B9 richiedono una verifica del rumore delle correzioni; B5.1 deve preservare l'ingresso booleano dello scan, come precisato sotto. |
| F83 | A124 termina 21 celle, 294 uscite corrette e 210 misure. L'audit successivo classifica 8 celle valide ai controlli pre/post, 12 con attività post elevata e una senza metadati driver. Il PASS originario non richiedeva quel successivo criterio post. Nessun monitor interno alla cella prova isolamento continuo; thread, carico e rapporti di stadio non identificano causalmente contributi degli E-core, copie, KS o un tetto allo scheduler. |

## Precisazioni del 22 settembre 2026

Queste precisazioni prevalgono sulle formulazioni delle schede storiche e
sulle loro precedenti note di aggiornamento. Diario, dati e rapporti originali
rimangono conservati; non sono stati eseguiti nuovi benchmark FHE.

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
confondendo le due serie, come faceva la precedente nota del diario.

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
storica, non un nuovo errore osservato nel runtime corrente o una prova FHE.
Tagli e tempi proposti vanno ricalcolati solo dopo aver verificato la
composizione; i conteggi «PBS equivalenti» fra articoli restano modelli di
costo, non prestazioni appaiate o una frontiera di velocità dimostrata.
