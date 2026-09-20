# Costo diretto del fix nella baseline corrente

Misura conclusa il 20 settembre 2026. **La baseline corretta con pack4 richiede
il 6,87% di tempo in più rispetto all'originale pre-fix del 19 settembre**, nel
confronto appaiato sui cinque scenari principali. La differenza mediana fra
i tempi di ciascuna coppia è **0,1207 secondi per query**. Questo è un confronto
diretto, con gli stessi input e chiavi di base, non il prodotto di percentuali
misurate in campagne diverse.

Il rapporto geometrico è **1,068737456**, con intervallo bootstrap al 95%
**[1,062058655; 1,075158509]**, cioè **+6,21%–+7,52%**, condizionato alle famiglie
e ai casi osservati. Le mediane marginali sono **1,701612 s per l'originale**
e **1,824226 s per pack4 corretto**; il loro rapporto non definisce il risultato
appaiato. Il timer riguarda il calcolo cifrato del core, non l'intera demo.

## Che cosa è stato confrontato

- Originale pre-fix: runtime congelato snapshot del 19 settembre, identificato nel protocollo pubblicato.
- Corretto: [runtime adottato](../runtime/README.md).
- Copie identiche di tutti i file, senza modifiche dei core; un solo binario
  contiene le due librerie. La variante di scheduling della fase 3 è esclusa.
- Tre famiglie B già disponibili, riusate con i loro input salvati. Per ciascuna
  famiglia ordinary e Head coincidono fra i due rami; cambiano le PFKS richieste
  dalle due funzioni del selettore. I componenti serializzati sono ricontrollati.
- Apple M4 Max, pool fisso di 16 thread, TFHE 1.7.0, Rust 1.98.0, profilo opt3,
  un'unità di code generation, senza LTO/PGO o feature opzionali del core.
  Piano FFT Dif4/base1024 installato prima della deserializzazione.

Le famiglie erano già state generate nella campagna B: non sono tre nuove
repliche indipendenti della precedente evidenza. Il protocollo ha fissato i
casi prima dell'esecuzione di questo confronto; nessuna selezione successiva
sui tempi o sulla correttezza.

## Correttezza e protocollo temporale

I tre gate precedono tutte le misure: 18 coppie, 36 query. Seguono 18 coppie
di riscaldamento e 72 misurate, quattro per ciascuna combinazione famiglia/scena.
L'ordine è bilanciato AB/BA, due volte per verso in ogni cella. I cinque scenari
principali producono **60 coppie misurate**; il controllo secondario ne produce 12.

**Tutte le 216 esecuzioni complessive dei due rami sono corrette.** Il lettore indipendente
verifica 648 LWE finali, cifre canoniche, ID atteso e distanza stretta dalla mezza
cella. L'originale riproduce esattamente i byte delle sue uscite archiviate.
Fra i due circuiti diversi si verifica l'esito decifrato, senza richiedere che
i cifrati coincidano. I conteggi delle operazioni e i percorsi attivi coincidono
con i modelli pubblici indipendenti. Gli input GLWE sono vincolati per hash al
corpus salvato, senza una nuova decifratura completa.

Il timer include la valutazione cifrata, il piano interno e le allocazioni;
esclude caricamento/generazione delle chiavi, cifratura degli input, piano
esterno, decifratura, serializzazione, hashing e HTTP. Nessuna coppia misurata
è scartata. Il protocollo avrebbe conservato anche eventuali errori dell'originale,
riportandoli separatamente; qui non se ne osservano.

## Risultati per scenario

Ogni riga contiene 12 coppie, distribuite sulle tre famiglie. Le prime cinque
contribuiscono al risultato principale; il controllo secondario è separato.

| Scenario | Costo relativo appaiato | Mediana originale | Mediana corretto |
|---|---:|---:|---:|
| N127, soglia generale | +7.11% | 1.673 s | 1.777 s |
| N128, percorso aligned | +6.33% | 1.688 s | 1.797 s |
| N129, soglie alternate | +9.64% | 1.792 s | 1.968 s |
| N128, soglie a blocchi | +6.67% | 1.688 s | 1.815 s |
| N225, soglia generale | +4.68% | 2.844 s | 2.970 s |
| N128, controllo secondario senza vantaggio anchor | +5.81% | 1.694 s | 1.804 s |

I costi primari per famiglia sono rispettivamente +6,82%, +6,49% e +7,32%.
Il controllo secondario misura +5,81%, con intervallo condizionato
[+4,49%; +6,96%]. Questi risultati descrivono circuiti e casi fissati, non
un costo uniforme per qualsiasi galleria o distribuzione degli input.

## Limiti della misura e rapporto con i risultati precedenti

Tutte le 144 query misurate hanno un indicatore di carico esterno oltre il 20%
di un core. Per 67 finestre la contabilità CPU è parzialmente incerta a causa
dei processi comparsi o terminati; la copertura temporale è completa in tutte.
I dati restano inclusi. Il bootstrap usa 10.000 ricampionamenti delle coppie
entro ciascuna cella famiglia/scena, seed 20260919, senza ricampionare le famiglie.
L'intervallo non copre nuove chiavi, altre macchine, popolazioni di input o effetti
sistematici del carico. Non si dichiara isolamento continuo della macchina.

Il **+13,17%** rimane il risultato storico B/pre-fix; il **−4,7438%** rimane quello
pack4/B. La loro combinazione indicativa di circa +7,8% non era una misura diretta.
Per il costo residuo della baseline corrente si usa ora **+6,87%**, con il metodo
e i limiti di questa campagna. Non si ricava da queste campagne separate una
nuova percentuale causale di risparmio attribuibile a pack4.

Anche l'originale passa tutti i casi di questo confronto. Ciò non elimina il
rischio della finestra stretta diagnosticato nella linea storica, né misura
la sua probabilità. Queste prove finali non certificano ogni intermedio o un
limite formale di fallimento del circuito composto. La baseline adottata rimane
quella corretta; non occorrono modifiche al runtime.

I grafici della progressione e CKKS/TFHE conservano le loro campagne già
rimisurate: usano riferimenti e circuiti distinti. Il nuovo costo non viene
applicato come fattore di correzione ai loro punti. Gli archivi e i pacchetti
congelati restano invariati.

## Evidenza e riproducibilità

Il [pacchetto pubblico delle evidenze](evidence/selector-direct-cost-20260920/README.md)
include tutte le 72 coppie misurate, il protocollo, i sei riepiloghi degli audit,
i controlli aggregati del carico e l'estimatore originale. Consente di ricalcolare
statistiche e intervalli, senza nuove prove FHE. Le copie pubbliche distinguono
le proprie impronte da quelle degli originali congelati.

Chiavi, cifrati e inventari dei processi restano nell'archivio locale della
campagna. I JSON pubblicati attestano gli audit già eseguiti; non consentono
da soli di ripetere le decifrazioni. Il controllo separato che lega il riepilogo
ai journal verificati è passato; era fissato prima dei tempi, dopo il freeze
principale. Nessuna misura o sorgente congelata è stata riscritta.

I quattro passi autorizzati sono conclusi: analisi delle ridondanze, guardia
pubblica, candidato di scheduling, confronto diretto. La guardia non qualifica
nessuno dei 254 controlli esaminati, senza dimostrare un'impossibilità generale.
La sovrapposizione refresh/PFKS passa 96 query e 288 LWE finali, ma osserva
+0,4874% sui 20 confronti primari di una sola famiglia riusata: non è adottata.
Tutte le 48 query misurate segnalano carico esterno, 32 hanno contabilità incerta;
il risultato non prova che questa pianificazione sia sempre più lenta.
La baseline corretta e le due campagne dei grafici restano invariate.
