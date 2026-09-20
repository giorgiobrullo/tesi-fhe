# Normalizzatore, composizione e demo

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati al 9 settembre 2026. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F88 - Normalizzatore condiviso: risparmio e rumore osservato

La variante carry-v2 deriva anche una cifra bassa dalla rotazione che produce
il riporto, trasformando linearmente l'intero ciphertext. Il controllo esteso
copre tutti i 4096 input, quattro modalità e tre chiavi: 49.152 estrazioni,
oltre a 384 selezioni successive. Sono verificate 592.128 fasi LWE e oltre
100 milioni di coefficienti GLWE. L'errore massimo delle cifre derivate usa
il 23,28% e l'11,74% del margine; i limiti conservativi condizionati ai vettori
salvati arrivano al 67,75% e al 31,74%. Non sono code di probabilità per nuove
chiavi o per il circuito completo.

Il primo confronto completo dà 12,39% su una famiglia e 24 coppie misurate,
tutte favorevoli. La successiva composizione riusa esattamente questo
normalizzatore: quel guadagno è già incorporato. Le mappe fuse dello stesso
normalizzatore passano 130 uscite e 390 fasi, ma sono circa 0,14% più lente,
con 9/24 coppie favorevoli; nessun risparmio dimostrato per quella variante.
Il primo controllo troppo restrittivo di una rappresentazione equivalente e
la sua correzione restano conservati.

Riferimenti: [esperimento 20](../../experiments/20_normalizzatori_carry/README.md),
[riepilogo dei risultati](../../experiments/20_normalizzatori_carry/RESULTS.json),
[mappe di errore](../../experiments/20_normalizzatori_carry/evidence/NORMALIZER_ERROR_MAPS.md).

## F89 - Parallelismo, costanti pubbliche e confronti delle combinazioni

La campagna notturna conferma i confronti classici paralleli: 6,51% su due
nuove chiavi, 56/56 coppie favorevoli. Nel confronto diretto G4 non aggiunge
un vantaggio al classico in quelle condizioni. La prima combinazione di
normalizzatore, confronto parallelo e soglie pubbliche dà 19,24% nella
seconda famiglia, 28/28 coppie favorevoli, mediane 2,324/1,820 secondi.
Il primo blocco, distinto dalla conferma, aveva dato 20,82%. Questi riferimenti
sperimentali avevano già entrambi i tagli sulle cifre ID; le percentuali non
misurano l'effetto di quei tagli rispetto alla demo precedente.

La conferma del 19,24% è geometrica. Il diverso estimatore mediano dà 18,37%,
con intervallo di ricampionamento 95% 17,81–19,00%, condizionato ai casi e alle
chiavi provate. Tale intervallo non è un intervallo per il 19,24% geometrico
né per tutte le chiavi future. Fra qualifica e timing le due famiglie della
combinazione passano 672 uscite e 2016 fasi terminali.

La successiva campagna diurna verifica componenti ulteriori contro i propri
riferimenti, già dotati del normalizzatore, parallelismo classico, soglie
pubbliche e tagli ID:

| Variante | Riduzione nelle due famiglie di conferma, screening escluso | Coppie favorevoli |
|---|---:|---:|
| Parallelismo interno del selettore | 3,642326% | 44/56 |
| Propagazione di cifre/costanti pubbliche | 4,087594% | 46/56 |
| Selezione G4 dinamica | 2,323432% | 45/56 |
| Attraversamento condiviso delle chiavi PFKS | Screening 0,991443% più lento; nessuna famiglia aggiuntiva | 11/28 nello screening |

Le quattro prove diurne passano 1716 uscite, 5148 fasi terminali e 796
uguaglianze complete. Sono controlli correlati, non altrettanti campioni
indipendenti. Le 840 finestre di timing conservano carico alto, 786 anche
attribuzione del carico parzialmente incerta. I guadagni dei tre componenti hanno riferimenti separati;
la selezione finale richiede il confronto della combinazione in F90.

Riferimenti: [esperimento 21](../../experiments/21_costanti_pubbliche_parallelismo/README.md),
[composizione notturna](../../experiments/20_normalizzatori_carry/evidence/night-composition.json),
[conferma classica](../../experiments/20_normalizzatori_carry/evidence/classic-confirmation.json),
[riepilogo della campagna diurna](../../experiments/21_costanti_pubbliche_parallelismo/RESULTS.json).

## F90 - Composizione selezionata e miglioramento della demo

Il confronto di composizione su 96 terne di conferma e due nuove famiglie
seleziona B, `public_parallel`: 6,596842% rispetto al riferimento A della
stessa campagna. Aggiungere G4 rende C 0,699159% più lento di B e richiede
296.404.088 byte di chiavi serializzate aggiuntive. La demo qualificata
usa B senza G4. L'integrazione è quindi completata. I guadagni G4
osservati in precedenza riguardano confronti con riferimenti diversi.

Il confronto diretto fra i servizi precedente e nuovo include una prima
famiglia e una distinta conferma, fissate prima della misura iniziale:

| Misura HTTP appaiata | Conferma, riduzione geometrica | Coppie favorevoli | Prima famiglia, separata |
|---|---:|---:|---:|
| Backend, otto scene N128/129 | 24,710555% | 32/32 | 25,295668% |
| Richiesta completa con immagini, due scene N129/T273 | 28,439223% | 12/12 | 27,406907% |

Le mediane delle richieste con immagini nella conferma sono 2,819970 e
2,011201 secondi; quelle backend 2,5103 e 1,8668 secondi. Passano 288
uscite complete e 864 fasi terminali, oltre a quattro controlli vuoti.
Le scene sono sintetiche; la cattura della telecamera è esclusa. Tutte le
288 finestre conservano carico alto; in 237 l’attribuzione ai processi è
parzialmente incerta. La copertura campionata è completa e nessun campione
è stato rimosso. La prova non misura l'accuratezza biometrica o la latenza di
una galleria personale, né dimostra isolamento continuo o una probabilità
formale di fallimento.
Backend, immagini e componenti sono misure distinte: i relativi vantaggi
non sono incrementi da sommare.

Riferimenti: [esperimento 22](../../experiments/22_demo_composita/README.md),
[riepilogo della selezione](../../experiments/22_demo_composita/RESULTS.json) e
[rapporto originale del confronto HTTP](../../experiments/22_demo_composita/evidence/ORIGINAL_SERVICE_RESULTS.md).
