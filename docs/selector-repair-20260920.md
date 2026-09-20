# Selettore: origine del guasto, correzione e costo

Aggiornamento del 20 settembre 2026. La baseline corrente è
[pack4](../PACK4_VALIDATION.md), con selettore corretto e gruppi fino a quattro
payload. Questa nota accompagna il [percorso della tesi](percorso-sperimentale-20260920.md)
e il [catalogo dei risultati](../findings.md). Le campagne storiche e i loro
identificatori restano conservati; la documentazione non modifica il runtime.

## Dalla geometria stretta alla diagnosi

| Data | Evidenza e portata |
|---|---|
| 6 settembre | Nella linea che porta a M viene eliminato il refresh della combinazione ternaria e adottato il packing con offset 0/41/82 e margine ±20. È la prima introduzione strutturale rintracciata. |
| 6 settembre, variante senza correzione della media | Uno scarto −23 supera il supporto; i payload osservati sono ancora corretti. Non è il caso ID75. |
| 6 settembre, successiva variante M | La correzione della media riduce una componente dello scarto, mantenendo la finestra ±20. Passano i test sulle famiglie osservate. |
| 9 settembre | Primo output errato rintracciato nella linea con correzione della media: ID75 invece di ID1. |
| 19 settembre, diagnosi della capsula storica | Le 127 estrazioni Head e i ternari passano. Nel nodo ID75/ID76 il controllo raggiunge 341, fuori dal supporto 300…340. Spostare quel solo controllo da 341 a 340 ripristina ID1 nel torneo. |
| 19 settembre, replay della baseline pre-fix più recente | La stessa capsula restituisce ID1, con indirizzo 318 nel nodo interessato. Il rischio geometrico persiste nei sorgenti, ma questa prova non osserva un errore della versione più recente. |
| 19–20 settembre | La correzione B del selettore rigenera il controllo e amplia il supporto; pack4 ne conserva il refresh e i margini, riducendo i gruppi payload. Entrambe ricevono verifiche separate. |

Le date identificano i primi artefatti rintracciati, non un commit introduttivo
accertato o il primo errore possibile. La
[cronologia documentata](selector-repair/INTRODUCTION_HISTORY.md) conserva
fonti e hash dei record locali, anche quando il dettaglio non è incluso nel
clone pubblico. Il cambiamento degli intermedi fra versioni non è attribuito
causalmente a una singola ottimizzazione.

## Correzione B e successivo pack4

La [correzione B del selettore](../SELECTOR_REPAIR_VALIDATION.md) applica
KS e correzione pubblica della media, rigenera il controllo verso 4/12 con
un bootstrap ordinario, poi applica una seconda KS con correzione della media.
La finestra PFKS è centrata a 1536, con raggio 127 e offset 0/256/512.
Rispetto al selettore stretto aggiunge una blind rotation, una conversione
di chiave e un campione estratto per selezione effettiva.

Pack4 conserva il refresh e riunisce score e cifre variabili di ID/soglia
in gruppi fino a quattro, agli offset 0/256/512/768. La funzione e i byte PFKS
coincidono nei due bracci correzione B/pack4; il diverso accumulatore richiede
comunque una verifica FHE propria. Il quinto payload consecutivo non è ammesso.
Restano i margini condizionali ±63 prima del refresh e ±127 dopo la seconda
KS, primo minimo, pareggi stabili, soglia del vincitore e risposta a tre cifre.
La geometria è una garanzia condizionata sui residui, non una probabilità
di fallimento già dimostrata per il circuito composto.

Il test storico del singolo nodo conserva il controllo a 341: il refresh
produce 12 e il secondo controllo raggiunge 1534. Il selettore sceglie
correttamente i **sei payload del candidato destro ID76: tre cifre dello score
e tre dell'ID**. Nel replay del torneo completo il risultato atteso è invece
**ID1**, restituito sia dalla correzione B sia da pack4. La funzione di refresh
è identica; la geometria a quattro payload è verificata separatamente.
Questo replay non è una nuova famiglia indipendente o una misura di latenza.

La campagna pack4 comprende tre famiglie nuove e 432 chiamate corrette,
con 1.296 LWE finali verificate indipendentemente. Gli input GLWE sono
vincolati dal codice e dagli hash, non ridecifrati integralmente da quel lettore.
Passano 83 test core, 36 del servizio, un test fixture e 32 controlli Python;
quattro test FHE storici restano ignorati. Tre roundtrip CLI/HTTP danno 1/0/0
e il vecchio envelope W287 è rifiutato. La PFKS interna della correzione B è
compatibile, mentre l'envelope dipende dalla nuova identità di circuito.
La [guida di esecuzione](../BUILD_AND_RUN.md) descrive la consegna corrente.

## Tre confronti, tre campioni distinti

| Confronto | Tempo relativo appaiato del core | Interpretazione |
|---|---:|---|
| Correzione B / originale pre-fix | +13,17% | Costo storico della prima correzione |
| Pack4 / correzione B | −4,7438% | Risparmio della successiva campagna pack4 |
| Pack4 / originale pre-fix | +6,8737456% | Costo residuo misurato direttamente |

Il [confronto diretto](selector-direct-cost-20260920.md) usa tre famiglie B
riusate, 18 coppie gate, 18 warmup e 72 misurate, di cui 60 primarie. Entrambe
le versioni passano: **216 chiamate complessive e 648 LWE finali** verificate
indipendentemente. L'originale coincide per byte con le sue uscite archiviate;
fra le versioni si confronta l'esito decifrato. L'intervallo bootstrap al 95%
del costo è **[+6,21%; +7,52%]**, condizionato alle famiglie e ai casi osservati;
la differenza mediana appaiata è **0,1207 s per query**. Carico esterno è
segnalato in tutte le 144 chiamate misurate, con contabilità CPU parzialmente
incerta in 67; nessuna misura è esclusa. Il timer riguarda il core, non HTTP
o l'intera demo. Gli input salvati sono vincolati per hash, senza nuova
decifratura GLWE completa.

I rapporti delle campagne separate non vengono moltiplicati. Il costo diretto
sostituisce la stima indicativa di circa +7,8%, conservando le misure storiche.
Le etichette B della composizione `public_parallel` e del controllo DAG con
barriera indicano altre varianti storiche, non questa correzione del selettore.

## Approfondimenti conclusi e limiti aperti

I quattro approfondimenti sul costo sono conclusi: nessun refresh duplicato
individuato; nessuna copertura qualificata per la guardia pubblica esaminata;
screening di una sovrapposizione refresh/PFKS; misura diretta del costo finale.
La guardia non passa su 127+127 controlli di due programmi sulla stessa
capsula, neppure assumendo errore precedente nullo. Il fallimento di una
condizione sufficiente non prova un errore o un'impossibilità generale.
La sovrapposizione conserva le uscite su 96 query, ma osserva +0,49% sui
cinque scenari primari e non raggiunge il criterio temporale. Una sola
famiglia riusata e il carico esterno limitano lo screening. Il candidato
non è adottato; il runtime corrente resta pack4.

Le [due rimisurazioni dei grafici](percorso-sperimentale-20260920.md) usano
campagne e circuiti propri. Nessuna delle percentuali sopra viene applicata
ai loro punti. Le vecchie risposte corrette restano tali; la diagnosi impone
di conservare il limite del selettore stretto insieme ai risultati positivi.
Restano aperti il limite formale di fallimento composto, la generalizzazione
a nuove chiavi e input, circuit privacy e validazione biometrica. I test
non dimostrano correttezza universale o superiorità SOTA.
