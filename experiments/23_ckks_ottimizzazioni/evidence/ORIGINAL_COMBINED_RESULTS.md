# CKKS: combinazione misurata su tre chiavi nuove

Il confronto diretto riduce il tempo della query dell’**8,10%**: tutte le18
coppie misurate favoriscono la variante combinata. Le mediane passano da
**3,212 a2,948secondi**. Il riferimento e la variante usano la stessa cache
pubblica, chiave e query cifrata all’interno di ogni coppia.

| Famiglia nuova | Riduzione geometrica sulle coppie | Coppie più veloci |
|---|---:|---:|
|0|7,657%|6/6|
|1|8,034%|6/6|
|2|8,602%|6/6|
|Tutte|8,098%|18/18|

La combinazione condivide le riduzioni dell’input e di x² nei polinomi e
riusa la decomposizione delle rotazioni del calcolo dei punteggi. Il confronto
tra punteggi migliora del14,094% e la fase punteggi del9,763%. Layout e prodotto
restano vicini alla parità; l’uscita peggiora dell’1,035% in questa misura.
Questi valori vengono dalle stesse coppie; le percentuali degli esperimenti
separati non sono state sommate o moltiplicate.

Prima dei tempi passano18 uscite e45 uguaglianze complete dei cifrati nei
cinque stadi, comprese soglia inclusiva, scarti di una unità, parità e R4096.
Le tre famiglie temporali aggiungono48 uscite e24 uguaglianze complete finali,
con input invariato:66 uscite e69 uguaglianze in totale. Ogni famiglia temporale
ha due coppie iniziali escluse e sei misurate, con ordine alternato.

Resta carico esterno elevato e non completamente determinabile: circa2,18–2,31
core comparabili nelle tre famiglie. È quindi un risultato descrittivo sotto
carico, non una conferma a macchina libera né un tempo dell’app completa.
La correttezza riguarda i casi provati; non costituisce un limite formale alla
probabilità di fallimento.

Dati e verifiche: [risultato completo](COMBINED_THREE_KEY_RESULT.json),
[impronte degli artefatti](THREE_KEY_FREEZE.json), [piano](RUN_PLAN.json).
La successiva prova8/12/16 thread è una sorgente separata, ancora da eseguire.
