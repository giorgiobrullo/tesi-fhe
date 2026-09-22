# Implicazioni e cronologia delle revisioni

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Fonti verificate il 19 settembre 2026; cronologia aggiornata il 22 settembre.
Le prove A33/A38 del 2 settembre sono concluse nei report conservati, superando
il precedente stato editoriale «A29 corrente, A33 da verificare». Il runtime
mantenuto è la successiva composizione Head/PFKS con selettore corretto,
anchor e pack4 adottata il 20 settembre.

## Precedenti e contributo

Argmin, selezione di label, top-k e nearest-ID protetto hanno precedenti.
Erkin e Sadeghi anticipano la famiglia minimo seguito da soglia globale;
regola al bordo e tie-break vanno verificati nel rispettivo protocollo.
Cong e i lavori TFHE successivi mostrano che query cifrata con database in
chiaro non è una nuova architettura. Le [schede dei sistemi](sistemi.md)
precisano le funzioni realmente restituite.

Un solo bit di membership comunica una funzione diversa da un'identità;
non segue automaticamente un minor costo del protocollo o una garanzia di
minor informazione nell'intero transcript. Nel contratto locale, prima si
sceglie il minimo e poi si verifica `T[k]`: un candidato più lontano con una
soglia permissiva non salva il vincitore rifiutato. La
[scheda del contratto](contratto-e-schemi.md#punteggio-soglia-ed-esattezza)
distingue questa semantica dalla privacy contro il possessore della chiave
e dagli attacchi a query ripetute.

Il contributo sostenuto dalle prove è la costruzione e valutazione della
pipeline su interi bounded: rappresentazione, estrazione, selezione,
trasporto di identità/soglia, adattamento delle primitive e composizione dei
miglioramenti. La [genealogia delle primitive](primitive-e-codesign.md)
attribuisce multi-output, Head, correzione media, packing e Tetris ai lavori
corrispondenti. La loro integrazione non costituisce una nuova primitiva.

## Dalle revisioni iniziali al runtime mantenuto

| Tappa | Stato documentato | Limite dell'affermazione |
|---|---|---|
| A28/A29, estrazione e multi-output | Confronti e suite storiche conservati | La specifica integrazione mixed-scale è oggetto di studio; multi-output e blind rotation condivisa hanno precedenti. |
| A33, specializzazione residuo/flag | [Suite primaria](../../benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.md), [servizio Docker](../../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md) e [coppie A29/A33](../../benchmark/results/fhe_digiface_exact_paired_a29_a33_2026-09-02.md) completati | Il vecchio stato «in attesa dei gate» è superato. I 632 casi corretti sono della revisione e della chiave indicate. |
| A38, ulteriore riduzione | [Suite primaria](../../benchmark/results/fhe_digiface_exact_primary_a38_2026-09-02.md) e [confronto A33/A38](../../benchmark/results/fhe_digiface_exact_paired_a33_a38_2026-09-02.md) completati | Non trasferire suite e contabilità del rumore ai circuiti successivi. |
| Head/PFKS M e prime estensioni | [Pacchetti 17–18](../../experiments/README.md): core, servizio, scaling e soglie miste | Il primo servizio M ha due cifre; l'estensione successiva ne usa tre. Taglie e chiavi restano quelle di ogni campagna. |
| Composizione pubblica/parallela | [Pacchetto 22](../../experiments/22_demo_composita/README.md): confronto di core e servizio | G4 è escluso dopo il confronto della composizione, pur avendo un precedente risultato favorevole di componente. |
| Campagna comune del 9 settembre | [Dodici versioni in due contratti](../risultati/campagna-comune.md) | Non confrontare velocità attraverso il cambio N8/D64 → N127/D512. Il caso errato di Head generale resta visibile. |
| Revisione del 18 settembre | [Verifiche di quella revisione](../runtime-verification.md) | Refactor con nuove identità; le sue prove non qualificano automaticamente le modifiche successive. |
| Selettore corretto e pack4 del 20 settembre | [Diagnosi](../selector-repair-20260920.md), [verifica pack4](../validazione/PACK4_VALIDATION.md) e [runtime mantenuto](../../runtime/README.md) | Il refresh corregge il meccanismo del guasto storico; la qualifica empirica non è un limite formale di fallimento composto. |
| Campagne rimisurate del 20 settembre | [Progressione e confronto CKKS/TFHE](../percorso-sperimentale-20260920.md#risultati-confrontabili), [costo diretto del fix](../selector-direct-cost-20260920.md) | Il finale del grafico, il TFHE del confronto CKKS e la demo anchor/pack4 sono circuiti distinti. Nessuna percentuale si trasferisce fra queste campagne. |

L'[accounting A33](../../benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.md)
va letto con le sue premesse condizionali. Il completamento dei gate di
correttezza o del servizio non chiude la probabilità di fallimento del
circuito composto. La successiva diagnosi ha localizzato il caso storico
ID75 nel selettore, con le 127 estrazioni Head corrette: la correzione del
meccanismo osservato non fornisce da sola una probabilità di errore su nuove chiavi.

## Come confrontare le alternative

Il packing CKKS può ridurre il costo degli score su grandi gallerie; il
vantaggio di un sistema che consegna score al client o a un key server
comprende una scelta di protocollo diversa. Il [CKKS discreto](ckks-discreto.md)
impedisce inoltre di trattare l'approssimazione come impossibilità generale
di ottenere decisioni discrete. Servono dominio, margine, rappresentazione
dell'ID e regole al bordo verificati per la costruzione concreta.

Gli esiti negativi di common-mask, Tetris o scheduling chiudono le costruzioni
provate nelle rispettive condizioni. Non sono teoremi di impossibilità.
I [risultati delle alternative](../risultati/alternative.md) conservano
riferimenti e condizioni; le regole di una successiva conferma non riscrivono
quelle dello screening.

Il [percorso sperimentale](../percorso-sperimentale-20260920.md)
permette di citare ogni risultato con versione, ambito e limite. La ricerca
bibliografica è datata e documentata, non esaustiva né una verifica di
brevettabilità o libertà di attuazione.
