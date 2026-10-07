# Profilo di un confronto — 4 ottobre 2026

Una copia del runtime 1.8.1 aggiunge timer sul primo merge del primo livello,
con N120/D512/T273 e 16 thread su M4 Max. Le operazioni FHE non cambiano.
Il runtime mantenuto rimane invariato. La copia ha un nuovo binding,
un binario compilato con Rust 1.98.1 e una nuova famiglia di chiavi.

Un servizio esegue quattro query: warmup Einstein, misura Einstein,
misura Curie, misura Turing. I tre input sono i vettori congelati già
calcolati da foto di iscrizione. Ogni output è decifrato e confrontato
con il primo minimo intero e la soglia inclusiva del vincitore.
Nessuna query è esclusa; i controlli offline del driver precedono l'avvio.

Il nodo selezionato confronta i candidati ID1/ID2 e trasferisce quattro
cifre in un gruppo. I 60 merge del primo livello possono procedere
in parallelo; all'interno di questo nodo confronto e selezione sono
sequenziali sul medesimo worker. I cinque intervalli sono disgiunti.
Packing/rotazione comprende la blind rotation; il suo tempo non misura
solo copie e packing. Il residuo è node meno la somma dei cinque timer.

Filtrare phase=measured nel CSV. Le percentuali sono durata della fase /
durata del nodo per ciascuna query; il report riporta soltanto i tre casi
e i loro intervalli osservati. Non moltiplicare i tempi per60 o aggiungerli
al torneo: il nodo è già compreso nel primo livello e nel torneo.

Le durate includono ritardi di scheduling sul worker osservato. Una
famiglia e tre misure non stimano il costo medio dei60merge, un intervallo
di confidenza, gli errori rari o l'accuratezza biometrica. Il tempo totale
della richiesta è conservato ma non è appaiato al confronto precedente:
nessuna accelerazione segue dal fatto che sia qui più basso.

SUMMARY.json contiene configurazione, esiti, scope e hash. Il CSV conserva
anche il warmup e il JSON completo del profilo. Header originali, cifrati
e chiavi restano nell'archivio locale tmp/current-merge-profile-20261004.
