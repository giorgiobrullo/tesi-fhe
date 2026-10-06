# Riuso del GLWE: risultato dell’analisi

Estratto documentale della campagna, conservato il 5 ottobre 2026.
Non è una nuova esecuzione. Fonte e trasformazione nel [manifest](PROVENANCE.json).

# Conservare il GLWE attuale non elimina le PFKS successive

Nel percorso mantenuto, il selettore prepara la differenza fra candidato destro e sinistro in un polinomio cifrato GLWE. Dopo la rotazione estrae le cifre della correzione; soltanto allora aggiunge le cifre del candidato sinistro, ottenendo il vincitore. Il polinomio interno conservabile contiene quindi una correzione, non il vincitore completo.

Anche la disposizione conta: la PFKS successiva costruisce finestre fisse, mentre il polinomio appena ruotato ha posizioni dipendenti dal controllo cifrato. La correttezza delle cifre estratte non rende intercambiabile l’intero polinomio. La rigenerazione del controllo non normalizza questo payload.

Root e revisore indipendente hanno verificato il percorso attivo Repack → smallcuts → selector_parallel e il fallback seriale: entrambi presentano lo stesso ostacolo. Cinque file attuali, con la quinta lettura limitata al dispatch effettivo, sono identificati in SOURCE_BINDING.json e source/OUTPUT_ROUTE.md. Il controllo scritto delle idee precedenti è limitato a cinque contesti pertinenti e non costituisce una ricerca universale di novità.

Conclusione: non implementare un semplice riuso dell’accumulatore con salto delle PFKS; violerebbe l’interfaccia corrente. Una nuova rappresentazione che conservi l’intero vincitore potrebbe invece essere studiata, ma deve definire costruzione delle foglie, layout, cifre pubbliche, dominio della chiave e rumore prima di contare operazioni risparmiate. Non è una dimostrazione di impossibilità per ogni torneo GLWE.

Questa fase è solo statica: nessun modello, compilazione, chiave, esecuzione FHE o tempo nuovo. Runtime mantenuto e grafici invariati; R123 e W134/protetti4 preservati.
