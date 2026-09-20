# Refresh B e raggruppamento pack4

Il controllo originale subisce KS e mean-centering, una BR ordinaria con
corpo costante 4·Delta59, estrazione del coefficiente zero e addizione pubblica
8·Delta59. Seguono una seconda KS e una seconda correzione della media.
Il controllo risultante è condiviso fra i gruppi dei payload.

Il refresh richiede l'indirizzo effettivo entro ±63 dal centro del predicato
ternario. La selezione richiede ±127 intorno a 512 (sinistra) o 1536 (destra).
La funzione PFKS vale 1 nei coefficienti 1409…1663 e zero negli altri, con
estensione negaciclica. È lo stesso polinomio di B; W287 è diverso.

Il piano pubblico pack4 concatena le tre cifre dello score con le cifre ID e
soglia non costanti, quindi divide questa sequenza in gruppi di massimo quattro.
Gli offset locali sono 0/256/512/768. Non cambiano i payload omessi, il ripristino
delle costanti, il torneo adiacente, le code dispari o il confronto stabile.
Cinque lane non sono ammesse: producono alias anche al centro del controllo.

Per una selezione di p payload in g gruppi si contano 2 KS, g+1 BR, p PFKS e
p+1 estrazioni. Le due correzioni della media restano separate dall'addizione
pubblica 8·Delta59. Rispetto a B, ogni gruppo effettivamente eliminato risparmia
una BR e un gadget level; KS, PFKS ed estrazioni non cambiano. Una somma GLWE
aggiuntiva sostituisce quel gruppo. I contatori globali includono anche score,
confronti e terminali e dipendono dal piano pubblico effettivo.

La geometria conserva i margini di B, ma accumulare quattro payload cambia il
rumore dell'accumulatore rispetto a tre. La prova statica non dimostra la
correttezza rumorosa, la probabilità di fallimento o un vantaggio temporale.
I relativi esiti appartengono alla campagna e ai gate separati del root.

Questa delivery non modifica alcuna funzione matematica del core congelato.
La sola modifica Rust di produzione è l'identità `service::ID_CONTRACT`.
I moduli storici inattivi restano conservati e non acquistano una nuova qualifica.
G4 resta rifiutato. La compatibilità della PFKS interna non implica compatibilità
automatica di vecchi envelope legati ad altre identità di sorgente e circuito.
