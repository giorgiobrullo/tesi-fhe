# Gradino 06 - costo dell’argmin cifrato sul server

Le misure sono riepilogate in `findings.md`, F6.

## Obiettivo

Il passaggio modificato è **punteggi cifrati → scelta del vincitore →
controllo della soglia**. *Argmin* significa «posizione del valore minimo»:
fra i punteggi `[7, 3, 5]` sceglie il secondo candidato, mentre il minimo
è il valore `3`. Il server deve calcolare questa posizione senza decifrare
i punteggi.

Nel gradino 05 il client decifra tutti gli N punteggi ed esegue l'argmin.
Questo esperimento sposta la selezione sul server, sotto FHE, per evitare di
rilasciare le distanze rispetto all'intera galleria.

Il circuito con soglia restituisce l'indice del minimo e un bit che indica
se il vincitore rientra nella soglia. È un protocollo storico: la demo successiva
usa una codifica 0/ID che nasconde anche l'identità nei rifiuti.

La differenza di uscita è concreta: prima arrivavano tutti i punteggi,
qui arrivano due valori cifrati, `(indice, è_match)`. Il client continua
quindi a conoscere l'indice più vicino anche se `è_match` vale zero.
Il [confronto successivo 0/ID](../../docs/come-funziona-il-confronto.md)
non ha questa stessa uscita.

## Il costo

Un **PBS**, o programmable bootstrapping, permette di valutare una funzione
sul dato cifrato e rinnovarne la rappresentazione. I confronti e le selezioni
introducono questo lavoro aggiuntivo rispetto ai soli punteggi del gradino 05.
La curva seguente isola l'argmin su punteggi già cifrati: non misura
acquisizione della foto, estrazione del vettore o latenza della demo web.

`np.argmin` non è nativo in Concrete, quindi si costruisce con confronti
e selezioni cifrate che richiedono PBS, in
`core/matching.py::circuito_distanza_argmin`. Il costo è dominato
dalla larghezza in bit dei punteggi e raddoppia ~ad ogni bit:

| larghezza punteggi (N=10) | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

Nelle configurazioni provate il costo cresce rapidamente con la larghezza dei
punteggi. Il prototipo PCA produce punteggi di circa 14 bit; a piena larghezza
sono emerse anche difficoltà di compilazione con Concrete 2.11. Il solo calcolo
dei punteggi del gradino 05 richiede circa 31 ms/query. La scelta della precisione
va valutata insieme all'accuratezza e al dominio valido della tecnica usata.

## Soglia di rifiuto e inputset

Il circuito completo (`core/matching.py::circuito_distanza_argmin_soglia`) ritorna
`(indice, è_match)`: la distanza² vera del match (`val_min + ‖a‖²`) è confrontata con
la soglia, e `è_match=0` significa "nessun match" (impostore/sconosciuto rifiutato).
Verificato 10/10, coi rifiuti che si attivano.

In questo sorgente storico il confronto è stretto, `distanza² < soglia`.
Non va confuso con la soglia inclusiva sullo score del
[runtime attuale](../../runtime/README.md). L'**inputset** è l'insieme di
esempi che Concrete usa durante la compilazione per dedurre gli intervalli
dei valori. Svolge un ruolo diverso dalla galleria da riconoscere e non
prova che ogni futuro ingresso rientrerà in quegli intervalli.

Limite osservato (F11): Concrete non ha `argmin` nativo (solo `min/max/where`, quindi si
costruisce da `<` + select), e il rifiuto si attiva solo se l'inputset è
rappresentativo dei probe reali: con un inputset troppo stretto il confronto della
soglia va in *overflow silenzioso* e restituisce sempre "match". Vedi `findings.md` F11.

## File

| file | ruolo |
|---|---|
| `costo.py` | run dell'argmin cifrato vs larghezza in bit |
| `results/muro_argmin.csv` | la curva misurata (N=10, 5→10 bit) |
