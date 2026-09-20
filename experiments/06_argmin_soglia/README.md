# Gradino 06 - costo dell’argmin cifrato sul server

Le misure sono riepilogate in `findings.md`, F6.

## Obiettivo

Nel gradino 05 il client decifra tutti gli N punteggi ed esegue l'argmin.
Questo esperimento sposta la selezione sul server, sotto FHE, per evitare di
rilasciare le distanze rispetto all'intera galleria.

Il circuito con soglia restituisce l'indice del minimo e un bit che indica
se il vincitore rientra nella soglia. È un protocollo storico: la demo successiva
usa una codifica 0/ID che nasconde anche l'identità nei rifiuti.

## Il costo

`np.argmin` non è nativo in Concrete, quindi si riduce a confronti cifrati a coppie (ogni
passo un PBS), in `core/matching.py::circuito_distanza_argmin`. Il costo è dominato
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

Limite osservato (F11): Concrete non ha `argmin` nativo (solo `min/max/where`, quindi si
costruisce da `<` + select), e il rifiuto si attiva solo se l'inputset è
rappresentativo dei probe reali: con un inputset troppo stretto il confronto della
soglia va in *overflow silenzioso* e restituisce sempre "match". Vedi `findings.md` F11.

## File

| file | ruolo |
|---|---|
| `costo.py` | run dell'argmin cifrato vs larghezza in bit |
| `results/muro_argmin.csv` | la curva misurata (N=10, 5→10 bit) |
