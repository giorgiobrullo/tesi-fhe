# Gradino 06 — argmin sul server (privacy): quanto costa

> Misura presa. Vedi `findings.md` F6.

## Perché

Nel gradino 05 l'argmin lo fa il **client**: comodo e gratis (nessun PBS), ma il
client decifra tutti gli N punteggi → impara la distanza con *ogni* iscritto, non solo
col match. Per privacy l'argmin (e in prospettiva la soglia open-set) **deve stare sul
server, sotto FHE**, così il client apprende solo *chi* è il match. Qui misuriamo
semplicemente quanto costa farlo lì.

Risposta scelta: **(A)** il server restituisce l'**indice/identità** del match oppure "nessun match 
se nessun match è entro la soglia prefissata.

## Il costo

`np.argmin` non è nativo in Concrete → riduzione a confronti cifrati a coppie (ogni
passo un PBS), in `core/matching.py::circuito_distanza_argmin`. Il costo è dominato
dalla **larghezza in bit dei punteggi** e raddoppia ~ad ogni bit:

| larghezza punteggi (N=10) | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

**È il centro di costo del passaggio privato:** da gratis (client) a un prezzo che
raddoppia per ogni bit di precisione del punteggio. → la leva di progetto è **tenere
stretta la larghezza dei punteggi**. A larghezze realistiche pesa (i punteggi PCA del
prototipo sono ~14 bit → secondi/decine di secondi per query; a piena larghezza
Concrete 2.11 fatica anche solo a compilare). Per riferimento, il solo calcolo dei
punteggi senza argmin (gradino 05) è ~31 ms/query.

La caratterizzazione fine (a quale larghezza conviene girare) si fa sulla tecnica
finale, sui parametri validi.

## La soglia "nessun match" — funziona (con l'inputset giusto)

Il circuito completo (`core/matching.py::circuito_distanza_argmin_soglia`) ritorna
`(indice, è_match)`: la distanza² vera del match (`val_min + ‖a‖²`) è confrontata con
la soglia → `è_match=0` significa **"nessun match"** (impostore/sconosciuto rifiutato).
Verificato 10/10, coi rifiuti che si attivano davvero.

⚠️ **Trappola (F11):** Concrete non ha `argmin` nativo (solo `min/max/where` → si
costruisce da `<` + select), e il rifiuto si attiva solo se l'**inputset è
rappresentativo dei probe reali**: con un inputset troppo stretto il confronto della
soglia va in *overflow silenzioso* e dice sempre "match". Vedi `findings.md` F11.

## File

| file | ruolo |
|---|---|
| `costo.py` | run dell'argmin cifrato vs larghezza in bit |
| `results/muro_argmin.csv` | la curva misurata (N=10, 5→10 bit) |
