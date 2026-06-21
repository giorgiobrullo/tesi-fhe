# Gradino 06 — argmin sotto FHE: la decisione e il suo costo

> Stato: **chiuso su PCA** (esito negativo, documentato). Da rivalutare salendo la
> scaletta (descrittori locali, poi CNN). Vedi `findings.md` F6.

## La decisione

Nel gradino 05 l'argmin lo fa il **client**: il server gli manda gli N punteggi, lui
li decifra e prende il minimo. Ma così il client impara la distanza con *tutta* la
galleria, non solo col match — informazione che non dovrebbe avere. Decisione (dal
meeting): spostare l'argmin (e in prospettiva la soglia open-set) **sul server, sotto
FHE**, così il client apprende solo *chi* è il match.

Risposta scelta: **(A)** il server restituisce l'**indice/identità** del match (è un
riconoscitore, non una verifica sì/no).

## Cosa abbiamo trovato

`np.argmin` non è nativo in Concrete → riduzione a confronti cifrati a coppie (ogni
passo un PBS), implementata in `core/matching.py::circuito_distanza_argmin`. Funziona
ed è corretta su input piccoli, **ma non scala**: il costo raddoppia ~ad ogni bit di
larghezza dei punteggi.

| larghezza punteggi (N=10) | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

I punteggi PCA reali (Olivetti, N=320, 50 comp, 6 bit) sono **~14 bit** → estrapolando
si arriva a decine di minuti/query, e già a galleria minuscola la compilazione di
Concrete 2.11 si rompe (assert sul bit-width / esplosione di memoria). **Intrattabile**
— contro i **~31 ms/query** del gradino 05.

## Conclusione

La decisione (cifrare l'argmin) è giusta per la privacy, ma su **PCA a piena
precisione non è praticabile**. Non investiamo oltre (PCA è debole sui dati reali,
F5): la caratterizzazione del costo va rifatta salendo la scaletta (descrittori
locali, poi CNN), sui soli parametri validi, e con eventuale riduzione di precisione
dei punteggi. La soglia
open-set è rimandata per lo stesso motivo (costo marginale rispetto all'argmin).

## File

| file | ruolo |
|---|---|
| `costo.py` | riproduce il muro: run dell'argmin cifrato vs larghezza in bit |
| `results/muro_argmin.csv` | la curva misurata (N=10, 5→10 bit) |
