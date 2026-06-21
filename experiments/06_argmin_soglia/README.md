# Gradino 06 — argmin + soglia sotto FHE

> Stato: **piano** (non ancora implementato). Questo file fissa obiettivo,
> benchmark e l'unica decisione di design aperta, prima di scrivere il circuito.

## Obiettivo

Spostare **argmin + soglia dentro il circuito**, sul server, sotto FHE. Oggi
(gradino 05) il server restituisce tutti gli N punteggi cifrati e l'**argmin lo fa
il client** dopo averli decifrati — quindi il client vede le distanze con *tutta* la
galleria. Qui invece il server riduce gli N punteggi al solo esito, e il client
**apprende solo il risultato**, non le N distanze.

Due cose nuove, entrambe confronti su cifrato → **reintroducono il PBS**:
1. **argmin cifrato** sugli N punteggi (trovare la faccia più vicina);
2. **soglia (open-set):** match solo se la distanza minima è sotto una soglia,
   altrimenti "nessun match" (rifiuto degli impostori) — un confronto cifrato in più.

È **il nuovo centro di costo e il numero chiave della tesi**: il salto dal regime
"niente PBS" (gradino 05) al regime "PBS nel matching".

## Il benchmark (il motivo del gradino)

Domanda guida: **spostando l'argmin sul server, quanto si perde in tempo?**

Confronto **prima/dopo** sullo stesso input:

| | argmin dove | PBS nel matching? | cosa apprende il client |
|---|---|---|---|
| **prima** (gradino 05) | client | no | tutte le N distanze |
| **dopo** (questo gradino) | server, sotto FHE | sì | solo l'esito |

Baseline "prima" già misurata (M4 Max, Olivetti, N=320, D=50, 6 bit):
`match server ≈ 29 ms/probe` + `decifra+argmin client ≈ 2 ms/probe`. Il "dopo" va
misurato e confrontato → **delta = costo in tempo della privacy**.

Poi i due assi di scaling (è qui che entra il **terzo asse del benchmark**, dopo
dimensione e precisione del gradino 02/03):
- **N (dimensione della galleria):** l'argmin cifrato costa ~N−1 confronti → atteso
  lineare in N. Sweep su N crescenti.
- **bit di precisione:** ogni confronto cifrato è un PBS, la cui tabella cresce
  ~2^bit → atteso esponenziale nei bit. Sweep sul range accettabile (dal param-search
  in chiaro, non a caso).

Output: `costo.py` → `results/bench_argmin.csv` + figura. Logga sempre i parametri
(N, bit, soglia) per riproducibilità.

## Decisione di design aperta (da confermare prima di implementare)

**Cosa restituisce il server al client?** Cambia il circuito e la storia di privacy:
- **(A) indice/identità del match, gated dalla soglia** — il client ottiene *chi* è
  (o "nessun match"). È un sistema di *riconoscimento*. Argmin completo (porta avanti
  l'indice) + confronto con soglia.
- **(B) solo il bit "sotto-soglia sì/no"** — il client ottiene solo *se* qualcuno
  matcha, non chi. Più privato, ma è *verifica*/autenticazione, non riconoscimento.

In entrambi i casi la parte cara (riduzione argmin + confronto soglia) è simile;
cambia solo cosa si decifra. Proposta: **(A) come primario** (è un riconoscitore) e
**(B) come variante più privata** da benchmarkare a parte, così il confronto di
costo tra le due diventa un altro numero della tesi.

## TODO

- [ ] Confermare la decisione di design (A / B / entrambe).
- [ ] Studiare in Concrete come fare argmin cifrato su N valori (riduzione a torneo:
      confronti a coppie + select; il confronto è `sign(x−y)` via PBS). Verificare il
      supporto nativo (`np.argmin`/`minimum`/comparatori su cifrato).
- [ ] Implementare il circuito in `core/matching.py` come
      `circuito_distanza_argmin_soglia(galleria_q, soglia)` (fonte unica, riusabile
      dai gradini superiori).
- [ ] `costo.py`: benchmark prima/dopo + sweep N + sweep bit → CSV + figura.
- [ ] Aggiornare `findings.md` (nuovo F6).
