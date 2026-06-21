## Concetti di base

**FHE (cifratura completamente omomorfica).** Permette di fare *calcoli su dati
cifrati* senza decifrarli: il server elabora il cifrato e produce un risultato
cifrato, che solo chi ha la chiave può aprire. Noi usiamo Zama **Concrete**, che si
basa sullo schema **TFHE** e lavora su **interi** (niente float: i valori vanno
quantizzati). Si definisce una funzione Python e Concrete la **compila in un
circuito** che opera sul cifrato.

**Rumore e bootstrapping.** Ogni testo cifrato porta del *rumore* (serve alla
sicurezza). Ogni operazione lo fa crescere; se cresce troppo, la decifratura dà un
risultato sbagliato. Il **bootstrapping** è l'operazione che "ripulisce" il rumore
e permette di calcolare all'infinito — è ciò che rende l'FHE *completa*.

**PBS (programmable bootstrapping).** In TFHE il bootstrapping è anche
*programmabile*: mentre ripulisce il rumore può applicare una funzione qualsiasi al
valore cifrato, tramite una **tabella** (input → output). È l'operazione **cara**,
e il suo costo cresce **~2^bit con la precisione** del valore (più bit = tabella più
grande). Quasi tutto il costo FHE è qui.

Cosa è economico e cosa è caro:

| operazione | costo | serve un PBS? |
|---|---|---|
| cifrato **+** cifrato | economico | no |
| cifrato **×** numero in chiaro | economico | **no** |
| cifrato **×** cifrato | **caro** | **sì** |
| funzione non lineare di un cifrato (quadrato, confronto, ReLU…) | **caro** | **sì** |

Regola pratica: *moltiplicare per un numero noto è quasi gratis; moltiplicare due
cifrati tra loro costa un PBS.*

**La "formula espansa".** La distanza al quadrato `‖a−b‖² = Σ(aᵢ−bᵢ)²`. Calcolata
in modo ingenuo, il quadrato `(aᵢ−bᵢ)²` è cifrato×cifrato → PBS (caro), anche se `b`
è in chiaro. Ma con l'algebra `(a−b)² = a² − 2ab + b²`:
`‖a−b‖² = Σaᵢ² − 2·Σaᵢbᵢ + Σbᵢ²`. Con `a` cifrato e `b` in chiaro:
- `Σbᵢ²` è tutto in chiaro → **gratis**;
- `Σaᵢbᵢ` (prodotto scalare) è cifrato×chiaro → **niente PBS**;
- `Σaᵢ²` è cifrato×cifrato (PBS) ma dipende solo dal probe `a`: si calcola **una
  volta**, e per trovare il più vicino (argmin) è una costante uguale per tutti →
  **si butta**.

Risultato: il costo *per faccia della galleria* è solo il prodotto scalare →
economico e lineare. (Misurato in F2.)

---

## F0 — Concrete gira nativo su macOS arm64, senza Docker
`concrete-python 2.11.0` si installa e funziona end-to-end (Esp. 00).

## F1 — Il modello di sicurezza
Il probe (il volto da riconoscere) è cifrato sotto la chiave del **client**, mentre
la **galleria sta in chiaro sul server** (è un dato del server: è lui che iscrive
le persone). Il server calcola il match alla cieca e non impara né il volto né
l'esito; solo il client decifra il risultato. Di conseguenza l'operazione reale è
**cifrato×chiaro**, non cifrato×cifrato.

## F2 — Tenere la galleria in chiaro da solo non basta: serve la formula giusta
Esp. 03 confronta tre modi di calcolare lo stesso punteggio per faccia:

- **V1** `‖a−b‖²` cifrato×cifrato — il caso peggiore.
- **V2** `‖a−b‖²` con galleria in chiaro, ingenuo — **costa quanto V1**: mettere la
  galleria in chiaro non basta, perché il quadrato `(a−b)²` resta cifrato×cifrato e
  richiede il bootstrapping.
- **V3** formula espansa `‖b‖² − 2·a·b` → solo prodotto scalare cifrato×chiaro →
  **niente bootstrapping**, e il costo per faccia crolla e resta quasi piatto al
  crescere della dimensione.

Il guadagno viene dallo spostare il quadrato cifrato fuori dal ciclo
sulla galleria, non dal semplice mettere la galleria in chiaro.

## F3 — Lezione pratica di Concrete: niente moltiplicazioni chiaro×chiaro nel circuito
Tentando V3 come `‖b‖² − 2·a·b` con `‖b‖²` calcolato nel circuito, Concrete
rifiuta: `clear-clear multiplications are not supported`. La parte tutta in chiaro
(`‖b‖²`) va **precalcolata in Python** e iniettata come scalare in chiaro. Nel
circuito resta solo ciò che tocca il cifrato.
→ Principio generale: tieni fuori dal circuito tutto ciò che è puramente in chiaro.

## F4 — Prototipo end-to-end funzionante (cartella `experiments/05_pca/`)
PCA in chiaro (client) + matching cifrato con formula espansa (server), sul dataset
Olivetti/ORL (volti in laboratorio).

- La **quantizzazione a pochi bit non costa accuratezza**: float e quantizzato
  danno lo stesso risultato.
- L'FHE dà **le stesse identiche predizioni** del calcolo in chiaro quantizzato →
  il percorso cifrato è **corretto, non approssimato**.
- Il match contro tutta la galleria sta in un'unica `run` cifrata e in tempi
  interattivi: il muro della galleria non c'è.

**Onestà intellettuale (limiti):** Olivetti è piccolo e in laboratorio (volti
allineati), quindi è una prova di fattibilità, non una garanzia nel mondo reale; è
inoltre il tier più semplice (PCA). Vedi F5.

## F5 — Su volti reali (LFW) la PCA crolla
Stesso prototipo sul dataset LFW (volti presi "in natura", molto più vari).

L'accuratezza **crolla** rispetto a Olivetti: gli eigenfaces non reggono la
variabilità reale (posa, luce, sfondo). La PCA fa meglio del caso, ma è lontana
dall'usabile.

## F6 — La decisione: l'argmin va cifrato (privacy), ma su PCA non è praticabile
**Decisione (dal meeting).** Nel gradino 05 l'argmin lo fa il client: il server
restituisce tutti gli N punteggi, il client li decifra e prende il minimo. Ma così
il client impara la **distanza con ogni faccia della galleria** (la similarità con
tutti gli iscritti), non solo col match — informazione che non dovrebbe avere.
Quindi l'argmin (più, in prospettiva, la soglia open-set per il rifiuto degli
impostori) va spostato **sul server, sotto FHE**: il client apprende solo l'esito.

**Costo: l'argmin cifrato non è gratis e non è nativo.** `np.argmin` non è
supportato da Concrete → va fatto a **riduzione**, con confronti cifrati a coppie
(`<`, select dell'indice/valore): ogni passo è un PBS. Il costo è dominato dalla
**larghezza in bit dei punteggi** e cresce ~×2 per bit (di nuovo la leva di F1–F3,
ora sull'argmin). Misurato (riduzione su N=10 valori):

| larghezza punteggi | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

**Su PCA non scala.** I punteggi del prototipo PCA reale (Olivetti, N=320, 50
componenti, 6 bit/componente) sono **~14 bit** di larghezza (range misurato ≈ 9000).
Estrapolando la curva (×2/bit da 172 s a 10 bit) si arriva all'ordine delle **decine
di minuti per singola query** — e N=320 (vs N=10 della curva) lo moltiplica ancora.
In pratica, già a galleria minuscola la compilazione di Concrete 2.11 sui punteggi
*calcolati* (larghi) si rompe in due modi diversi: assert interno sul bit-width
(`np.minimum`) oppure esplosione di memoria (~34 GB a N=6 con la variante a select).
→ **Intrattabile.** Per contro, il solo calcolo dei punteggi (gradino 05, argmin sul
client) è **~31 ms/query** (29 ms match + 2 ms decifra/argmin).

**Conclusione.** La decisione di cifrare l'argmin è giusta per la privacy, ma con la
PCA a piena precisione non è praticabile senza ridurre drasticamente la larghezza
dei punteggi (meno bit/componenti, o troncamento prima della riduzione — lossy). Non
investiamo oltre: la PCA è comunque debole sui dati reali (F5). La caratterizzazione
del costo dell'argmin cifrato va **rifatta sulla tecnica che useremo davvero** —
salendo la scaletta (prima i descrittori locali, poi la CNN) — sui soli parametri
che danno accuratezza accettabile (metodo: prima i parametri in chiaro, poi il costo
FHE su quel range). La soglia open-set sotto FHE è rimandata
con lo stesso motivo: è un confronto in più, marginale rispetto agli N−1 dell'argmin.
Tenuto qui come dato di fattibilità: *abbiamo provato a cifrare l'argmin su PCA, ed
ecco i numeri.*

## F7 — Descrittori locali: battono la PCA sui volti reali, ma con un bivio FHE
Secondo gradino della scaletta (LBP, HOG), validato **in chiaro** prima di toccare
l'FHE. A parità di protocollo (1-NN, split per persona):

| | Olivetti | LFW (volti reali) |
|---|---|---|
| PCA + euclidea (gradino 05) | 98,8% | **32,4%** (il crollo, F5) |
| LBP + χ² (nri_uniform, ottimizzato) | 100% | **74,8%** (≈2,3× la PCA) |
| HOG + euclidea (celle 4×4) | 98,8% | **64,8%** |

Su Olivetti (laboratorio) sono tutti equivalenti; la differenza emerge **sui volti
reali**, dove i descrittori locali codificano texture/forma locali e reggono la
variabilità che fa crollare gli eigenfaces globali. Salire di gradino era la mossa
giusta.

**Ricerca dei parametri (in chiaro, su LFW)** — prima di pensare all'FHE, abbiamo
cercato i parametri buoni (`ricerca_parametri.py`, dati in `results/ricerca_lfw.csv`).
Leve principali:
- LBP: la codifica **`nri_uniform`** (59 bin, il classico per i volti) batte nettamente
  `uniform` (10 bin): da ~65% a ~75%. Griglia più fitta e raggio R=2 aiutano.
- HOG: celle più piccole (4×4 invece di 8×8) salgono da 55% a ~65%, ma a costo di una
  **dimensione molto più grande** (540 → 3168).
- **χ² vs euclidea su LBP:** la χ² è migliore di ~4-6 punti (74,8% vs 70,4% a parità di
  config), **ma l'euclidea regge** e resta ben sopra la PCA. → si può **evitare la
  divisione** della χ² (ostica per l'FHE) pagando pochi punti.

Le config migliori sono **ad alta dimensione** (LBP ~3776-5900, HOG ~3168): è la
dimensione, non più la precisione per-valore, a guidare il costo FHE qui.

**Il bivio FHE** (è il trade-off centrale della tesi, potere vs costo):
- **LBP + χ²** è il più accurato, ma la χ² `Σ(h−g)²/(h+g)` ha una **divisione** per
  `h+g` che dipende dal probe cifrato → divisione per quantità cifrata, ostile
  all'FHE (servirebbe un PBS costoso / un inverso).
- **HOG + euclidea** è meno accurato ma **FHE-friendly**: vettore di feature +
  distanza euclidea → riusa *identico* il circuito del gradino 05 (cifrato×chiaro,
  niente PBS nel match). E fa comunque ~1,7× la PCA.

→ Prossimo passo (lato FHE, sui parametri appena validati): caratterizzare il costo
di HOG+euclidea cifrata (è il circuito del 05 sulla dimensione HOG reale) e valutare
la fattibilità della divisione χ² per LBP. *Niente sweep su config non valide.*