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

## F4 — Prototipo end-to-end funzionante (cartella `experiments/05_prototipo_e2e/`)
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