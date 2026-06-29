# Argmin cifrato: struttura sequenziale vs torneo (+ dataflow)

Obiettivo: restando su **Concrete/TFHE**, vedere se ottimizzando la **struttura**
dell'argmin (torneo invece di catena) e attivando il **parallelismo dataflow** il match
privato sul server scende a "umano" (pochi secondi) o no.

Eseguito su **home server Linux x86_64, 12 core, 94 GB RAM** (concrete-python 2.11.0).
Perché lì e non sul Mac: il linker dell'M4 Max è rotto (manca l'SDK delle Command Line
Tools) **e** il `dataflow_parallelize` di Concrete è disponibile solo su Linux, non su macOS.

Parametri: dim embedding 64, quantizzazione Q=±2, quindi punteggi ~8 bit, strategia CHUNKED.

## Risultati (run = tempo dell'argmin cifrato, secondi)

| N (galleria) | sequenziale | seq + dataflow | **torneo** | torneo + dataflow |
|---|---|---|---|---|
| 4 | 78,3 s | 73,9 s | **36,1 s** | 33,2 s |
| 8 | 180,4 s | 185,6 s | **69,1 s** | **CRASH compilatore** |

Tutti i risultati corretti (argmin = atteso). Il crash su torneo+dataflow a N=8 è un
**bug del compilatore Concrete** (assertion MLIR `cast<Ty>() incompatible type`).

## Cosa dicono i numeri

1. **Il torneo è l'ottimizzazione che conta.** Vince sul sequenziale **2,2× a N=4** e **2,6× a
   N=8**: il vantaggio **cresce** con la galleria. Motivo: il sequenziale è una catena di
   N−1 confronti dipendenti (+ un indice accumulato che si allarga), il torneo ha
   profondità **log N**. Scaling per raddoppio della galleria: sequenziale ×2,3 (4→8),
   torneo ×1,9, quindi il torneo scala meglio.

2. **Il dataflow non serve (e a volte rompe).** Sul sequenziale è inutile (niente da
   parallelizzare: 78→74 s, 180→186 s = rumore); sul torneo a N=4 aggiunge solo ~8%
   (36→33 s); sul torneo a N=8 **fa crashare il compilatore**. Il parallelismo HW non è la
   leva qui.

3. **Il pavimento del real-time.** Anche la config migliore (torneo, N=8) è **69 s** per
   una galleria di **8** persone. Il costo è il **singolo confronto cifrato: ~26 s a 8 bit**
   su questa CPU. Nessuna ristrutturazione scende sotto ~log(N) × (costo confronto), quindi
   decine di secondi anche per N piccolo. Estrapolando il torneo (×1,9/raddoppio): N=16
   ≈ 130 s, N=32 ≈ 250 s, N=64 ≈ 480 s.

## Verdetto
Ottimizzare **aiuta** (torneo: 2-2,6× più veloce, scaling migliore, un punto in
più sulla "linea del tempo che scende"), ma **"real-time in secondi" NO**: il pavimento è
il costo del singolo PBS/confronto in TFHE (~decine di secondi a precisione utile). Per i
secondi servirebbe abbattere quel costo, quindi precisione molto più bassa (accuratezza che
crolla) o un altro schema (CKKS, vedi findings F27). Conferma F25/F26: l'argmin privato
sul server con Concrete è classe-minuti, non real-time.
