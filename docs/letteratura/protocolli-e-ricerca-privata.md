# Protocolli complementari e ricerca privata

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

## Protocolli complementari e ricerca privata

**Monchi e Funshade.** [Monchi](https://eprint.iacr.org/2024/654.pdf) comprende Gate, BIP,
due parti FSS non colluse e un key server offline
fidato, nel modello semi-honest con corruzione statica di al più una parte. Combina BFV con FSS
nello stile [Funshade](https://petsymposium.org/popets/2023/popets-2023-0096.php). A K=1.024 e
dimensione 512, la tabella 2 di Monchi riporta 0,914 s di computation overhead online su quattro
core e 52 MB; non è una misura end-to-end della rete. Il confronto è discreto sul dominio
intero con fallimento BFV trascurabile. Il paper è inoltre internamente ambiguo fra «one-bit
output» e il vettore di soglie ricostruito dagli algoritmi, quindi non prova la stessa uscita
globale di questa tesi. Funshade è un protocollo separato a due parti con preprocessing.

**Oracolo binario.** [Rahimi et al.](https://doi.org/10.1109/IJCB65343.2025.11410617), IJCB 2025
(manoscritto [pubblicato nel 2026](https://arxiv.org/abs/2601.17620)), studiano un attacco di ricostruzione da risposte accept/reject. L'attacco recupera
un template 1:1 sotto
un'interfaccia più forte: identità target dichiarata, vettori post-feature arbitrari, un falso
accept iniziale e circa 10^4 query adattive a d=512. Non è una dimostrazione diretta contro il
bit globale 1:N con terminale di cattura controllato. Il contratto exact-id corrente espone
l'identità soltanto sulle accettazioni e nulla sul vicino dei rifiuti: è comunque più
informativo di un solo bit e richiede la stessa cautela su query adattive.

**Bootstrapping ammortizzato.** [Sharing-the-Mask](https://eprint.iacr.org/2025/2112) richiede una
maschera LWE condivisa. [BatchBoot](https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao)
parte invece da messaggi già nei coefficienti di un singolo RLWE a segreto sparso: non accetta
direttamente la lista degli score LWE indipendenti di questo progetto. Sullo Xeon Gold 6258R
single-thread, la tabella 4 riporta 3,86 s per 1.024 messaggi a 4 bit, 18,31 s per 2.048 a 6 bit e
54,54 s per 2.048 a 8 bit; batch, p-fail e chiavi cambiano tra le righe. Resta da implementare il
ponte pre-bootstrap di packing/key-switch compatibile coi parametri.

**k-NN CKKS single-server.** [Pan, Lou e Shao](https://doi.org/10.1007/s12083-026-02267-x),
pubblicato il 9 luglio 2026, cifra sia database sia query e restituisce gli indici top-k cifrati da
un solo server semi-honest. `MEHP-kNN` usa sorting sicuro CKKS e `iMEHP-kNN` elimina il lavoro non
necessario al solo top-k; confronti e indicatori restano approssimazioni polinomiali. È un precedente
diretto per server singolo e output di indici, ma non include il contratto open-set di questa tesi:
primo argmin intero esatto, soglia per-template del solo vincitore e unico `0`/ID.

**ANN omomorfica su grafo.** [GraSS](https://eprint.iacr.org/2024/2012.pdf) mantiene in chiaro il
database strutturato come grafo, cifra la query e combina CKKS con FHEW per confronti, tournament
ArgMin e indici cifrati. È un precedente adiacente per query cifrata, dati chiari e restituzione
di indici; realizza però una ricerca ANN approssimata sul grafo, non il confronto esaustivo
open-set con soglia del vincitore e codice `0`/ID.

**Ricerca privata sublineare.** [SANNS](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-hao)
combina ANN clusterizzato, AHE, garbled circuits e DORAM.
[PANTHER](https://doi.org/10.1145/3719027.3765190) sostituisce DORAM con batch PIR e combina
leveled HE, secret sharing e top-k interattivo; entrambi cambiano la funzione da confronto
esaustivo esatto ad ANN. [RAM-FHE](https://eprint.iacr.org/2019/632.pdf) offre una costruzione teorica
single-hop polylog N sotto assunzioni molto forti, senza realizzazione nearest-neighbor; il
multi-hop è N^epsilon. [Isozaki et al.](https://arxiv.org/abs/2608.21131), arXiv v1 dell'agosto
2026 senza implementazione pubblica trovata, riportano ANN gerarchica CKKS fino al miliardo: il
client decifra e instrada a ogni livello, i tempi warm escludono rete/decrypt e il percorso
d'accesso rivela struttura geometrica anche quando il padding ne riduce parte.
