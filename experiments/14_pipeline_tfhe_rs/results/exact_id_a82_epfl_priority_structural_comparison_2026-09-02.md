# A82: A53 contro il priority encoder EPFL/BOLT

Data: 2026-09-02/03. Stato: **PASS strutturale ed equivalenza simbolica; runtime non
confrontabile**.

L'analisi usa l'RTL ufficiale del benchmark priority EPFL citato da BOLT,
disponibile dalla repository LSILS indicata nelle fonti.
L'interfaccia e' davvero comparabile per taglia: 128 flag Boolean in ingresso, sette bit di indice
e un flag valido in uscita.

Un interprete fail-closed ha ricostruito 978 assegnazioni e verificato 258 pattern diagnostici:

- nessun hit: indice 0, flag 0;
- tutti i 128 one-hot: indice `i`, flag 1;
- 127 coppie adiacenti, coppia `0/127` e tutti attivi: prevale l'indice maggiore.

Il solo reverse degli ingressi non basta a descrivere l'intero protocollo. La composizione completa
è `A[127-i]=gallery_flag[i]` e, dopo la decifratura, `code=0` se `F=0`, altrimenti
`code=128-P`. Un gate Z3 sulle stesse 978 equazioni ha dimostrato `UNSAT` per l'esistenza di un
controesempio: per tutti i `2^128` vettori questa mappa restituisce esattamente rifiuto o il primo ID
attivo. Il decode è pubblico/client-side e non viene contato come lavoro FHE; il wire format EPFL
resta comunque otto bit cifrati, non le due cifre p16 A53.

Il modello A53 pin-nato restituisce a N=128 due cifre p16 del codice exact `0/ID` con
`136 BR / 136 KS / 168 marginali`.

| route, 128 flag | nodi non lineari riportati |
|---|---:|
| Yu et al. LUT/FBS, Tabella V BOLT | 818 |
| Singh et al. gate-based, Tabella V BOLT | 681 |
| BOLT gate-based, Tabella V | 686 |
| A53 exact `0/ID` scan/output | 136 BR |

Il rapporto numerico grezzo A53/BOLT e' `136/686 = 19,825%`: 5,044 gate BOLT per BR A53. Il
complemento `80,175%` è soltanto aritmetico fra unità diverse, non una riduzione di costo né uno
speedup. Resta un segnale strutturale da verificare con una baseline matched.

L'RTL contiene 978 assegnazioni, mentre la colonna Initial di BOLT riporta 974 gate dopo il proprio
flow Yosys. La discrepanza di quattro viene conservata; senza il netlist intermedio degli autori
non ne attribuiamo la causa.

Non e' uno speedup: BOLT usa gate bootstrap tradizionali e riporta 4.221 ms su un altro runtime,
parametro, hardware e formato d'uscita; A53 usa accumulatori raw multi-valore e sample correlati.
La semantica Boolean tie-first è ora provata esaustivamente nel modello simbolico, ma il confronto
di performance pubblicabile richiede ancora una baseline matched per runtime, parametro, hardware
e formato di uscita.

Il replay congelato usa Python 3.12.11 e Z3 4.13.0: audit RTL PASS, formula negata `UNSAT`, 9/9 test
Python PASS e Ruff PASS. Il campo JSON usa il nome
`arithmetic_count_complement_percent`, non “reduction”, perché l'80,175% non è una riduzione di
costo fra unità omogenee.

Il programma di interpretazione e verifica simbolica non è incluso qui.

Fonti primarie:

- [RTL ufficiale LSILS](https://raw.githubusercontent.com/lsils/benchmarks/master/random_control/priority.v);
- [BOLT ePrint 2026/153](https://eprint.iacr.org/2026/153), Tabelle V-VI p. 11.
