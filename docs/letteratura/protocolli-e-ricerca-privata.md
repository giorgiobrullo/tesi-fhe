# Protocolli complementari e ricerca privata

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Aggiornamento mirato al 19 settembre 2026. Questi lavori cambiano interazione,
informazione restituita, distribuzione della fiducia o funzione di ricerca.
Le differenze delimitano il confronto con il [contratto locale](contratto-e-schemi.md)
e impediscono di ordinare i sistemi usando soltanto i tempi pubblicati.

## Protocolli complementari e ricerca privata

**Monchi e Funshade.** [Monchi](https://eprint.iacr.org/2024/654.pdf) comprende Gate, BIP,
due parti FSS non colluse e un key server offline
fidato, nel modello semi-honest con corruzione statica di al più una parte. Combina BFV con FSS
nello stile [Funshade](https://petsymposium.org/popets/2023/popets-2023-0096.php). A K=1.024 e
dimensione 512, la tabella 2 di Monchi riporta 0,914 s di computation overhead online su quattro
core e 52 MB; non è una misura end-to-end della rete. Il confronto è discreto sul dominio
intero, sotto le condizioni crittografiche del paper. Il testo è inoltre internamente ambiguo fra «one-bit
output» e il vettore di soglie ricostruito dagli algoritmi, quindi non prova la stessa uscita
globale di questa tesi. Funshade è un protocollo separato a due parti con preprocessing.

**Oracolo binario.** [Rahimi, Osadchy e Dunkelman](https://doi.org/10.1109/IJCB65343.2025.11410617), IJCB 2025
(preprint [depositato nel 2026](https://arxiv.org/abs/2601.17620)), studiano un attacco di ricostruzione da risposte accept/reject. L'attacco recupera
un template 1:1 sotto
un'interfaccia più forte: identità target dichiarata, vettori post-feature arbitrari, un falso
accept iniziale e circa 10^4 query adattive a d=512. Non è una dimostrazione diretta contro il
bit globale 1:N con terminale di cattura controllato. Il contratto exact-id corrente espone
l'identità soltanto sulle accettazioni, mentre il codice decodificato di
rifiuto non identifica il vicino: tale funzione è comunque più informativa
di un solo bit. Non è stato eseguito un attacco di ricostruzione sul prototipo.
La nuova [lettura del PDF completo](testi-integrali/privacy-e-indicizzazione.md)
precisa che i tempi dell'attacco escludono la decisione binaria cifrata completa
e che il successo varia con immagine ed estrattore. Le query riportate non
sono una stima dei tentativi necessari contro questa applicazione.

**Circuit privacy.** La confidenzialità della query verso il server e la
riservatezza della galleria verso il destinatario del risultato sono proprietà
diverse. Restituire un codice 0/ID anziché una lista di score limita la funzione
rivelata, ma non prova che il ciphertext e il transcript siano simulabili
conoscendo soltanto quel codice. Il possessore della chiave può avere accesso
anche a informazioni sulla valutazione presenti nel cifrato, a seconda della
costruzione e delle assunzioni. Sono pertinenti
[Kluczniak, Circuit Privacy for FHEW/TFHE-Style Fully Homomorphic Encryption
in Practice](https://cic.iacr.org/p/1/4/33), IACR Communications in Cryptology
1(4), pubblicato il 13 gennaio 2025,
[DOI 10.62056/av11c3w9p](https://doi.org/10.62056/av11c3w9p), e il lavoro
fondativo di [Ducas e Stehlé sulla sanitizzazione, EUROCRYPT 2016](https://iacr.org/cryptodb/data/paper.php?pubkey=27639).
Il precedente ePrint 2022/1459, ricevuto nel 2022 e revisionato l'8 marzo 2024,
mantiene l'etichetta preprint; l'edizione pubblicata è stata verificata
separatamente. La nuova [lettura dei testi completi](testi-integrali/privacy-e-indicizzazione.md)
include la correzione Ducas–Stehlé del marzo 2025, che restringe la correttezza
del bootstrap ai ciphertext generati onestamente. Nell'edizione CiC, i tempi
del campionatore Box–Muller arrotondato sono dichiarati euristici rispetto
alla prova basata su Gaussiane discrete. Nessuna di queste proprietà si
trasferisce automaticamente al runtime locale.

Questa obbligazione è separata dall'oracolo adattivo: anche una risposta
perfettamente protetta oltre il proprio contenuto autorizzato può rivelare
informazioni attraverso molte interrogazioni. Il runtime locale assume un
terminale fidato per acquisizione, embedding, cifratura e decifratura e un
server honest-but-curious con galleria visibile. Non dispone di una prova di
circuit privacy contro un terminale arbitrario né di una sanitizzazione
integrata e misurata. Una prova di intervallo dell'input non attesterebbe da
sola l'origine biometrica o la presenza fisica della persona. Le
[questioni aperte](../limiti.md#3-integrità-freschezza-e-autorizzazione-del-servizio) mantengono distinti questi limiti.
Nella [demo web ospitata](../../demo/web/README.md#sessioni-e-verifiche) le due
parti logiche sono sullo stesso host e l'operatore ha accesso ai dati in chiaro;
quel dimostratore non realizza una separazione di fiducia fra visitatore e host.

**Bootstrapping ammortizzato.** [Sharing the Mask](https://eprint.iacr.org/2025/2112),
TCHES 2025(4), usa una rappresentazione common-mask con segreti matriciali e
più corpi cifrati. Condividere ingenuamente la stessa maschera e lo stesso
segreto tra due messaggi farebbe cancellare il termine della maschera nella
differenza dei corpi; questa osservazione non è un attacco alla costruzione
matriciale del paper. Le conversioni richieste dal consumatore locale restano
parte del costo da valutare. [BatchBoot](https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao)
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
primo argmin sul dominio intero dichiarato, soglia per-template del solo
vincitore e codice `0`/ID. Questa osservazione riguarda i due algoritmi del
paper, non tutte le [costruzioni discrete basate su CKKS](ckks-discreto.md).

**Argmax interattivo.** [HEArgmax, Nguyen et al.](https://doi.org/10.1016/j.csi.2025.104071),
2026, è stato ora letto nel PDF editoriale completo con appendice. Il client
decifra differenze mascherate e ricifra i segni; HT lavora su batch, LC su
un vettore. Le varianti `loose` autorizzano più informazione dell'indice.
La [verifica della specifica ideale](testi-integrali/heargmax-edizione-pubblicata.md)
mostra che anche la giustificazione della garanzia `tight` richiede correzioni:
casualità moltiplicativa e permutazione non bastano a simulare le viste
sulla base del solo output per tutti gli ingressi dichiarati.
Non è un attacco CKKS eseguito, né una prova contro la nostra demo.
Il paper rimane pertinente alla progettazione interattiva; privacy,
pareggi e margini numerici non vanno adottati senza una specifica verificata.

**ANN omomorfica su grafo.** [GraSS](https://eprint.iacr.org/2024/2012.pdf) mantiene in chiaro il
database strutturato come grafo, cifra la query e combina CKKS con FHEW per confronti, tournament
ArgMin e indici cifrati. È un precedente adiacente per query cifrata, dati chiari e restituzione
di indici; realizza però una ricerca ANN approssimata sul grafo, non il confronto esaustivo
open-set con soglia del vincitore e codice `0`/ID.

**Indicizzazione biometrica protetta.** [Drozdowski et al., Feature Fusion
Methods for Indexing and Retrieval of Biometric Data](https://arxiv.org/abs/2107.12675),
2021, studiano fusione di caratteristiche, indicizzazione e filtraggio
progressivo dei candidati, con valutazione anche open-set. Il filone interessa
il costo della scansione della galleria, ma recall empirico e garanzia di
conservare sempre il primo minimo sono proprietà diverse. La lettura della
tabella VI del PDF mostra un compromesso misurato tra carico e accuratezza;
il percorso NTRU più veloce lascia inoltre un'aggregazione fuori dal dominio
cifrato. La [scheda completa](testi-integrali/privacy-e-indicizzazione.md)
precisa perché non è una sostituzione già qualificata della scansione FHE locale.

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

Altre famiglie adiacenti includono ricerca mediante PIR e indicizzazione
protetta. Sono piste per ampliare il corpus, non baseline numeriche già
qualificate. Il criterio resta verificare quale vicino venga restituito,
quali accessi e risultati siano visibili e quali assunzioni rendano valido
il confronto.
