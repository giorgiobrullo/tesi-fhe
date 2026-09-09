# Refresh dell'audit di novita' A33/A34

Data di chiusura della ricerca mirata: 2026-09-02.

## Esito in una frase

Non e' difendibile rivendicare una nuova funzione di argmin/nearest-ID, una nuova semantica
open-set `0`/ID, una nuova primitiva multi-output TFHE, una nuova codifica pesata o un nuovo
priority encoder. Nel corpus primario mirato non e' stato invece trovato un lavoro valutato che
riproduca **l'intera specializzazione A33**:

```text
riallineamento pubblico della soglia uniforme a 2^10-1
  -> classificatore di stati sparsi che da una BR emette (residuo signed, flag signed)
  -> pesi alternati 1/3 e canonicalizzatore per coppia
  -> continuazione bitwise esatta e tie-first
  -> un solo ciphertext 0/ID
```

Questo consente un claim prudente di **co-design applicativo, implementazione e valutazione**
della composizione specifica. Non consente `first`, `novel primitive`, brevettabilita' o FTO.
"Non trovato" descrive soltanto il corpus e le query esaminate alla data sopra.

## Evidenza nuova che restringe il claim

### Winner/indice TFHE esiste almeno dal 2018

Jaeschke e Armknecht descrivono `FindMin` per K-means su dati cifrati: l'output e' una riga
one-hot con l'unico `1` in corrispondenza della distanza minima, e dichiarano di aver implementato
la procedura in TFHE. Segnalano anche la variante ad albero a profondita' logaritmica. Il testo ha
una discrepanza interna fra pseudocodice e definizione della comparazione nel caso di uguaglianza,
quindi non viene usato come prova del tie-break piu' a sinistra; e' pero' prior art diretto contro
un claim di primo winner/one-hot TFHE.

- paper SAC 2018: <https://doi.org/10.1007/978-3-030-10970-7_21>
- copia primaria/institutional PDF: <https://d-nb.info/1193732409/34>
- ePrint 2018/411: <https://eprint.iacr.org/2018/411>

Schubert et al. rendono il precedente ancora piu' vicino: nel circuito TFHE per LVQ separano
winner determination e class verification, descrivono una `FindMin` modificata che restituisce
l'indice vincente, recuperano la classe con LUT TFHE e producono il segno `+1/-1` usato
dall'aggiornamento del prototipo. Gli esperimenti sono eseguiti con Concrete. Il successivo
articolo peer-reviewed del 2026 presenta esplicitamente, nel suo abstract accessibile, un
proof-of-concept TFHE di nearest prototype classifier. Il testo ESANN non realizza il contratto
A33 open-set con soglia, tie-first e singolo `0`/ID; l'abstract 2026 non dichiara questi dettagli,
quindi qui viene usato soltanto contro il claim piu' ampio di primo nearest-prototype TFHE.

- ESANN 2025: <https://doi.org/10.14428/esann/2025.es2025-47>
- PDF ESANN: <https://www.esann.org/sites/default/files/proceedings/2025/ES2025-47.pdf>
- codice degli autori: <https://github.com/lvlanson/LVQ_TFHE>
- Neurocomputing 2026: <https://doi.org/10.1016/j.neucom.2026.132673>

### La fusione di uscite con input condiviso e' prior art generale

`PBSmanyLUT` calcola piu' funzioni dello stesso input con una sola blind rotation. La famiglia
brevettuale Zama con priorita' 2021 descrive esplicitamente piu' coefficienti estratti dallo stesso
test polynomial e, in una costruzione particolarmente vicina, uscite di funzione insieme a una
costante corretta fino allo stesso segno, poi usata per correzione o selezione. Scytale, DATE
2026, identifica LUT con gli stessi input ordinati e le fonde in LUT multi-output; usa pero'
CBS/vertical packing e non l'accumulatore raw/sample-extraction di A33.

Questi lavori impediscono di chiamare nuova la regola generale "da una valutazione TFHE con
input condiviso otteniamo valore e flag". Non pubblicano la specifica tabella p8 di A33, le sue
due estrazioni `(r, flag)` o il loro consumo nel seguito exact-ID.

- `PBSmanyLUT`: <https://eprint.iacr.org/2021/729>
- EP4096148A1, `Computation on LWE-encrypted values`: <https://patents.google.com/patent/EP4096148A1/en>
- Scytale, DATE 2026: <https://past.date-conference.com/proceedings-archive/2026/DATA/1425.pdf>

### Residui sparsi, proiezioni pesate e canonicalizzazione non sono primitive nuove

Legiest et al. rappresentano valori intermedi tramite differenze ternarie `{-1,0,1}`, riscrivono
due uscite affinche' condividano la parte non lineare, e comprimono stati tramite una combinazione
pesata prima di una sola PBS. Yu et al. formalizzano la proiezione di pattern Booleani sulla somma
pesata degli input, la compressione delle truth table e la fusione multi-output; valutano anche un
priority encoder TFHE generico.

Di conseguenza, ne' "residuo piccolo/sparso", ne' "pesi 1/3", ne' "una LUT riconosce un insieme
di somme raggiungibili" sono claim autonomi di novita'. Resta specifico il disegno con cui A33
sceglie proprio i pesi `1/3`, prova la disgiunzione dei reachable set della coppia e collega il
Booleano canonico alla prosecuzione exact-ID.

- Leuvenshtein, ePrint 2025/012: <https://eprint.iacr.org/2025/012.pdf>
- Yu et al., WAHC 2024: <https://doi.org/10.1145/3689945.3694803>
- PDF degli autori: <https://si2.epfl.ch/demichel/publications/archive/2024/wahc06-yu.pdf>

## Matrice claim-per-claim

| Oggetto | Stato dopo il refresh | Precedente/limite decisivo | Claim utilizzabile |
|---|---|---|---|
| Exact argmin o nearest-ID cifrato | **non nuovo** | Erkin 2009 restituisce gia' l'ID cifrato del minimo; Jaeschke 2018 produce winner one-hot in TFHE; Schubert 2025/2026 produce winner index/classe in TFHE | Il nostro e' un circuito TFHE specifico e misurato. |
| Open-set closest-or-reject e singolo `0`/ID | **non nuovo** | Erkin inserisce la soglia come candidato con identita' zero; SCiFI definisce closest-or-reject; CEA WO2025027253 combina query FHE, profili biometrici, soglia e argmin/argmax a livello di sistema | Descrivere il contratto conservato, non la sua priorita'. |
| Tie-break sul primo minimo | **non nuovo** | Kolesnikov et al. definiscono il minimo piu' a sinistra; lavori TFHE successivi trasportano label/index | Semantica esatta implementata e testata. |
| Riallineamento pubblico della soglia uniforme a `1023` | **nessun identico schedule trovato; non claim autonomo** | E' una traslazione affine pubblica che conserva ordine e pareggi, seguita da una specializzazione di dominio | Ottimizzazione guarded del workload uniforme, con fallback generale. |
| Residuo signed sparso | **tecnica generale non nuova** | Leuvenshtein usa differenziali ternari per ridurre il dominio TFHE | La particolare funzione di stato di A33 e il suo ruolo nell'exact-ID. |
| Una BR emette residuo numerico e flag signed | **meccanismo generale non nuovo** | `PBSmanyLUT`, EP4096148A1, precedenti Axell e, piu' astrattamente, Scytale producono/fondono piu' uscite con input condiviso | La tabella, le scale, i coefficienti di estrazione e l'integrazione A33, non una nuova primitiva. |
| Pesi `1/3` e pair canonicalizer | **metodo generale non nuovo** | Yu proietta pattern con pesi; Legiest usa packing pesato e reachable gaps | La codifica esatta, la prova dei due reachable set e il saving nel circuito completo. |
| Continuazione bitwise esatta | **non nuova** | minimum/argmin bitwise, tournament, stable label transport e candidate narrowing hanno numerosi precedenti | Il collegamento senza perdita dal classificatore A33 all'oracolo exact-ID. |
| Risultato server-side in un solo ciphertext | **funzione non nuova** | Erkin restituisce gia' `[Id]` con `0` per rifiuto; il sistema CEA copre high-level encrypted sought information | Formato e assenza di leakage addizionale nel prototipo specifico, subordinati al threat model dichiarato. |
| A34 two-nibble | **nessuna novita' di primitiva; solo modello clear** | Trama et al. rappresentano 8 bit come due digit base 16 e usano MVB/MVLUT; multi-output selector e priority encoding sono noti | Eventuale futura ottimizzazione di protocollo/composizione, solo dopo implementazione e FHE validation. |
| A34 top-category | **nessuna novita' di primitiva; solo modello clear** | Yu copre weighted projection, truth-table compression e priority encoder; Legiest copre dense weighted state encoding | Eventuale codifica applicativa bounded exact-ID, non nuovo encoder o nuovo FBS. |

Fonti della riga A34:

- Trama et al., TCHES 2025: <https://eprint.iacr.org/2024/1201.pdf>
- Yu et al., WAHC 2024: <https://doi.org/10.1145/3689945.3694803>
- Legiest et al., ePrint 2025/012: <https://eprint.iacr.org/2025/012.pdf>

## Prior art applicativo recente: vicino nella funzione, diverso nel boundary crittografico

Il corpus 2025-2026 rafforza la necessita' di un claim stretto, ma aiuta anche a spiegare cosa
A33 fa di diverso:

- IDFace calcola score omomorfi su larga scala, poi un key server li decifra e trova
  massimo/soglia in chiaro. Non e' selezione esatta single-server cifrata:
  <https://openaccess.thecvf.com/content/ICCV2025/papers/Kim_IDFace_Face_Template_Protection_for_Efficient_and_Secure_Identification_ICCV_2025_paper.pdf>.
- BioZKFHE calcola similarity cifrate con BGV e una decryption committee recupera il vettore,
  quindi deriva `argmax` e decisione di soglia; e' stato pubblicato in early access nel luglio
  2026. Non mantiene la selezione dentro un unico server FHE:
  <https://doi.org/10.1109/TDSC.2026.3716308>.
- il preprint sul nearest-neighbor billion-scale restituisce score cifrati che il client decifra
  e ordina; nel percorso facciale di membership usa invece una soglia cifrata ma non restituisce
  l'identita' nearest esatta: <https://arxiv.org/abs/2608.21131>.
- il preprint `Lightweight, Practical Encrypted Face Recognition with GPU Support` restituisce
  decisioni o indici corrispondenti dopo thresholding CKKS approssimato, non il solo nearest-ID
  esatto in un ciphertext: <https://arxiv.org/abs/2604.00546>.
- Attrapadung et al. realizzano closest identity piu' reject in protocolli MPC; e' prior art sulla
  funzione applicativa, ma non sulla microarchitettura TFHE single-server:
  <https://doi.org/10.1109/OJCS.2025.3580739>.
- Pan, Lou e Shao restituiscono indici top-k cifrati da un solo server con CKKS; confronti e
  indicatori sono approssimati e manca il contratto open-set con un solo `0`/ID:
  <https://doi.org/10.1007/s12083-026-02267-x>.
- GraSS combina CKKS e FHEW per tournament ArgMin e indici cifrati con query cifrata e database
  in chiaro, ma realizza ANN su grafo e non la scansione esaustiva exact open-set di A33:
  <https://eprint.iacr.org/2024/2012.pdf>.

Il contrasto corretto non e' quindi "gli altri non identificano". E': alcuni identificano con
interazione, committee/key server, score restituiti o approssimazioni; A33 mira a mantenere
selezione esatta, rifiuto e singolo codice cifrato nello stesso percorso TFHE server-side.

## Formulazione prudente per la tesi

> Progettiamo, implementiamo e valutiamo una specializzazione TFHE guarded per un workload di
> identificazione facciale 1:N open-set, bounded e con soglia uniforme. Una traslazione affine
> pubblica riallinea la soglia a un confine binario; un accumulatore specifico degli stati
> raggiungibili co-produce da una blind rotation un residuo signed e un indicatore signed; una
> codifica per coppie e un canonicalizzatore alimentano una continuazione first-argmin esatta e
> un singolo risultato cifrato `0`/ID. Non proponiamo nuove primitive di argmin, thresholding,
> proiezione pesata, bootstrapping multi-output, priority encoding o rappresentazione base 16.
> In una ricerca tecnica mirata chiusa il 2 settembre 2026 non abbiamo identificato una
> pubblicazione valutata che combini tutte queste scelte; questa e' un'osservazione sul corpus,
> non un claim di priorita' assoluta.

Questa formulazione va usata per A33 soltanto insieme all'evidenza realmente congelata e allo
stato di promozione corrente. A34 deve restare descritto come proposta/modello clear finche' non
esistono un core FHE integrato, test su chiavi fresche, confronto causale e accounting del
fallimento.

## Altre fonti primarie di controllo

- Erkin et al., PETS 2009: <https://doi.org/10.1007/978-3-642-03168-7_14>.
- Kolesnikov et al., CANS 2009: <https://eprint.iacr.org/2009/411>.
- SCiFI, IEEE S&P 2010: <https://doi.org/10.1109/SP.2010.39>.
- Cong et al., exact TFHE top-k: <https://eprint.iacr.org/2023/852>.
- CEA WO2025027253A1: <https://patents.google.com/patent/WO2025027253A1/fr>.
- IBM tournament-league FHE argmin/argmax, US12476788B2:
  <https://patents.google.com/patent/US12476788/en>.
- Axell multi-coefficient/multi-output examples:
  <https://patents.google.com/patent/US20240154786A1/en>,
  <https://patents.google.com/patent/US20240121077A1/en>,
  <https://patents.google.com/patent/US20240187210A1/en>.

## Limite metodologico

Questa e' una ricerca tecnica mirata su pubblicazioni, preprint, codice pubblico e alcune famiglie
brevettuali emerse dalle query; non e' una ricerca brevettuale completa, un parere legale, una
valutazione di brevettabilita' o una freedom-to-operate. I brevetti sono citati soltanto come
documenti tecnici pubblici. Le differenze riportate sono confronti di architettura inferiti dai
documenti, non conclusioni sull'ambito giuridico delle rivendicazioni.
