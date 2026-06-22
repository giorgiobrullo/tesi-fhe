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

## F6 — L'argmin deve stare sul server (privacy): quanto costa
Nel gradino 05 l'argmin lo fa il **client**: comodo e gratis (nessun PBS), ma il
client decifra tutti gli N punteggi → impara la distanza con **ogni** iscritto, non
solo col match. Per privacy l'argmin (e, in prospettiva, la soglia open-set) **deve
stare sul server, sotto FHE**, così il client apprende solo l'esito. Qui misuriamo
semplicemente quanto costa farlo in quel modo.

L'argmin cifrato non è nativo in Concrete (`np.argmin` non supportato) → si fa a
**riduzione**: confronti cifrati a coppie con select di indice/valore, ogni passo un
PBS. Il costo è dominato dalla **larghezza in bit dei punteggi** e raddoppia ~ad ogni
bit (di nuovo la leva di F1–F3, ora sull'argmin). Misurato (riduzione su N=10):

| larghezza punteggi | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

**È il centro di costo del passaggio "privato".** Spostare l'argmin sul server lo fa
passare da gratis (client) a un costo che **raddoppia per ogni bit** di precisione del
punteggio. Quindi la leva di progetto è chiara: **tenere stretta la larghezza dei
punteggi**. A larghezze realistiche pesa (es. i punteggi PCA del prototipo sono ~14
bit → secondi/decine di secondi per query; a piena larghezza Concrete 2.11 fatica
anche solo a compilare). Per riferimento, il solo calcolo dei punteggi senza argmin
(gradino 05) è ~31 ms/query.

→ Misura presa. La caratterizzazione fine (a quale larghezza/precisione conviene
girare) si fa sulla tecnica finale, sui parametri validi. La soglia open-set è un
confronto cifrato in più, marginale rispetto agli N−1 dell'argmin.

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

**Lato FHE (sui parametri validati).** Via FHE-friendly: **LBP + euclidea** (evita la
divisione χ², ~70% in chiaro, meglio di HOG). È esattamente il circuito del gradino
05 (`b_sq − 2·a·b`), ma a dimensione 3776 invece di 50. Misurato (LFW, M4 Max):

| | risultato |
|---|---|
| quantizzazione a 6 bit | **non perde**: 70,4% (float) → 72,9% (quant) |
| match cifrato (N=10→50, dim 3776) | **~75 → 95 ms/query**, punteggi esatti (cifrato == quant) |
| compilazione | ~150 ms |

Il contrasto con F6 è netto e istruttivo: la **distanza** è cifrato×chiaro (niente
PBS) → scala bene anche a dimensione 75× quella della PCA, restando interattiva; è
l'**argmin** (confronti cifrati → PBS) a esplodere. Quindi la pipeline FHE-friendly —
**embedding locale + distanza euclidea cifrata, argmin sul client** — è **fattibile e
interattiva su volti reali a ~73%** di accuratezza. La χ² (75%, il massimo in chiaro)
è più accurata ma richiede la divisione cifrata: trade-off potere/costo, da pagare
solo se serve quell'1-2% in più.

**Verso un benchmark più duro.** LFW è saturo/quasi-frontale/sbilanciato → solo
sanity-check. Lo scenario reale è un **varco cooperativo** (identificazione **1:N
open-set** con rifiuto degli sconosciuti = la galleria+soglia del gradino 06): il volto
è a **risoluzione decente**, quindi l'asse giusto è **posa/età/luce/etnia**, non la
micro-risoluzione da sorveglianza (scartati QMUL-SurvFace/SCface/TinyFace:
richiederebbero super-risoluzione). Scelta: **VGGFace2** come set duro principale (1:N
nativo, folder-per-identità, già allineato 112×112 → pronto anche per la CNN del
gradino 08), con **CPLFW + CFP-FP** come misura-posa rapida (pronti su HuggingFace,
`gaunernst/face-recognition-eval`). Metrica: **TPIR@FPIR**, non Rank-k. Divario
LFW→CPLFW ≈ 7 punti (stesso modello). **Verdetto verificato** (ricerca dedicata): dal
2018 nessun benchmark pubblico di volti reali 1:N batte VGGFace2 per attualità +
scaricabilità — il progresso è andato su training/modelli e molti dataset sono stati
ritirati per consenso. La novità post-2018 sono i **sintetici** (DCFace, DigiFace-1M,
Vec2Face: volti generati, license-clean, a tema privacy), ma per il training/verifica
1:1, non benchmark 1:N pronti. Scelta finale: **VGGFace2 + LFW + DigiFace-1M**
(sintetico 1:N maneggevole, 72 img/id). Dettagli, formati 1:1 vs 1:N, rotte di download e
citazioni in [`docs/benchmark_dataset.md`](docs/benchmark_dataset.md).

**Modello di embedding per il gradino CNN.** Intuizione chiave: l'embedding gira **in
chiaro sul client** → peso/FLOPs del modello **non toccano l'FHE**; conta solo la
**dimensione dell'embedding** (512 standard, la leva lineare del gradino 07). Quindi
possiamo usare un modello **forte**, non per forza leggero (la "CNN leggera" serve solo
per realismo edge / split-inference futura). Scelta: **`buffalo_l` di InsightFace**
(ResNet50@WebFace600K, IJB-C 97,25%, emb 512, drop-in con detection+allineamento) come
primario; **EdgeFace-S** come opzione edge. Più i sintetici **DCFace/DigiFace**
(license-clean, a tema privacy). Dettagli, licenze e accesso in
[`docs/modelli_embedding.md`](docs/modelli_embedding.md).

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

## F8 — Dataset duri integrati nel codice + split open-set per il varco
Dopo aver scelto i dataset (vedi sopra e `docs/benchmark_dataset.md`), li abbiamo resi
**usabili nella pipeline**, aggiungendo a `core/dataset.py`:

- **`carica_da_cartelle(radice, …)`** — loader generico **una sottocartella per
  identità**: vale per **VGGFace2** (reale 1:N) e **DigiFace-1M** (sintetico
  license-clean), o qualunque set in quel formato. Opzioni per gallerie maneggevoli
  (`max_identita`, `max_per_identita`) e per LBP/HOG (`grigio`).
- **`split_openset(X, y, …)`** — lo split **open-set 1:N** che ci mancava: divide in
  *galleria* (iscritti registrati), *probe noti* (devono fare match) e *probe ignoti*
  (identità fuori galleria, da **rifiutare**). È esattamente lo scenario del varco e il
  presupposto della metrica **TPIR@FPIR** del gradino 06 (identificare i noti *e*
  rifiutare gli sconosciuti). Verificato: insiemi disgiunti, nessun ignoto in galleria.

Olivetti/LFW restano scaricabili da soli via sklearn; VGGFace2/DigiFace-1M sono cartelle
locali (download pesante, separato — rotte in `docs/benchmark_dataset.md`). Il codice è
pronto: appena i dati sono presenti, i gradini di riconoscimento li usano senza modifiche.

**Dataset 1:N scaricati e funzionanti** (cartelle locali gitignorate):
- **DigiFace-1M P1** (sintetico): 2000 identità × 72 img, 112×112 già allineato →
  `carica_digiface()`. Il più comodo per l'1:N (tante img/identità, no gate).
- **VGGFace2 test** (reale): 500 identità × ~200 img, dimensioni variabili →
  ridimensionato a 112×112, `carica_vggface2_test()`.

**Primo split open-set 1:N su dati reali** (verificato): `split_openset` su DigiFace
produce galleria (50 id iscritte) + probe noti (devono matchare) + probe ignoti (50 id
da rifiutare). La macchina 1:N del varco gira end-to-end. Pronti per la metrica
TPIR@FPIR e il gradino 08.

## F10 — Le tecniche attuali nel NOSTRO protocollo (1:N open-set): il varco non regge
Finalmente la misura che conta: PCA / LBP / HOG in **identificazione 1:N open-set**
(galleria iscritti + probe noti + probe ignoti da **rifiutare**) sui dataset 1:N veri,
DigiFace (sintetico) e VGGFace2 (reale). Cartella `benchmark/`
(`identificazione_1n.py`, dati in `results/identificazione_1n.csv`). Galleria 50 id
iscritte, 50 id ignote, ~500/500/1000 immagini.

`DIR@FPIR=1%` = punto di lavoro **sicuro** (soglia che lascia passare solo l'1% di
impostori): a quella soglia, quanti **autorizzati** riconosci?

| | | Rank-1 | **DIR@FPIR=1%** | DIR@FPIR=10% |
|---|---|---|---|---|
| DigiFace (sintetico) | PCA | 8,2% | 0,2% | 1,8% |
| | LBP+χ² | 46,0% | 6,6% | 21,8% |
| | HOG | 42,2% | 10,4% | 21,4% |
| VGGFace2 (reale) | PCA | 8,6% | 0,6% | 2,6% |
| | LBP+χ² | 18,4% | **1,8%** | 4,4% |
| | HOG | 14,4% | **2,2%** | 3,8% |

**Esito.** Al punto di lavoro sicuro (FPIR=1%), su volti reali il meglio è **~2%**: il
varco negherebbe l'accesso al **~98% degli autorizzati** pur di tenere fuori gli
impostori. Il "no match" open-set c'è, ma rifiutare *bene* richiede una separazione che
queste feature non hanno (è la risposta, a numeri, alla domanda "il 50% non basta?": in
1:N il caso è 1/N, e qui siamo vicini al pavimento).

Due osservazioni:
- **PCA è morta in 1:N reale**: Rank-1 ~8% su 50 identità (il caso è 2%), DIR ≈ 0.
- **Reale ≫ sintetico in difficoltà**: VGGFace2 dimezza/triplica il calo rispetto a
  DigiFace (LBP 46%→18%, HOG 42%→14%). I volti sintetici sono puliti/frontali; i reali
  (posa, luce) distruggono le feature hand-crafted. → DigiFace è un set "di controllo"
  facile, VGGFace2 è il duro vero.

È la motivazione **misurata nel nostro protocollo** per il gradino 08 (embedding CNN):
non un "sarebbe meglio", ma "così com'è il varco non funziona".

## F9 — Le tecniche hand-crafted crollano al caso sui benchmark duri (il pavimento)
Prima di salire alla CNN, abbiamo misurato le tecniche **già fatte** (PCA del gradino
05, LBP/HOG del gradino 07) sui benchmark duri **CPLFW** (cross-posa) e **CFP-FP**
(frontale↔profilo), a buona risoluzione 112×112, nel loro protocollo nativo di
**verifica 1:1** (6.000 coppie, 10-fold, soglia migliore). Cartella
`benchmark/`, dati in `results/verifica_duri.csv`.

| benchmark | PCA+eucl | LBP+χ² | LBP+eucl | HOG+eucl |
|---|---|---|---|---|
| LFW (facile) | 61,6% | 67,6% | 62,9% | 66,3% |
| **CPLFW** (cross-posa) | **53,3%** | **51,5%** | **50,4%** | **49,5%** |
| CFP-FP (front↔profilo) | 58,0% | 61,1% | 63,2% | 63,3% |

**Su CPLFW tutte le tecniche crollano al ~caso (≈50%).** La verifica è bilanciata,
quindi 50% = lancio di moneta: le feature lineari/locali non hanno **alcuna robustezza
alla posa**. CFP-FP (front↔profilo) un po' meglio (~60%), LFW ~65%. È il **pavimento
empirico** che motiva il salto alla CNN (gradino 08): un estrattore addestrato a essere
invariante a posa/luce/età è *esattamente* ciò che qui manca.

**Caveat onesti:**
- È **verifica 1:1**, non l'1:N dei demo (metrica diversa) → confronta il *degrado*
  riga per riga (facile→duro), non i valori assoluti tra protocolli.
- Anche su LFW i numeri sono bassi (~65%): scala di grigi grezza, nessun tuning per-set,
  PCA non supervisionata sulle immagini del set. Lo scopo non è il massimo assoluto ma
  il **trend**: le tecniche semplici non reggono la posa. (Le CNN qui fanno ~92-99%.)

## F11 — Argmin + soglia ("nessun match") sotto FHE funziona; la trappola è l'inputset
L'operazione vera del varco è **argmin + verifica soglia**: il server trova il più
vicino e dice "match id=X" **oppure "nessun match"** se nessuno è entro la soglia
(impostore/sconosciuto rifiutato). Due punti chiusi qui.

**1. Concrete non ha un argmin nativo — confermato dal sorgente.** La lista
`SUPPORTED_NUMPY_OPERATORS` di `concrete-python 2.11` contiene `np.dot, np.min,
np.max, np.minimum, np.maximum, np.sum, np.where` — **non** `np.argmin`/`np.argmax`. Ha
il *valore* minimo, non l'*indice*: coerente col modello a circuito/LUT (un indice non
è un'operazione naturale sul cifrato). Quindi l'argmin si costruisce da `<` + select
(`np.where`/aritmetica), in `core/matching.py`.

**2. Il rifiuto "nessun match" funziona, ma serve l'inputset giusto.** Il circuito
completo (`circuito_distanza_argmin_soglia`) ritorna `(indice, è_match)` dove la
soglia confronta la distanza² **vera** `val_min + ‖a‖²` (il termine `‖a‖²` scartato per
il ranking va rimesso per una soglia assoluta). All'inizio il ramo "nessun match" **non
si attivava mai**: causa = **inputset troppo stretto**. Concrete inferisce la larghezza
in bit dei valori cifrati *dall'inputset*; passando solo le righe della galleria, il
range era insufficiente e il confronto della soglia andava in **overflow silenzioso**
(il valore gira modulo a un numero piccolo → sempre "sotto soglia" → sempre "match").
L'argmin restava giusto (i suoi valori erano nel range); solo la soglia sballava — un
bug subdolo, niente errore, solo risultato sbagliato.

Con un inputset **rappresentativo dei probe reali**, il circuito è corretto: verificato
**10/10**, con i "nessun match" che si attivano davvero (4/10 nel test a soglia stretta).

→ Lezione (cugina di F3/F6): **l'inputset definisce il range valido del circuito.** Va
costruito coi probe reali (o un campione che ne copra la gamma), non con la sola
galleria — altrimenti i confronti cifrati overflowano in silenzio. Vale per ogni
circuito con soglie/somme che dipendono dal probe.

## F12 — Prima/dopo: il costo (in tempo) di spostare l'argmin sul server
Il numero che il meeting chiedeva, misurato sul prototipo PCA (Olivetti). Figura:
`experiments/06_argmin_soglia/results/prima_dopo.png` (dati `prima_dopo.csv`).

| N (galleria) | PRIMA (argmin client) | DOPO (argmin server, FHE) | fattore |
|---|---|---|---|
| 2 | 51 ms | 293 ms | 6× |
| 8 | 37 ms | 1.357 ms | 36× |
| 16 | 37 ms | 3.264 ms | 87× |
| 32 | 37 ms | 7.043 ms | **190×** |

- **PRIMA** (gradino 05, argmin sul client): tempo **piatto ~37 ms/query**, quasi
  indipendente da N (è solo decifrare gli N punteggi + un argmin numpy). Nessun PBS.
- **DOPO** (gradino 06, argmin sul server sotto FHE): **cresce con N** (i confronti
  cifrati sono ~N−1), da 6× a **190×** il costo del client.

**Caveat di onestà (importante).** Il "dopo" è misurato a **precisione ridotta** (8
componenti, 3 bit → punteggi ~6 bit) per renderlo eseguibile: alla precisione della
**PCA decente** (50 comp, 6 bit → ~14 bit) l'argmin server è **fuori scala** (pannello
B della figura: il costo raddoppia ~ad ogni bit, F6). Quindi i fattori 6–190× sono un
**limite inferiore**: sulla PCA piena il divario è molto maggiore. La figura mostra
entrambe le leve: (A) la galleria N, (B) la larghezza in bit dei punteggi (quella
dominante), con segnato dove cade la PCA decente.

Conclusione: lo spostamento dell'argmin sul server — necessario per privacy — ha un
costo reale e quantificato; la leva di progetto per renderlo praticabile è **ridurre la
larghezza dei punteggi** (meno componenti/bit, o troncamento prima della riduzione).

## F13 — Come scala la PCA sui nostri dataset: accuratezza vs bit dei punteggi
Caratterizzazione in chiaro della PCA al variare delle componenti, su tutti e quattro i
dataset, misurando insieme **accuratezza (Rank-1 1:N)** e **larghezza-bit dei
punteggi** (la leva di costo dell'argmin, F6/F12). Figura
`benchmark/results/pca_scaling.png` (dati `pca_scaling.csv`).

| dataset | Rank-1 (8→128 comp) | bit punteggi |
|---|---|---|
| Olivetti (laboratorio) | 77% → 87% | 13–14 |
| LFW | 14% → 30% | 13–15 |
| DigiFace (sintetico) | 7% → 9% | 13–15 |
| VGGFace2 (reale) | 7% → 9% | 13–14 |

Due fatti, entrambi importanti:

1. **Accuratezza (pannello A):** solo Olivetti (volti da laboratorio) regge (~87%); su
   tutto ciò che è reale/duro la PCA è **al pavimento** (LFW ~30%, DigiFace/VGGFace2
   ~8–9%, vicino al caso 1/50=2%). Aggiungere componenti non salva: la PCA non
   generalizza. Conferma F5/F10 su scala più ampia.

2. **Bit dei punteggi (pannello B):** la larghezza è **già ~13 bit con sole 8
   componenti** e sale appena a 14–15. Il motivo: il punteggio è `‖b‖²−2ab`, e il
   termine `‖b‖²` (somma di quadrati) **domina e satura la larghezza** quasi subito,
   indipendentemente da quante componenti aggiungi. Quindi non c'è una zona "poche
   componenti = punteggi stretti = argmin economico": **la PCA è intrinsecamente nella
   zona cara** (~14 bit) della curva di costo dell'argmin.

→ Doppio vincolo: la PCA è **debole dove serve** (dati reali) **e cara da rendere
privata** (punteggi larghi). Non c'è un punto di lavoro buono. È la motivazione, a
numeri e su una figura, per (a) salire a un embedding migliore della PCA, e (b) per
l'argmin: se la larghezza dei punteggi non si comprime "gratis", serve un troncamento
esplicito (`truncate_bit_pattern`) o un embedding nativamente a pochi bit.