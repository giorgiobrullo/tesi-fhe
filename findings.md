# Findings — diario del progetto

Diario in ordine cronologico di cosa abbiamo fatto e capito, dal primo "hello world"
FHE fino al sistema che riconosce volti reali. Ogni voce (F0, F1, …) è un passo: cosa
abbiamo provato, cosa è venuto fuori, e perché. Si legge dall'alto. I concetti vengono
ripresi ogni volta che servono, senza darli per scontati. Prima un ripasso dei termini,
poi i passi.

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

## F10 — Le tecniche attuali nel NOSTRO protocollo (1:N open-set): il varco non regge
Finalmente la misura che conta: PCA / LBP / HOG in **identificazione 1:N open-set**
(galleria iscritti + probe noti + probe ignoti da **rifiutare**) sui dataset 1:N veri,
DigiFace (sintetico) e VGGFace2 (reale). Cartella `benchmark/`
(`identificazione_1n.py`, dati in `results/identificazione_1n.csv`, figura
`results/tecniche_1n.png`). Galleria 50 id
iscritte, 50 id ignote, ~500/500/1000 immagini.

**Le due metriche (non confonderle).** Rispondono a domande diverse:
- **Rank-1** — la versione *facile*: "dato che la persona **è** iscritta, il volto più
  vicino in galleria è il suo?". **Ignora la soglia** (dà sempre una risposta, non può
  rifiutare). Su 50 identità il **caso** è 1/50 = **2%**, quindi un Rank-1 dell'8% è
  solo ~4× il caso → sbaglia comunque l'identità del ~92% degli iscritti. *Generosa.*
- **DIR@FPIR=1%** (Detection & Identification Rate a False Positive Identification Rate
  = 1%) — la versione *vera*, il varco: a una soglia tarata perché **solo l'1% degli
  impostori** entri, **quanti autorizzati riconosci e fai passare?**. Chiede due cose
  insieme — identità giusta **e** sotto soglia — e include il "no match". È il numero
  che conta per il controllo-accessi.

Stesso esempio (PCA su VGGFace2): **Rank-1 8,6%** (appena sopra il caso) ma
**DIR@FPIR=1% 0,6%** (≈ zero). La PCA fa pietà su *entrambe*; il Rank-1 sembra meno
disastroso solo perché è la metrica indulgente.

| | | Rank-1 | **DIR@FPIR=1%** | DIR@FPIR=10% |
|---|---|---|---|---|
| DigiFace (sintetico) | PCA | 8,2% | 0,2% | 1,8% |
| | LDA/Fisherfaces | 16,6% | 0,2% | 1,2% |
| | LBP+χ² | 46,0% | 6,6% | 21,8% |
| | HOG | 42,2% | 10,4% | 21,4% |
| VGGFace2 (reale) | PCA | 8,6% | 0,6% | 2,6% |
| | LDA/Fisherfaces | 7,6% | 0,4% | 1,6% |
| | LBP+χ² | 18,4% | **1,8%** | 4,4% |
| | HOG | 14,4% | **2,2%** | 3,8% |

**Esito.** Al punto di lavoro sicuro (FPIR=1%), su volti reali il meglio è **~2%**: il
varco negherebbe l'accesso al **~98% degli autorizzati** pur di tenere fuori gli
impostori. Il "no match" open-set c'è, ma rifiutare *bene* richiede una separazione che
queste feature non hanno (è la risposta, a numeri, alla domanda "il 50% non basta?": in
1:N il caso è 1/N, e qui siamo vicini al pavimento).

Tre osservazioni:
- **PCA è morta in 1:N reale**: Rank-1 ~8% su 50 identità (il caso è 2%), DIR ≈ 0.
- **LDA/Fisherfaces (l'ultima geometrica) non salva.** La versione *supervisionata*
  della PCA raddoppia la PCA sul sintetico (16,6% su DigiFace, pulito/frontale) ma **sui
  volti reali non aiuta** (7,6%, perfino un filo sotto la PCA): le direzioni
  discriminanti stimate sulla galleria non generalizzano alla variabilità reale. →
  **lo scalino geometrico è esaurito** (PCA *e* LDA falliscono sul reale).
- **Reale ≫ sintetico in difficoltà**: VGGFace2 dimezza/triplica il calo rispetto a
  DigiFace (LBP 46%→18%, HOG 42%→14%). I volti sintetici sono puliti/frontali; i reali
  (posa, luce) distruggono le feature hand-crafted. → DigiFace è un set "di controllo"
  facile, VGGFace2 è il duro vero.

È la motivazione **misurata nel nostro protocollo** per il gradino 08 (embedding CNN):
abbiamo provato *tutte* le tecniche pre-CNN — geometriche (PCA, LDA) e descrittori
locali (LBP, HOG) — e nessuna fa funzionare il varco su volti reali (DIR@FPIR=1% ≤ 2%).
Non un "sarebbe meglio", ma "così com'è il varco non funziona, ed è il momento della CNN".

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

## F14 — La CNN (anche leggera) sfonda il pavimento: il varco funziona
Terzo gradino della scaletta (CNN), partendo dalla **bassa profondità**:
**MobileFaceNet** (InsightFace `buffalo_s`, `w600k_mbf`, linea ArcFace, embedding
512-dim, 13 MB), eseguito in chiaro sul client. Stesso protocollo 1:N open-set e stessa
figura dei pre-CNN (`benchmark/results/tecniche_1n.png`, gradino
`experiments/08_cnn/`).

| | | Rank-1 | **DIR@FPIR=1%** |
|---|---|---|---|
| DigiFace (sintetico) | migliore pre-CNN (HOG) | 42,2% | 10,4% |
| | **CNN MobileFaceNet** | **99,6%** | **94,2%** |
| VGGFace2 (reale) | migliore pre-CNN (HOG) | 14,4% | 2,2% |
| | **CNN MobileFaceNet** | **97,8%** | **96,0%** |

**Il salto.** Su volti reali (VGGFace2), al punto di lavoro sicuro (FPIR=1%) si passa da
**~2% a 96%**: il varco da inutilizzabile a **pienamente funzionante** — e con la CNN
*leggera*, il primo gradino CNN di Carnemolla. Conferma tutto il filo: le tecniche
semplici falliscono perché manca l'invarianza a posa/luce (F9–F13), la CNN ce l'ha.

**Lezione (importante, vale come finding a sé): l'allineamento è critico per le CNN.**
Al primo tentativo la CNN su VGGFace2 dava solo **10,4%** Rank-1 (peggio dei
descrittori!), perché avevamo solo *ridimensionato* le immagini a 112×112. ArcFace/
MobileFaceNet pretendono il volto **allineato sui 5 landmark** al template canonico:
con la detection+allineamento di InsightFace (sui volti grezzi a piena risoluzione) la
CNN sale a **97,8%**. DigiFace era già allineato (sintetico, frontale) → funzionava
subito (99,6%). → Il preprocessing (detect+align) è parte integrante della pipeline CNN,
non un dettaglio.

**Implicazione FHE (gancio col seguito):** l'embedding è **512-dim** — più *piccolo*
della dimensione dei descrittori (gradino 07, dim 3776) → la distanza cifrata costerà
*meno*, non di più. E siccome l'embedding gira in chiaro sul client, la potenza della
CNN non tocca il costo FHE. La pipeline privacy-preserving con un riconoscimento che
**funziona davvero** è quindi alla portata: prossimo passo, il costo FHE a dim 512.

## F15 — Lato FHE della CNN: la quantizzazione non costa, il match è interattivo
Chiusura del cerchio end-to-end (`experiments/08_cnn/costo.py`). Sugli embedding
MobileFaceNet (DigiFace, dim 512):

| | risultato |
|---|---|
| quantizzazione a 6 bit | **non perde**: DIR@FPIR=1% 89,3% (float) = 89,3% (quant) |
| match cifrato (dim 512, N=25–50) | **~63 ms/query**, punteggi esatti (cifrato == quant) |

**Più economico del gradino 07** (descrittori, dim 3776 → ~75–95 ms): l'embedding CNN è
più piccolo → la distanza cifrata costa meno. Conferma l'intuizione: la potenza del
modello (in chiaro sul client) non tocca l'FHE, conta solo la dimensione dell'embedding.

→ La pipeline completa è coerente e interattiva: **client** calcola l'embedding CNN in
chiaro, quantizza (senza perdita), cifra; **server** calcola la distanza cifrata in
~63 ms; il riconoscimento **funziona** (89–96% DIR@FPIR, F14). Resta aperto il solo
argmin cifrato sul server (F6/F12) — da rendere praticabile con `truncate_bit_pattern`
o tenendo l'embedding a pochi bit (qui 6 bit bastano e non costano accuratezza).

## F16 — CNN profonda (ResNet50): un ritocco, e a costo FHE invariato
Gradino 08b: salita all'**alta profondità** della scaletta — ResNet50 (InsightFace
`buffalo_l`, `w600k_r50`, embedding 512-dim), confrontata con la leggera MobileFaceNet
sullo stesso protocollo 1:N.

| | | MobileFaceNet (leggera) | ResNet50 (profonda) |
|---|---|---|---|
| DigiFace (sintetico) | DIR@FPIR=1% | 94,2% | **97,2%** |
| VGGFace2 (reale) | DIR@FPIR=1% | 96,0% | **97,0%** |
| VGGFace2 | Rank-1 | 97,8% | **98,8%** |

La profonda è **un filo meglio** (+1–3 punti DIR), ma su questo benchmark a 50 identità
siamo già vicini al soffitto. Due conclusioni:

1. **Il salto vero è hand-crafted → CNN** (~2% → 96%), non *leggera → profonda* (~1–3
   punti). La CNN leggera prende già quasi tutto il guadagno.
2. **A parità di dimensione (512), il costo FHE è identico.** L'embedding gira in chiaro
   sul client, quindi salire alla ResNet costa di più solo *lì*, non sul cifrato. Per la
   pipeline FHE la profonda è quindi un upgrade "gratis" (stesso match cifrato ~63 ms,
   F15) che regala l'ultimo punto di accuratezza, se il client se la può permettere.

→ La scaletta di Carnemolla è completa (geometriche → descrittori → CNN leggera →
profonda), tutta su un'unica figura (`benchmark/results/tecniche_1n.png`) e nello stesso
protocollo 1:N open-set. Il sistema privacy-preserving riconosce volti reali al ~97% al
punto di lavoro sicuro, con match cifrato interattivo.

## F17 — Il benchmark è saturo? Test scalando la galleria
Sospetto legittimo: a 50 identità la CNN fa ~96-97% e leggera≈profonda — segno che il
benchmark è troppo facile e non distingue più i modelli. Test: far crescere il numero
di identità iscritte e vedere se il DIR@FPIR scende (`scaling_galleria.py`, figura
`results/scaling_galleria.png`).

| galleria iscritte | DigiFace MFN | DigiFace RN50 | VGGFace2 MFN | VGGFace2 RN50 |
|---|---|---|---|---|
| 25 | 83% | 94% | 91% | 94% |
| 50 | 89% | 96% | 93% | 95% |
| 125 | 85% | 90% | 91% | 94% |
| 250–500 | 84%→81% | 92%→90% | — | — |

Tre risposte:

1. **NON è saturo nel senso "tutto al 99%".** Il DIR **tiene** (80-96%) anche fino a 500
   iscritti, scendendo solo lievemente. La CNN **scala davvero** a gallerie grandi — è
   un risultato genuino, non un artefatto di galleria minuscola. (Buona notizia per il
   varco reale.)

2. **Ma a 50 id c'era saturazione "tra modelli".** Lì leggera e profonda pareggiavano;
   **allo scale ResNet50 sta costantemente sopra MobileFaceNet** (~+5-10 punti su
   DigiFace, ~+2-3 su VGGFace2). Quindi il benchmark *piccolo* non distingueva i modelli;
   quello *grande* sì → il modello profondo si guadagna il suo posto solo quando il test
   è abbastanza duro.

3. **DigiFace (sintetico) è più duro di VGGFace2 (reale)** per la CNN — controintuitivo
   ma logico: i modelli sono addestrati su volti reali (WebFace600K), quindi il sintetico
   è **fuori-distribuzione** e fa da stress test. È il caveat di onestà sui numeri alti:
   VGGFace2 è *in-distribuzione*; gallerie enormi (migliaia), condizioni out-of-domain e
   non-cooperative abbasserebbero ancora il DIR. Entro ciò che possiamo testare, però, il
   sistema è forte e scala.

## F18 — Scaling su larga scala: a migliaia di iscritti il DIR scende davvero
Spinto oltre i 500 iscritti (richiesta di scalare ancora). Scaricata la parte DigiFace
a **33.333 identità** (×5 img), sweep fino a **8000 iscritti** (sintetico = stress test
out-of-distribution, F17). Figura `benchmark/results/scaling_grande.png`.

| iscritti | MobileFaceNet | ResNet50 |
|---|---|---|
| 250 | 88,3% | 91,7% |
| 1000 | 81,4% | 88,5% |
| 2000 | 77,0% | 85,5% |
| 4000 | 74,3% | — |
| **8000** | **70,7%** | — |

**Ora il calo si vede.** A galleria grande il DIR@FPIR=1% scende in modo netto e
regolare: MobileFaceNet **88% → 71%** da 250 a 8000 iscritti. Conferma definitiva che
**il ~96% a 50 identità era ottimistico/saturo**: il numero *onesto* a gallerie
realistiche (migliaia di persone) è sensibilmente più basso. È la correzione che il
sospetto di saturazione meritava — e un risultato di scalabilità vero per la tesi.

Due cose:
- **La profonda regge meglio allo scale.** ResNet50 degrada più dolcemente (92% → 85% a
  2000 iscritti) di MobileFaceNet (84% → 77%): il modello profondo si guadagna il posto
  proprio sulle gallerie grandi (coerente con F16/F17, ora marcato). NB: ResNet50 è
  ~20× più lenta da embeddare (CPU), per questo il suo sweep si ferma a 2000.
- **Caveat sul caveat:** è sintetico/OOD; su volti reali in-distribuzione i valori
  assoluti sarebbero più alti, ma la **forma** (degrado col crescere della galleria) è
  reale e attesa. Il sistema resta usabile (70-90%), ma "il varco funziona al 96%" va
  detto come "a galleria piccola"; a migliaia di iscritti è ~70-85%.

## F19 — Scaling su volti REALI puliti (VGGFace2 train): regge bene allo scale
Controparte reale di F18 (che era sintetico). Scaricato VGGFace2 **train** (8.631
identità reali, 37 GB) — è il dataset che avevamo scelto (F8, `docs/`) e **non** è
training dei modelli buffalo → numeri **onesti/difendibili**. Allineati 30.000 volti
(detection, ~35 min), embedding MFN + ResNet50, sweep galleria. Figure
`scaling_reale.png` e — combinata reale vs sintetico — `scaling_combinato.png`.

Spinto al **massimo di iscritti reali** (tutte le 8.631 identità di VGGFace2 train, 52k
volti allineati):

| iscritti | MobileFaceNet | ResNet50 |
|---|---|---|
| 250 | 93,3% | 96,3% |
| 1000 | 90,2% | 95,8% |
| 2000 | 88,4% | 95,5% |
| 4000 | 86,6% | 94,5% |
| **4300 (max)** | **86,0%** | **94,2%** |

**Su volti reali il sistema scala molto meglio del sintetico, fino al massimo.** Al
**massimo di iscritti reali (4.300, tutte le identità VGGFace2 train)** ResNet50 tiene
**94,2%** — cala solo ~2 punti da 250 a 4.300 (curva quasi orizzontale); MobileFaceNet
**86,0%**, calo dolce e regolare. Molto meglio del DigiFace OOD (che a 2000 era 77/85%
e a 8000 scende a 71%).

**Quadro finale dello scaling (figura combinata):** la verità sta tra le due curve.
- *Reale, in-distribuzione* (VGGFace2): ~87-95% anche a 1000-2000 iscritti → **regge**.
- *Sintetico, OOD* (DigiFace): ~70-85% a migliaia → stress test pessimistico.
- In entrambi: **la profonda (ResNet50) scala meglio della leggera** — il guadagno del
  modello profondo è proprio sulle gallerie grandi, dove serve.

→ Risposta onesta e completa al sospetto di saturazione: il ~96% iniziale era a
galleria piccola; allo scale su volti reali puliti la profonda (ResNet50) **resta a
~95% fino a 2000 iscritti** (quasi nessun calo), la leggera ~87% a 4000. Su un dominio
davvero ostile (sintetico/OOD) si scende a ~70-85%. Il varco è **realisticamente
usabile** anche a migliaia di iscritti reali — e il modello profondo lo fa quasi senza
perdite.

**Nota metodologica (importante):** non addestriamo nulla — la CNN è **pre-addestrata e
congelata**, usata solo come estrattore. La separazione train/test è già garantita dal
protocollo: **iscrizione ≠ probe** (foto diverse della stessa persona) e **iscritti ≠
impostori** (identità disgiunte) → non si valuta mai su dati "visti". Per PCA/LDA, che
si stimano sulla galleria, vale lo stesso (galleria = loro training, probe = test). Il
solo residuo è la possibile sovrapposizione di *celebrità* tra VGGFace2 e il training
originale della CNN — caveat standard del campo, non eliminabile senza il dataset di
training del modello.
## F20 — Modelli più grandi: si sale, ma poco — il 99% non è di questo protocollo
Domanda: salendo di modello (e con la distillazione, come da Carnemolla) si arriva al
99%? Confronto tre profondità crescenti sullo stesso protocollo 1:N open-set reale
(VGGFace2), embedding sempre in chiaro → **costo FHE invariato** (dim 512 per tutti).
Figura `benchmark/results/scaling_modelli.png`.

| iscritti | MobileFaceNet | ResNet50 | ResNet100 |
|---|---|---|---|
| 250 | 93,3% | 96,3% | **96,7%** |
| 1000 | 90,2% | 95,8% | **96,5%** |
| 4300 (max) | 86,0% | 94,2% | **95,5%** |

**Salire di modello aiuta, ma poco.** ResNet100 (antelopev2, Glint360K) è il migliore e
quasi piatto (96,7% → 95,5% da 250 a 4.300 iscritti), ma stacca ResNet50 solo di
**+0,4 / +1,3 punti**. → Siamo **vicini al tetto pratico**: ~95-96% è il massimo per
questo protocollo duro (1:N open-set, migliaia di iscritti).

**Il 99% non è raggiungibile qui — ed è giusto così.** I "99,8%" che si citano sono
**verifica 1:1 su LFW**, un compito molto più facile; il nostro 1:N open-set a migliaia
di iscritti è duro, e anche i modelli SOTA stanno ~95-97%. Confermata la previsione: un
modello più grande dà +1-3 punti, non il salto al 99%.

**Sulla distillazione (chiarimento metodologico):** *non* serve per alzare
l'accuratezza — lo student ≤ teacher (lo imita, non lo supera), quindi distillare
ResNet100 darebbe al massimo ~95%. La distillazione serve solo se si vuole l'embedding
**sotto FHE** (split inference): un modello piccolo *compilabile* in Concrete che imita
il grande, per nascondere anche il modello al client. È un obiettivo di privacy, non di
accuratezza. Per più accuratezza, lato nostro, basta un modello più grande **direttamente**
(gratis lato FHE, gira in chiaro sul client).

→ Conclusione: il sistema è **vicino al massimo pratico** (~95-96% con ResNet100 a
migliaia di iscritti reali). Oltre non si va cambiando modello; servirebbe un protocollo
più facile (verifica 1:1) o accettare che ~95% è l'ottimo onesto per il varco 1:N.

**Conferma a numeri — il costo FHE è indipendente dal modello** (`costo_modelli.py`):
il match cifrato su DigiFace è ~102 ms (MobileFaceNet), ~111 ms (ResNet50), ~97 ms
(ResNet100) — **uguale per tutti**, perché dipende solo dalla dimensione (512), non dal
modello (l'embedding gira in chiaro sul client). La quantizzazione a 6 bit non perde e
il cifrato dà i punteggi esatti per tutti e tre. → **Si può usare il modello migliore
(ResNet100, ~95,5%) a costo cifrato identico al più leggero.** La potenza del
riconoscimento è gratis lato FHE.

## F21 — Argmin cifrato sul server con embedding CNN: il muro, e cosa abbiamo provato
A questo punto davamo per scontato che l'argmin (e la soglia) **dovessero** stare sul
server, sotto FHE: farli sul client sembrava vanificare la privacy (il client imparerebbe
la distanza con ogni iscritto, F6). *(In F22 ridimensioneremo questa premessa — dipende
da quanto ci si fida del client. Ma intanto proviamo a farlo sul server.)* E sui punteggi
degli embedding **CNN a 512 dimensioni** troviamo un muro duro. Diario dei tentativi.

**Il problema.** Il punteggio `‖b‖² − 2·a·b` su 512 dimensioni quantizzate a 6 bit è
largo **~18 bit**. Il confronto cifrato di Concrete 2.11 è limitato a **~16 bit**:
l'argmin sui punteggi CNN **non compila** (`this 18-bit value is used as an operand to a
comparison operation`). E i ~18 bit nascono dall'accumulatore su 512 dimensioni, non
dalla precisione per-valore → non si abbassano facilmente.

**Cosa abbiamo provato (e perché non basta):**
1. **`round_bit_pattern`** (arrotonda via i bit bassi dei punteggi prima del confronto).
   *No.* Azzera i bit bassi ma **non riduce il range**: il valore resta a 18 bit, quindi
   il confronto è ancora su 18 bit → rifiutato. Lo strumento serve a far seguire una
   tabella a precisione ridotta, non a stringere un confronto.
2. **Dividere i punteggi** (`// 2^k`, per tagliare il range alla metà). *No.* L'operazione
   stessa prende in input il valore a 18 bit → tabella su 18 bit → non compila. Qualunque
   manipolazione *a valle* del punteggio largo è bloccata dallo stesso limite.
3. **Comprimere l'embedding** (PCA a meno dimensioni + meno bit), per stringere i
   punteggi **alla sorgente**. È l'unica leva che funziona, **ma**: per rendere l'argmin
   *veloce* (secondi) serve comprimere così tanto (≤16-32 dim, 2-3 bit) da **distruggere
   l'accuratezza** che la CNN ci aveva dato. Non è un'ottimizzazione, è un trade-off:
   o accuratezza piena e argmin intrattabile, o argmin veloce e riconoscimento a pezzi.

**Conclusione (onesta).** Non esiste una "linea che scende coi miglioramenti": l'argmin
cifrato sul server **non scala agli embedding CNN ad alta dimensione** — è un **muro**
(limite di bit-width del confronto in Concrete), non una discesa. Estende ed è il
contraltare di F6/F12: lì il costo cresceva ~2×/bit; qui i bit sono troppi a priori.

→ Come farlo davvero (da esplorare): (a) **punto di compromesso dimensione/accuratezza** —
PCA dell'embedding a ~128-256 dim, argmin tractabile ma lento (~minuti/query) con qualche
punto di accuratezza in meno; (b) **privacy a livello di protocollo** invece che di
circuito — es. il server **mescola** i punteggi così il client vede solo distanze
anonime + l'identità vincente, senza argmin cifrato; (c) un argmin **a torneo/gerarchico**
che non materializzi mai il punteggio pieno. Il client-argmin (~100 ms) resta solo come
*baseline funzionante ma non privata*, non come soluzione.

## F22 — L'argmin server serve davvero? Dipende dal modello di minaccia
Ripensando: con l'**argmin sul client** (la demo funzionante, ~100 ms) il server calcola
i punteggi cifrati e li rimanda **senza mai decifrare**. Quindi il server **non impara
nulla** — né il volto, né i punteggi, né l'esito. L'unico a vedere le distanze è il
**client** (che ha la chiave). Conseguenza importante:

- Sotto il modello di minaccia naturale del varco — **server honest-but-curious, client
  fidato** (il terminale è del gestore) — il sistema **client-argmin a ~100 ms è già
  privacy-preserving**: protegge il volto e l'esito dal server. Niente argmin cifrato.
- L'argmin (e soglia) **sul server** serve **solo** se il **client non è fidato** (un
  client malevolo non deve poter sondare la galleria imparando le distanze). È un
  irrobustimento extra, ed è quello che sbatte sul muro FHE (F21).

→ Quindi "l'argmin cifrato sul server è necessario" **non è assoluto**: dipende da quanto
si fida il client. Il contributo della tesi può legittimamente fermarsi al sistema
client-argmin (funziona, è privato verso il server, ~100 ms con ResNet100 al ~95%), e
trattare il server-argmin come hardening per il caso untrusted-client (fattibile solo a
dimensione ridotta, vedi F23).

## F23 — Comprimere l'embedding: a 128 dim quasi gratis (la leva per l'FHE)
Per stringere i punteggi (e avvicinare l'argmin cifrato al fattibile, F21) si riduce la
**dimensione** dell'embedding con PCA. Misurato il trade-off accuratezza↔dimensione
(`scaling_dimensione.py`, 1000 iscritti reali, figura `scaling_dimensione.png`):

| dim | MobileFaceNet | ResNet50 |
|---|---|---|
| 512 | 90,4% | 95,8% |
| 256 | 90,4% | 95,6% |
| **128** | **88,6%** | **94,4%** |
| 64 | 78,1% | 86,8% |
| 32 | 47,9% | 55,9% |
| 16 | 12,2% | 14,0% |
| 8 | 0,6% | 1,0% |

**Si comprime fino a 128 dimensioni quasi gratis** (ResNet50 −1,4 punti, MobileFaceNet
−1,8), e 256 è identico a 512. Sotto c'è un **ginocchio netto**: 64 ancora usabile
(~87%), a 32 dimezza, sotto 16 crolla. → **128 dim è il punto FHE-friendly**: stesso
riconoscimento, punteggi più stretti (e match cifrato più economico, costo ~lineare
nella dimensione). NB: per rendere l'argmin cifrato *tractabile* serve 128 dim **+**
quantizzazione bassa (~4 bit) → punteggi ~14 bit → argmin lento (~minuti/query) ma non
intrattabile. È l'operating point del server-argmin privato: lento, per basso throughput.

**Velocità del match cifrato vs dimensione** (`velocita_dimensione.py`, figura
`velocita_dimensione.png`): 512→152 ms, 256→65, 128→63, 64→59, 32→57. Il match
(cifrato×chiaro, no PBS) è **economico e quasi piatto sotto 256** (~60 ms): dominano i
costi fissi, non la dimensione. Ridurre l'embedding aiuta poco il *match* (già a terra),
ma è la leva per rendere l'*argmin* cifrato fattibile (F21/F23). Quadro completo: la
dimensione 128 è il punto dolce — accuratezza ~94% (ResNet50), match ~63 ms, e punteggi
abbastanza stretti da avvicinare l'argmin privato al fattibile.

## F24 — Ottimizzare l'argmin server: niente hardware-lever, e la compressione aiuta al margine
Tentativo di "ottimizzare fortissimo" l'argmin cifrato sul server. Due fatti duri.

**Niente leve hardware su questa macchina.** Il parallelismo dataflow di Concrete
**non è disponibile su macOS** (`Dataflow parallelism is not available in macOS`), e la
GPU nemmeno (Apple Silicon, no CUDA). Quindi l'unica leva è **comprimere l'embedding**
(meno bit nei punteggi). Numeri veri misurati (argmin su N=8, 4 bit):

| dim PCA | accuratezza | argmin cifrato |
|---|---|---|
| 16 | ~14% | **42 s** (misurato) |
| 32 | ~56% | minuti |
| 64 | ~87% | **esplode la RAM in compilazione** (decine di GB) |
| 128 | ~94% | intrattabile |
| 512 | ~95% | muro (non compila) |

→ Dove l'accuratezza è usabile (≥64 dim) l'argmin è intrattabile (tempo *o* memoria);
dove è veloce (16 dim) l'accuratezza è inutile. Niente operating point buono.

**La compressione migliore aiuta, ma non rompe la frontiera.** Abbiamo usato la PCA;
provata anche la **LDA** (supervisionata, `compressione.py`, figura `compressione.png`):
a dim bassa la LDA batte la PCA (dim 16: 25% vs 14%; dim 32: 65% vs 56%), sopra 64 la
PCA torna avanti (la LDA si sovra-adatta agli iscritti). Ma anche con LDA, dim 32 = 65%
(tractabile ma lento) e dim 64 = 84% (RAM esplode) → la compressione sposta i punti di
qualche punto, **non sposta il muro**.

**Conclusione (definitiva su questo hardware).** L'argmin cifrato sul server con
embedding CNN di qualità è **non praticabile** ottimizzando software/compressione: serve
**hardware diverso** (GPU / parallelismo) o un'**idea nuova** (proiezione *appresa* a
bassa dimensione — distillazione dell'embedding; argmin a torneo *con* parallelismo;
oppure privacy a livello di protocollo). Il sistema valido resta quello con **argmin sul
client** (~95%, ~100 ms, server cieco), che è privacy-preserving sotto il modello di
minaccia naturale (F22). Il server-argmin (difesa dal client non fidato) è lavoro futuro.
