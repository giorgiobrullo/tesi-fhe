# Findings — diario del progetto

Diario in ordine cronologico di cosa abbiamo fatto e capito, dal primo "hello world"
FHE fino al sistema che riconosce volti reali.

I pallini nei titoli segnano il filone: 🔵 riconoscimento (la scaletta delle tecniche),
🔴 lato FHE (cifratura, match cifrato, argmin privato sul server). I due filoni si intrecciano.

## Concetti di base

**FHE** (cifratura completamente omomorfica). Permette di fare *calcoli su dati
cifrati* senza decifrarli: il server elabora il cifrato e produce un risultato
cifrato, che solo chi ha la chiave può aprire. Lo schema che usiamo è **TFHE**, che lavora su
interi (niente float: i valori vanno quantizzati). Lo abbiamo esplorato prima con Zama
**Concrete-python** — si definisce una funzione Python e il compilatore produce il circuito
cifrato, comodo per capire cosa è fattibile — e poi implementato in **tfhe-rs**, la libreria TFHE
nativa, che è dove vive il sistema finale: sullo stesso calcolo e sulla stessa macchina è ~100×
più veloce (F32, F64), perché il collo di bottiglia di Concrete è il compilatore, non lo schema.

Rumore e bootstrapping. Ogni testo cifrato porta del *rumore* (serve alla
sicurezza). Ogni operazione lo fa crescere; se cresce troppo, la decifratura dà un
risultato sbagliato. Il **bootstrapping** è l'operazione che "ripulisce" il rumore
e permette di calcolare all'infinito, ed è ciò che rende l'FHE *completa*.

**PBS** (programmable bootstrapping). In TFHE il bootstrapping è anche
*programmabile*: mentre ripulisce il rumore può applicare una funzione qualsiasi al
valore cifrato, tramite una tabella (input → output). È l'operazione cara,
e il suo costo cresce ~2^bit con la precisione del valore (più bit = tabella più
grande). Quasi tutto il costo FHE è qui.

Cosa è economico e cosa è caro:

| operazione | costo | serve un PBS? |
|---|---|---|
| cifrato + cifrato | economico | no |
| cifrato × numero in chiaro | economico | no |
| cifrato × cifrato | caro | sì |
| funzione non lineare di un cifrato (quadrato, confronto, ReLU…) | caro | sì |

Regola pratica: *moltiplicare per un numero noto è quasi gratis; moltiplicare due
cifrati tra loro costa un PBS.*

La **"formula espansa"**. La distanza al quadrato `‖a−b‖² = Σ(aᵢ−bᵢ)²`. Calcolata
in modo ingenuo, il quadrato `(aᵢ−bᵢ)²` è cifrato×cifrato, cioè un PBS (caro), anche se `b`
è in chiaro. Ma con l'algebra `(a−b)² = a² − 2ab + b²`:
`‖a−b‖² = Σaᵢ² − 2·Σaᵢbᵢ + Σbᵢ²`. Con `a` cifrato e `b` in chiaro:
- `Σbᵢ²` è tutto in chiaro, quindi gratis;
- `Σaᵢbᵢ` (prodotto scalare) è cifrato×chiaro, niente PBS;
- `Σaᵢ²` è cifrato×cifrato (PBS) ma dipende solo dal probe `a`: si calcola una
  volta, e per trovare il più vicino (argmin) è una costante uguale per tutti,
  così si butta.

Risultato: il costo *per faccia della galleria* è solo il prodotto scalare,
quindi economico e lineare. (Misurato in F2.)

---

## 🔴 F0 — Concrete gira nativo su macOS arm64, senza Docker
`concrete-python 2.11.0` si installa e funziona end-to-end (Esp. 00).

## 🔴 F1 — Il modello di sicurezza
Il probe (il volto da riconoscere) è cifrato sotto la chiave del client, mentre
la galleria sta in chiaro sul server (è un dato del server: è lui che iscrive
le persone). Il server calcola il match alla cieca e non impara né il volto né
l'esito; solo il client decifra il risultato. Di conseguenza l'operazione reale è
cifrato×chiaro, non cifrato×cifrato. Chiamiamo questo **Mondo 1**, ed è il default.

Esiste anche un **Mondo 2**, in cui la galleria è cifrata: in TFHE si può fare a costo *leveled*
con il prodotto esterno GGSW⊡GLWE (F51), quindi senza il rincaro che paga la letteratura in
CKKS/BFV. Non è però «più privacy» in senso assoluto: il prodotto esterno vuole la **stessa
chiave**, quindi chi cifra il probe può decifrare la galleria. È uno **scambio** — protegge dal
server, indebolisce verso il client — e va scelto in base a chi si teme.

## 🔴 F2 — Tenere la galleria in chiaro da solo non basta: serve la formula giusta
Esp. 03 confronta tre modi di calcolare lo stesso punteggio per faccia:

- V1 `‖a−b‖²` cifrato×cifrato, il caso peggiore.
- V2 `‖a−b‖²` con galleria in chiaro, ingenuo: costa quanto V1, perché mettere la
  galleria in chiaro non basta, dato che il quadrato `(a−b)²` resta cifrato×cifrato e
  richiede il bootstrapping.
- V3 formula espansa `‖b‖² − 2·a·b`, solo prodotto scalare cifrato×chiaro, quindi
  niente bootstrapping, e il costo per faccia crolla e resta quasi piatto al
  crescere della dimensione.

Il guadagno viene dallo spostare il quadrato cifrato fuori dal ciclo
sulla galleria, più che dal semplice mettere la galleria in chiaro.

## 🔴 F3 — Lezione pratica di Concrete: niente moltiplicazioni chiaro×chiaro nel circuito
Tentando V3 come `‖b‖² − 2·a·b` con `‖b‖²` calcolato nel circuito, Concrete
rifiuta: `clear-clear multiplications are not supported`. La parte tutta in chiaro
(`‖b‖²`) va precalcolata in Python e iniettata come scalare in chiaro. Nel
circuito resta solo ciò che tocca il cifrato.
Principio generale: tieni fuori dal circuito tutto ciò che è puramente in chiaro.

## 🔵 F4 — Prototipo end-to-end funzionante (cartella `experiments/05_pca/`)
PCA in chiaro (client) + matching cifrato con formula espansa (server), sul dataset
Olivetti/ORL (volti in laboratorio).

- La quantizzazione a pochi bit non costa accuratezza: float e quantizzato
  danno lo stesso risultato.
- L'FHE dà le stesse identiche predizioni del calcolo in chiaro quantizzato,
  quindi il percorso cifrato è corretto e non approssimato.
- Il match contro tutta la galleria sta in un'unica `run` cifrata e in tempi
  interattivi: il limite della galleria non c'è.

Olivetti è piccolo e in laboratorio (volti allineati), quindi è una prova di fattibilità, n
on una garanzia nel mondo reale; è inoltre il tier più semplice (PCA). Vedi F5.

## 🔵 F5 — Su volti reali (LFW) la PCA crolla
Stesso prototipo sul dataset LFW (volti presi "in natura", molto più vari).

L'accuratezza crolla rispetto a Olivetti: gli eigenfaces non reggono la
variabilità reale (posa, luce, sfondo). La PCA fa meglio del caso, ma è lontana
dall'usabile.

## 🔴 F6 — L'argmin deve stare sul server (privacy): la decisione, e quanto costa
Nell'experiment 05 l'argmin lo fa il client che è comodo e gratis (nessun PBS), ma il client
decifra tutti i punteggi e impara la distanza con ogni iscritto, non solo col match. Per
privacy l'argmin (e in prospettiva la soglia open-set) va tenuto sul server, sotto FHE, così
il client apprende solo l'esito.

Chiamiamo **N** il numero di iscritti in galleria: a ogni query si calcolano N distanze (il
probe contro le N facce note) e l'argmin sceglie la più vicina. L'argmin cifrato non è nativo
in Concrete (`np.argmin` non supportato), quindi si fa a riduzione: N−1 confronti cifrati a
coppie, ognuno con un select di indice/valore e un PBS. Il costo dipende da due cose, la
larghezza in bit dei punteggi e N, e le misuriamo entrambe.

La prima leva sono i bit. ⚠️ La legge esatta non è «raddoppia a ogni bit» (F31: quello che conta è
il **numero di chunk** in cui Concrete spezza il confronto, che cresce a scalini), ma la direzione
è quella. A N=10 fisso, il tempo dell'argmin cresce rapidamente a ogni bit di
punteggio (di nuovo la leva di F1–F3, ora sull'argmin):

| larghezza punteggi | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

La seconda leva è N, dove guardiamo il prima e il dopo, cioè quanto rallenta spostare l'argmin dal client al
server al crescere della galleria (prototipo PCA su Olivetti; figura
`experiments/06_argmin_soglia/results/prima_dopo.png`):

| N (iscritti in galleria) | prima (argmin client) | dopo (argmin server, FHE) | fattore |
|---|---|---|---|
| 2 | 51 ms | 293 ms | 6× |
| 8 | 37 ms | 1.357 ms | 36× |
| 16 | 37 ms | 3.264 ms | 87× |
| 32 | 37 ms | 7.043 ms | 190× |

Il client è piatto a ~37 ms/query (decifra gli N punteggi + un argmin numpy, nessun PBS); il
server cresce con N (i confronti cifrati sono ~N−1), da 6× a 190× il costo del client nonostante N sia ancora molto basso. Va
notato che il "dopo" è a precisione ridotta (8 componenti, 3 bit, quindi punteggi ~6 bit) per
renderlo eseguibile; alla precisione della PCA decente (50 comp, ~14 bit) l'argmin server è
fuori scala, quindi 6–190× è un limite inferiore.

A questo punto, visto il costo e visto che la PCA stessa regge male sui volti reali (F5),
abbiamo deciso di non ottimizzare ancora l'argmin sul server e di tornare sul riconoscimento;
l'argmin lo riprenderemo più avanti, sulla pipeline buona.

## 🔵 F7 — Descrittori locali: battono la PCA sui volti reali, ma con un bivio FHE
Secondo gradino della scaletta (LBP, HOG), validato in chiaro prima di toccare
l'FHE. A parità di protocollo (1-NN, split per persona):

| | Olivetti | LFW (volti reali) |
|---|---|---|
| PCA + euclidea (gradino 05) | 98,8% | 32,4% (il crollo, F5) |
| LBP + χ² (nri_uniform, ottimizzato) | 100% | 74,8% (≈2,3× la PCA) |
| HOG + euclidea (celle 4×4) | 98,8% | 64,8% |

Su Olivetti (laboratorio) sono tutti equivalenti; la differenza emerge sui volti
reali, dove i descrittori locali codificano texture/forma locali e reggono la
variabilità che fa crollare gli eigenfaces globali.

Prima di pensare all'FHE, abbiamo cercato i parametri buoni (`ricerca_parametri.py`, dati in `results/ricerca_lfw.csv`).
Leve principali:
- LBP: la codifica `nri_uniform` (59 bin, il classico per i volti) batte nettamente
  `uniform` (10 bin): da ~65% a ~75%. Griglia più fitta e raggio R=2 aiutano.
- HOG: celle più piccole (4×4 invece di 8×8) salgono da 55% a ~65%, ma a costo di una
  dimensione molto più grande (540 → 3168).
- χ² vs euclidea su LBP: la χ² è migliore di ~4-6 punti (74,8% vs 70,4% a parità di
  config), ma l'euclidea regge e resta ben sopra la PCA, così si può evitare la
  divisione della χ² (ostica per l'FHE) pagando pochi punti.

Le config migliori sono ad alta dimensione (LBP ~3776-5900, HOG ~3168): è la
dimensione, non più la precisione per-valore, a guidare il costo FHE qui.

Lato FHE (sui parametri validati). Via FHE-friendly: LBP + euclidea (evita la
divisione χ², ~70% in chiaro, meglio di HOG). È il circuito del gradino
05 (`b_sq − 2·a·b`), ma a dimensione 3776 invece di 50. Misurato (LFW, M4 Max):

| | risultato |
|---|---|
| quantizzazione a 6 bit | non perde: 70,4% (float) → 72,9% (quant) |
| match cifrato (N=10→50, dim 3776) | ~75 → 95 ms/query, punteggi esatti (cifrato == quant) |
| compilazione | ~150 ms |

La distanza è cifrato×chiaro (niente PBS) e quindi scala bene anche a dimensione 75× quella della PCA, 
restando interattiva; è l'argmin (confronti cifrati, quindi PBS) a esplodere. Quindi la pipeline FHE-friendly,
embedding locale + distanza euclidea cifrata con argmin sul client, è fattibile e
interattiva su volti reali a ~73% di accuratezza. La χ² (75%, il massimo in chiaro)
è più accurata ma richiede la divisione cifrata: trade-off potere/costo, da pagare
solo se serve quell'1-2% in più.

Il bivio FHE (è il trade-off centrale della tesi, potere vs costo):
- LBP + χ² è il più accurato, ma la χ² `Σ(h−g)²/(h+g)` ha una divisione per
  `h+g` che dipende dal probe cifrato, cioè una divisione per quantità cifrata, ostile
  all'FHE (servirebbe un PBS costoso / un inverso).
- HOG + euclidea è meno accurato ma FHE-friendly: vettore di feature +
  distanza euclidea, quindi riusa *identico* il circuito del gradino 05 (cifrato×chiaro,
  niente PBS nel match). E fa comunque ~1,7× la PCA.

Prossimo passo (lato FHE, sui parametri appena validati): caratterizzare il costo
di HOG+euclidea cifrata (è il circuito del 05 sulla dimensione HOG reale) e valutare
la fattibilità della divisione χ² per LBP. *Niente sweep su config non valide.*

## 🔵 F8 — Verso il benchmark vero: dataset più duri, modello forte, integrazione
Fin qui abbiamo misurato su Olivetti e LFW, ma nessuno dei due è il nostro caso. 
Olivetti è un giocattolo da laboratorio (volti allineati,
posa e luce fisse). LFW è reale ma ormai saturo: quasi-frontale, demograficamente
sbilanciato, e i modelli moderni lo risolvono al ~99%, quindi non distingue più una tecnica
buona da una ottima. E soprattutto è pensato per la verifica 1:1, mentre il nostro scenario
è un varco cooperativo: identificazione 1:N open-set, cioè riconoscere gli iscritti e
rifiutare gli sconosciuti (la galleria + soglia del gradino 06).

I due protocolli, verifica 1:1 sui set a coppie (LFW/CPLFW/CFP-FP) e identificazione 1:N
open-set sui set 1:N (VGGFace2/DigiFace), hanno metriche diverse, che spieghiamo dove le
usiamo: il livello del caso (il 50%) della verifica in F9, la DIR@FPIR del varco in F10.

Cosa ci serviva, quindi: volti a risoluzione decente (al varco la persona collabora, niente
super-risoluzione da sorveglianza, per questo scartati QMUL-SurvFace/SCface/TinyFace), con
la difficoltà sugli assi che contano per noi: posa, età, luce, etnia. Scelta: VGGFace2 come
set duro principale (1:N nativo, folder-per-identità, già allineato 112×112, quindi pronto anche per
la CNN del gradino 08), con CPLFW + CFP-FP per la posa/profilo (verifica 1:1, su HuggingFace
`gaunernst/face-recognition-eval`), e DigiFace-1M come 1:N sintetico maneggevole (72 img/id).
Divario LFW→CPLFW ≈ 7 punti, stesso modello. Razionale, formati e download in
[`docs/benchmark_dataset.md`](docs/benchmark_dataset.md).

Il modello di embedding può essere forte. Gira in chiaro sul client, quindi il suo peso non
tocca l'FHE: conta solo la dimensione dell'embedding (512). Usiamo `buffalo_l` di InsightFace
(ResNet50/ArcFace su WebFace600K, IJB-C 97,25%), pre-addestrato e congelato: noi non
addestriamo niente. I nostri dataset servono a valutare, non ad allenare, e iscrivere una
persona è solo calcolare e salvare il suo embedding, e il modello riconosce anche identità mai
viste in training (è metric learning, impara la similarità tra volti, non le persone).
Dettagli in [`docs/modelli_embedding.md`](docs/modelli_embedding.md).

Integrati nel codice (`core/dataset.py`): `carica_da_cartelle` (loader folder-per-identità,
vale per VGGFace2 e DigiFace) e `split_openset` (divide in galleria, probe noti e probe ignoti
da rifiutare, lo scenario del varco). Scaricati e verificati DigiFace P1 (2000 id) e VGGFace2
test (500 id), con il primo split open-set 1:N funzionante. Pronti per il gradino 08 (CNN).

## 🔵 F9 — Le tecniche hand-crafted crollano al caso sui benchmark duri (il livello del caso)
Prima di salire alla CNN, abbiamo misurato le tecniche già fatte (PCA del gradino
05, LBP/HOG del gradino 07) sui benchmark duri CPLFW (cross-posa) e CFP-FP
(frontale↔profilo), a buona risoluzione 112×112, nel loro protocollo nativo di
verifica 1:1 (6.000 coppie, 10-fold, soglia migliore). Cartella
`benchmark/`, dati in `results/verifica_duri.csv`.

| benchmark | PCA+eucl | LBP+χ² | LBP+eucl | HOG+eucl |
|---|---|---|---|---|
| LFW (facile) | 61,6% | 67,6% | 62,9% | 66,3% |
| CPLFW (cross-posa) | 53,3% | 51,5% | 50,4% | 49,5% |
| CFP-FP (front↔profilo) | 58,0% | 61,1% | 63,2% | 63,3% |

Su CPLFW tutte le tecniche crollano al ~caso (≈50%). La verifica è bilanciata,
quindi 50% = lancio di moneta: le feature lineari/locali non hanno alcuna robustezza
alla posa. CFP-FP (front↔profilo) un po' meglio (~60%), LFW ~65%. È il livello del caso
empirico che motiva il salto alla CNN (gradino 08): un estrattore addestrato a essere
invariante a posa/luce/età è *esattamente* ciò che qui manca.

Caveat onesti:
- È verifica 1:1, non l'1:N dei demo (metrica diversa), quindi confronta il *degrado*
  riga per riga (facile→duro), non i valori assoluti tra protocolli.
- Anche su LFW i numeri sono bassi (~65%): scala di grigi grezza, nessun tuning per-set,
  PCA non supervisionata sulle immagini del set. Lo scopo non è il massimo assoluto ma
  il trend: le tecniche semplici non reggono la posa. (Le CNN qui fanno ~92-99%.)

## 🔵 F10 — Le tecniche attuali nel NOSTRO protocollo (1:N open-set): il varco non regge
Finalmente la misura che conta: PCA / LBP / HOG in identificazione 1:N open-set
(galleria iscritti + probe noti + probe ignoti da rifiutare) sui dataset 1:N veri,
DigiFace (sintetico) e VGGFace2 (reale). Cartella `benchmark/`
(`identificazione_1n.py`, dati in `results/identificazione_1n.csv`, figura
`results/tecniche_1n.png`). Galleria 50 id
iscritte, 50 id ignote, ~500/500/1000 immagini.

Le due metriche (non confonderle). Rispondono a domande diverse:
- Rank-1, la versione *facile*: "dato che la persona è iscritta, il volto più
  vicino in galleria è il suo?". Ignora la soglia (dà sempre una risposta, non può
  rifiutare). Su 50 identità il caso è 1/50 = 2%, quindi un Rank-1 dell'8% è
  solo ~4× il caso, e sbaglia comunque l'identità del ~92% degli iscritti. *Generosa.*
- DIR@FPIR=1% (Detection & Identification Rate a False Positive Identification Rate
  = 1%), la versione *vera*, il varco: a una soglia tarata perché solo l'1% degli
  impostori entri, quanti autorizzati riconosci e fai passare?. Chiede due cose
  insieme, identità giusta e sotto soglia, e include il "no match". È il numero
  che conta per il controllo-accessi.

Stesso esempio (PCA su VGGFace2): Rank-1 8,6% (appena sopra il caso) ma
DIR@FPIR=1% 0,6% (≈ zero). La PCA fa pietà su *entrambe*; il Rank-1 sembra meno
disastroso solo perché è la metrica indulgente.

| | | Rank-1 | DIR@FPIR=1% | DIR@FPIR=10% |
|---|---|---|---|---|
| DigiFace (sintetico) | PCA | 8,2% | 0,2% | 1,8% |
| | LDA/Fisherfaces | 16,6% | 0,2% | 1,2% |
| | LBP+χ² | 46,0% | 6,6% | 21,8% |
| | HOG | 42,2% | 10,4% | 21,4% |
| VGGFace2 (reale) | PCA | 8,6% | 0,6% | 2,6% |
| | LDA/Fisherfaces | 7,6% | 0,4% | 1,6% |
| | LBP+χ² | 18,4% | 1,8% | 4,4% |
| | HOG | 14,4% | 2,2% | 3,8% |

Al punto di lavoro sicuro (FPIR=1%), su volti reali il meglio è ~2%: il
varco negherebbe l'accesso al ~98% degli autorizzati pur di tenere fuori gli
impostori. Il "no match" open-set c'è, ma rifiutare *bene* richiede una separazione che
queste feature non hanno (è la risposta, a numeri, alla domanda "il 50% non basta?": in
1:N il caso è 1/N, e qui siamo vicini al livello del caso).

Tre osservazioni:
- PCA è morta in 1:N reale: Rank-1 ~8% su 50 identità (il caso è 2%), DIR ≈ 0.
- LDA/Fisherfaces (l'ultima geometrica) non salva. La versione *supervisionata*
  della PCA raddoppia la PCA sul sintetico (16,6% su DigiFace, pulito/frontale) ma sui
  volti reali non aiuta (7,6%, perfino un filo sotto la PCA): le direzioni
  discriminanti stimate sulla galleria non generalizzano alla variabilità reale,
  quindi lo scalino geometrico è esaurito (PCA *e* LDA falliscono sul reale).
- Reale ≫ sintetico in difficoltà: VGGFace2 dimezza/triplica il calo rispetto a
  DigiFace (LBP 46%→18%, HOG 42%→14%). I volti sintetici sono puliti/frontali; i reali
  (posa, luce) distruggono le feature hand-crafted. Quindi DigiFace è un set "di controllo"
  facile, VGGFace2 è il duro vero.

È la motivazione misurata nel nostro protocollo per il gradino 08 (embedding CNN):
abbiamo provato *tutte* le tecniche pre-CNN, geometriche (PCA, LDA) e descrittori
locali (LBP, HOG), e nessuna fa funzionare il varco su volti reali (DIR@FPIR=1% ≤ 2%).
Non è un "sarebbe meglio": così com'è il varco non funziona, ed è il momento della CNN.

## 🔴 F11 — Argmin + soglia ("nessun match") sotto FHE funziona; la trappola è l'inputset
L'operazione vera del varco è argmin + verifica soglia: il server trova il più
vicino e dice "match id=X" oppure "nessun match" se nessuno è entro la soglia
(impostore/sconosciuto rifiutato). Due punti chiusi qui.

1. Concrete non ha un argmin nativo, confermato dal sorgente. La lista
`SUPPORTED_NUMPY_OPERATORS` di `concrete-python 2.11` contiene `np.dot, np.min,
np.max, np.minimum, np.maximum, np.sum, np.where`, ma non `np.argmin`/`np.argmax`. Restituisce
il *valore* minimo e non l'*indice*, in linea col modello a circuito/LUT (un indice non
è un'operazione naturale sul cifrato). Quindi l'argmin si costruisce da `<` + select
(`np.where`/aritmetica), in `core/matching.py`.

2. Il rifiuto "nessun match" funziona, ma serve l'inputset giusto. Il circuito
completo (`circuito_distanza_argmin_soglia`) ritorna `(indice, è_match)` dove la
soglia confronta la distanza² vera `val_min + ‖a‖²` (il termine `‖a‖²` scartato per
il ranking va rimesso per una soglia assoluta). All'inizio il ramo "nessun match" non
si attivava mai, perché l'inputset era troppo stretto. Concrete inferisce la larghezza
in bit dei valori cifrati *dall'inputset*; passando solo le righe della galleria, il
range era insufficiente e il confronto della soglia andava in overflow silenzioso
(il valore gira modulo a un numero piccolo, quindi sempre "sotto soglia" e sempre "match").
L'argmin restava giusto, perché i suoi valori erano nel range, mentre solo la soglia sballava. Era un bug subdolo, senza alcun errore segnalato e con il solo sintomo di un risultato sbagliato.

Con un inputset rappresentativo dei probe reali, il circuito è corretto: verificato
10/10, con i "nessun match" che si attivano davvero (4/10 nel test a soglia stretta).

La lezione, cugina di F3/F6, è che l'inputset definisce il range valido del circuito. Va
costruito coi probe reali (o un campione che ne copra la gamma), non con la sola
galleria, altrimenti i confronti cifrati overflowano in silenzio. Vale per ogni
circuito con soglie/somme che dipendono dal probe.

## 🔵 F12 — Come scala la PCA sui nostri dataset: accuratezza vs bit dei punteggi
Caratterizzazione in chiaro della PCA al variare delle componenti, su tutti e quattro i
dataset, misurando insieme accuratezza (Rank-1 1:N) e larghezza-bit dei
punteggi (la leva di costo dell'argmin, F6). Figura
`benchmark/results/pca_scaling.png` (dati `pca_scaling.csv`).

| dataset | Rank-1 (8→128 comp) | bit punteggi |
|---|---|---|
| Olivetti (laboratorio) | 77% → 87% | 13–14 |
| LFW | 14% → 30% | 13–15 |
| DigiFace (sintetico) | 7% → 9% | 13–15 |
| VGGFace2 (reale) | 7% → 9% | 13–14 |

Due fatti, entrambi importanti:

1. Accuratezza (pannello A): solo Olivetti (volti da laboratorio) regge (~87%); su
   tutto ciò che è reale/duro la PCA è al livello del caso (LFW ~30%, DigiFace/VGGFace2
   ~8–9%, vicino al caso 1/50=2%). Aggiungere componenti non salva: la PCA non
   generalizza. Conferma F5/F10 su scala più ampia.

2. Bit dei punteggi (pannello B): la larghezza è già ~13 bit con sole 8
   componenti e sale appena a 14–15. Il motivo: il punteggio è `‖b‖²−2ab`, e il
   termine `‖b‖²` (somma di quadrati) domina e satura la larghezza quasi subito,
   indipendentemente da quante componenti aggiungi. Quindi non c'è una zona "poche
   componenti = punteggi stretti = argmin economico": la PCA è intrinsecamente nella
   zona cara (~14 bit) della curva di costo dell'argmin.

Doppio vincolo: la PCA è debole dove serve (dati reali) e cara da rendere
privata (punteggi larghi). Non c'è un punto di lavoro buono. È la motivazione, a
numeri e su una figura, per (a) salire a un embedding migliore della PCA, e (b) per
l'argmin: se la larghezza dei punteggi non si comprime "gratis", serve un troncamento
esplicito (`truncate_bit_pattern`) o un embedding nativamente a pochi bit.

## 🔵 F13 — La CNN (anche leggera) supera il livello del caso: il varco funziona

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Terzo gradino della scaletta (CNN), partendo dalla bassa profondità:
MobileFaceNet (InsightFace `buffalo_s`, `w600k_mbf`, linea ArcFace, embedding
512-dim, 13 MB), eseguito in chiaro sul client. Stesso protocollo 1:N open-set e stessa
figura dei pre-CNN (`benchmark/results/tecniche_1n.png`, gradino
`experiments/08_cnn/`).

Protocollo: 100 identità, **20 foto ciascuna**, metà identità ignote, metà foto in galleria, seed 0
(`benchmark/identificazione_1n.py`).

| | | Rank-1 | DIR@FPIR=1% |
|---|---|---|---|
| DigiFace (sintetico) | migliore pre-CNN (HOG) | 42,2% | 10,4% |
| | CNN MobileFaceNet | 99,6% | 94,2% |
| VGGFace2 (reale) | migliore pre-CNN (HOG) | 14,4% | 2,2% |
| | CNN MobileFaceNet | 97,8% | 96,0% |

Su volti reali (VGGFace2), al punto di lavoro sicuro (FPIR=1%) si passa da
~2% a 96%: il varco da inutilizzabile a pienamente funzionante, e con la CNN
*leggera*, il primo gradino CNN di Carnemolla. Conferma tutto il filo: le tecniche
semplici falliscono perché manca l'invarianza a posa/luce (F9–F12), la CNN ce l'ha.

Lezione (importante, vale come finding a sé): l'allineamento è critico per le CNN.
Al primo tentativo la CNN su VGGFace2 dava solo 10,4% Rank-1 (peggio dei
descrittori!), perché avevamo solo *ridimensionato* le immagini a 112×112. ArcFace/
MobileFaceNet pretendono il volto allineato sui 5 landmark al template canonico:
con la detection+allineamento di InsightFace (sui volti grezzi a piena risoluzione) la
CNN sale a 97,8%. DigiFace era già allineato (sintetico, frontale), quindi funzionava
subito (99,6%). Il preprocessing (detect+align) è parte integrante della pipeline CNN,
non un dettaglio.

Implicazione FHE (gancio col seguito): l'embedding è 512-dim, più *piccolo*
della dimensione dei descrittori (gradino 07, dim 3776), quindi la distanza cifrata costerà
*meno*, non di più. E siccome l'embedding gira in chiaro sul client, la potenza della
CNN non tocca il costo FHE. La pipeline privacy-preserving con un riconoscimento che
funziona davvero è quindi alla portata: prossimo passo, il costo FHE a dim 512.

## 🔴 F14 — Lato FHE della CNN: la quantizzazione non costa, il match è interattivo
Chiusura del cerchio end-to-end (`experiments/08_cnn/costo.py`). Sugli embedding
MobileFaceNet (DigiFace, dim 512; 100 identità, **12 foto ciascuna**, metà in galleria — con 20
foto, come in F13, la stessa misura dà 94,2%: il numero di foto in galleria è il motivo per cui i
due finding riportano cifre diverse per lo stesso modello e lo stesso dataset):

| | risultato |
|---|---|
| quantizzazione a 6 bit | non perde: DIR@FPIR=1% 89,3% (float) = 89,3% (quant) |
| match cifrato, dim 512 | **151,9 ms/query**, punteggi esatti (cifrato == quant) |
| match cifrato, dim 128 | 62,7 ms/query |

Fonte: `benchmark/results/velocita_dimensione.csv`, stessa configurazione per entrambe le righe.

Il match cifrato a piena dimensione è quindi **più caro**, non più economico, del gradino 07
(descrittori, dim 3776, ~75-95 ms): 151,9 ms contro ~85. Quello che regge è l'enunciato
qualitativo: la potenza del modello (in chiaro sul client) non tocca l'FHE, conta solo la
**dimensione** dell'embedding — ed è proprio la dipendenza dalla dimensione che il CSV mostra
(151,9 → 62,7 ms dimezzando due volte).

⚠️ **Attenzione a chi riusa questo numero.** Lo stesso circuito compare nel repo con tre misure
diverse (63,8 / ~102-111 / 151,9 ms), e il valore di dim 128 è stato usato come costante in F15,
F19 e F22 come se fosse quello di dim 512: le stime di costo in quei tre finding vanno lette con
questa avvertenza.

La pipeline completa è coerente e interattiva: client calcola l'embedding CNN in
chiaro, quantizza (senza perdita), cifra; server calcola la distanza cifrata in
~63 ms; il riconoscimento funziona (89–96% DIR@FPIR, F13). Resta aperto il solo
argmin cifrato sul server (F6), da rendere praticabile con `truncate_bit_pattern`
o tenendo l'embedding a pochi bit (qui 6 bit bastano e non costano accuratezza).

## 🔵 F15 — CNN profonda (ResNet50): un ritocco, e a costo FHE invariato

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Gradino 08b: salita all'alta profondità della scaletta, ResNet50 (InsightFace
`buffalo_l`, `w600k_r50`, embedding 512-dim), confrontata con la leggera MobileFaceNet
sullo stesso protocollo 1:N.

| | | MobileFaceNet (leggera) | ResNet50 (profonda) |
|---|---|---|---|
| DigiFace (sintetico) | DIR@FPIR=1% | 94,2% | 97,2% |
| VGGFace2 (reale) | DIR@FPIR=1% | 96,0% | 97,0% |
| VGGFace2 | Rank-1 | 97,8% | 98,8% |

La profonda è un filo meglio (+1–3 punti DIR), ma su questo benchmark a 50 identità
siamo già vicini al soffitto. Due conclusioni:

1. Il salto vero è quello da hand-crafted a CNN (~2% → 96%), non da *leggera* a
   *profonda* (~1–3 punti). La CNN leggera prende già quasi tutto il guadagno.
2. A parità di dimensione (512), il costo FHE è identico. L'embedding gira in chiaro
   sul client, quindi salire alla ResNet costa di più solo *lì*, non sul cifrato. Per la
   pipeline FHE la profonda è quindi un upgrade "gratis" (stesso match cifrato ~63 ms,
   F14) che regala l'ultimo punto di accuratezza, se il client se la può permettere.

La scaletta di Carnemolla è completa (geometriche, descrittori, CNN leggera,
profonda), tutta su un'unica figura (`benchmark/results/tecniche_1n.png`) e nello stesso
protocollo 1:N open-set. Il sistema privacy-preserving riconosce volti reali al ~97% al
punto di lavoro sicuro, con match cifrato interattivo.

## 🔵 F16 — Il benchmark è saturo? Test scalando la galleria

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Sospetto legittimo: a 50 identità la CNN fa ~96-97% e leggera≈profonda, segno che il
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

1. NON è saturo nel senso "tutto al 99%". Il DIR tiene (80-96%) anche fino a 500
   iscritti, scendendo solo lievemente. La CNN scala davvero a gallerie grandi, è
   un risultato genuino, non un artefatto di galleria minuscola. (Buona notizia per il
   varco reale.)

2. Ma a 50 id c'era saturazione "tra modelli". Lì leggera e profonda pareggiavano;
   allo scale ResNet50 sta costantemente sopra MobileFaceNet (~+5-10 punti su
   DigiFace, ~+2-3 su VGGFace2). Quindi il benchmark *piccolo* non distingueva i modelli;
   quello *grande* sì, e il modello profondo si guadagna il suo posto solo quando il test
   è abbastanza duro.

3. DigiFace (sintetico) è più duro di VGGFace2 (reale) per la CNN a galleria grande
   (a 50 iscritti i due sono pari, ResNet50 97,2 vs 97,0%; il divario si apre scalando),
   controintuitivo
   ma logico: i modelli sono addestrati su volti reali (WebFace600K), quindi il sintetico
   è fuori-distribuzione e fa da stress test. È il caveat di onestà sui numeri alti:
   VGGFace2 è *in-distribuzione*; gallerie enormi (migliaia), condizioni out-of-domain e
   non-cooperative abbasserebbero ancora il DIR. Entro ciò che possiamo testare, però, il
   sistema è forte e scala.

## 🔵 F17 — Scaling su larga scala: a migliaia di iscritti il DIR scende davvero

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Spinto oltre i 500 iscritti (richiesta di scalare ancora). Scaricata la parte DigiFace
a 33.333 identità (×5 img), sweep fino a 8000 iscritti (sintetico = stress test
out-of-distribution, F16). Figura `benchmark/results/scaling_grande.png`.

Nota: il CSV e la figura `scaling_grande` sono stati poi riscritti in F29 col dataset intero
(99.999 identità, 3 modelli), quindi i numeri qui sotto sono la misura parziale storica di questa
iterazione e non combaciano più col CSV attuale. Per i numeri validi vedi F29.

| iscritti | MobileFaceNet | ResNet50 |
|---|---|---|
| 250 | 88,3% | 91,7% |
| 1000 | 81,4% | 88,5% |
| 2000 | 77,0% | 85,5% |
| 4000 | 74,3% | — |
| 8000 | 70,7% | — |

Ora il calo si vede. A galleria grande il DIR@FPIR=1% scende in modo netto e
regolare: MobileFaceNet 88% → 71% da 250 a 8000 iscritti. Conferma definitiva che
il ~96% a 50 identità era ottimistico/saturo: il numero *onesto* a gallerie
realistiche (migliaia di persone) è sensibilmente più basso. È la correzione che il
sospetto di saturazione meritava, e un risultato di scalabilità vero per la tesi.

Due cose:
- La profonda regge meglio allo scale. ResNet50 degrada più dolcemente (92% → 85% a
  2000 iscritti) di MobileFaceNet (84% → 77%): il modello profondo si guadagna il posto
  proprio sulle gallerie grandi (coerente con F15/F16, ora marcato). NB: ResNet50 è
  ~20× più lenta da embeddare (CPU), per questo il suo sweep si ferma a 2000.
- Caveat sul caveat: è sintetico/OOD; su volti reali in-distribuzione i valori
  assoluti sarebbero più alti, ma la forma (degrado col crescere della galleria) è
  reale e attesa. Il sistema resta usabile (70-90%), ma "il varco funziona al 96%" va
  detto come "a galleria piccola"; a migliaia di iscritti è ~70-85%.

## 🔵 F18 — Scaling su volti REALI puliti (VGGFace2 train): regge bene allo scale

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Controparte reale di F17 (che era sintetico). Scaricato VGGFace2 train (8.631
identità reali, 37 GB), è il dataset che avevamo scelto (F8, `docs/`) e non è
training dei modelli buffalo, quindi numeri onesti/difendibili. Allineati 30.000 volti
(detection, ~35 min), embedding MFN + ResNet50, sweep galleria. Figure
`scaling_reale.png` e, combinata reale vs sintetico, `scaling_combinato.png`.

Spinto al massimo di iscritti reali (tutte le 8.631 identità di VGGFace2 train, 52k
volti allineati):

| iscritti | MobileFaceNet | ResNet50 |
|---|---|---|
| 250 | 93,3% | 96,3% |
| 1000 | 90,2% | 95,8% |
| 2000 | 88,4% | 95,5% |
| 4000 | 86,6% | 94,5% |
| 4300 (max) | 86,0% | 94,2% |

Su volti reali il sistema scala molto meglio del sintetico, fino al massimo. Al
massimo di iscritti reali (4.300, tutte le identità VGGFace2 train) ResNet50 tiene
94,2%, cala solo ~2 punti da 250 a 4.300 (curva quasi orizzontale); MobileFaceNet
86,0%, calo dolce e regolare. Molto meglio del DigiFace OOD (che a 2000 era 77/85%
e a 8000 scende a 71%).

Quadro finale dello scaling (figura combinata): la verità sta tra le due curve.
- *Reale, in-distribuzione* (VGGFace2): ~87-95% anche a 1000-2000 iscritti, e regge.
- *Sintetico, OOD* (DigiFace): ~70-85% a migliaia, uno stress test pessimistico.
- In entrambi: la profonda (ResNet50) scala meglio della leggera, e il guadagno del
  modello profondo è proprio sulle gallerie grandi, dove serve.

Risposta onesta e completa al sospetto di saturazione: il ~96% iniziale era a
galleria piccola; allo scale su volti reali puliti la profonda (ResNet50) resta a
~95% fino a 2000 iscritti (quasi nessun calo), la leggera ~87% a 4000. Su un dominio
davvero ostile (sintetico/OOD) si scende a ~70-85%. Il varco è realisticamente
usabile anche a migliaia di iscritti reali, e il modello profondo lo fa quasi senza
perdite.

Nota metodologica (importante): non addestriamo nulla, la CNN è pre-addestrata e
congelata, usata solo come estrattore. La separazione train/test è già garantita dal
protocollo: iscrizione ≠ probe (foto diverse della stessa persona) e iscritti ≠
impostori (identità disgiunte), quindi non si valuta mai su dati "visti". Per PCA/LDA, che
si stimano sulla galleria, vale lo stesso (galleria = loro training, probe = test). Il
solo residuo è la possibile sovrapposizione di *celebrità* tra VGGFace2 e il training
originale della CNN, caveat standard del campo, non eliminabile senza il dataset di
training del modello.
## 🔵 F19 — Modelli più grandi: si sale, ma poco; e il tetto ~95-96% è quello a frame singolo

*Numeri a **seed singolo**: indicativi. Le misure definitive dello stesso protocollo, su 15 semi con intervallo di confidenza al 95%, sono in F29 (scala) e F30 (modelli); dove i due divergono vale F29/F30.*
Domanda: salendo di modello (e con la distillazione, come da Carnemolla) si arriva al
99%? Confronto tre profondità crescenti sullo stesso protocollo 1:N open-set reale
(VGGFace2), embedding sempre in chiaro, quindi costo FHE invariato (dim 512 per tutti).
Figura `benchmark/results/scaling_modelli.png`.

| iscritti | MobileFaceNet | ResNet50 | ResNet100 |
|---|---|---|---|
| 250 | 93,3% | 96,3% | 96,7% |
| 1000 | 90,2% | 95,8% | 96,5% |
| 4300 (max) | 86,0% | 94,2% | 95,5% |

Salire di modello aiuta, ma poco. ResNet100 (antelopev2, Glint360K) è il migliore e
quasi piatto (96,7% → 95,5% da 250 a 4.300 iscritti), ma stacca ResNet50 solo di
+0,4 / +1,3 punti. Siamo vicini al tetto pratico: ~95-96% è il massimo per
questo protocollo duro (1:N open-set, migliaia di iscritti).

Il 99% non è raggiungibile qui, ed è giusto così. I "99,8%" che si citano sono
verifica 1:1 su LFW, un compito molto più facile; il nostro 1:N open-set a migliaia
di iscritti è duro, e anche i modelli SOTA stanno ~95-97%. Confermata la previsione: un
modello più grande dà +1-3 punti, non il salto al 99%.

Sulla distillazione (chiarimento metodologico): *non* serve per alzare
l'accuratezza: lo student ≤ teacher (lo imita, non lo supera), quindi distillare
ResNet100 darebbe al massimo ~95%. La distillazione serve solo se si vuole l'embedding
sotto FHE (split inference): un modello piccolo *compilabile* in Concrete che imita
il grande, per nascondere anche il modello al client. È un obiettivo di privacy, non di
accuratezza. Per più accuratezza, lato nostro, basta un modello più grande direttamente
(gratis lato FHE, gira in chiaro sul client).

Conclusione: il sistema è vicino al massimo pratico (~95-96% con ResNet100 a
migliaia di iscritti reali). Oltre non si va cambiando modello; servirebbe un protocollo
più facile (verifica 1:1) o accettare che ~95% è l'ottimo onesto per il varco 1:N.

Conferma a numeri: il costo FHE è indipendente dal modello (`costo_modelli.py`):
il match cifrato su DigiFace è ~102 ms (MobileFaceNet), ~111 ms (ResNet50), ~97 ms
(ResNet100), uguale per tutti, perché dipende solo dalla dimensione (512), non dal
modello (l'embedding gira in chiaro sul client). La quantizzazione a 6 bit non perde e
il cifrato dà i punteggi esatti per tutti e tre. Si può usare il modello migliore
(ResNet100, ~95,5%) a costo cifrato identico al più leggero. La potenza del
riconoscimento è gratis lato FHE.

## 🔴 F20 — Argmin cifrato sul server con embedding CNN: il limite, e cosa abbiamo provato
A questo punto davamo per scontato che l'argmin (e la soglia) dovessero stare sul
server, sotto FHE: farli sul client sembrava vanificare la privacy (il client imparerebbe
la distanza con ogni iscritto, F6). *(In F21 ridimensioneremo questa premessa, dipende
da quanto ci si fida del client. Ma intanto proviamo a farlo sul server.)* E sui punteggi
degli embedding CNN a 512 dimensioni troviamo un limite netto, e di seguito il diario dei tentativi.

Il problema è la larghezza in bit. Il punteggio `‖b‖² − 2·a·b` su 512 dimensioni quantizzate a 6 bit è
largo ~18 bit. Il confronto cifrato di Concrete 2.11 è limitato a ~16 bit:
l'argmin sui punteggi CNN non compila (`this 18-bit value is used as an operand to a
comparison operation`). E i ~18 bit nascono dall'accumulatore su 512 dimensioni, non
dalla precisione per-valore, e non si abbassano facilmente.

Cosa abbiamo provato (e perché non basta):
1. `round_bit_pattern` (arrotonda via i bit bassi dei punteggi prima del confronto).
   Non funziona, perché azzera i bit bassi ma non riduce il range: il valore resta a 18 bit, quindi
   il confronto è ancora su 18 bit ed è rifiutato. Lo strumento serve a far seguire una
   tabella a precisione ridotta, non a stringere un confronto.
2. Dividere i punteggi (`// 2^k`, per tagliare il range alla metà). Di nuovo non basta, perché l'operazione
   stessa prende in input il valore a 18 bit, cioè una tabella su 18 bit, quindi non compila. Qualunque
   manipolazione *a valle* del punteggio largo è bloccata dallo stesso limite.
3. Comprimere l'embedding (PCA a meno dimensioni + meno bit), per stringere i
   punteggi alla sorgente. Sembrava la leva, ma non lo è (corretto in F31): misurato dopo, l'argmin
   non scende con la dimensione (455/540/586 s a 512/128/64) e a tenere il confronto sotto i 16 bit
   basta la quantizzazione a 4 bit, non la riduzione di dimensione. Resta vero che comprimere a
   poche dimensioni o a 2-3 bit distrugge l'accuratezza della CNN. Più che un'ottimizzazione è
   quindi un vicolo cieco: la compressione non rende l'argmin veloce e intanto rovina il
   riconoscimento.

Tirando le somme, onestamente, non esiste un calo progressivo coi miglioramenti: l'argmin
cifrato sul server non scala agli embedding CNN ad alta dimensione, perché è un limite
(limite di bit-width del confronto in Concrete) e non una discesa. Estende ed è il
contraltare di F6, dove il costo cresceva ~2×/bit mentre qui i bit sono troppi a priori.

Come farlo davvero (da esplorare): (a) un punto di compromesso dimensione/accuratezza,
cioè PCA dell'embedding a ~128-256 dim, argmin tractabile ma lento (~minuti/query) con qualche
punto di accuratezza in meno; (b) privacy a livello di protocollo invece che di
circuito, per esempio il server mescola i punteggi così il client vede solo distanze
anonime + l'identità vincente, senza argmin cifrato; (c) un argmin a torneo/gerarchico
che non materializzi mai il punteggio pieno. Il client-argmin (~100 ms) resta soltanto una *baseline funzionante ma non privata*, e non una soluzione.

## 🔴 F21 — L'argmin server serve davvero? Dipende dal modello di minaccia
Ripensandoci, con l'argmin sul client (la demo funzionante, ~100 ms) il server calcola
i punteggi cifrati e li rimanda senza mai decifrare. Quindi il server non impara
nulla: né il volto, né i punteggi, né l'esito. L'unico a vedere le distanze è il
client (che ha la chiave). La conseguenza è importante:

- Sotto il modello di minaccia naturale del varco (server honest-but-curious, client
  fidato, il terminale è del gestore) il sistema client-argmin a ~100 ms è già
  privacy-preserving, perché protegge il volto e l'esito dal server senza bisogno di argmin cifrato.
- L'argmin (e soglia) sul server serve solo se il client non è fidato (un
  client malevolo non deve poter sondare la galleria imparando le distanze). È un
  irrobustimento extra, ed è quello che incontra il limite FHE (F20).

Quindi "l'argmin cifrato sul server è necessario" non è assoluto: dipende da quanto
si fida il client. Il contributo della tesi può legittimamente fermarsi al sistema
client-argmin (funziona, è privato verso il server, ~100 ms con ResNet100 al ~95%), e
trattare il server-argmin come hardening per il caso untrusted-client (fattibile solo a
dimensione ridotta, vedi F22).

## 🔴 F22 — Comprimere l'embedding: a 128 dim quasi gratis in accuratezza (ma non è una leva FHE, corretto in F31)
Per stringere i punteggi (e avvicinare l'argmin cifrato al fattibile, F20) si riduce la
dimensione dell'embedding con PCA. Misurato il trade-off accuratezza↔dimensione
(`scaling_dimensione.py`, 1000 iscritti reali, figura `scaling_dimensione.png`):

| dim | MobileFaceNet | ResNet50 |
|---|---|---|
| 512 | 90,4% | 95,8% |
| 256 | 90,4% | 95,6% |
| 128 | 88,6% | 94,4% |
| 64 | 78,1% | 86,8% |
| 32 | 47,9% | 55,9% |
| 16 | 12,2% | 14,0% |
| 8 | 0,6% | 1,0% |

Si comprime fino a 128 dimensioni quasi gratis (ResNet50 −1,4 punti, MobileFaceNet
−1,8), e 256 è identico a 512. Sotto c'è un ginocchio netto: 64 ancora usabile
(~87%), a 32 dimezza, sotto 16 crolla. 128 dim è il punto FHE-friendly: stesso
riconoscimento, punteggi più stretti (e match cifrato più economico, costo ~lineare
nella dimensione). Da notare che per rendere l'argmin cifrato *tractabile* serve 128 dim +
quantizzazione bassa (~4 bit), quindi punteggi ~14 bit e argmin lento (~minuti/query) ma non
intrattabile. È l'operating point del server-argmin privato, lento e adatto a basso throughput.

Velocità del match cifrato vs dimensione (`velocita_dimensione.py`, figura
`velocita_dimensione.png`): 512→152 ms, 256→65, 128→63, 64→59, 32→57. Il match
(cifrato×chiaro, no PBS) è economico e quasi piatto sotto 256 (~60 ms): dominano i
costi fissi, non la dimensione. Ridurre l'embedding aiuta poco il *match* (già a terra),
ma è la leva per rendere l'*argmin* cifrato fattibile (F20/F22). Nel quadro completo la
dimensione 128 è il punto dolce, accuratezza ~94% (ResNet50), match ~63 ms, e punteggi
abbastanza stretti da avvicinare l'argmin privato al fattibile.

⚠️ **Ma la dimensione non è una leva per l'FHE, e questa è la parte che conta.** La conclusione
accuratezza↔dimensione qui sopra regge (a 128 dim il riconoscimento è quasi intatto); quella sul
costo cifrato no. Misurando l'argmin cifrato al variare della dimensione su embedding reali
(`benchmark/argmin_dimensione.py`, Concrete, CHUNKED, 4 bit, N=4) il costo **non scende**, e non è
nemmeno monotono: **512 dim → 158,7 s con 44 PBS, 128 dim → 237,9 s con 81 PBS** (cioè *peggio*),
64 dim → 74,8 s ma con **risultato errato**. A far compilare l'argmin è la quantizzazione a 4 bit
(limite di 16 bit del confronto), non la riduzione di dimensione: 512 dim compila lo stesso.

La compressione aiuta il **match** (prodotto scalare, 152 → 63 ms), che però è già gratis; non
aiuta l'**argmin**, che è la selezione ed è dove sta tutto il costo.

## 🔴 F23 — Ottimizzare l'argmin server: niente hardware-lever, e la compressione aiuta al margine
Tentativo di "ottimizzare fortissimo" l'argmin cifrato sul server, da cui emergono due fatti duri.

Su questa macchina non ci sono leve hardware. Il parallelismo dataflow di Concrete
non è disponibile su macOS (`Dataflow parallelism is not available in macOS`), e la
GPU nemmeno (Apple Silicon, no CUDA). Quindi l'unica leva è comprimere l'embedding
(meno bit nei punteggi). Numeri veri misurati (argmin su N=8, 4 bit):

| dim PCA | accuratezza | argmin cifrato |
|---|---|---|
| 16 | ~14% | 42 s (misurato) |
| 32 | ~56% | minuti |
| 64 | ~87% | esplode la RAM in compilazione (decine di GB) |
| 128 | ~94% | intrattabile |
| 512 | ~95% | intrattabile (non compila) |

Dove l'accuratezza è usabile (≥64 dim) l'argmin è intrattabile (tempo *o* memoria);
dove è veloce (16 dim) l'accuratezza è inutile, e così non c'è un operating point buono.

⚠️ **Questa tabella è pre-CHUNKED e le sue conclusioni non reggono.** Con la strategia CHUNKED più
la quantizzazione a 4 bit il 512 dim **compila e gira**, quindi non è «intrattabile»; e comprimere
**non abbassa il costo** — l'argmin è quasi indipendente dalla dimensione, e a 128 dim costa
addirittura di più (158,7 s a 512 dim contro 237,9 s a 128, misurati in
`benchmark/argmin_dimensione.py`). Quindi «l'unica leva è comprimere» è falso: **la dimensione non è
una leva FHE**. Il 42 s a 16 dim era il regime a ~9 bit su embedding degeneri, non un punto
operativo reale. Quello che resta valido di questo finding è il primo fatto: su questa macchina non
ci sono leve hardware.

Una compressione migliore aiuta al margine senza rompere la frontiera. Abbiamo usato la PCA;
provata anche la LDA (supervisionata, `compressione.py`, figura `compressione.png`):
a dim bassa la LDA batte la PCA (dim 16: 25% vs 14%; dim 32: 65% vs 56%), sopra 64 la
PCA torna avanti (la LDA si sovra-adatta agli iscritti). Ma anche con LDA, dim 32 = 65%
(tractabile ma lento) e dim 64 = 84% (RAM esplode), e la compressione sposta i punti di
qualche punto, non sposta il limite.

La conclusione, definitiva su questo hardware, è che l'argmin cifrato sul server con
embedding CNN di qualità non è praticabile ottimizzando software/compressione, e serve
hardware diverso (GPU / parallelismo) o un'idea nuova (proiezione *appresa* a
bassa dimensione, cioè distillazione dell'embedding; argmin a torneo *con* parallelismo;
oppure privacy a livello di protocollo). Il sistema valido resta quello con argmin sul
client (~95%, ~100 ms, server cieco), che è privacy-preserving sotto il modello di
minaccia naturale (F21). Il server-argmin (difesa dal client non fidato) è lavoro futuro.

## 🔴 F24 — La soluzione: la strategia CHUNKED supera il limite dell'argmin server
Sulla wiki di Concrete abbiamo trovato la leva che ci mancava. Concrete ha strategie
configurabili per i confronti e i min/max
([bitwise](https://docs.zama.ai/concrete/explanations/advanced-features/bitwise),
[min/max](https://docs.zama.ai/concrete/explanations/advanced-features/minmax)). Con la
strategia di default l'operazione esplode in RAM quando i punteggi sono larghi; la strategia
`CHUNKED` la spezza invece in pezzi ed è molto più parca di memoria (9-21 table-lookup per
confronto). Si attiva con
`Configuration(comparison_strategy_preference=[CHUNKED], min_max_strategy_preference=[CHUNKED])`.

Il limite dei 16 bit sul confronto resta anche con CHUNKED (*"only up to 16-bit comparison
operations are supported"*). Ma combinandolo con la quantizzazione a 4 bit, così che i punteggi
stiano sotto i 16 bit, l'argmin sul server finalmente compila e gira, dove con la strategia di
default esplodeva la RAM (F23):

| dim PCA | accuratezza | argmin cifrato (N=8) |
|---|---|---|
| 128 | ~90% | 123 s |
| 256 | ~93% | 130 s |

Il limite, quindi, era la strategia sbagliata e non un limite della FHE, perché con CHUNKED l'argmin
sul server funziona, a circa 90-93% di accuratezza. Resta il problema del tempo: circa due
minuti su CPU per N=8, perché ogni confronto CHUNKED costa una quindicina di secondi. Non sono
i 2-3 secondi che vorremmo, ma il sistema funziona, ed è privato anche verso il client.

⚠️ **Quei 123-130 s valgono solo nel regime a ~9 bit** (embedding sintetici, quantizzazione
stretta), non nella configurazione reale. Sugli embedding reali a 512 dim e 4 bit l'argmin a N=8 sta
in classe-minuti, e **ridurre la dimensione non lo abbassa**: il tempo dipende dalla larghezza del
punteggio, non dalla dimensione. E l'argmin a 512 dim **compila senza comprimere**, quindi la
compressione non serviva nemmeno a far compilare: a tenere il confronto sotto i 16 bit è la
quantizzazione a 4 bit.

A questo punto l'ipotesi naturale è la GPU: Concrete ha un backend CUDA, e il PBS su GPU
dovrebbe essere 50-100 volte più veloce, quindi i due minuti diventerebbero secondi. Non
possiamo provarlo su questo Mac (Apple Silicon, niente CUDA), ma sembrava la conclusione
difendibile. La verifichiamo in F25, che la smentisce.

## 🔴 F25 — La verifica sul campo: la GPU non è la leva (misurato su Tesla T4)
F24 si chiudeva con un'ipotesi: «su GPU il PBS è ~50-100× più veloce, quindi i ~2 min di
argmin diventano 2-3 s». L'abbiamo misurata, e il risultato la ribalta.

Arrivarci non è stato banale. Su questo Mac non c'è CUDA; il backend GPU di Concrete è solo
CUDA e per di più vuole compute capability ≥ 7.0 (Volta), così la GTX 1060 del server di
casa (sm_61, Pascal) è sotto il minimo e non esegue i kernel. La via pulita è la Tesla T4 di
Google Colab (sm_75, 15 GB), pilotata via il Colab MCP ufficiale. (Ostacoli reali
d'installazione: cert SSL scaduto su `pypi.zama.ai/gpu`, risolto con `--trusted-host`; il wheel GPU
vuole numpy 1.26 mentre Colab ha numpy 2, quindi pin numpy 1.26 + scipy 1.12 e riavvio kernel.)

La misura usa lo stesso circuito di F24 (argmin 1:N, N=8, CHUNKED, Q=±2, punteggi 8-10 bit):

| dim | bit | GPU T4 (run) |
|---|---|---|
| 64 | 8 | 629 s |
| 128 | 9 | 1082 s (18 min) |
| 256 | 10 | 1267 s (21 min) |

Per riferimento, l'M4 Max (F24) faceva dim 128 in ~123 s, e il baseline CPU sulla stessa VM
Colab girava da oltre 17 minuti senza finire. In pratica la T4 è ~9× più lenta della CPU desktop,
e non dà speedup nemmeno rispetto alla CPU debole della sua stessa macchina. L'ipotesi di
F24 è falsa.

Capire il perché è importante. L'accelerazione GPU di TFHE serve al throughput in batch: tante
bootstrap indipendenti che riempiono insieme i core. Il nostro argmin è l'opposto, una
riduzione sequenziale (N−1 confronti dipendenti) su una singola query, niente da
parallelizzare, e ogni PBS minuscolo paga solo l'overhead di lancio del kernel. La GPU
servirebbe a fare molte persone insieme (throughput), non la latenza del singolo al varco.

Non è una congettura nostra. Zama stessa scrive che la GPU di TFHE-rs privilegia un
tradeoff latenza/throughput perché "i casi reali raramente calcolano un singolo bootstrap"
([Zama](https://www.zama.org/post/bootstrapping-tfhe-ciphertexts-in-less-than-one-millisecond),
[TFHE-rs GPU docs](https://docs.zama.org/tfhe-rs/hardware-acceleration/run-on-gpu)); e la
letteratura sugli acceleratori FHE-GPU dà il meccanismo preciso: l'overhead di lancio dei
kernel (~2-10 µs) serializza le tante operazioni piccole, e il rimedio è il batching in
un'unica chiamata ([Theodosian](https://arxiv.org/abs/2512.18345),
[Chameleon](https://arxiv.org/abs/2410.05934)). Il nostro argmin è batch ≈ 1, fuori dal
regime in cui la GPU conviene. (I numeri assoluti dipendono dalla build GPU 2024.12.19 e da
CHUNKED; cambierebbero con un backend più recente, ma non l'asse del problema.)

In conclusione, non c'è una scorciatoia hardware ai 2-3 s del riconoscimento privato-verso-il-
client. Le leve vere restano algoritmiche (meno confronti, batch tra query, torneo
parallelo) o di protocollo. Il sistema veloce-e-accurato resta quello con argmin sul client
(F21); il server-argmin privato funziona (F24, ~90% a ~2 min) ma non è realtime, e, ora
verificato, la GPU non rende tale **l'argmin sequenziale**. Il verdetto è ristretto a quel carico:
una catena di confronti dipendenti è il caso peggiore per un acceleratore. Il varco a soglia è
l'opposto — N bootstrap indipendenti — ed è il carico per cui le API GPU sono scritte (F66).

## 🔴 F26 — Cosa fa la letteratura: non è tutto CKKS, e quasi nessuno fa l'argmax sul server
Dopo aver incontrato il limite dell'argmin siamo andati a vedere come lo risolvono gli altri. La
rassegna completa, 16 sistemi con le fonti lette direttamente, sta in `letteratura.md`, e qui ne riassumiamo il succo.

Sul fronte degli schemi, CKKS è il più diffuso per la similarità (Blind-Match, GROTE, CryptoFace, BSGS,
Mazzone): lavora su vettori di reali e fa packing SIMD, cioè una sola operazione cifrata agisce
su centinaia di slot in parallelo, così impacchetta le similarità della galleria in un
ciphertext e batcha i confronti. TFHE, il nostro, è l'opposto: ottimo per le funzioni
non-lineari arbitrarie via PBS, ma ogni confronto è un'operazione a sé, quindi l'argmin è una
riduzione sequenziale lenta (F24), peggio su GPU (F25). Non è però tutto CKKS: c'è il BFV/FV per
gli interi esatti (HERS, Boddeti, che poi scaricano l'argmax al client), e c'è una linea TFHE
sul nostro stesso problema (Blind Counting Sort e Blind Top-k di PoPETs'25, RevoLUT, k-NN
simmetrico di PSD'22, che fanno argmin e top-k via LUT e counting-sort). Quindi nello schema non
eravamo fuori strada.

La cosa importante è che quasi nessuno calcola un argmax cifrato vero sul server. Lo evitano in
quattro modi. Lo scaricano sul client, che decifra tutti gli score e fa l'argmax in chiaro
(HERS, Blind-Match, CryptoFace; è il nostro F21). Lo riducono a una soglia, un solo bit "c'è un
match?" (CryptoMask) o i soli indici senza score (BSGS). Lo approssimano sul server con polinomi
(GROTE col group testing, confronti K→2√K; Mazzone con un vettore one-hot, argmin di 128 in
~13 s). Oppure usano due server, dove un Key Server decifra gli score (IDFace, 1M sotto il secondo).

Gli ordini di grandezza del related-work sono questi: IDFace 1M sotto il secondo (CKKS, due server); Blind-Match LFW
99,63% in 0,74 s (CKKS); BSGS 99,99% su 44K, sub-secondo su GPU (CKKS); HERS 100 M in ~500-740 s
(BFV); GROTE 14,6 s a K=16.384 (CKKS); Mazzone argmin di 128 in 12,8 s (CKKS); Blind Counting
Sort k-NN in ~2,4 s (TFHE).

Quanto a dove siamo noi, quasi tutti cifrano anche la galleria (enc×enc); il nostro Mondo 1 (galleria in
chiaro, solo probe cifrata, quindi enc×plaintext senza PBS sul prodotto scalare) è più leggero,
ma va detto con franchezza che è anche la metà più facile del problema: togliendo la cifratura
della galleria togliamo la parte crittografica più costosa (la distanza enc×enc, pesante di
PBS) e proteggiamo la probe di passaggio lasciando esposto l'archivio degli iscritti. La
versione difficile, con galleria cifrata (Mondo 2), resta lavoro futuro. L'unico parente
stretto è il k-NN TFHE simmetrico di PSD'22 (probe cifrata, galleria in chiaro, non-interattivo,
identico a noi, ma con costo PBS quadratico). È un punto distinto e poco esplorato dello spazio,
e va dichiarato.

La lezione per il varco è che spesso l'argmin non serve. A un controllo accessi basta "c'è qualcuno
sotto soglia? apri o non aprire", più economico e con meno leakage (il client non impara né gli
score né chi sei). La soglia ce l'abbiamo già (F11); l'argmin serve solo per dire quale
identità. Il nostro lavoro non è scoprire CKKS in ritardo, ma aver costruito e misurato un 1:N
privacy-preserving su Concrete/TFHE nel setup galleria-in-chiaro, poco battuto, e aver situato
il risultato nello stato dell'arte: ⚠️ il limite misurato qui è di **Concrete-python**, non di TFHE
(F31: lo stesso calcolo in tfhe-rs è classe-secondi), e gli altri lo
aggirano, e per il varco la soglia è la risposta giusta, quella che da noi già funziona.

## 🔴 F27 — Ottimizzare l'argmin su Concrete: il torneo aiuta, ma il real-time resta fuori
Prima di pensare a CKKS abbiamo ottimizzato Concrete: si può rendere veloce l'argmin sul server
cambiando struttura e attivando il parallelismo? L'abbiamo misurato sull'home server Linux
(x86_64, 12 core), non sul Mac, perché il linker dell'M4 Max è rotto e il `dataflow_parallelize`
di Concrete esiste solo su Linux. Parametri: dim 64, Q=±2, ~8 bit, CHUNKED (dettagli e CSV
in `experiments/10_argmin_struttura/`).

Confronto fra argmin sequenziale (catena di N−1 confronti) e a torneo (profondità log N),
con e senza dataflow:

| N | sequenziale | seq+dataflow | torneo | torneo+dataflow |
|---|---|---|---|---|
| 4 | 78,3 s | 73,9 s | 36,1 s | 33,2 s |
| 8 | 180,4 s | 185,6 s | 69,1 s | crash compilatore |

**Il torneo conviene solo se c'è parallelismo che ne sfrutti la profondità.** Misurato in due
condizioni:

| | sequenziale | torneo | |
|---|---|---|---|
| server Linux, **con** dataflow | — | — | torneo 2,2× a N=4, 2,6× a N=8 |
| M4 Max, **senza** dataflow (`Dataflow parallelism is not available in macOS`) | 47,35 s (N=4) · 98,29 s (N=8) | 63,31 s · 102,44 s | torneo **più lento** |

Il vantaggio del torneo è la **profondità** (log N livelli invece di N−1 confronti in catena), e la
profondità si incassa solo se qualcosa esegue in parallelo i confronti dello stesso livello; senza,
restano solo le sue operazioni in più. Il 2,2× era quindi del **dataflow**, non della struttura — e
lo stesso meccanismo spiega perché in tfhe-rs (F52) il torneo guadagna davvero: lì rayon i livelli
li esegue in parallelo per davvero.

Con il dataflow attivo:

L'ottimizzazione che conta è il torneo: 2,2× più veloce a N=4, 2,6× a N=8, e il vantaggio cresce
con la galleria (il sequenziale scala ×2,3 per raddoppio, il torneo ×1,9). La catena paga
anche l'indice accumulato che si allarga, mentre l'albero no. Il dataflow invece non è la leva:
inutile sul sequenziale (niente da parallelizzare), solo ~8% sul torneo a N=4, e a N=8 fa
crashare il compilatore (un bug, assertion MLIR).

Ma c'è un limite inferiore. La config migliore, torneo a N=8, è 69 s per soli 8 iscritti, perché
il singolo confronto cifrato costa ~26 s a 8 bit, e nessuna struttura scende sotto ~log(N)
volte quel costo. Quindi ottimizzare la struttura aiuta sul serio (un passo avanti verso
tempi più bassi, tutto in Concrete), ma il limite inferiore resta il costo del PBS in
TFHE. Per i secondi bisognerebbe abbattere *quello* (precisione molto più bassa, e
l'accuratezza crolla) oppure cambiare schema (CKKS, F26). È la chiusura coerente di
F24→F27: il sistema veloce-e-accurato resta quello con argmin sul client (F21); il
server-argmin privato è fattibile e caratterizzato, ma non realtime.

## 🔴 F28 — Il varco a soglia misurato: più economico dell'argmin, ma scala lineare (non real-time)
F26 dice che per un varco basta la soglia (un bit: "c'è un iscritto sotto soglia?
apri/non apri"), non l'argmin. E sulla carta la soglia ha tre vantaggi: i confronti
`distanza < T` sono indipendenti (parallelizzabili, dove l'argmin sequenziale non lo era),
il confronto è con una costante in chiaro (più economico), e la riduzione è una somma di
bit (gratis, niente PBS). L'abbiamo misurato su Concrete (server Linux 12 core, dim 64, ~bit 10,
`np.sum(p < T)`):

| N (iscritti) | run (latenza/query) | vs argmin |
|---|---|---|
| 8 | 31,2 s | argmin a torneo era 69 s → ~2,2× più veloce |
| 64 | 347,6 s (~6 min) | — |

Tutti corretti (conteggio = atteso), e il dataflow non aiuta (31,2 vs 32,0 s a N=8). Conta
però lo scaling: 8→64 iscritti (×8) porta 31→348 s (×11), cioè ~lineare in N. La
parallelizzazione dà solo un fattore costante (≈ numero di core), non spezza la linearità.
La soglia quindi abbassa il costante (è più economica dell'argmin, è il primitivo giusto,
fa trapelare un solo bit) ma non cambia la legge: a un ufficio (decine di iscritti) è
plausibile, qualche minuto; estrapolando, N=256 ≈ 23 min, N=1024 ≈ 1,5 h. In più il keygen
esplode con N: a N=64 il processo usava 27 GB di RAM, e oltre va in OOM su questo box,
quindi è un secondo limite, sul setup più che sulla query.

Il verdetto chiude la domanda "il varco a soglia è realtime?", e la risposta è no, a scala reale. In TFHE
restano N PBS indipendenti, tempo lineare in N, e la parallelizzazione è solo un fattore
costante. Operativamente: varco TFHE con galleria in chiaro è pratico solo per gallerie
piccole (decine di iscritti, latenza minuti); per centinaia o migliaia serve il packing SIMD
di CKKS (F26: IDFace, 1M sotto il secondo), che batcha gli N confronti invece di pagarli uno per
uno. È la conferma sperimentale, dal lato giusto del problema, della conclusione di F24→F27:
su TFHE il match privato 1:N non è realtime a scala: lo è solo nel caso piccolo, o
spostando la decisione fuori dal server (client, F21) o su un altro schema (CKKS).

Aggiorniamo il quadro sul reale. Fin qui il varco l'avevamo misurato solo in tempo, su vettori
sintetici, senza un numero di riconoscimento, e l'accuratezza (~95%) veniva da un percorso
diverso, l'argmin sul client (F21, veloce ma il client vede gli score). Li abbiamo uniti: il
varco a soglia cifrato fatto girare su embedding ResNet100 reali (VGGFace2), per misurare
insieme esattezza, accuratezza e tempo (`benchmark/soglia_reale.py`).

Descriviamo il setup. Una galleria di N iscritti (una foto ciascuno), probe genuine (le altre foto degli
iscritti) e probe impostori (id non iscritti); il server calcola le N distanze cifrate
(`‖g‖² − 2·g·a`, enc×plaintext, niente PBS sul prodotto scalare) e ritorna un bit: c'è un
iscritto sotto soglia? La soglia è tarata per FPIR=1% sugli impostori, gli embedding
quantizzati a 4 bit (obbligatorio a 512 dimensioni, F31). Un dettaglio che ci ha morso: per
compilare correttamente, l'inputset di Concrete deve venire dai probe veri. Con vettori casuali
sottostima il range (i probe genuini danno distanze piccole, valori estremi che il caso non
mostra) e il circuito li tronca, dando esiti errati (12 su 24); con i probe veri il
dimensionamento è giusto e l'esito torna esatto.

| N | dim | TPIR@FPIR=1% cifrato | float | larghezza | PBS | tempo/probe |
|---|---|---|---|---|---|---|
| 8 | 512 | 97,5% | 95,0% | 14 bit | 8 | 12,5 s |
| 8 | 128 | 92,5% | 92,5% | 12 bit | 8 | 10,0 s |
| 8 | 64 | 90,0% | 90,0% | 11 bit | 8 | 8,4 s |
| 64 | 512 | 92,5% | 92,5% | 14 bit | 64 | 91,7 s |
| 64 | 128 | **93,4%** | 94,1% | 12 bit | 64 | 88,2 s |
| 64 | 64 | 86,6% | 86,2% | 11 bit | 64 | 61,9 s |

L'esito è esatto ovunque: il bit decifrato coincide con la decisione in chiaro
quantizzata in 16 casi su 16, a ogni N e dimensione, quindi il percorso privato non perde nulla
rispetto al chiaro, privacy e accuratezza sono lo stesso numero. 512 dimensioni ci stanno: a 4
bit il punteggio è 14 bit, sotto il limite di 16 del confronto (F31), quindi il varco esatto
gira a piena dimensione. Sul costo di ridurre la dimensione la tabella dice una cosa precisa e non
ovvia: a N=64 le **128 dimensioni fanno 93,4% contro il 92,5% delle 512**, cioè ridurre lì
*migliora*; il crollo arriva solo a **64 dimensioni** (86,6%). Fra 128 e 512 la differenza sta
dentro il rumore di campione (16 probe). La lettura corretta non è «ridurre costa accuratezza», ma
**«sotto 128 dimensioni sì»**. La quantizzazione a 4 bit non costa (i numeri cifrati
combaciano col float a meno del rumore di campione). Il costo è quello dell'argmin meno la
catena: N PBS (un confronto per iscritto con la soglia in chiaro) contro i 108 dell'argmin a
512 dimensioni (F33). I 12,5 s a N=8 sono tutti negli 8 confronti (8 PBS a 14 bit, ~1,5 s
l'uno), mentre il prodotto scalare cifrato è gratis (0 PBS, ~0,07 s, è una combinazione lineare
sul cifrato con pesi in chiaro), come misurato nel breakdown di F33. Resta lineare in N
(N=64: 64 PBS, ~92 s).

Questo chiude i "due binari" privacy/accuratezza: esiste un sistema unico, privato e accurato,
che misuriamo davvero. Il varco cifrato su volti reali decide accetta/rifiuta sotto cifratura,
riproduce esattamente il chiaro, e riconosce al 97,5% (N=8) o 92,5% (N=64) con FPIR all'1%. A
non essere realtime è solo la latenza, lo stesso limite di sopra. Messo accanto a F21, il quadro
onesto è che nessun singolo sistema è insieme veloce, accurato e privato: l'argmin sul client è
veloce e accurato ma non privato, il varco sul server è privato e accurato ma non veloce.

## 🔵 F29 — Scaling DigiFace completato fino a 48000: sul sintetico la profondità satura
F17 era parziale: una sola parte di DigiFace (33.333 identità), due modelli, fermo a 8000
iscritti perché l'embedding ResNet50 per-immagine era lentissimo. Ripreso col dataset
intero (99.999 identità, ×5 img) e tre modelli, spinto fino a 48000 iscritti. Figura
aggiornata `benchmark/results/scaling_grande.png` (in F30 aggiungiamo AdaFace come quarta
curva sullo stesso sweep).

| iscritti | MobileFaceNet | ResNet50 | ResNet100 |
|---|---|---|---|
| 250 | 86,5% | 92,3% | 91,9% |
| 1000 | 79,6% | 86,7% | 87,3% |
| 8000 | 70,8% | 77,4% | 77,2% |
| 16000 | 66,5% | 74,5% | 73,9% |
| 32000 | 62,1% | 69,8% | 69,1% |
| 48000 | 59,7% | 67,1% | 66,6% |

Il calo continua regolare fino al fondo scala: ResNet50 va da 92% a 67% tra 250 e 48000
iscritti, decadimento quasi lineare nel logaritmo di N. Conferma ed estende F17 al massimo
che il sintetico ci permette: a decine di migliaia di iscritti il DIR@FPIR onesto è
~60-67%, non il 96% delle gallerie piccole.

ResNet50 e ResNet100 si equivalgono sul sintetico: stanno entro mezzo punto, si incrociano
un paio di volte, ResNet50 è un soffio avanti al fondo scala. È diverso dal reale, dove
ResNet100 vince (F19): la profondità in più paga sui volti veri ma satura sul sintetico. La
lettura è che su DigiFace il collo di bottiglia è il divario di dominio (render sintetici
fuori dalla distribuzione di addestramento, F16), non la capacità del modello, quindi due
reti profonde incontrano lo stesso limite. Lo riprendiamo con AdaFace e il confronto
reale in F30.

Serve una nota metodologica, perché senza non saremmo arrivati a 48000. L'embedding girava una
immagine per volta (ResNet50 ~9 h di CPU per 500k volti). Tre interventi: inferenza a batch
(256 alla volta) per 3× di velocità, con embedding identici al per-immagine entro 1e-6;
`dir_at_fpir` riscritto con algebra a blocchi (‖p‖² − 2·p·gᵀ + ‖g‖²) per ~44× sullo sweep,
numericamente identico al calcolo per-probe; CoreML scartato, non dà guadagno e sposta gli
embedding del 2%. Gli embedding sono in cache per riuso. Verificata anche la correttezza
della pipeline: 1:1 verification su DigiFace a 98,9% (d'=3,8), crop allineati a sufficienza,
split open-set senza leakage, quindi il calo a scala è difficoltà vera e non un errore.

## 🔵 F30 — AdaFace e il divario di dominio: il reale conta più del modello
Aggiunto un quarto modello, AdaFace IR101 (WebFace12M), come controprova. Ha la stessa
profondità di ResNet100 (architettura iresnet100) ma una ricetta di addestramento diversa,
margine adattivo alla qualità invece di ArcFace. Pesi dal repo CVLface dell'autore
(safetensors, ~249 MB), backbone vendorizzato, loader in `experiments/08_cnn/adaface.py`.
L'abbiamo validato: carica strict 917/917 chiavi, 1:1 su DigiFace 98,9% (d'=4,98), quindi caricamento
e preprocessing sono corretti.

Sul sintetico AdaFace non stacca. L'ho aggiunto a tutto lo sweep DigiFace fino a 48000,
quindi la figura `scaling_grande.png` ora ha quattro curve. AdaFace traccia vicino ai due
modelli profondi, un soffio sopra a galleria piccola e media (93,9% a 250 contro 92,3% di
ResNet50, 78,3% contro 77,4% a 8000) e converge al fondo scala (66,8% contro 67,1% a 48000).
Il margine di AdaFace su ResNet50 è piccolo ed è a seed singolo (`scaling_grande.csv`): ~+1 punto a
galleria media (93,9 contro 92,3% a 250), che si annulla al fondo scala. È dentro il rumore di seed,
~±1,5 punti a N piccolo, e sul sintetico non abbiamo salvato un per-seed come per il reale, quindi
qui non c'è un IC. Conferma F29, sul sintetico la ricetta di addestramento, come la profondità,
cambia poco.

Sul reale (VGGFace2, estende F19 a quattro modelli). La tabella l'abbiamo rimisurata con protocollo
dichiarato e media su 15 seed con IC95, per non appoggiarci al seme singolo dei finding precedenti:
open-set 1:N, metà identità ignote, metà foto in galleria, 6 immagini per identità (tutte quelle nel
nostro estratto, 8.631 identità × 6). Codice `benchmark/rimisura_1n.py`, dati `rimisura_1n.csv`.
DIR@FPIR=1% (media ± IC95):

| iscritti | MobileFaceNet | ResNet50 | ResNet100 | AdaFace |
|---|---|---|---|---|
| 50 | 94,6 ±0,7 | 96,4 ±0,7 | 96,7 ±0,7 | 96,6 ±0,8 |
| 250 | 93,0 ±0,6 | 96,1 ±0,4 | 96,4 ±0,3 | 96,3 ±0,3 |
| 1000 | 90,1 ±0,3 | 95,3 ±0,1 | 95,9 ±0,1 | 95,6 ±0,1 |
| 2000 | 88,4 ±0,2 | 95,0 ±0,1 | 95,8 ±0,1 | 95,4 ±0,1 |
| 4300 | 85,9 ±0,2 | 94,1 ±0,1 | 95,4 ±0,1 | 94,8 ±0,1 |

Con gli IC in mano l'ordinamento a scala è netto e significativo: ResNet100 > AdaFace > ResNet50 >
MobileFaceNet, con IC a ±0,1 a galleria grande. A galleria piccola (≤250) i tre modelli profondi
hanno IC sovrapposti, quindi le differenze di 1-3 punti che i finding a seed singolo (F13-F19)
riportavano tra loro erano dentro il rumore: vale solo che i profondi battono MobileFaceNet (~2
punti, sempre significativo) e che ResNet100 è in testa a scala. Questa tabella sostituisce i valori
puntuali a seed singolo di F13-F19. Il varco a 50 iscritti è 96,7 ±0,7% con ResNet100 e 94,6 ±0,7%
con MobileFaceNet; il numero dipende dal protocollo (con 6 foto/id invece di 5 si guadagnano ~1
punto su MobileFaceNet e ~0,4 sui profondi, e i "96%" a seed singolo di F13 usavano fino a 20 foto/id
dal dataset grezzo, un filo ottimistici e non dichiarati).

AdaFace pareggia ResNet100 sui piccoli N e gli scende appena sotto a scala: a 4000-4300 il
margine appaiato su 20 seed è −0,52 punti (IC95 ±0,04, negativo in 20 seed su 20) contro
ResNet100 e +0,65 punti (IC95 ±0,04, positivo in 20/20) contro ResNet50, quindi entrambi
piccoli ma reali, non rumore di split (per-seed in `benchmark/results/adaface_per_seed.csv`).
ResNet100 rimane il migliore. AdaFace è progettato per i volti reali di bassa qualità (sfocati,
bassa risoluzione), e né VGGFace2 (volti web puliti) né DigiFace (render puliti) lo mettono
alla prova, quindi resta un soffio sotto ResNet100. Per vederlo staccare servirebbe un set
reale difficile, tipo TinyFace o IJB-C hard, che non abbiamo.

Il finding che conta è il confronto tra i due domini. A parità di galleria il reale sta
molto più in alto del sintetico, e le curve hanno forma diversa, piatte sul reale e in
caduta sul sintetico. A 4000 iscritti:

| dominio | ResNet50 | ResNet100 | AdaFace |
|---|---|---|---|
| reale (VGGFace2) | 94,5% | 95,5% | 95,0% |
| sintetico (DigiFace) | 81,4% | 80,7% | 82,3% |

Tra i 13 e i 15 punti di divario, costante. La scelta del modello vale 1-2 punti, il
dominio ne vale quindici. Per la tesi il messaggio è che il finding "ResNet100 non è più
forte" vale solo sul sintetico ed è un artefatto del dominio, non una verità sul modello:
sul reale la gerarchia è netta (ResNet100 ≥ AdaFace > ResNet50, e tutti molto sopra
MobileFaceNet). E la leva per renderlo più forte è allineare il test al dominio d'uso reale, più che cambiare rete. Quello che ancora manca è il reale a grande scala (MegaFace,
1M), fermo sulle credenziali di download.

Sul piano tecnico, embeddare AdaFace su tutte le 500k immagini DigiFace richiede attenzione alla
memoria. Convertire l'intero array immagini in float32 in un colpo arriva a ~150 GB e manda
in OOM; va fatto in streaming, caricando ed embeddando poche migliaia di immagini per volta
(picco ~2 GB). Sui set più piccoli (VGGFace2 reale, ~50k crop) non si nota.

Una controprova mostra che si tratta di dominio e non di allineamento. Un dubbio su questo divario: VGGFace2 passa per
detection e `norm_crop` sul template canonico ArcFace, mentre DigiFace lo usavamo nativo a
112×112 senza ri-allineare, quindi i 13-15 punti potevano essere in parte un artefatto di
allineamento asimmetrico. L'abbiamo misurato: su 250 identità DigiFace (1.250 immagini, 5.000
coppie) abbiamo ri-allineato i volti con lo stesso detector di VGGFace2 (buffalo_s, `det_500m`
→ `norm_crop`), ri-embeddati con ResNet100, e confrontata la verifica 1:1.

| allineamento | 1:1 acc | d' |
|---|---|---|
| nativo (DigiFace 112×112) | 98,84% | 4,46 |
| ri-allineato (come VGGFace2) | 98,48% | 4,31 |

Il detector trova il volto nel 98,3% delle immagini, quindi ha davvero ri-warpato i crop, non è
caduto sul resize. La separabilità non migliora: il d' resta uguale, semmai cala di un soffio.
I crop nativi di DigiFace sono già praticamente canonici (sintetico, frontale), quindi
ri-allinearli al template ArcFace non aggiunge nulla. La separabilità 1:1 (il d') è la leva
sottostante: se ri-allineare non la muove, non può sollevare la curva 1:N. Il divario regge
come effetto di dominio, non come artefatto di pipeline, e la controprova lo rafforza.

## 🔴 F31 — Ottimizzare Concrete il più possibile: il limite è l'API, non TFHE
Dopo F26 e F27 abbiamo voluto ottimizzare ancora l'argmin sul server e leggere bene la
letteratura su come si fa l'argmin cifrato veloce. Il risultato corregge una cosa che avevamo
detto sbrigativamente (F26: "il limite è TFHE").

Secondo la letteratura, il TFHE può fare l'argmin molto più veloce di noi. Chakraborty e
Zuber (WAHC 2022, eprint 2022/622) fanno un argmin a torneo con un bootstrap che emette
minimo e indice insieme in ~2 PBS, a ~0,17-0,18 s per confronto single-thread su un laptop
del 2016; il paper misura tornei su 128 elementi (~10-24 s secondo la config), e i ~10,8 s
su 64 interi a 8 bit che citiamo sono un'estrapolazione dal loro costo per confronto. Azogagh et al. (Blind Counting Sort, PoPETs 2025) fanno
argmin e sort senza confronti, via counting-sort su LUT (k-NN ~2,4 s a piccola scala). Ma
entrambi sono scritti a mano sulle primitive TFHE a basso livello (Chakraborty sulla libreria
TFHE originale in C/C++, Azogagh su tfhe-rs), non in Concrete-python. Per la scala vera
resta CKKS con packing SIMD (IDFace, 1M sotto il secondo), che è un altro schema.

Cosa abbiamo provato su Concrete, e i verdetti:
- Quantizzazione aggressiva. Sugli embedding CNN veri (ResNet50, DigiFace, N=1000) la
  quantizzazione a 3 bit è quasi gratis: DIR@FPIR 86,2% contro 86,7% del float; a 2 bit crolla
  a 61%. Ma non dà velocità: l'argmin a N=8 resta ~135-180 s per q = 2, 3, 4, persino
  non-monotòno. E a 512 dimensioni la quantizzazione a ≤4 bit è obbligatoria per compilare,
  perché il confronto cifrato di Concrete è limitato a 16 bit e i punteggi a 6 bit lo superano (circa 18, F20).
- Riduzione di dimensione. Non abbassa il costo dell'argmin, al contrario di quello che
  pensavamo. Misurato su embedding reali (N=4, 4 bit, inputset dai probe veri): a 512 dim l'argmin
  è 158,7 s (44 PBS), a 128 dim **237,9 s** (81 PBS, cioè peggio) e a 64 dim 74,8 s ma con risultato
  **errato**: piatto se non peggio, e non monotono. Comprimendo, i bit del
  punteggio calano (14→12) ma il compilatore non emette meno PBS in proporzione (44→81→22), e il totale non scende. Il
  costo dell'argmin sono gli N−1 confronti, non la dimensione; la dimensione vive nel prodotto
  scalare, che è gratis (F33). In più comprimere costa accuratezza sul reale (DIR@FPIR: 512 = 95,5%,
  128 = 94,5%, 64 = 84,9%). La dimensione quindi non è una leva per il costo FHE. Lo sarebbe la
  larghezza del punteggio, che però la compressione non stringe abbastanza; la stringe il ternario
  (valori ±1, ~7-8 bit) senza toccare le 512 dimensioni, e per questo mantiene l'accuratezza. Questo
  corregge la lettura di F20/F22/F23/F24, dove la compressione sembrava la leva per rendere l'argmin
  fattibile: a renderlo compilabile è la quantizzazione a 4 bit (limite di 16 bit del confronto), non
  la riduzione di dimensione.
- Strategie di confronto e min (ONE_TLU_PROMOTED, THREE_TLU_CASTED). Più lente del CHUNKED di
  default (28,9 s contro 20,9 s a N=8) o crashano, per un bug interno di Concrete su un assert
  di bit-width dentro `np.minimum`.
- Rounding approssimato (`round_bit_pattern`). Aggiunge un PBS suo che annulla il risparmio,
  rumoroso, e crasha anch'esso con `np.minimum`.
Alcune le avevamo già fatte prima: torneo 2,6× (F27), soglia (F28), GPU 9× più lenta (F25), argmin sul client
(F21).

Il numero che spiega tutto è questo: il nostro argmin sequenziale su 8 elementi compila in ~210
bootstrap (PBS), ~30 per confronto, e gira in ~180 s, cioè ~0,85 s per bootstrap (misurato
ricompilando il circuito e leggendo `programmable_bootstrap_count`). Chakraborty-Zuber fanno lo
stesso su 8 elementi con ~14 PBS a ~0,09 s l'uno, ~1,2 s in tutto (stima dai loro costi per
PBS: il paper misura a 128 elementi). Il divario di ~150× viene da due
cose insieme: facciamo ~15× più bootstrap, e ognuno è ~10× più lento.

Il perché sta nel compilatore. Concrete-python compila una funzione Python qualsiasi in automatico: scriviamo
`p[i] < val`, `np.minimum`, i select, e lui mette un PBS generico per ognuno. È comodo (si
scrive Python, compila da solo, ottimo per uno studio di fattibilità), ma non lascia scrivere
il bootstrap a mano. Chi nella letteratura va veloce ha fatto il contrario: ha scritto a mano
il circuito TFHE in Rust, fondendo minimo e indice in un solo functional bootstrap e tarando i
parametri. Quella leva in Concrete-python non c'è: decide il compilatore come implementare `<`
e `min`, non noi. Le nostre manopole (strategia, quantizzazione, rounding) stanno sopra questo
collo di bottiglia, quindi non possono chiuderlo.

Scendendo di un livello si vede cosa fa davvero il compilatore, e perché comprimere non aiuta. La
strategia CHUNKED spezza ogni confronto in chunk larghi metà del valore (nel sorgente
`context.py`, `chunk_size = floor(w/2)` in `best_chunk_ranges`), non in tanti chunk da pochi bit.
Così un confronto sta sempre in 2 chunk se la larghezza w del punteggio è pari, 3 se è dispari (il
bit spaiato forza un terzo chunk). Il numero di chunk, e quindi di PBS, non dipende dalla
magnitudine: un confronto a 16 bit e uno a 4 bit costano uguale, 7 PBS misurati ciascuno (un min
15). È questa la ragione per cui stringere i punteggi non compra meno bootstrap. In più i bit
dispari costano ~45% in più. Questi conteggi vengono da un argmin isolato su punteggi indipendenti
(a N=8: ~150 PBS a larghezza pari, 149-153 da 8 a 14 bit; ~215 a dispari, 209-217 da 9 a 15 bit).
Il nostro argmin reale compila a un conteggio più basso, perché il circuito deriva gli N punteggi
da un solo probe cifrato, ma segue la stessa logica e comunque non risparmia comprimendo: 95 PBS a
512 dim (14 bit, pari), 146 a 128 (12 bit, pari), 183 a 64 (11 bit, dispari). Il 64-dim reale,
oltre a non risparmiare bootstrap, cadeva su una larghezza dispari, il caso peggiore. Corollario pratico e
contro-intuitivo: conviene arrotondare la larghezza dei punteggi a un numero pari, perché
aggiungere un bit per renderla pari fa scendere i PBS (da 13 a 14 bit scendono da ~209 a ~153,
−27%) invece che salire. Spiega anche la variabilità che avevamo visto: lo stesso argmin a 512 dim
usciva a volte a 13 bit (dispari, 108 PBS, ~455 s) a volte a 14 (pari, 95 PBS, ~457 s) a seconda
dell'inputset, e con essa cambiavano PBS e tempo. È il conteggio che sta dietro i 108 PBS di F33.

Il limite misurato in F26/F27 non è il limite inferiore di TFHE,
è il limite inferiore di Concrete-python: la sua API ad alto livello, non lo schema. La frase giusta
per la tesi è che il match 1:N privato in Concrete-python è classe-minuti, mentre lo stesso in
TFHE scritto a basso livello (C/C++ originale o tfhe-rs) è classe-secondi a questa scala
(Chakraborty-Zuber: ~1 s a N=8, ~11 s a N=64, stime dal loro costo per confronto), e in CKKS
sub-secondo a un milione (IDFace); portarlo
lì è ingegneria crittografica fuori dallo scopo di questa tesi. Le sole
vie viste e non provate restano la delta-matrix one-hot (O(N²) confronti paralleli, serve il
dataflow di Linux, comunque fattore costante) e `fhe.multivariate` (fonde compare e select ma
vuole operandi a 4-5 bit, i nostri punteggi sono 10-14), e nessuna delle due spezza il
lineare-in-N.

Nota: questi esperimenti girano in locale, Concrete compila nativo sul Mac (su macOS beta serve
un piccolo accorgimento sul linker).

## 🔵 F32 — Il 100× misurato: lo stesso argmin in tfhe-rs sulla stessa macchina
F31 conclude che il limite di velocità è l'API di Concrete-python, non lo schema TFHE né la
macchina, ma lo deduceva da numeri di paper diversi (Chakraborty-Zuber su un laptop del 2016).
L'abbiamo misurato direttamente: lo stesso match 1:N cifrato (prodotto scalare più argmin
sequenziale) scritto in tfhe-rs, la libreria TFHE nativa in Rust, alla stessa config del nostro
circuito Concrete (DIM=64, valori in [-2,2], punteggi signed via FheInt16, che ha più bit dei
~9-10 di Concrete, quindi semmai conservativo), compilato `--release` con `target-cpu=native`,
sullo stesso M4 Max e con l'indice verificato contro il chiaro. Codice in
`experiments/13_tfhe_rs_headtohead/`.

Sull'argmin il divario è netto e confermato:

| N | argmin Concrete | argmin tfhe-rs | rapporto |
|---|---|---|---|
| 4 | 47,35 s | 0,45 s | **105×** |
| 8 | 98,29 s | 1,05 s | **94×** |
| 64 | (non misurato, troppo lento) | 9,49 s | — |

Stessa macchina (M4 Max), stesso circuito, indici verificati contro il chiaro a ogni N: a N=8
l'argmin in tfhe-rs è **1,05 s** contro i **98,29 s** di Concrete, **94×**; a N=4, 105×.
⚠️ Il rapporto **non è normalizzato sui thread**: su macOS Concrete gira di fatto mono-core (il
dataflow non è disponibile) mentre il lato tfhe-rs usa l'API alta, che parallelizza internamente su
16 core. Per core il rapporto scende plausibilmente a **6-30×**. La conclusione qualitativa non
dipende dai thread: F31 la sostiene col conteggio dei PBS (~210 contro ~14). Il confronto è
schema, tutto corretto. Il valore combacia con
le stime da Chakraborty-Zuber (N=8 ~1,2 s, N=64 ~10,8 s), quindi la letteratura era riproducibile. Sull'argmin i
~180 s non sono colpa dell'hardware né di TFHE, ma di come Concrete-python compila in automatico
la riduzione (F31: ~210 PBS grandi contro i ~14 piccoli di un circuito a basso livello). E non
serve nemmeno scrivere il bootstrap a mano: questi 1,05 s vengono già dall'API ad alto livello
di tfhe-rs (`FheInt16`, `min`, `lt`, select).

Misurando il pipeline intero, però, è saltata fuori una sfumatura che corregge una conclusione
troppo facile. In tfhe-rs ad alto livello il prodotto scalare è carissimo: a N=8 il dot+argmin
è 49,86 s, di cui l'argmin è 1,05 s, quindi il prodotto scalare da solo è ~48,8 s, perché l'API
intera propaga i riporti delle somme via bootstrap (~0,1 s a operazione). In Concrete è
l'opposto: il prodotto scalare enc×plaintext è leveled e gratis (0 PBS, ~0,07 s, F33). I due
profili sono specchiati, Concrete con dot gratis e argmin caro, tfhe-rs ad alto livello con dot
carissimo e argmin economico, e il pipeline intero naïf in tfhe-rs è solo ~2× più veloce di
Concrete (49,9 contro 98,3 s, stessa macchina), non 100×.

La conclusione per la tesi, ora misurata e più onesta, è che il ~100× vale per l'argmin, la
primitiva non lineare che è il vero collo di bottiglia algoritmico (quella che la letteratura
evita), e a parità di config. Ma "basta riscrivere in tfhe-rs e si va 100× end-to-end" non
regge: l'alto livello di tfhe-rs paga il lineare. Il sistema davvero veloce (Chakraborty-Zuber) scrive
a basso livello, dove sia le somme (leveled, in LWE) sia il confronto (un bootstrap) sono
economiche. Portarlo lì è ingegneria crittografica fuori dallo scopo di questa tesi; per la
scala resta CKKS col packing SIMD (IDFace, 1M sotto il secondo).

## 🔵 F33 — Dove va il tempo: il breakdown end-to-end di una query privata
Dopo F32 (l'argmin è ~100× più veloce in tfhe-rs, ma il pipeline intero dipende anche dal
prodotto scalare) abbiamo voluto vedere il costo di ogni tappa di una query 1:N privata, non
solo dell'argmin, alla config reale (512 dimensioni, 4 bit, embedding ResNet100 veri). Misure
su M4 Max, codice in `benchmark/soglia_reale.py` e negli script di breakdown.

| tappa | dove | costo (N=8, 512-dim) |
|---|---|---|
| embedding ResNet100 | client | 84 ms (26 ms/img in batch) |
| quantizza e cifra | client | 16 ms |
| prodotto scalare (N distanze) | server | 0,07 s (0 PBS) |
| selezione con argmin | server | **207 s (57 PBS)** |
| selezione con soglia | server | 12,5 s (8 PBS) |
| decifra l'esito | client | 1 ms |

Tutto tranne la selezione sta sotto i 0,2 s: il lavoro del client (embedding, cifra, decifra) è
classe-millisecondi, e il prodotto scalare cifrato è gratis. Il prodotto scalare ha 0 PBS perché
la galleria è in chiaro (Mondo 1), quindi è una combinazione lineare sul ciphertext con pesi in
chiaro, leveled, e non scala nemmeno con N (a N=64 resta 0,06 s). Questo corregge un'attribuzione
sbagliata che avevamo dato al varco in F28: i suoi 12,5 s sono tutti negli 8 confronti, non nel
prodotto scalare.

L'intero costo della privacy è quindi la selezione cifrata, cioè i confronti. E il costo per
confronto è dominato dalla precisione del punteggio, non dalla dimensione: un PBS a 9 bit è
~0,85 s, a 13-14 bit è ~1,5-4 s. Attenzione però a non leggerlo come "comprimere la dimensione
abbassa il costo". Il 64-dim a ~180 s è una misura sintetica, dove i punteggi cadono a 9 bit per
via della distribuzione fortunata degli embedding sintetici. Sugli stessi embedding reali ridotti
con PCA a 64 dim i punteggi sono a 11 bit e l'argmin sale a ~586 s, cioè più lento del 512 dim
reale (457 s). Apples-to-apples (stessi dati, stessa macchina) l'argmin non scende con la
dimensione: 512 = 158,7 s, 128 = 237,9 s, 64 = 74,8 s ma con risultato errato (F64). La precisione per-confronto conta, ma
comprimere la dimensione non la stringe abbastanza da aiutare, e intanto costa accuratezza (F31).

Per la tesi tutto il problema di un riconoscimento 1:N privato e veloce si riduce a una sola
operazione, la selezione cifrata (argmin o soglia). Il riconoscimento (l'embedding) e il
trasporto (cifra e decifra) non sono il collo di bottiglia, e con la galleria in chiaro nemmeno
il prodotto scalare lo è. Il varco se la cava perché gli basta la soglia (8 confronti, 12,5 s)
invece dell'argmin completo (57 PBS, 207 s); e l'unica leva per rendere veloce la
selezione è il bootstrap scritto a basso livello (F32), o cambiare schema verso CKKS (F26).

## 🔴 F34 — "Si può avere entrambi": il prodotto scalare leveled a basso livello, e l'argmin esatto
F32 lasciava una sfumatura scomoda: in tfhe-rs l'argmin è ~100× più veloce di Concrete, ma il
prodotto scalare ad alto livello (`FheInt16`) costa ~48,8 s a N=8, perché l'API radix propaga i
riporti di ogni somma via bootstrap. Ne veniva un pipeline intero solo ~2× più veloce di
Concrete. Dopo l'incontro di luglio ("quindi Rust") abbiamo chiuso la sfumatura con due binari in
`experiments/13_tfhe_rs_headtohead/src/bin/`, misurati il 30 agosto sull'M4 Max.

`basso_livello.rs`: lo stesso prodotto scalare scritto sulle primitive `core_crypto` di tfhe-rs.
Il probe è una manciata di cifrati LWE grezzi, e il punteggio p_i = ‖g_i‖² − 2·g_i·a è una pura
combinazione lineare a coefficienti in chiaro: moltiplicazioni per uno scalare e somme sul
cifrato, operazioni leveled, zero bootstrap. Alla config dell'head-to-head (DIM=64, valori in
[−2,2]) costa **0,1 ms a N=4, 0,2 ms a N=8, 2 ms a N=64**, sempre corretto alla decifratura.
Contro i ~99 s dell'alto livello sono cinque ordini di grandezza, e si torna al profilo di
Concrete (dot gratis, F33): la lentezza di F32 era dell'API `FheInt`, non di TFHE. Caveat onesto:
questo binario usa parametri LWE scelti a mano (n=1024, rumore ~2^−44) per far decifrare 12 bit
dopo l'accumulo, non un set validato a 128 bit; il costo delle operazioni leveled però dipende da
n·DIM·N e non dal rumore, quindi l'ordine di grandezza regge, e il passo successivo (F37) rifà
il conto coi parametri standard di tfhe-rs.

`correttezza.rs`: l'argmin cifrato di tfhe-rs (lt + select + min, la catena dell'head-to-head) è
esatto o va veloce perché sbaglia? TFHE è aritmetica esatta, l'unico errore possibile è l'overflow
di bit-width. Confronto con il chiaro su **208 casi**: per N = 4, 8, 16, 32 quindici vettori
casuali su tre range (12 bit, largo, estremi di i16) più sette casi avversari per N (tutti uguali,
pareggio al minimo, crescente, decrescente, minimo in coda, in testa, alternato). **208/208
corretti**, pareggi risolti come in chiaro (vince il primo), 462 s in tutto. Il 100× è esatto.

Il punto che resta, ed è il vero nodo tecnico. I due pezzi veloci vivono in due rappresentazioni
diverse: il punteggio leveled è **un solo LWE con un messaggio largo** (13-14 bit alla config
reale, F31), mentre l'argmin economico lavora su cifrati **radix**, blocchi da 2 bit ciascuno
in un LWE proprio. Per unirli bisognerebbe estrarre le cifre del punteggio largo con dei PBS, ed
è qui che i parametri standard di tfhe-rs (N=2048, pensati per LUT a 4 bit) non bastano: il
modulus switch del bootstrap risolve ~12 bit del torus e i bit bassi del punteggio, che sono
dati e non rumore, mangiano il margine di errore della LUT. È lo stesso motivo per cui Concrete,
che fa esattamente questa estrazione (CHUNKED, F31), sceglie polinomi enormi e paga 1,5-4 s a
PBS (F33). Quindi "dot leveled + argmin radix" non è gratis: o si paga il ponte con PBS a
precisione larga (la strada di Concrete), o si evita il ponte. F36 e F37 fanno la seconda cosa.

## 🔴 F35 — Le decisioni dell'incontro di luglio: il design da chiudere
Incontro con il prof. Di Raimondo e Carnemolla a metà luglio 2026, dopo l'email con F0–F33. Le
decisioni, che da qui in poi trattiamo come vincoli di progetto:

- **Obiettivo numerico**: galleria da azienda piccola, **N = 64 e 128** (numeri omogenei), e
  **latenza sotto i 10 s**, 5 s "accettabili" con un'animazione di attesa. I 455 s a N=8 di
  F33 sono "il tempo di prepararsi un caffè".
- **Strada tecnica**: "quindi Rust". La funzione è semplice (distanze, minimo, soglia), il
  convertitore Python ad alto livello non aggiunge valore: si scrive il match con le funzioni di
  tfhe-rs. Limite esplicito del prof: non un'implementazione crittografica ottimale da zero, non
  è l'obiettivo della tesi. Carnemolla: fare comunque un **confronto con CKKS** per misurare
  quanto vale lo schema (packing SIMD sulle distanze indipendenti).
- **Ordine delle operazioni**: prima la selezione, poi la **soglia sul solo vincitore**. Il
  ragionamento del prof: la computazione è blind, applicare la soglia a ogni distanza non fa
  saltare nessun elemento (si trattano comunque tutti e N), quindi non accelera la selezione; il
  suo unico vantaggio sarebbe che quei confronti sono indipendenti e parallelizzabili.
- **Uscita**: solo l'esito (identità più vicina e match/no-match), **mai la distanza**. Un
  client malicious non parte da un volto: manda vettori arbitrari, e con una distanza per
  tentativo scende per gradiente fino a un embedding della galleria. L'esito a soglia rende
  l'attacco molto più costoso, ma ⚠️ **non lo elimina**: F56 mostra che con un Δ tarato sui dati
  il varco si apre in una query, e F61 che anche col Δ onesto un vettore bipolare legale apre.
  One-hot o indice sono equivalenti per la privacy (rivelano al più N).
- **Modello di minaccia**, formalizzato. Tre attori: il server (ha la galleria), il client (il
  dispositivo al varco: calcola l'embedding in chiaro, cifra, apre il cancello), la persona.
  Client honest-but-curious: la persona non manomette il dispositivo, la sicurezza è quella
  biometrica; il client segue il protocollo e cancella i dati; il server non deve capire chi si
  autentica. Client malicious: la persona compromette il dispositivo; non si può impedirle di
  aprire il cancello fisicamente, si deve impedire che **estragga gli embedding degli iscritti**.
  Per questo la galleria sta sul server e la selezione avviene sul server: non è un hardening
  opzionale (come lo avevamo inquadrato in F21/F22), è il design. Server honest-but-curious:
  ci protegge la FHE (chi entra, correlare gli accessi della stessa persona).
- **Struttura della selezione**: torneo a profondità log N con i confronti di ogni livello in
  parallelo; galleria non potenza di due → completare l'albero con sentinelle (massimo del
  dominio). Il parallelismo hardware (thread sui confronti indipendenti) è accettabile "se rende
  il sistema fattibile"; non è il packing, che dipende dallo schema.
- **Metrica**: la distanza euclidea al quadrato va bene, è già un polinomio di grado due senza
  radice, non si approssima nulla. Si cambia solo se la letteratura mostra un guadagno di
  accuratezza in chiaro. Embedding sul client confermato; il modello è indifferente per l'FHE.
- **Metodo**: microbenchmark con vettori casuali della dimensione e precisione reali (la
  correttezza non conta, la complessità sì). Per la tesi: mostrare il percorso naïve →
  ottimizzato, solo le tecniche con miglioramento osservabile.

Nota di lettura per la tesi: quanto segue (F36 in poi) è la chiusura di questo design.

## 🔵 F36 — Quanti bit del punteggio servono davvero? Otto (validato in chiaro)
Prima di misurare il costo cifrato della selezione, il metodo dell'incontro: validare in chiaro.
Il costo di un confronto in tfhe-rs cresce con la larghezza del punteggio (FheUint8 = 4 blocchi,
FheUint16 = 8), e il punteggio reale a 512 dimensioni e 4 bit occupa 13-14 bit (F31). Ma per
decidere (chi è il più vicino, e sta sotto soglia?) forse bastano i bit alti. Misura in
`experiments/14_pipeline_tfhe_rs/precisione_punteggio.py`: embedding ResNet100 su VGGFace2
(volti reali), quantizzazione a 4 bit, punteggio reso non-negativo con un offset in chiaro e
troncato ai suoi k bit più significativi (s' = ⌊(s + C) / 2^t⌋), poi argmin (vince il primo
minimo, come la catena cifrata) e soglia sul minimo, tarata al quantile 1% dei minimi di 2000
impostori. Venti scene per N = 64, 128 (i target) e 1000 (riferimento stabile).

| bit tenuti | N=64: DIR | FPIR eff. | N=128: DIR | FPIR eff. | N=1000: DIR | FPIR eff. |
|---|---|---|---|---|---|---|
| tutti (13-14) | 94,0% | 1,01% | 93,8% | 1,00% | 93,2% | 1,00% |
| 10 | 94,0% | 1,04% | 93,8% | 1,03% | 93,2% | 1,02% |
| 8 | 94,0% | 1,12% | 93,9% | 1,13% | 93,3% | 1,15% |
| 7 | 94,0% | 1,22% | 93,9% | 1,23% | 93,3% | 1,34% |
| 6 | 94,1% | 1,52% | 93,9% | 1,39% | 93,5% | 2,37% |
| 5 | 94,1% | 2,47% | 94,0% | 2,35% | 93,6% | 8,57% |
| 4 | 94,4% | 9,84% | 94,2% | 7,92% | 93,5% | 53,75% |

(float, senza quantizzazione: 94,0 / 93,8 / 93,2%; deviazione tra scene ±1,3-1,8 punti a
N=64-128, ±0,5 a 1000.)

La DIR non si muove, nemmeno a 4 bit. Quello che degrada è il controllo della FPIR: troncando,
molti punteggi collassano sullo stesso valore e la soglia, che è un valore osservato, accetta
per pareggio più impostori di quanto tarato (a 4 bit su N=1000 la metà). A **8 bit** la FPIR
effettiva resta 1,1-1,15% con DIR invariata: è il punto operativo. Sotto i 6 bit no.

Conseguenza per l'FHE: la selezione può lavorare su punteggi a 8 bit (`FheUint8`, 4 blocchi)
invece che a 14 (`FheInt16`, 8 blocchi), quindi circa la metà del costo per confronto, e
qualunque "ponte" dal punteggio leveled dovrebbe estrarne solo le 4 cifre alte. Nota di
metodo: questa è la seconda volta che il conto in chiaro sposta il costo FHE più di
un'ottimizzazione del circuito (la prima era la quantizzazione a 4 bit, F31).

## 🔴 F37 — Il varco senza ponte: una soglia parallela sul punteggio leveled, 0,18 s a N=128
F34 lascia il nodo: il punteggio leveled è un LWE largo, il confronto economico è radix, e il
ponte tra i due coi parametri standard non è affidabile. La via d'uscita è non costruire il
ponte. Per decidere "s_i ≤ T?" non serve conoscere le cifre di s_i: serve il **segno** di
s_i − T, e il segno di un LWE largo si legge con **un solo bootstrap negaciclico ad
accumulatore costante**, qualunque sia la larghezza del messaggio (il PBS guarda in quale metà
del torus cade il valore). Il circuito del varco diventa quindi, per ogni iscritto i:

1. server, leveled (0 PBS): x_i = (s_i − T)·Δ_s − Δ_s/2, con s_i = ‖g_i‖² − 2·g_i·a calcolato
   come combinazione lineare del probe cifrato (la formula espansa di F2), T la soglia in
   chiaro (la conosce il server: è tarata all'iscrizione) e il −Δ_s/2 che centra la frontiera
   tra s_i = T e s_i = T+1;
2. server, un keyswitch e un PBS: b_i = [x_i nella metà negativa] = [s_i ≤ T];
3. client: decifra gli N bit. Se uno solo è acceso, è l'identità (one-hot, la forma che
   Carnemolla ha proposto e il prof ha accettato: "rivela al massimo quanti elementi").

Gli N confronti sono indipendenti: **profondità 1**, tutti in parallelo. In più c'è un'uscita
compatta, tutta leveled sui bit freschi del PBS: il conteggio Σ b_i e l'indice in binario (bit k
= Σ dei b_i con il bit k di i acceso), log₂N + 1 cifrati invece di N. Codice in
`experiments/14_pipeline_tfhe_rs/varco_leveled.rs`.

Parametri: quelli **standard** di tfhe-rs, `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`
(132 bit di sicurezza, n=879, N=2048, k=1), presi dalle chiavi dell'API ad alto livello con
`into_raw_parts`. Il probe è cifrato sotto la chiave grande (n=2048, rumore GLWE) con Δ_s = 2^51,
scelto dal range **osservato** dei punteggi (|s − T| < 2^12). ⚠️ Questa scelta è comoda ma non
difendibile: il codice guarda i probe della scena per fissarlo, e F56 mostra che un client malicious
lo sfrutta per aprire il varco in una query. Il Δ da usare è quello del **bound indipendente dal
probe** (2q·max‖g_i‖₁ + max‖g_i‖² + |T|), e con quello i tempi qui sotto vanno letti nella
configurazione sicura di F56 (0,153 s a N=128 invece di 0,177 s). Dati: la scena reale di
`esporta_dati.py`, ResNet100 su VGGFace2, 4 bit, 128 iscritti, 64 probe genuini e 64 impostori,
T al quantile 1% dei minimi di 2000 impostori.

| N | dot leveled | KS+PBS ×N (16 thread) | **totale per query** | per PBS, per thread |
|---|---|---|---|---|
| 8 | 0,001 s | 0,016 s | **0,017 s** | 32 ms |
| 16 | 0,002 s | 0,027 s | **0,029 s** | 27 ms |
| 32 | 0,002 s | 0,047 s | **0,049 s** | 23 ms |
| 64 | 0,005 s | 0,089 s | **0,094 s** | 22 ms |
| 128 | 0,007 s | 0,170 s | **0,177 s** | 21 ms |

Esattezza: **0 discrepanze su 31.744 confronti** cifrato/chiaro (128 probe × 248 iscritti
complessivi), esito per probe identico al chiaro (58/64 genuini riconosciuti = 90,6%, 0/64
impostori accettati), uscita compatta corretta 128/128 a ogni N in 0,2 ms. Su un thread solo il
PBS costa 13,5-13,9 ms e la query a N=128 fa **1,76 s** (0,89 s a N=64), contro 0,177 s a 16
thread: il parallelismo dei confronti indipendenti vale ~10× (12 P-core e 4 E-core).

Il confronto con quello che avevamo. La soglia in Concrete (F28, F33) costava 12,5 s a N=8 e
92 s a N=64: qui 0,017 e 0,094 s (set 1_1, Δ tarato sui dati), **~700-1000×**. L'argmin Concrete a N=8, 207 s: **12.000×**.
Il torneo radix in tfhe-rs (F38), che è il meglio che si ottiene *con* la rappresentazione
radix, 4,7 s a N=128: **27×**, ed è già dentro il target del prof. Il target dell'incontro (N =
64 e 128 sotto i 10 s, 5 accettabili) è superato di due ordini di grandezza, con parametri
standard a 128 bit, senza toccare i bootstrap a mano e senza cambiare schema.

**La banda di sfocatura.** Zero discrepanze non vuol dire esatto. Il PBS decide dopo il modulus
switch a 2N = 4096, che aggiunge al valore un errore di deviazione ~√(n/24)·q/2N = 2^54,6
(la stima standard di TFHE): in unità di punteggio a Δ_s = 2^51 fa 2^3,6 ≈ 12. Misurato
apposta a cavallo della soglia (`banda_soglia.rs`: 400 prove per ogni d = s − T da −48 a +48):
P(match | d) è una sigmoide con σ ≈ 12 unità a 2^51, 6,5 a 2^52, 25 a 2^50, esattamente come
previsto. È lo stesso fenomeno delle "zone rosse" del sign bootstrapping di Zuber e Sirdey. Sui
dati reali non scatta mai: nelle 20 scene di F36 le coppie (probe, iscritto) entro ±24 unità da
T sono lo 0,003-0,006% (i punteggi dei genuini stanno a centinaia di unità sotto T, quelli
degli impostori sopra), e simulando la sfocatura su ogni decisione (`effetto_banda.py`) la
DIR resta identica (92,9 / 92,9 / 92,3% a N = 64 / 128 / 1000, la variante one-hot di F36) con
FPIR effettiva 0,97-1,03% contro 1,00% (simulata a σ=30 e σ=50, cioè i set 2_1 e 1_1; il σ≈12 del 2_2 non è nel CSV). La banda esiste, è misurata e non tocca la decisione.
Se servisse stringerla, Δ_s più grande la dimezza a ogni bit (2^52: σ 6,5) al prezzo di un range
di punteggio più stretto.

**Perché non contraddice il prof.** All'incontro il ragionamento era: applicare la soglia a
ogni distanza non accelera la selezione, perché la computazione è blind e gli N elementi vanno
trattati comunque; l'unico vantaggio sarebbe che quei confronti sono indipendenti e
parallelizzabili. È esattamente quello che succede qui, con un passo in più: la soglia non
precede la selezione, **la sostituisce**. La selezione (argmin, log N livelli di confronti
dipendenti) sparisce, resta il lotto parallelo di N confronti che lui aveva previsto, e su un
multicore con un PBS da 20 ms quel lotto è tutto il costo. L'identità viene dal one-hot. Il
delta di privacy rispetto ad "argmin poi soglia sul vincitore" va detto con precisione, perché
NON è stato discusso all'incontro: il prof ha accettato la one-hot *dell'argmax* ("al massimo si
rivela quanti elementi sono entrati nel benchmark", cioè N), non un bit di soglia per ogni
iscritto. Con gli N bit il client riceve fino a N oracoli di appartenenza per query invece di
uno; con l'uscita compatta riceve ciò che chiedeva il prof (indice ed esito) più il **conteggio**
dei sotto-soglia (nei dati reali sempre 0 o 1; un client malicious può però costruire vettori a
metà tra due iscritti e vederne 2). In nessun caso riceve distanze, quindi la discesa per
gradiente verso un embedding della galleria non c'è; resta l'attacco lento al bordo della
palla di raggio T, che è inerente a qualunque accetta/rifiuta biometrico (anche al design del
prof; Zuber-Sirdey lo dicono e rimandano al rate limiting). Il conteggio è un punto da portare
al prof, non un punto acquisito; l'alternativa che lo azzera è scegliere il vincitore tra i
sotto-soglia, cioè rimettere un argmin, cioè il ponte. E c'è un costo di accuratezza, non di
privacy: la regola "esattamente uno sotto soglia" rifiuta quando due iscritti sono sotto T
invece di scegliere il più vicino, ~1 punto di DIR (92,9% contro 94,0% di F36).

**Letteratura (verificata sul testo).** Il precedente diretto è Zuber e Sirdey, *Efficient
homomorphic evaluation of k-NN classifiers* (PoPETs 2021): query cifrata contro modello in
chiaro (o viceversa), distanza quadratica calcolata leveled con l'encoding polinomiale, e il
confronto fatto con un "sign bootstrapping" che ha "una zona di input (le zone rosse) per cui
l'operazione non dà necessariamente il valore corretto: dà un valore casuale", accettata
perché il k-NN a maggioranza la tollera (sul loro dataset il 4% delle differenze cade sotto la
precisione del segno). La differenza è cosa si confronta: loro il segno di ogni differenza
d_i² − d_j², cioè (d² − d)/2 bootstrap e complessità quadratica (d=10 modelli in 4 s, d=457 in
71 minuti sequenziali sulla libreria TFHE originale, λ=110), perché vogliono i k più vicini;
il varco confronta ogni distanza con una **costante**, quindi N bootstrap, profondità 1, e
lineare in N. La stessa idea è alla base del loro lavoro precedente sul riconoscimento del
parlante (Zuber, Carpov, Sirdey 2019). La primitiva "un bit per iscritto" è quella che
la rassegna F26 indicava come la più naturale per un varco (CryptoMask restituisce un bit;
BSGS gli indici).

Due note oneste. Il probe cifrato come 512 LWE grezzi sotto la chiave grande pesa 8,4 MB per
query: è la forma più semplice, non la più compatta; l'encoding polinomiale di Zuber-Sirdey (una
sola TRLWE, ~16 KB, con il prodotto scalare come moltiplicazione di polinomi, sempre leveled) o
i cifrati "seeded" di tfhe-rs lo riducono di tre ordini di grandezza, e sono un passo di
ingegneria, non di idea. E la garanzia sulla banda è empirica più la formula standard del
modulus switch, non una p-fail formale: per la tesi va detto così.

## 🔴 F38 — La selezione radix in tfhe-rs: il torneo a 8 bit fa 4,7 s a N=128, ma vuole il ponte
Il microbenchmark che l'incontro chiedeva, nella forma "punteggi già in radix": vettori casuali
della precisione reale, argmin poi soglia sul vincitore, in `selezione.rs`. Quattro varianti in
ordine di percorso: la catena sequenziale di F32 (lt + min + select), la stessa senza il `min`
ridondante (il select del valore basta), il torneo con i livelli in parallelo (rayon, ogni
thread con la sua server key), e il confronto scalare in più sul vincitore. Due larghezze
(FheUint8, che F36 dice sufficiente; FheUint16, la larghezza intera) e due set di parametri a
128 bit: il default e il multi-bit group 3, il PBS che Zama pensa per il multicore. 16 thread.

| param | N | seq-F32 | seq | **torneo** | +soglia |
|---|---|---|---|---|---|
| default, 8 bit | 8 | 0,82 s | 0,61 s | **0,36 s** | 0,029 s |
| default, 8 bit | 64 | 7,36 s | 5,50 s | **2,32 s** | 0,028 s |
| default, 8 bit | 128 | 14,57 s | 10,81 s | **4,69 s** | 0,029 s |
| default, 16 bit | 8 | 1,12 s | 0,82 s | 0,57 s | 0,029 s |
| default, 16 bit | 64 | 10,23 s | 7,65 s | 4,55 s | 0,028 s |
| default, 16 bit | 128 | 20,78 s | 14,98 s | 9,07 s | 0,029 s |
| multi-bit, 8 bit | 128 | 8,27 s | 6,59 s | 4,84 s | 0,012 s |
| multi-bit, 16 bit | 128 | 14,88 s | 11,56 s | 9,86 s | 0,013 s |

Tutti gli esiti verificati contro il chiaro (tabella completa e run single-thread in
`experiments/14_pipeline_tfhe_rs/results/`). Su un thread solo: catena a 8 bit 48 s a N=128
(torneo 47 s: senza core liberi non guadagna nulla), multi-bit 21 s, 16 bit 94 s. Cosa dicono:

1. **La larghezza paga**: 8 bit contro 16 vale 1,5-2× su ogni variante. È il dividendo di F36.
2. **Il `min` ridondante costa il 25%**: la catena di F32 faceva due confronti per passo.
3. **Il torneo vale 2,3×** a N=128, non i 127/7 del rapporto di profondità: le operazioni radix
   di tfhe-rs sono già parallele al loro interno (sui blocchi), e con 16 core i due parallelismi
   si contendono le stesse CPU. Il lavoro totale resta N−1 confronti; il torneo compra
   throughput, non profondità, una volta saturati i core. Per la stessa ragione il multi-bit
   accelera la catena sequenziale (−40%) ma non il torneo.
4. Contro Concrete (F27, F32): torneo a N=8, 69 s contro 0,57 s a 16 bit (120×); catena
   sequenziale 180 s contro 1,12 s. Il multi-bit vale 2,3× su un thread (21 contro 48 s) ma
   niente a 16 thread sul torneo: è un altro modo di spendere gli stessi core.
5. **N=64 in 2,3 s e N=128 in 4,7 s**: il target dell'incontro è rispettato anche dalla strada
   "argmin poi soglia" che il prof aveva in mente. Ma con una condizione: questi numeri
   presuppongono i punteggi in forma radix, e portarceli dal prodotto scalare leveled è il
   ponte che F34 dice non affidabile coi parametri standard (o costoso con parametri larghi
   alla Concrete). La cosa onesta da scrivere in tesi è che il torneo radix è il costo della
   *selezione*, non del pipeline; il pipeline intero che sta nel target senza ponte è il varco
   leveled di F37, 27× più economico.

Il "percorso" per la figura della tesi, a N=8 dove abbiamo tutti i punti: Concrete sequenziale
98 s → Concrete torneo 102 s (il torneo non guadagna senza dataflow) → tfhe-rs sequenziale 1,1 s → tfhe-rs torneo 0,57 s (16 bit) /
0,36 s (8 bit) → varco leveled 0,017 s. A N=64: soglia Concrete 92 s → torneo radix 2,3 s →
varco leveled 0,094 s (set 1_1; nella configurazione sicura di F56, 0,153 s a N=128). A N=128: 4,7 s → 0,177 s. Cinque ordini di grandezza dal punto di
partenza, ognuno con una ragione misurata.

## 🔴 F39 — Lo stesso varco in CKKS: quanto vale lo schema (il confronto chiesto da Carnemolla)
All'incontro Carnemolla ha chiesto di misurare il beneficio dello schema, non di dedurlo dai paper:
CKKS col packing SIMD è ciò che usa quasi tutta la letteratura (F26). Abbiamo quindi rifatto il
varco di F37 in CKKS (Microsoft SEAL via TenSEAL `sealapi`, parametri a 128 bit), stessa scena
reale, stessa uscita, in `experiments/15_ckks_confronto/ckks_varco.py`. Il packing è quello
classico: il probe (512 valori) replicato R = slot/512 volte in **un solo cifrato**; per ogni
blocco di R iscritti una moltiplicazione per il plaintext −2·G, poi rotate-and-sum (9 rotazioni)
che porta il prodotto scalare nello slot 512k; una maschera e una rotazione per blocco
compattano tutti gli N punteggi in un cifrato. La soglia è il **segno** di (T + ½ − s)/RANGE
calcolato come polinomio composto g_n^{d_g} poi f_n^{d_f} di Cheon, Kim e Kim (ASIACRYPT 2020,
coefficienti verificati sul testo: f₁ = (3x − x³)/2, g₁ = (2126x − 1359x³)/2¹⁰, …): **una sola
valutazione per tutti gli N punteggi insieme**, è questo il vantaggio SIMD. Il prezzo è la
profondità: ogni composizione consuma 2 livelli (grado 3) o 4 (grado 7), i livelli vogliono
primi in più nel modulo, e con più primi ogni operazione costa di più. SEAL è single-thread.

| parametri (poly, livelli) | segno | banda | N=8 | N=64 | **N=128** | di cui distanze | di cui segno |
|---|---|---|---|---|---|---|---|
| 16384, 9 | g₁²f₁ | ±293 | 0,17 s | 0,53 s | 1,01 s | 0,96 s (8 blocchi) | 0,05 s |
| 32768, 13 | g₁⁴f₁ | ±67 | 0,71 s | 1,19 s | 2,14 s | 1,88 s (4 blocchi) | 0,26 s |
| 32768, 19 | g₁⁶f₁² | **±10** | 1,63 s | 2,51 s | **4,25 s** | 3,54 s (4 blocchi) | 0,71 s |
| 32768, 19 | g₃³f₃ | ±9 | 1,83 s | 2,72 s | 4,44 s | 3,46 s | 0,98 s |

Tempi per query, un thread, M4 Max. La banda è misurata direttamente: uno sweep di d = s − T su
tutti gli slot, una valutazione = tutta la curva; è l'intervallo dove l'uscita non è ancora ±1, e
fuori da lì il segno è **deterministicamente** giusto (diverso dalla banda di TFHE, che è
probabilistica con σ ≈ 12). Esattezza sui probe reali: **0 discrepanze su 4096** confronti a
N=128 per ogni configurazione, su un campione **bilanciato** di 32 probe (16 genuini + 16
impostori — la scena elenca prima tutti i genuini, quindi un `P[:32]` ingenuo non conterrebbe nessun
impostore e la colonna «impostori accettati» risulterebbe vuota, non zero). Risultato: **0
discrepanze su 4.096, genuini one-hot giusto 30/32** in tutte e tre le
configurazioni a 32768; il campione salvato è però ; errore CKKS sui punteggi interi ≤ 0,03, quindi esatti dopo l'arrotondamento
ed esito per probe uguale al chiaro.

Cosa dicono i numeri, con onestà in entrambe le direzioni:

1. **Il packing mantiene la promessa sul segno.** La soglia costa lo stesso a N=8 e a N=128
   (0,71 s), e coprirebbe fino a 16.384 iscritti con una valutazione. In TFHE è un PBS per
   iscritto: 13,7 ms × N. Su questa operazione CKKS scala meglio, come dice la letteratura.
2. **Ma le distanze non sono gratis come in TFHE.** Ogni blocco di 32 iscritti costa una
   moltiplicazione e nove rotazioni, e una rotazione a 32768 con 20 primi vale ~90 ms: 0,86 s per
   blocco, **27 ms per iscritto**, contro i 13,7 ms per iscritto dell'intero varco TFHE (PBS
   compreso) e i 0,05 ms del suo prodotto scalare leveled. Le rotazioni sono key-switching, e il
   key-switching cresce con il numero di primi, cioè con la profondità del segno.
3. **Il tradeoff banda/tempo è la profondità.** A 9 livelli il varco fa 1 s ma la banda è ±293
   unità (8% del range: inutilizzabile); a 13 livelli ±67 e 2,1 s; a 19 livelli ±10 e 4,2 s.
   Due composizioni di g₁ in più (4 livelli) stringono la banda ~6× e costano il doppio su
   tutto, perché i primi in più rincarano anche le distanze. È il Corollario 3 di Cheon-Kim-Kim
   (d_g ≈ log(1/ε)/log g'(0)) visto dal lato del portafoglio.
4. **Il confronto a parità di thread, e attenzione a come si legge.** A N=128, un thread: TFHE
   leveled 1,76 s contro i 4,25 s misurati qui, con banda paragonabile (±10 contro σ 12). Ma il
   packing usato in questo finding è quello a blocchi, che non è il migliore per questa forma:
   **F67 misura lo stesso calcolo con il packing corretto e ottiene 1,67 s**, cioè CKKS *sotto*
   il nostro tempo-thread. Il confronto va quindi letto lì, non qui; questo finding resta valido
   per il *meccanismo* — dove va il tempo, quanto costa la profondità, come si comporta la banda —
   non per stabilire chi vince.
5. **Dove CKKS vincerebbe, e perché la letteratura va veloce.** Il punto di pareggio per il
   solo segno è alto (migliaia di iscritti), ma le distanze CKKS restano 2× più care per
   iscritto del varco TFHE intero finché servono parametri profondi. I sistemi CKKS veloci della
   rassegna (Blind-Match: 6.144 template in 0,74 s; HERS; CryptoFace) sono veloci perché **non
   fanno il confronto cifrato**: restituiscono i punteggi e l'argmax lo fa il client (F26,
   strategia 1). Senza il segno la profondità è 1, i parametri sono piccoli, le rotazioni
   costano 11 ms e il packing rende: a 16384 le nostre distanze fanno 7,5 ms per iscritto. Chi
   invece fa la selezione sul server in CKKS paga con approssimazioni e bootstrapping (GROTE
   ~16.000 volti in ~15 s, Mazzone argmin di 128 in ~13 s), cioè numeri della stessa classe dei
   nostri 4 s, non dei nostri 0,18 s.
6. Dimensioni: il probe CKKS è un cifrato da ~11 MB a 32768 (2,6 MB misurati a 16384), contro gli
   8,4 MB dei 512 LWE grezzi di F37 (riducibili a ~33 KB con il nostro encoding polinomiale, F41); le chiavi di
   rotazione CKKS pesano gigabyte a 32768.

La frase per la tesi: **la scelta dello schema vale meno della scelta dell'operazione**. Il
varco 1:N con esito cifrato costa, in ordine, Concrete-python 92 s (N=64) → CKKS 4,2 s (N=128,
un thread) → TFHE radix a torneo 4,7 s (N=128, 16 thread, e vuole il ponte) → TFHE leveled
0,18 s (N=128, 16 thread). CKKS ha il packing, TFHE ha il bootstrap economico; per un varco
da decine o centinaia di iscritti, dove la decisione è una soglia per iscritto, conta il secondo.

La tabella schema × operazione che chiedeva l'incontro (N=128 dove misurato, tempi per query):

| operazione | Concrete-python (F28/F33) | tfhe-rs radix (F38) | tfhe-rs leveled (F37) | CKKS/SEAL (F39) |
|---|---|---|---|---|
| prodotto scalare ×N | 0,07 s (0 PBS) | — (vuole il ponte) | 0,007 s (0 PBS) | 3,5 s (rotazioni) |
| soglia per iscritto | 92 s a N=64 | — | 0,17 s (16 thr) / 1,76 s (1 thr) | 0,7 s, indipendente da N |
| argmin + soglia sul vincitore | 455 s a N=8 | 4,7 s (16 thr) / 47 s (1 thr) | — | letteratura: ~13 s (Mazzone, 128) |
| **varco intero** | 92 s a N=64 | — | **0,18 s** (16 thr) | **4,25 s** (1 thr, packing a blocchi; 1,67 s col packing corretto, F67) |
| banda alla soglia | esatto (PBS larghi) | esatto | σ ≈ 12, probabilistica | ±10, deterministica |

## 🔴 F40 — Cosa rivela il bit di esito: l'attacco con l'oracolo di appartenenza, misurato
Il modello di minaccia dell'incontro (F35) vieta di restituire la distanza: un client malicious
manda vettori arbitrari e con una distanza per tentativo scende per gradiente fino all'embedding
di un iscritto. Ma anche il solo esito è un'informazione: ogni query è un **oracolo di
appartenenza** ("il mio vettore è accettato per l'iscritto i?"). Quanto rivela, misurato in
chiaro sulla scena reale (`experiments/14_pipeline_tfhe_rs/attacco_oracolo.py`).

Un'osservazione prima dei numeri. Il server calcola s_i(v) = ‖g_i‖² − 2·g_i·v, senza ‖v‖²
(i probe onesti sono L2-normalizzati e la soglia lo assorbe, F33). Per un client che manda v
qualunque la regione di accettazione {v : s_i(v) ≤ T} non è una palla ma un **semispazio**
g_i·v ≥ c_i: l'oracolo risponde a una disuguaglianza lineare in v. Vale per il design del prof
(bit sul più vicino) esattamente come per il varco di F37 (bit per iscritto): per un v vicino a
g_i il più vicino è i, e il bit è lo stesso.

| risposta del server | partenza | query | risultato |
|---|---|---|---|
| distanza in chiaro | foto dell'iscritto (probe genuino) | **513** | embedding **esatto** 20/20 (2 query per coordinata) |
| bit di esito | foto dell'iscritto | 1.000 | coseno 0,61 con g_i |
| bit di esito | foto dell'iscritto | 3.000 | coseno 0,91 |
| bit di esito | foto dell'iscritto | 10.000 | coseno 0,99 |
| bit di esito | foto dell'iscritto | 30.000 | coseno 0,999 |
| bit di esito | vettore **bipolare** ±q, nessuna foto | **1** | **apre**, 200 volte su 200 (F61) |

L'attacco col bit: si porta il probe sulla frontiera del semispazio per bisezione lungo il
raggio (12 query), poi si interrogano perturbazioni sparse attorno a quel punto, adattandone
l'ampiezza per tenere l'oracolo vicino al 50% (altrimenti le risposte non informano), e si
stima la normale del semispazio con una regressione logistica sulle etichette. Con 30.000 query
l'embedding è ricostruito a coseno 0,999, e già a 1.000 il vettore ricostruito viene accettato
dal varco. Quindi:

1. Il divieto della distanza **è giusto ma non basta**: la distanza rende l'attacco esatto in
   513 query, il bit lo rende approssimato in migliaia. È un fattore 20-60, non un muro.
2. **Il bit parte da zero, e questo è il punto grave.** Non serve possedere un volto accettato:
   basta un vettore **bipolare** ±q — tutti i valori legali — per aprire il varco alla prima query
   (F61 lo misura: 200 volte su 200 a 4 bit; 15,2% a N=128 e 98,2% a N=4096 nella configurazione a
   3 bit). Perturbare un punto già rifiutato non funziona, ed è per questo che una prima versione
   di questa misura concludeva il contrario — ma un attaccante non perturba, sceglie la direzione.
   Quindi quello che l'attaccante ricava non è solo l'**embedding**: è **l'accesso**, e a costo
   quasi nullo. La difesa è vincolare la **norma** del probe (F61).
3. La contromisura non è crittografica: **limitare le query** (blocco dopo pochi rifiuti, come
   un PIN), perché l'attacco ne consuma migliaia e ne genera a decine rifiutate. Zuber e Sirdey
   dicono la stessa cosa del loro k-NN ("this latter leakage is inherent to the service
   provided… throttling the request rate"). È un punto da mettere nella tesi accanto al modello
   di minaccia, non da lasciare implicito.
4. La formula espansa senza ‖v‖² rende la regione un semispazio invece di una palla, e viene
   da chiedersi se rimettere ‖v‖² nel punteggio (cifrato, un prodotto cifrato×cifrato in più,
   F2) renderebbe l'attacco più difficile. **No, misurato**: con la palla l'attaccante, che
   conosce la norma del proprio vettore, aggiunge ‖v‖² come feature e il punteggio torna
   lineare nelle incognite (g, c); a 10.000 query il coseno è 0,995 contro 0,989 del
   semispazio. E far dichiarare ‖v‖² in chiaro al client non serve: un client malicious
   dichiara quello che vuole. La geometria del punteggio non è una leva di difesa; lo è solo
   il numero di query.

Letteratura, verificata sugli abstract e sui riassunti disponibili: gli attacchi *hill-climbing*
ai sistemi biometrici sono noti da Adler (2003: ricostruzione di immagini dai template; 2004:
rigenerazione da **punteggi quantizzati**) e Galbally, McCool et al. (Pattern Recognition 2010,
attacco bayesiano alla verifica facciale), che trovano l'attacco robusto alla quantizzazione del
punteggio: "even for the biggest value of quantization step, the success rate of the attack is
still over 60%". Il bit di esito è il caso limite della quantizzazione, e il nostro risultato è
coerente: rallenta, non ferma. Per il varco cifrato questo va detto come limite del modello,
non come difetto del circuito: il server non impara nulla; il client impara ciò che qualunque
varco accetta/rifiuta lascia imparare, e va rate-limitato.

## 🔴 F41 — Il varco in forma consegnabile: tre ruoli, un GLWE da 33 KB, stessi 0,18 s
Il caveat di F37 era il probe come 512 LWE grezzi, 8,4 MB per query. Chiuso con l'encoding
polinomiale di Zuber-Sirdey in una CLI a tre ruoli (`experiments/14_pipeline_tfhe_rs/src/bin/varco.rs`:
`keygen`, `encrypt`, `server`, `decrypt`, file su disco al posto della rete). Il client cifra il
probe come **un solo GLWE** (k=1, N=2048: il polinomio A(X) = Σ a_j X^j sotto la chiave grande);
il server, per l'iscritto i, moltiplica per il polinomio in chiaro P_i(X) = Σ (−2 g_ij) X^{511−j}
(leveled, un prodotto di polinomi) ed estrae il coefficiente 511, che è −2·g_i·a in un LWE sotto
la chiave grande: da lì la costante, il keyswitch, il PBS di segno e l'uscita compatta di F37.

Misurato sulla scena reale (N=128, 512 dim, 16 thread): probe cifrato **32.800 byte**, esito
(conteggio + indice, a blocchi di 64) 229 KB — che con il packing keyswitch di F59 scendono a **32 KB**, una sola GLWE — chiave client 23 KB, chiave server 130 MB (una volta, alla
registrazione del dispositivo); cifratura 0,4 ms, server **0,18 s** (prodotti polinomiali 7-16
ms, PBS 0,16-0,18 s), decifratura 0,03 ms. Esiti: probe genuino → conteggio 1, indice 104 =
l'identità vera; impostore → conteggio 0. Il costo per query non cambia rispetto a F37 (i
prodotti polinomiali costano quanto le combinazioni lineari), la banda passante scende di
**250×**. È il pezzo di ingegneria che rende il varco un sistema e non un microbenchmark; non
aggiunge idee, e in tesi va in una riga.

## 🔴 F42 — Il percorso: cosa tenere e cosa scartare (la regola dell'incontro)
Il prof, per la tesi: mostrare la baseline e le ottimizzazioni, "non serve riportare ogni singolo
tentativo; riportiamo le tecniche principali che producono un miglioramento osservabile; se due
tecniche danno più o meno lo stesso risultato non vale la pena soffermarsi su entrambe". Applicata
a tutto quello che abbiamo provato da F6 in poi, con il guadagno misurato di ciascuna. La figura
è `benchmark/results/percorso.png` (a: il percorso a N=8, un passo per tecnica; b: i design
finali al crescere di N con i traguardi dei 10 e 5 s nel margine).

**Da tenere** (ognuna cambia il numero di un fattore misurabile, e ha un perché):

| passo | tecnica | guadagno misurato | dove |
|---|---|---|---|
| 1 | galleria in chiaro + formula espansa: il prodotto scalare è enc×chiaro, 0 PBS | il prodotto scalare sparisce dal costo (0,07 s, poi 0,007 s) | F2, F33 |
| 2 | quantizzare l'embedding a 4 bit | lossless in accuratezza, e l'unico modo di far compilare il confronto (limite 16 bit) | F14, F31 |
| 3 | la strategia CHUNKED | l'argmin server compila e gira invece di esplodere in RAM | F24 |
| 4 | il torneo al posto della catena | 2,3× in tfhe-rs a 16 thread; in Concrete solo col dataflow, senza è più lento | F27, F38, F64 |
| 5 | tfhe-rs al posto di Concrete-python | **105× / 94×** sull'argmin, verificato a parità di macchina (F64) | F32 |
| 6 | 8 bit di punteggio bastano (validato in chiaro) | 1,5-2× su ogni confronto radix | F36 |
| 7 | prodotto scalare leveled a basso livello | da 99 s a 0,2 ms (l'API radix propagava i riporti) | F34 |
| 8 | la soglia per iscritto con un PBS di segno **al posto** della selezione | 27× sul torneo radix, ~1000× sulla soglia Concrete; profondità 1 | F37 |
| 9 | i confronti indipendenti in parallelo | 10× (1,76 → 0,177 s a N=128) | F37 |
| 10 | encoding polinomiale del probe | 250× sulla banda (8,4 MB → 33 KB), stesso tempo | F41 |

**Da citare in una riga, non da sviluppare** (nessun guadagno osservabile, o equivalente a un
altro passo):

| tentativo | esito | dove |
|---|---|---|
| GPU (Tesla T4) sull'argmin | 9× **più lenta** della CPU: il PBS in batch non serve alla latenza di una query | F25 |
| `dataflow_parallelize` di Concrete | nulla sul sequenziale, +8% sul torneo, crash a N=8 | F27 |
| `round_bit_pattern`, strategie di confronto alternative | più lente o crash | F31 |
| comprimere l'embedding (PCA/LDA) per abbassare l'argmin | il costo non scende (158,7 → 237,9 s da 512 a 128 dim, F64), l'accuratezza sì | F31 |
| togliere il `min` ridondante dalla catena | −25%: vero ma minore, assorbito dal torneo | F38 |
| parametri multi-bit | 2,3× su un thread, nulla a 16 thread: stesso guadagno del parallelismo, non si somma | F38 |
| one-hot contro indice | equivalenti per privacy e costo; l'uscita compatta dà entrambi | F37 |
| soglia per template (T-norm/Z-norm) | gratis ma +0,3 punti: gli embedding ArcFace sono già normalizzati | F54 |
| cambiare schema (CKKS) | non è un'ottimizzazione del varco (4,2 s contro 0,18): resta come **confronto**, con la sua lettura | F39 |

Due cose non sono ottimizzazioni ma vanno nel percorso perché lo delimitano: il **ponte**
leveled→radix che coi parametri standard non c'è (F34), che spiega perché il passo 8 è una
sostituzione e non un'aggiunta; e la **banda** del PBS di segno (σ ≈ 12 unità), misurata e
innocua (F37), che è il prezzo del passo 8. E accanto al percorso il modello di minaccia con
quello che il bit rivela (F40) e il conteggio da discutere col prof (F37).

La figura del percorso mostra, a N=8, 455 s → 12,5 s → 1,1 s → 0,36 s → (CKKS 1,6 s) → 0,017 s:
quattro ordini di grandezza in cinque passi, ciascuno con una tecnica e un motivo; a N=128 i
design finali sotto i traguardi dell'incontro sono solo quelli tfhe-rs.

## 🔴 F43 — Scala e rifiniture: il varco fino a N=1024, l'uscita compatta a blocchi, il multi-bit non serve
Tre verifiche dopo il percorso, sulla stessa scena reale (ResNet100, VGGFace2, 4 bit), con una
galleria portata a **1024 iscritti** (`esporta_dati.py 1024`, T al quantile 1% di 2000 impostori):

| N | totale per query (16 thread) | per PBS per thread | discrepanze |
|---|---|---|---|
| 128 | 0,177 s | 21 ms | 0 / 16.384 | *(scena a 128 iscritti, F37: su questa scena non misurato)*
| 256 | 0,34 s | 21 ms | 0 / 32.768 |
| 512 | 0,70 s | 21 ms | 0 / 65.536 |
| **1024** | **1,41 s** | 22 ms | **0 / 131.072** |

Esito per probe uguale al chiaro (62/64 genuini = 96,9%, 0/64 impostori). Il varco è lineare
in N con lo stesso costo per iscritto di F37, e a mille iscritti — il numero che all'incontro
sembrava "molto" — sta a 1,4 s, un terzo dei 5 s accettabili. La scala non è più una domanda.

**L'uscita compatta a blocchi.** A N=1024 la prima versione dell'uscita compatta (conteggio e
indice come somme leveled su tutti gli N bit) sbagliava 8 probe su 128 (uno su 128 a N=512): il
rumore del PBS (~2^48) sommato su N addendi cresce come √N e a 1024 arriva a ~2^53, contro un
margine di decodifica di 2^55, cioè ~4σ. Corretto sommando **per blocchi di 64** (conteggio e
indice locale per blocco, il client somma i blocchi in chiaro): rumore ≤ 2^51, 16σ di margine,
**128/128 corretto a ogni N**, 1,5 ms a N=1024. L'esito pesa 16 KB per LWE, quindi 229 KB a
N=128 e 1,8 MB a N=1024 (contro 16 MB degli N bit). Lezione da diario: le somme leveled sui bit
freschi non sono gratis in rumore, e il conteggio del numero di addendi va fatto prima, non
dopo (è la stessa regola con cui Zuber-Sirdey limitano gli addendi tra un bootstrap e l'altro).

**Il PBS multi-bit non aiuta il varco.** Con i parametri multi-bit (group 3, n=909, N=2048) e
i 7 thread interni scelti da tfhe-rs, N=128 fa 0,198 s contro 0,177 s del PBS classico; con 1
thread interno 0,210 s. Come in F38: il varco è già parallelo su N con tutti i core occupati, e
il multi-bit è un altro modo di spendere gli stessi core, non un guadagno che si somma. Va in
una riga nel percorso (F42), tra le cose provate senza effetto.

Da F40, riportato qui perché chiude la stessa lista: rimettere ‖v‖² nel punteggio (la palla
invece del semispazio) **non** difende dall'attacco con l'oracolo (coseno 0,995 in 10.000
query): l'attaccante conosce la norma del suo vettore. GhostFaceNet (Carnemolla) è misurato in F44: indifferente per l'FHE, non per l'accuratezza
(+1 su MobileFaceNet, −7-8 sui profondi a 4300 iscritti).

## 🔵 F44 — GhostFaceNet, misurato: "indifferente" vale per l'FHE, non per l'accuratezza
All'incontro Carnemolla aveva proposto GhostFaceNet come modello "economico dal punto di vista
computazionale ma con buona accuratezza", aggiungendo che "un modello o l'altro cambia
relativamente poco". Lo avevamo lasciato in coda come indifferente: una deduzione (per l'FHE conta
solo la dimensione dell'embedding, 512 per tutti), non una misura. Misurato.

Modello: GhostFaceNetV1 W1.3 S1 ArcFace addestrato su MS1MV3, pesi ufficiali `.h5` (Keras 2) dal
repo degli autori (Alansari et al., *GhostFaceNets: Lightweight Face Recognition Model From Cheap
Operations*, IEEE Access 2023), **4,09 M parametri**, embedding 512, preprocessing preso dal loro
`evals.py` ((x − 127,5)·0,0078125, RGB, somma con l'immagine specchiata, L2-normalizzazione). Gira
in un venv TensorFlow separato dal progetto (`experiments/08_cnn/ghostfacenet_embed.py`,
`ghostfacenet_bench.py`), 6,7 ms per immagine su CPU; gli embedding vanno in cache e il resto è
il harness di sempre (`benchmark/verifica_ghost.py`, `scaling_modelli.py`).

Verifica 1:1 (stessi `.bin`, 10-fold, distanza euclidea sugli embedding L2-normalizzati):

| | LFW | CPLFW | CFP-FP | AgeDB-30 | CALFW |
|---|---|---|---|---|---|
| MobileFaceNet | 99,7 | 92,5 | 97,8 | 96,6 | 95,5 |
| **GhostFaceNet** | **99,7** | **91,8** | **97,9** | **97,8** | **95,8** |
| ResNet50 | 99,8 | 94,4 | 99,3 | 98,1 | 96,1 |
| ResNet100 | 99,8 | 94,5 | 99,1 | 98,4 | 96,2 |

I numeri dichiarati dagli autori (LFW 99,73, CFP-FP 96,83, AgeDB-30 98,0) tornano: la
riproduzione è sana. Identificazione 1:N open-set su VGGFace2 reale (DIR@FPIR=1%, protocollo
di F19, iscritti da 250 a 4300):

| iscritti | 250 | 1000 | 2000 | 4000 | 4300 |
|---|---|---|---|---|---|
| MobileFaceNet | 93,3 | 90,2 | 88,4 | 86,6 | 86,0 |
| **GhostFaceNet** | **93,6** | **91,1** | **90,1** | **88,0** | **87,2** |
| ResNet50 | 96,3 | 95,8 | 95,5 | 94,5 | 94,2 |
| ResNet100 | 96,7 | 96,5 | 96,4 | 95,5 | 95,5 |
| AdaFace | 96,3 | 96,0 | 96,0 | 95,0 | 94,9 |

Lettura, in tre righe:

1. **Rispetto a MobileFaceNet**, GhostFaceNet è un filo meglio ovunque sull'1:N (+0,3 a 250,
   +1,7 a 2000, +1,2 a 4300) e pari sull'1:1 (±1 punto, sotto su CPLFW). Carnemolla aveva
   ragione: dentro la classe dei modelli leggeri "cambia relativamente poco", e Ghost è la
   scelta migliore di quella classe.
2. **Rispetto ai profondi**, restano 7-8 punti a 4300 iscritti (87,2 contro 94,2-95,5). Il
   divario che conta non è tra un leggero e l'altro, è tra la classe leggera e quella profonda,
   e F19/F20 lo dicevano già per MobileFaceNet. La frase di F30 ("la rete vale 1-2 punti") vale
   tra i profondi; tra leggero e profondo vale 7-8, cioè metà del divario di dominio.
3. **Per l'FHE è davvero indifferente**: 512 dimensioni, stesso encoding, stesso varco (F37/F41),
   stesso costo. La scelta del modello è un tradeoff tutto sul **client** (4 M parametri e 6,7 ms
   contro le decine di milioni delle ResNet), non sul server. Se il terminale è un dispositivo
   embedded, GhostFaceNet è il candidato; se può eseguire una ResNet, i 7-8 punti sono gratis
   lato cifrato e vanno presi.

Per la tesi: la figura dei modelli (`scaling_modelli.png`) ha ora cinque curve e quella
dell'accuratezza per tecnica (`accuratezza_tecniche.png`) quattro CNN; la conclusione del
gradino 08 non cambia, ma ora la proposta dell'incontro ha il suo numero invece di una
supposizione.

## 🔴 F45 — La strada del ponte, esplorata: l'argmin esatto senza cifre costa 14 s, il ponte molto di più
Dopo F37 la domanda naturale: si può avere di più del varco, cioè l'**argmin esatto sul server**
(il design dell'incontro: indice del più vicino, poi soglia solo su di lui, niente conteggio
rivelato, pareggi risolti)? Due strade, entrambe misurate.

**1. Il ponte vero: quanto costa un PBS largo.** Il ponte leveled→radix deve estrarre le cifre di
un punteggio a 13-14 bit, e per farlo il PBS deve risolvere tutti quei bit (F34). tfhe-rs offre
set di parametri validati a 128 bit fino a **8 bit** di precisione; misurati sulla stessa
macchina, un thread (`pbs_largo.rs`, LUT identità verificata su tutto il dominio):

| set | precisione | N | keyswitch + PBS | chiave di bootstrap |
|---|---|---|---|---|
| MESSAGE_2_CARRY_2 (il nostro) | 4 bit | 2048 | **13,9 ms** | 54 MB |
| MESSAGE_8_CARRY_0 | 8 bit | 32768 | **548 ms** | 2,2 GB |
| MESSAGE_4_CARRY_4 | 8 bit | 32768 | 715 ms | 3,3 GB |

Da 4 a 8 bit il PBS costa **40×** e la chiave 40×. A 13-14 bit non c'è un set validato; il costo
cresce almeno come N·log N e Concrete, che quei bit li risolve, paga 1,5-4 s a PBS (F33). Il
conto del ponte a N=128, **fatto con un PBS largo per cifra**: 4 cifre × 128 punteggi = 512 PBS
larghi ≈ 512 × ~2 s / 16 thread ≈ **60-70 s**, più i 4,7 s del torneo radix (F38). Contro 0,18 s:
il ponte riporterebbe il sistema abbondantemente sopra i 10 s dell'incontro.

❓ **Domanda aperta: il ponte con un PBS largo per cifra è il modo più caro di farlo.** Nessuno lo
costruisce così: si usa la **bit extraction del WoP-PBS**, che è *b* PBS **piccoli** più un
keyswitch, uno per bit, e tfhe-rs la espone già
(`extract_bits_from_lwe_ciphertext_mem_optimized`). Stimando col nostro stesso costo per PBS WOPBS
(~40 ms di tempo-thread, ricavabile da F52), 8 bit × 40 ms × 128 punteggi / 16 thread ≈ **2,6 s**,
più i 4,7 s del torneo radix = **~7,3 s**, cioè **un ordine di grandezza meno** dei 60-70 s qui
sopra. **Non l'ho misurato**, e finché non lo misuro questo finding chiude la strada del ponte su
una stima pessimistica. La conclusione operativa non cambia — 7,3 s restano ~47× il varco a soglia
(0,153 s) — ma il margine con cui la strada è chiusa sì, e va detto.

**2. L'argmin esatto senza ponte: la matrice dei confronti.** Il confronto tra due punteggi larghi
è un segno, come la soglia: a_ij = [s_i ≤ s_j] costa **un PBS da 14 ms**, nessuna cifra. Con tutte
le N(N−1)/2 coppie si ha la matrice; la riga del primo minimo (s_i < s_j per j<i, s_i ≤ s_j per
j>i) è tutta a uno, e "tutti a uno" si verifica a blocchi di 8 con una LUT a 4 bit (~19 PBS per
riga a N=128). Poi la soglia solo sul vincitore: match = Σ_i AND(w_i, t_i). È la δ-matrix di
Zuber-Sirdey con i nostri parametri, in `argmin_delta.rs`; scena reale, 16 thread, 16 probe:

| N | coppie | vincitore | soglia | **totale** | PBS | one-hot esatto | match |
|---|---|---|---|---|---|---|---|
| 8 | 0,05 s | 0,02 s | 0,03 s | **0,09 s** | 52 | 16/16 | 16/16 |
| 16 | 0,17 s | 0,07 s | 0,05 s | **0,29 s** | 200 | 14/16 | 16/16 |
| 32 | 0,64 s | 0,24 s | 0,09 s | **0,97 s** | 720 | 16/16 | 16/16 |
| 64 | 2,67 s | 0,80 s | 0,18 s | **3,66 s** | 2.720 | 15/16 | 16/16 |
| 128 | 10,73 s | 3,31 s | 0,34 s | **14,4 s** | 10.816 | 16/16 | 16/16 |

Funziona: il vincitore esce esatto, con i pareggi risolti come in chiaro, e il bit di match è
sempre giusto. I tre one-hot sbagliati sono la **banda** (F37): le differenze s_i − s_j vogliono
un bit in più di range (Δ = 2^50, σ ≈ 25 unità), e nei tre casi il minimo e il secondo distavano
10-24 unità — probe impostori, con la vera identità fuori dai primi N, il cui "più vicino" è
uno qualunque tra punteggi quasi uguali. In quei casi la riga vincente ha uno zero e l'uscita è
"nessun vincitore", che il client vede (Σ w_i = 0) e che per il varco è comunque un rifiuto
corretto. Quando il minimo è isolato di più della banda (sempre, per un genuino), l'argmin è
esatto.

Il costo è quadratico: **3,7 s a N=64** (dentro i 5 s), **14,4 s a N=128** (fuori dai 10 s),
lineare nella riga, N²/2 nelle coppie. Contro il varco: 40× a N=64, 80× a N=128, per togliere
il conteggio dall'uscita e scegliere il più vicino tra due sotto soglia. È lo stesso rapporto
che la letteratura paga: Zuber-Sirdey sono quadratici per la stessa ragione.

**Cosa succederebbe, quindi.** Il ponte non conviene: la sua unità di costo è 40× la nostra a 8
bit e ~150× a 14, e riporterebbe il sistema a un minuto. L'argmin esatto senza ponte esiste,
costa 40-80× il varco, sta nel target del prof a N=64 e non a N=128 **(corretto in F52: con il
circuit bootstrapping il torneo lo porta a 1,273 s anche a N=128)**, e la sua esattezza dipende
dalla stessa banda del varco. **Il varco resta il design**; l'argmin a matrice è l'opzione da
offrire al prof se il conteggio nell'uscita non gli va bene, con il suo prezzo scritto accanto.
Per la tesi il percorso guadagna un punto: "argmin esatto sul server a N=64 in 3,7 s, senza
scrivere un bootstrap a mano".

## 🔴 F46 — Spremere i parametri: il PBS di segno vuole 1 bit, non 4 → varco 2× più veloce
*(la lettura del "muro" data qui è sbagliata: vedi la correzione in F55 — il minimo vero è 0,064 s)*
Il varco (F37) usava il set `MESSAGE_2_CARRY_2` (LUT a 4 bit, N=2048), ereditato dall'API ad alto
livello. Ma la soglia calcola un **segno**: gli basta una LUT a 1 bit. I set "piccoli" di tfhe-rs
(sempre validati a 128 bit, p-fail 2⁻⁶⁴) hanno polinomi più corti e un PBS più economico. Aggiunti
al varco (`--params`, `varco_leveled.rs`) e misurati sulla scena reale, 16 thread:

| set | LUT | N (poly) | N=128 | N=1024 | esattezza | banda σ (a Δ=2^51) |
|---|---|---|---|---|---|---|
| MESSAGE_2_CARRY_2 (era il nostro) | 4 bit | 2048 | 0,177 s | 1,41 s | esatto | 12 |
| MESSAGE_2_CARRY_1 | 3 bit | 1024 | 0,134 s | ~0,9 s | esatto | ~30 |
| **MESSAGE_1_CARRY_1** | **2 bit** | **512** | **0,100 s** | **0,72 s** | **esatto** | **~50** |
| MESSAGE_2_CARRY_0 | 2 bit | 512 | 0,083 s | — | errori (vedi sotto) | — |
| MESSAGE_1_CARRY_0 | 1 bit | 256 | 0,072 s | — | errori (vedi sotto) | — |

Il salto di qualità è a **MESSAGE_1_CARRY_1**: PBS a 12 ms (era 22), N=128 in **0,100 s** e
N=1024 in **0,72 s**, cioè **~2×** su tutta la linea, con 0 discrepanze su 131.072 confronti a
N=1024. La banda si allarga (σ ≈ 50 unità invece di 12), ma resta due ordini di grandezza sotto
i gap reali: simulata sulle 20 scene di F36 (`effetto_banda.py`), DIR@FPIR=1% invariata
(92,8-93,0% contro 92,9%), FPIR 1,01% — e persino a σ=100 la DIR scende solo di 0,1-0,2 punti.

`MESSAGE_2_CARRY_0` e `MESSAGE_1_CARRY_0` (N=512 e 256) qui **sbagliano un quinto dei confronti** (20,7% e 17,5% a N=128), con
gli errori distribuiti uniformemente in |s−T| invece che concentrati sulla soglia. Non è il numero
di bit della LUT (2_0 ha gli stessi 2 bit di 1_1) e non è la banda in ingresso: **F55 mostra che è
la codifica dell'uscita** — quei due set hanno un rumore in uscita dal PBS σ = 2^55, contro
l'ampiezza 2^55 con cui `LOG_DO = 56` codificava il bit, cioè 1σ di margine. Alzando il margine
(`--log-do 60 --blocco 8`) diventano esatti, e sono anzi **i più veloci**: 1_0 fa 0,064 s a N=128.

Il che non li rende utilizzabili, per un motivo diverso e successivo: con il Δ onesto imposto da
F56 la loro banda in unità di punteggio si allarga fino a 48-89, e producono decisioni sbagliate
lontano dalla soglia. **La configurazione che regge è il set 2_2**, ed è quella di F56.

Con il set 1_1 il varco è **0,10 s a N=128 e 0,72 s a N=1024**. ⚠️ Non è però il numero del
sistema: quel set regge solo se il client è fidato. Con il Δ difendibile contro un client malicious
(F56) la sua banda si allarga a 44 unità e accetta 4 impostori su 64, quindi la configurazione da
portare in tesi è il **set 2_2**, che costa **0,152 s a N=128** ed è esatto.

**Ancora non spremuto**: la GPU con tfhe-rs. Il test di F25 (GPU 9× più lenta) era su Concrete e
sull'argmin *sequenziale*, il caso peggiore per una GPU; il varco è N PBS **indipendenti in un
lotto**, il carico per cui il backend CUDA di tfhe-rs è progettato. Serve una NVIDIA (via Colab,
come in F25): esperimento su hardware esterno, non fatto in questa sessione.

## 🔴 F47 — I 3 bit come bonus di robustezza, e perché i set piccoli sbagliano
Dopo F46 l'ipotesi: i set più piccoli (2_0 N=512, 1_0 N=256) crollano perché Δ è limitato dal
range del punteggio; quantizzando l'embedding a **3 bit** invece di 4 il range si dimezza (da |s−T|
< 2^13 a < 2^10), Δ sale da 2^51 a 2^53, e forse i set veloci diventano esatti. Provato
(`esporta_dati.py 128 3`; accuratezza in chiaro identica: 90,6% a N=128, 96,9% a N=1024, come F31).

**L'ipotesi non si verifica, e il motivo è istruttivo.** A 3 bit e Δ=2^53:
- **1_1** (N=512): banda da σ≈50 a **σ≈4** (Δ 4× più grande), N=1024 in 0,83 s, **0 discrepanze**;
- **2_0** e **1_0**: ancora rotti, banda mediana ~344 unità, un quinto dei confronti sbagliato (19,0% e 17,2%).

**Perché 2_0 e 1_0 sbagliano** — la spiegazione, calcolata dai parametri del crate, è in **F55**:
non è la banda pre-PBS (che per 2_0 è *uguale* a quella di 1_1) ma il **rumore in uscita** dal blind
rotate, σ = 2^55 per entrambi, contro l'ampiezza 2^55 con cui `LOG_DO = 56` codificava il bit: il
bit usciva annegato nel proprio rumore con 1σ di margine. È una scelta di **codifica dell'uscita**,
non un limite dei set: alzando `LOG_DO` quei set diventano esatti (F55) — salvo poi non poter essere
usati lo stesso, per il Δ onesto di F56.

Attenzione a un'inferenza che sembra naturale e non lo è: la banda mediana degli errori scende con Δ
(1878 → 344, ~5×) **non** perché la banda si stringa, ma perché gli errori sono **uniformi** — con
errori indipendenti da |s−T| la mediana degli sbagliati coincide con la mediana su tutte le coppie,
e 1878/344 = 5,5 è semplicemente il rapporto fra le scale dei punteggi a 4 e a 3 bit.

Cosa resta dei 3 bit: non velocità (il conteggio dei PBS e la loro dimensione non cambiano: 0,72 s
a N=1024 come i 4 bit), ma **robustezza gratis**. La banda si dimezza (σ da ~22 a ~11 unità a Δ=2^53, F50), cioè il varco
sbaglia solo entro poche unità di punteggio da T, con l'accuratezza in chiaro invariata.
Per la tesi: i 3 bit sono la scelta migliore per il varco veloce (set 1_1), perché stringono la
banda di un ordine di grandezza a costo zero. Il punto operativo con client fidato è **3 bit, set
1_1, 0,10 s a N=128**; quello difendibile contro un client malicious è **3 bit, set 2_2, 0,152 s**
(F56), ed è quello che va in tesi.

**La sola leva di velocità ancora aperta, ovunque, è la GPU** (un lotto di N PBS indipendenti è il
carico ideale del backend CUDA di tfhe-rs, l'opposto dell'argmin sequenziale di F25). Tutto il
resto — schema, struttura, precisione del punteggio, parametri del PBS, quantizzazione — è
misurato e al fondo. Sul solo CPU il varco è spremuto.

## 🔵 F48 — La leva che avevamo ignorato: la fusione multi-frame porta il varco a ~99% GRATIS
La domanda "abbiamo davvero esplorato tutti i modi di migliorarlo?" ha una risposta che avevamo
mancato, perché per settimane "migliore" aveva voluto dire "più veloce lato FHE". Ma al cancello la
telecamera dà una **raffica di frame**, non una foto, e ogni iscritto può registrarsi con più foto.
Aggregare (media degli embedding, poi L2-normalizzazione) è lo standard biometrico, e qui è **gratis
lato FHE**: il client media i k_probe frame in UN embedding *prima* di cifrare, e il server esegue
lo stesso identico varco; il template della galleria (media di k_gal foto) è in chiaro sul server.
Zero costo cifrato in più, zero PBS in più.

Misurato in chiaro (`benchmark/multiframe.py`, ResNet100, VGGFace2 reale, foto di galleria e di
probe **disgiunte** per non barare, 5 seed), DIR@FPIR=1% a 4000 iscritti:

| | k_probe=1 | k_probe=2 | k_probe=3 |
|---|---|---|---|
| **k_gal=1** | 90,5% | 94,1% (+3,6) | 95,2% (+4,7) |
| **k_gal=2** | 94,3% (+3,8) | 97,6% (+7,1) | 98,5% (+8,1) |
| **k_gal=3** | 95,3% (+4,8) | 98,5% (+8,0) | **99,2% (+8,7)** |

Il guadagno è **+7-9 punti** a 4.000 iscritti (a N=1000 la misura non è stata salvata). Due letture importanti per la tesi:

1. **Il tetto del ~95-96% di F19/F20 era il tetto *a frame singolo*, non del protocollo.** Lì il
   1:N open-set a migliaia di iscritti si fermava a ~95-96% e il 99% sembrava appartenere alla
   verifica 1:1 facile. Vale per una query da un fotogramma. Con 2-3 frame per query e 2-3 foto per iscritto — la
   condizione reale di un varco — il 1:N open-set arriva a **99,2% anche a 4000 iscritti**. Il
   99% è raggiungibile su questo protocollo, e non serve un modello più grande (F44 dava +1-2
   punti): serve usare più di una foto. La media riduce il rumore dell'embedding su entrambi i
   lati (√k), che è esattamente ciò che serve al ginocchio della curva DIR-FPIR.

   **Il numero da citare è +3,9, non +8,7.** La colonna dei "+" nella tabella è misurata contro
   (1,1), cioè contro una baseline a *una sola foto per iscritto*, che non è mai stata la nostra:
   i ~95-96% di F19/F20 corrispondono a **(3,1) = 95,3%**. Il guadagno della fusione *del probe* —
   l'unica cosa nuova qui, perché le foto multiple in galleria la tesi le usava già — è quindi
   **95,3% → 99,2% = +3,9 punti**; gli altri +4,8 vengono dal passare da una a tre foto in
   registrazione, ed erano già acquisiti.

2. **È la migliore leva dell'intero lavoro sul lato accuratezza, ed è gratis lato FHE.** +3,9 punti
   sulla baseline vera (+8,7 su quella a una foto) contro i +1-2 del modello (F44) e gli 0 della
   compressione (F31); e a differenza di tutto il
   resto non tocca il server. Il tradeoff è pratico: k_gal costa foto alla registrazione (una
   volta), k_probe costa ~k·6,7 ms di embedding sul client e qualche decimo di secondo di
   raffica al cancello, invisibili accanto agli 0,1 s del match. Il punto di equilibrio
   ragionevole è **(2,2)**: 97,6% a 4000 iscritti, due foto in registrazione e due frame alla
   sbarra, tutto sul client.

Con F48 il sistema, nella sua configurazione difendibile, è: varco privato in **0,152 s a N=128 /
1,26 s a N=1024** (set 2_2 con Δ onesto, F56), accuratezza **97-99%** DIR@FPIR=1% a migliaia di
iscritti reali grazie al multi-frame, server cieco, client che vede solo l'esito. È il numero da
portare in tesi.

Nota su cosa NON aiuta, per completezza dell'esplorazione: la trasformazione ternaria (trucco
IDFace, memoria [[fhe-compression-not-a-lever]]) stringe la larghezza del punteggio, ma F47 ha
mostrato che la larghezza non governa il costo del varco,
quindi il ternario non dà velocità qui — il motivo è che l'accumulatore del PBS di segno è
**costante**, quindi il costo è quello di un PBS e non dipende dalla larghezza del messaggio (F55);
e la compressione di dimensione non dà né velocità (F31)
né accuratezza. La fusione multi-frame è invece la leva vera, sull'asse giusto.

## 🔵 F49 — La demo end-to-end: i due ruoli come due processi, e la soglia come parametro d'installazione
Il sistema in funzione, non più come benchmark: una pagina con la telecamera, un **client** che è
il terminale fidato e un **server** che è la macchina remota, in due processi separati (due
container) che si parlano solo con byte cifrati. Codice in `demo/`, il servizio in
`experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` (sottocomandi `keygen`, `encrypt`,
`decrypt`, `serve`; HTTP minimale con la sola libreria standard, nessuna dipendenza in più).

Il giro completo, misurato su M4 Max con 127 iscritti:

| tappa | dove | tempo |
|---|---|---|
| 3 frame → ResNet100 (in chiaro) | client | ~170 ms |
| fusione multi-frame + quantizzazione 3 bit + cifratura (un GLWE) | client | ~10 ms |
| **varco cifrato: 127 soglie in parallelo** | **server** | **~110 ms** |
| decifratura dell'esito | client | ~8 ms |
| **totale per query** | | **~300 ms** |

⚠️ I ~10 ms e i ~8 ms delle righe client cronometrano `subprocess.run` di un binario Rust, cioè
soprattutto l'avvio del processo e la lettura delle chiavi da disco: **non** sono il costo della
crittografia. Le operazioni vere, misurate dentro il binario in F41, sono **0,4 ms** per la
cifratura e **0,03 ms** per la decifratura. Il totale resta quello che l'utente percepisce, ma le
due righe non vanno citate come costo del cifrato.

Sul filo: probe cifrato **32,8 KB** (encoding polinomiale, F41), esito cifrato 115 KB a 48 iscritti (230 KB a 127, perché cresce a blocchi di 64), chiave di
valutazione **130 MB** una volta sola. Verificato: 4 identità iscritte su 4 riconosciute con
l'indice giusto, 3 identità non iscritte su 3 rifiutate (`conteggio 0`). Il server, per
costruzione, non ha la chiave segreta: la pagina mostra i byte che riceve, ed è tutto quello che
vede.

**Il risultato inatteso della demo: la soglia è un parametro di installazione, non una costante.**
La prima esecuzione dava sistematicamente "ambiguo" (più iscritti sotto soglia). Il motivo: la
galleria della demo è fatta di volti **sintetici** (DigiFace: volti generati, così nelle
schermate della tesi non compaiono persone reali), mentre T=269 era calibrata sui volti **reali**
di VGGFace2. Misurato: sul dominio sintetico la soglia corretta a FPIR=1% è **T=23**, e usando
quella dei volti reali quasi tutti gli impostori verrebbero accettati. **Numeri da uno
script riproducibile** (`benchmark/soglia_dominio.py`, 7 semi, N=128 — è importante che siano
prodotte da uno script, perché senza sono inverificabili):

| soglia | one-hot corretti | impostori accettati | iscritti sotto soglia per query (genuini / impostori) |
|---|---|---|---|
| T=269 (dominio reale, **sbagliata qui**) | 6,4% | **93,8%** | 7,00 / 5,99 |
| T=23 (dominio sintetico, giusta) | **98,8%** | 1,6% | 1,01 / 0,02 | È il divario di dominio di F30 visto dal lato operativo, e per la tesi vale come
avvertenza pratica: la stessa identica pipeline, tarata sul dominio sbagliato, apre a chiunque.
`demo/calibra.py` ora calcola entrambe le soglie e scrive in `config.json` quella del dominio
installato.

Nota di ingegneria, non di crittografia: il client fa `keygen` all'avvio e consegna al server la
sola chiave di **valutazione** (130 MB, 0,2 s su rete locale); la chiave segreta non lascia mai
il container del client, ed è ciò che rende la separazione dei due processi una separazione vera
e non una formalità.

## 🔴 F50 — Il bilancio del rumore: perché la banda è quella, e perché l'accumulo leveled non c'entra
Fin qui la correttezza del varco era **empirica** ("0 discrepanze su 131.072 confronti", F43/F46) e
la banda misurata per campionamento (F37). Un revisore severo ha però una domanda legittima: *i
parametri di tfhe-rs sono tarati per cifrati freschi; voi ci mettete dentro l'accumulo leveled di
512 termini moltiplicati per coefficienti fino a 6 — la garanzia vale ancora?* Misurato, tappa per
tappa, decifrando e confrontando con l'atteso (`experiments/14_pipeline_tfhe_rs/src/bin/rumore.rs`,
400 campioni, Δ = 2^52, dim 512, valori a 3 bit).

| tappa | σ (set 1_1, N=512) | σ (set 2_2, N=2048) |
|---|---|---|
| GLWE fresco (il probe appena cifrato) | 2^15,7 | 2^16,2 |
| dopo il prodotto scalare leveled | 2^22,2 | 2^22,7 |
| dopo il keyswitch | 2^56,0 | 2^53,3 |
| modulus switch a 2N (teorico) | 2^56,0 | 2^54,1 |
| **totale all'ingresso del PBS** | **2^56,5** | **2^54,3** |
| **banda della decisione (σ/Δ)** | **22,5 unità** | **4,9 unità** |

Tre cose, e sono tutte importanti.

1. **L'accumulo leveled è previsto e innocuo.** Il prodotto scalare alza σ di ×92,7 (set 1_1) e
   ×92,3 (set 2_2), contro il valore atteso ‖p‖ = √8186 = 90,5: la teoria torna al 2%. Ma in
   assoluto porta il rumore solo da 2^15,7 a 2^22,2, mentre il PBS ne assorbe comunque 2^56 dai
   suoi passaggi obbligati. **L'accumulo contribuisce 2^−34 della varianza totale: è invisibile.**
   La risposta al revisore è quindi quantitativa: la garanzia dei parametri non è intaccata perché
   il nostro uso "fuori specifica" sta 34 bit sotto il rumore che il PBS gestisce per costruzione.
2. **La banda non viene da noi, viene dalla geometria del bootstrap.** È il keyswitch e il modulus
   switch a 2N a dominare, e sono le due tappe che qualunque PBS di TFHE fa comunque. Il modulus
   switch quantizza il toro in passi di q/2N, quindi σ_MS ≈ (q/2N)·√(n/12): a N=512 vale 2^56, a
   N=2048 vale 2^54. Il keyswitch è tarato *apposta* per stare a quel livello (sarebbe inutile
   essere più precisi di ciò che il modulus switch poi butta via).
3. **Da qui esce una regola di progetto in forma chiusa.** Δ è limitato dal range dei punteggi
   (serve |s−T|·Δ < 2^63), quindi Δ ≈ 2^63/range e

   **banda ≈ σ_tot · range / 2^63 ≈ range / 2^6,5 ≈ range / 90**  (set 1_1; range/360 per il 2_2).

   Cioè: la decisione cifrata ha una **precisione relativa fissa di ~6,5 bit sul punteggio**, e la
   banda in unità di punteggio si stringe solo (a) allargando N — la banda va come 1/N, ed è
   il rapporto misurato qui, 22,5/4,9 ≈ 4,6, contro il 4,0 di 2048/512 previsto — oppure (b) stringendo il range
   dei punteggi, che è ciò che fa la quantizzazione a 3 bit (F47). Le due manopole di F46/F47
   erano la stessa manopola vista da due lati, e ora si capisce perché.

**La garanzia diventa un numero, non un aneddoto.** Con σ_banda = 22,5 unità (1_1, Δ = 2^52), la
probabilità che il varco sbagli la decisione su un iscritto a distanza d dalla soglia è
P = ½·erfc(d/(σ√2)):

| d (unità di punteggio) | 10 | 25 | 50 | 100 | 200 |
|---|---|---|---|---|---|
| P(decisione errata) | 3·10⁻¹ | 1,3·10⁻¹ | 1,3·10⁻² | 4·10⁻⁶ | 3·10⁻¹⁹ |

Sui dati reali (F37) le distanze in gioco sono 300–3600 unità: la probabilità d'errore è sotto
10⁻¹⁹, cioè oltre il p-fail 2^−64 dichiarato dai parametri. **Questo sostituisce "0 discrepanze su
131.072" con un limite quantificato**, ed è la forma giusta dell'enunciato: il PBS di segno non
"fallisce" con probabilità p, ha un **confine sfocato** di larghezza nota; l'unico modo di
sbagliare è che un punteggio cada dentro la banda, e sui volti reali non ci cade praticamente mai.

Correzione a F47: lì scrivevo che a 3 bit la banda scende "a σ ≈ 4". Era una lettura affrettata di
due soli errori osservati a distanza 4; il modello dà σ ≈ 11 unità a Δ = 2^53, e due errori a
distanza 4 sono perfettamente compatibili con una banda di 11. Il guadagno dei 3 bit resta (la
banda si dimezza passando da Δ = 2^52 a 2^53), ma il numero giusto è ~11, non 4.

**Conferma sul campo, a grande scala.** Fino a N=1024 non avevamo mai visto un errore (0 su
131.072). Salendo, sono comparsi — e sono esattamente quelli che il modello prevede:

| N | tempo | confronti | errori | distanze |s−T| degli errori |
|---|---|---|---|---|
| 1024 | 0,72 s | 131.072 | 0 | — |
| 2048 | 1,59 s | 262.144 | **2** | 3, 4 |
| 4096 | 3,07 s | 524.288 | **3** | 4, 4, 13 |

Cinque errori su 786.432 confronti, tutti a **distanza ≤ 13 unità** dalla soglia, con σ_banda ≈ 11 a
Δ=2^53: cioè tutti dentro 1,2σ, esattamente dove il modello dice che la decisione è incerta. E
nessuna decisione per probe è cambiata (uscita compatta corretta 128/128 a ogni N). È la
validazione del modello di F50 su un campione grande abbastanza da vedere la coda. Nota anche la
scala: 0,72 → 1,59 → 3,07 s da 1024 a 4096, perfettamente lineare in N.

Nota sulla sicurezza, per chiudere il punto: il rumore che cresce **non** indebolisce la
cifratura — la sicurezza dipende dalla dimensione del reticolo e dal rumore *minimo*, e il probe
che il client manda è una cifratura GLWE fresca con la distribuzione standard del set di
parametri. Il server non fa che aggiungere rumore. Quindi i 128 bit di sicurezza dichiarati dal
set valgono senza asterischi; l'asterisco, se c'è, è solo sulla *correttezza*, ed è quello che
questa misura quantifica.

## 🔴 F51 — La galleria si può CIFRARE gratis: il prodotto esterno GGSW⊡GLWE (Mondo 2 a costo leveled)
Il limite dichiarato di tutto il lavoro, e la prima cosa che un revisore attaccherebbe, è che la
galleria sta **in chiaro** sul server (Mondo 1, F1): il prodotto scalare è cifrato×chiaro, quindi
leveled e gratis, ma il server vede i template degli iscritti. Tutta la letteratura che cifra anche
la galleria (HERS/Boddeti in BFV, Blind-Match e GROTE in CKKS) paga moltiplicazioni
**cifrato×cifrato**, con relinearizzazione e rescaling, ed è il motivo per cui i loro prodotti
scalari costano. In TFHE però esiste una terza via che quella letteratura non usa: il **prodotto
esterno**.

Se il template è cifrato come **GGSW** e la probe come GLWE, allora GGSW(P_i) ⊡ GLWE(A) = GLWE(P_i·A)
è un'operazione **leveled**: è lo stesso mattone con cui il blind rotate fa i suoi CMUX, e un blind
rotate ne incatena ~800. Quindi il prodotto scalare su galleria **cifrata** dovrebbe costare
~1/800 di un PBS, cioè niente rispetto al PBS di segno che paghiamo comunque. Provato e misurato
(`experiments/14_pipeline_tfhe_rs/src/bin/galleria_cifrata.rs`).

Un ostacolo pratico: tfhe-rs sa cifrare in GGSW solo messaggi **costanti**
(`encrypt_constant_ggsw_ciphertext`), mentre a noi serve la GGSW di un **polinomio** (il template).
L'abbiamo costruita con la stessa formula della libreria, generalizzata: le righe del gadget sono
GLWE(−S_i·μ·q/Bʲ) per i<k e GLWE(μ·q/Bʲ) per i=k, con il prodotto negaciclico al posto del prodotto
per scalare. La correttezza non è argomentata, è **verificata decifrando**.


**Il prodotto scalare, per iscritto** (dim 512, configurazione sicura: set 2_2, Δ = 2^51 dal bound
onesto di F56):

| gadget della GGSW | dimensione | tempo | banda aggiunta | verdetto |
|---|---|---|---|---|
| 2^8 × 2 | 128 KB | 0,025 ms | 57,21 unità | domina la banda: inutilizzabile |
| 2^12 × 2 | 128 KB | 0,022 ms | 0,44 unità | trascurabile |
| **2^10 × 3** | **192 KB** | **0,030 ms** | **0,01 unità** | **la scelta** |
| 2^16 × 1 | 64 KB | 0,015 ms | 134,68 unità | domina la banda: no |

**Il varco completo con galleria cifrata** (scena reale a 3 bit, 16 probe, gadget 2^10×3, decisioni
confrontate col chiaro):

| N | prodotto scalare cifrato | PBS di segno | **totale** | galleria cifrata | decisioni corrette |
|---|---|---|---|---|---|
| 8 | 0,0001 s | 0,0139 s | **0,014 s** | 1 MB | 128/128 |
| 32 | 0,0003 s | 0,0455 s | **0,046 s** | 6 MB | 512/512 |
| 128 | 0,0012 s | 0,1774 s | **0,179 s** | 24 MB | **2048/2048** |
| 512 | 0,0038 s | 0,6424 s | **0,646 s** | 96 MB | **8192/8192** |
| 1024 | 0,0070 s | 1,2074 s | **1,214 s** | 192 MB | **16384/16384** |

Log: `experiments/14_pipeline_tfhe_rs/results/galleria_cifrata_2_2.txt`.

**Il risultato: cifrare la galleria non costa niente in tempo.** Misurato fianco a fianco, stessa
macchina e stesso momento, sulla stessa scena e nella stessa configurazione sicura: a N=128 il varco
con galleria **cifrata** fa **0,179 s** contro gli **0,152 s** con galleria in chiaro, e a N=1024
**1,214 s** contro **1,204 s**. A N=1024 sono lo stesso numero; a N=128 il Mondo 2 è ~18% più
lento, ma la dispersione fra run è del 3-5% e i due run non sono simultanei, quindi il divario è al
limite di ciò che questa misura può risolvere. Il motivo è che il costo è tutto nel PBS di segno (il 99%), e il PBS non sa né gli importa
se la galleria è cifrata.

Anzi, il pezzo che cambia va nella direzione opposta a quella che ci si aspetterebbe: il prodotto
scalare **cifrato** costa **1,2 ms** contro i **3 ms** di quello in chiaro, cioè è ~2,5× più
economico. Non è un paradosso — il prodotto esterno lavora in dominio di Fourier, mentre la nostra
moltiplicazione per polinomio in chiaro (`polynomial_wrapping_add_mul_assign`) usa Karatsuba. Il
conto torna anche in astratto: un PBS *è* n prodotti esterni, quindi con n=781 un prodotto esterno
costa 1/781 di PBS a ℓ=1 e ~1/358 a ℓ=3, cioè **~34 µs**, contro i 55-125 µs per iscritto del
polinomio in chiaro (F41). Per onestà: anche il Mondo 1 potrebbe usare la FFT precalcolando la
trasformata del polinomio in chiaro, e tornerebbe il più veloce dei due. L'affermazione che conta è
strutturale e non dipende da quale delle due implementazioni è meglio ottimizzata: **entrambi i
prodotti scalari sono invisibili accanto al PBS**.

**Il prezzo vero è la memoria**: 192 KB per iscritto contro 4 KB in chiaro, cioè 24 MB a N=128 e
**192 MB a N=1024**. È il costo di tenere una galleria cifrata, e a queste scale è pagabile.

**Cosa cambia per il modello di minaccia — ed è uno scambio, non un miglioramento.** Il prodotto
esterno **richiede** che galleria e probe stiano sotto la **stessa chiave**: non è un dettaglio
implementativo, è il vincolo dell'operazione. Quindi chiunque possa cifrare il probe può
**decifrare la galleria**. Ne segue che i due mondi proteggono da parti diverse:

- **Mondo 1** (galleria in chiaro): 0,195 s a N=128, galleria 0,5 MB. Il server conosce i template
  degli iscritti. Ma il terminale la galleria non la vede **mai**, quindi un client malicious che
  volesse estrarre gli embedding degli iscritti — la minaccia primaria secondo F35 — è bloccato per
  costruzione.
- **Mondo 2** (galleria cifrata): 0,192 s a N=128, galleria 24 MB. Il server **non conosce nulla**:
  né il volto, né i template, né la soglia (che entra nella costante cifrata), né l'esito. Ma la
  galleria è cifrata **sotto la chiave del client**, quindi lo scenario è «il proprietario della
  galleria affida calcolo e archiviazione a un server non fidato» — ed è più debole del Mondo 1
  sull'asse del client.

La formulazione giusta è quindi «galleria cifrata **verso il server**, in uno scenario a
proprietario terzo», non «massimo di privacy». Va aggiunto che in Mondo 2 la difesa di F56 si
indebolisce: con ‖g_i‖² cifrato il server non può più calcolare il bound onesto sulla galleria.

Codice: `experiments/14_pipeline_tfhe_rs/src/bin/galleria_cifrata.rs` (il flag `--veloce` riproduce
le misure fatte col set 1_1 e Δ=2^53, che però non reggono contro un client malicious).

## 🔴 F52 — L'argmin esatto del prof, reso praticabile: torneo con circuit bootstrapping, 1,3 s a N=128
F45 aveva chiuso la strada dell'argmin esatto sul server con un numero: la matrice di tutti i
confronti a coppie è **quadratica** — 3,7 s a N=64 e 14,4 s a N=128, 10.816 PBS — e a N=128 esce
dal budget dei 10 s dell'incontro. Il motivo per cui non si poteva fare un **torneo** (N−1 confronti
invece di N(N−1)/2) era preciso: il bit di confronto esce come LWE, ma per *selezionare* il vincitore
serve un CMUX, e il CMUX vuole una **GGSW**. Il ponte fra i due esiste e si chiama **circuit
bootstrapping** (LWE → GGSW); tfhe-rs lo espone (`circuit_bootstrap_boolean`), e non l'avevamo mai
provato. Provato ora: `experiments/14_pipeline_tfhe_rs/src/bin/argmin_torneo.rs`.

Il candidato di ogni nodo del torneo è **un solo GLWE** che porta due cose: il punteggio s_i, che
il prodotto scalare polinomiale deposita al coefficiente dim−1, e l'indice i, scritto in chiaro al
coefficiente N−1 (gratis). Il posto dell'indice non è arbitrario: il prodotto P_i·A ha supporto
[0, 2·dim−2], quindi **i coefficienti oltre 2·dim−2 sono esattamente zero** ed è lì che l'indice
resta pulito. Un solo CMUX seleziona punteggio e indice insieme. Per confronto:

  estrai i due punteggi (gratis) → differenza (gratis) → keyswitch → **PBS di segno** che produce il
  bit pulito in cima al toro → keyswitch → **circuit bootstrap** → **CMUX**.

Il PBS di segno non è un di più: `circuit_bootstrap_boolean` con `DeltaLog(63)` pretende un LWE che
contenga **solo** il bit in cima (moltiplica per 1 e tratta il resto come rumore), mentre la
differenza dei punteggi ha i bit bassi pieni di dati. Passargli la differenza grezza — il nostro
primo tentativo — dà risultati casuali. Sono 4 PBS per confronto (1 di segno + 3 del circuit
bootstrap, con `cbs_level = 3`).

Parametri: `LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS` di tfhe-rs (128 bit, N=2048, k=1, PBS a 2
livelli, CBS 2^5×3, PFKS 2^15×2) — gli unici del set pensati per il circuit bootstrapping. Misure su
M4 Max, 16 thread, scena reale a 3 bit, confronti di ogni livello in parallelo:

| N | prodotto scalare | torneo | **totale** | confronti | indice esatto | …se il divario > 20 | **…se il minimo è sotto soglia** | matrice F45 |
|---|---|---|---|---|---|---|---|---|
| 8 | 0,001 s | 0,259 s | **0,260 s** | 7 | 15/16 | 12/12 | **2/2** | 0,09 s |
| 16 | 0,001 s | 0,346 s | **0,347 s** | 15 | 13/16 | 9/12 | **3/3** | 0,29 s |
| 32 | 0,002 s | 0,482 s | **0,484 s** | 31 | 14/16 | 11/13 | **5/5** | 0,97 s |
| 64 | 0,003 s | 0,747 s | **0,750 s** | 63 | 15/16 | 14/14 | **7/7** | 3,66 s |
| **128** | 0,006 s | 1,267 s | **1,273 s** | 127 | **16/16** | 16/16 | **14/14** | **14,4 s** |

**Tre riserve, da dire prima che le dica un revisore.** (1) L'indice **non è sempre esatto**, e con
il Δ onesto lo è ancora meno: su 32 probe l'indice è corretto **136 volte su 160** (85%), contro le 77/80 (96%) che la matrice
di F45 fa su 16 probe. Il torneo è quindi **più veloce e meno accurato** della cosa che
sostituisce. Conta però *quali* casi sbaglia: sui probe in cui il minimo è davvero sotto soglia —
gli unici che aprono il varco — l'indice è corretto **68 volte su 68**, e a N=128 **32/32**.
Log: `results/argmin_torneo_onesto.txt`. (2) Il "31 su 31" della
colonna «minimo sotto soglia» è una selezione **a posteriori sull'esito in chiaro**, e le numerosità
sono 2, 3, 5, 7, 14: su 14/14 l'intervallo di Wilson al 95% parte da ~78%. È un indizio, non una
misura. (3) I parametri `LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS` sono dichiarati dalla libreria
«security between **123 and 128** bits» e non espongono `log2_p_fail`: scrivere «128 bit» è
impreciso. E un vincolo strutturale: l'indice sta al coefficiente N_poly−1, che funziona solo se
N_poly ≥ 2·dim−1 — quindi il torneo **non è portabile** sul set veloce 1_1 (N=512) con dim=512.

**L'argmin esatto sul server non è quadratico per necessità**: con il
circuit bootstrapping è **lineare in N con profondità log N**, e a N=128 costa **1,3 s invece di
14,4 s — 11× meno — cioè dentro il budget dei 10 s (e dei 5 s) dell'incontro**. A N=64 fa 0,75 s. (Su una macchina carica gli stessi run danno 1,8-2,2 s a N=128: i tempi qui
sono a macchina scarica.) Il
punto di pareggio con la matrice sta fra N=16 e N=32: sotto, la matrice vince perché i suoi confronti
usano PBS piccoli, mentre il torneo paga i parametri WOPBS, più pesanti; sopra, vince il torneo
perché N−1 ≪ N²/2.

Onestà sui limiti, e qui la statistica dice una cosa precisa. L'indice esatto è 73 su 80 in
generale, ma **31 su 31 quando il minimo sta sotto soglia**, cioè in tutti i casi in cui il varco
apre davvero. Gli errori stanno tutti sui probe **impostori**, dove il "vincitore" è un candidato
qualunque fra punteggi lontanissimi dalla soglia e quasi appaiati fra loro: il costo medio
dell'errore (differenza fra il punteggio scelto e il minimo vero) va da 30 unità a N=8 a **0 a
N=128**, su un range di ~1300, e in quei casi il varco rifiuta comunque. È lo stesso meccanismo
della banda di F50: quando due punteggi distano meno del rumore (misurato sul vincitore dopo i log N
CMUX: 1,5-5,6 unità), il confronto può ribaltarsi. Nota controintuitiva ma sensata: **la precisione
migliora al crescere di N** (16/16 a N=128), perché con più candidati il minimo è più
distintamente separato dal secondo. (b) Resta **8,3× più lento** del varco a soglia (0,153 s a
N=128, F56): per un varco la soglia resta il design giusto, e F37/F43 mostrano che su dati reali il
caso "due iscritti sotto soglia" non capita mai. (c) La costruzione usa il set WOPBS legacy della
libreria, non parametri tarati da noi; il gadget del circuit bootstrap è quello standard (2^5×3, cioè
3 PBS per confronto). Provato a scendere a 2 livelli (2^7×2): il torneo va **31% più veloce**
(0,90 s invece di 1,31 s a N=128) ma la GGSW più rumorosa produce errori **veri**, non
quasi-pareggi — uno con costo 345 unità di punteggio contro le 0-30 del gadget standard. Non è
un compromesso che vale: si tengono i 3 livelli. (d) Il PBS di segno finale contro la soglia va aggiunto
(un PBS in più, ~40 ms).

**E si combina con F51: la configurazione di massima privacy.** L'opzione `--cifrata` usa la
galleria GGSW di F51 dentro il torneo, così il prodotto scalare che costruisce i candidati è un
prodotto esterno su template **cifrati**. Misurato sulla stessa scena:

| N | prodotto scalare | torneo | **totale** | indice esatto | quando il varco apre |
|---|---|---|---|---|---|
| 8 | 0,015 s | 0,301 s | **0,316 s** | 8/8 | 0/0 |
| 32 | 0,009 s | 0,661 s | **0,670 s** | 7/8 | 3/3 |
| 64 | 0,010 s | 1,153 s | **1,163 s** | 8/8 | 4/4 |
| **128** | 0,015 s | 1,995 s | **2,009 s** | **8/8** | **7/7** |

**1,2-2,0 s a N=128 per un server che non conosce assolutamente nulla** (il valore dipende dal
carico della macchina): non la galleria (cifrata come GGSW), non la norma ‖g_i‖² dei template — che
è un dato dell'iscritto e quindi arriva anch'essa **cifrata**, come un GLWE sommato gratis: la prima
versione di questo esperimento la sommava in chiaro, ed è un errore che una rilettura critica del
nostro stesso codice ha corretto — non il volto, non i punteggi, non l'esito. E restituisce
l'**indice esatto** del più vicino. (L'indice resta in chiaro perché è la numerazione interna del
server, non un dato dell'iscritto; il test finale contro la soglia aggiunge un PBS, con T dentro
una costante cifrata.) È il massimo di privacy che questo sistema può
offrire, ed è dentro il budget dell'incontro. Il prodotto scalare, quando la macchina è scarica, è
dello stesso ordine di quello in chiaro (0,006-0,015 contro 0,006 s): la FFT del prodotto esterno
contro la Karatsuba (F51).

**Cosa cambia per la conclusione della tesi.** All'incontro il prof aveva chiesto argmin poi soglia
sul vincitore; noi abbiamo consegnato la soglia per iscritto, motivandolo con il costo dell'argmin.
Quel motivo era vero per la matrice (F45) ma non in assoluto: ora il suo design originale è
misurato e sta nel budget. La conclusione onesta non è più "l'argmin non si può fare", ma:
**si può fare, costa 8,3× il varco a soglia, e serve solo se si vuole il vincitore anche quando più
iscritti sono sotto soglia** — cioè quasi mai, sui dati veri. È una scelta di progetto con due
numeri, non un limite tecnologico.

## 🔴 F53 — Il consuntivo dell'incontro: cosa era stato chiesto, cosa c'è, dove abbiamo deviato
Verifica sistematica del percorso contro le decisioni prese con il prof. Di Raimondo e Carnemolla
(F35), perché una tesi si giudica anche su quanto ha fatto ciò che si era detto di fare.

| chiesto all'incontro | stato | dove |
|---|---|---|
| embedding sul client, in chiaro; il modello conta poco | fatto; e GhostFaceNet, che era la sua proposta, è misurato: +1 punto su MobileFaceNet, −7/−8 sui profondi | F44 |
| il fulcro del lavoro è la **selezione** cifrata | è stato il fulcro: F34, F37, F38, F45, F46, F47, F52 | — |
| galleria realistica: **N = 64 e 128** | fatto, e oltre: fino a 1024 misurato, 4096 in verifica | F43, F51 |
| **meno di 10 s**, 5 accettabili | **0,153 s a N=128**, 1,26 s a N=1024 nella configurazione sicura — due ordini di grandezza sotto | F56 |
| «quindi Rust»: usare le funzioni di tfhe-rs, non scrivere crittografia da zero | tutto in tfhe-rs; le uniche righe "nostre" sono la GGSW polinomiale di F51, costruita sulla formula della libreria | F37-F52 |
| Carnemolla: **confrontare con CKKS** | fatto e misurato, con la lettura del perché | F39 |
| torneo con i confronti di ogni livello **in parallelo** | fatto in tre versioni: radix, matrice, e torneo vero con circuit bootstrapping | F38, F45, F52 |
| distanza euclidea al quadrato, niente approssimazioni | invariata | — |
| microbenchmark con vettori della dimensione e precisione reali | metodo seguito in tutti gli esperimenti | F36, F38, F50 |
| in tesi: percorso naïve → ottimizzato, solo le tecniche con guadagno osservabile | fatto, con figura e lista tieni/scarta | F42 |
| **mai restituire la distanza** al client | rispettato ovunque; e ora sappiamo *quanto* rivela il solo bit | F40 |
| client malicious ⇒ la **selezione sta sul server** | rispettato. La galleria può anche stare cifrata (F51), ma è uno **scambio**: protegge dal server e indebolisce verso il client, perché il prodotto esterno vuole la stessa chiave | F51 |

**Le tre deviazioni, dichiarate.**

1. **Soglia per iscritto al posto di «argmin, poi soglia sul vincitore».** È la deviazione vera.
   La motivazione data finora — l'argmin esatto costa troppo — era corretta per la matrice
   quadratica (F45: 14,4 s a N=128) ma **non è più vera in assoluto**: F52 mostra che con il
   circuit bootstrapping il torneo lo porta a 1,3 s, dentro il budget. Quindi la formulazione
   onesta cambia: non «l'argmin non si può fare», ma «la soglia costa 8,3× meno e sui dati reali
   dà la stessa risposta, perché il caso in cui due iscritti stanno sotto soglia non capita mai
   (F37, F43); l'argmin esatto resta disponibile a 1,3 s se lo si vuole». È una scelta di
   progetto documentata da due numeri, ed è la cosa da mettere davanti al prof.
2. **Il conteggio nell'uscita compatta.** Il varco restituisce quanti iscritti sono sotto soglia,
   non solo il vincitore. All'incontro era stata accettata la one-hot dell'**argmax** («rivela al
   massimo quanti elementi»), non un bit per iscritto: il delta non è stato discusso e va portato.
   Se il conteggio non piace, l'alternativa è esattamente il punto 1 (argmin esatto, 1,3 s).
3. **Il rate limiting entra nel modello di minaccia.** F40 misura che il solo bit di esito è un
   oracolo di appartenenza: con una foto dell'iscritto e ~30.000 query si ricostruisce il suo
   embedding. Non è un difetto del nostro circuito (vale per qualunque varco accetta/rifiuta, e
   la letteratura lo dice), ma è una contromisura non crittografica che il modello di minaccia
   dell'incontro non nominava e che va aggiunta.

**Una cosa in più rispetto a quanto chiesto:** all'inizio il Mondo 1 (galleria in chiaro sul
server) era un vincolo accettato. F51 lo toglie: la galleria si può cifrare **allo stesso costo**,
con il prodotto esterno GGSW⊡GLWE. Il risultato non era nel programma dell'incontro ed è la
risposta alla critica più prevedibile di un revisore.

**Verdetto sul percorso.** Le decisioni dell'incontro sono state rispettate o superate, con una
deviazione sostanziale (punto 1) che oggi è una scelta e non più una necessità, e due punti da
discutere (2 e 3). Il numero che riassume tutto: si era chiesto **meno di 10 secondi a 128
iscritti**; nella configurazione sicura (F56) il sistema fa **0,153 s** con la galleria in chiaro (F56),
**0,179 s** con la galleria cifrata (F51), e **~1,5 s** se si pretende anche l'argmin esatto invece della
soglia.

## 🔵 F54 — Soglia per template (Z-norm): gratis, ma vale poco — e si capisce perché
Un'idea che sembrava un guadagno gratuito. In biometria è noto che i template non sono
equivalenti: alcuni attirano punteggi bassi da chiunque ("lupi") e alzano i falsi positivi. La
normalizzazione di coorte corregge questo, e nel nostro circuito **sarebbe gratis**: la condizione
s_i ≤ T con soglia unica diventa s_i ≤ μ_i + σ_i·T, cioè solo un'altra costante per iscritto — e la
costante per iscritto il circuito la calcola già (‖g_i‖² − T). Stesso numero di operazioni, stesso
costo cifrato. Misurato in chiaro (`benchmark/soglia_per_template.py`, ResNet100 su VGGFace2, 3 bit,
coorte di 300 identità disgiunte dalla galleria e dagli impostori del test, 10 scene):

| N | fusione | soglia unica | −μ_i (T-norm) | (s−μ)/σ (Z-norm) |
|---|---|---|---|---|
| 128 | 1+1 | 90,4% | 90,9% (+0,5) | 90,9% (+0,5) |
| 128 | 2+3 | 98,4% | 98,7% (+0,3) | 98,2% (−0,2) |
| 1000 | 1+1 | 90,0% | 90,3% (+0,3) | 90,2% (+0,1) |
| 1000 | 2+3 | 97,8% | 97,9% (+0,1) | 98,0% (+0,1) |

**+0,3 punti in media, e la Z-norm piena non aggiunge nulla sopra la sola T-norm.** Per la regola
dell'incontro (in tesi solo le tecniche con un miglioramento osservabile) questa va nella lista da
citare in una riga, non da sviluppare. Ma la spiegazione è interessante e vale la riga: gli
embedding ArcFace/ResNet100 sono **già normalizzati per costruzione** — L2 sulla sfera e margine
angolare in addestramento rendono le distribuzioni dei template molto più omogenee di quanto fossero
ai tempi in cui T-norm e Z-norm furono inventate (sistemi a GMM/eigenface). La normalizzazione di
coorte trova poco da correggere perché il lavoro l'ha già fatto la rete.

Resta comunque adottabile: costa zero e non peggiora mai la T-norm. Confronto con le altre leve di
accuratezza provate: fusione multi-frame **+3,9 punti** (F48), modello più grande +1-2 (F44, F20),
compressione 0 o negativa (F31), soglia per template +0,3 (qui).

## 🔴 F55 — Il modello di rumore dei set di parametri: quale regge, quale no, e perché
Perché i set piccoli (2_0 con N=512, 1_0 con N=256) sbagliano un quinto dei confronti mentre 1_1
con lo **stesso** N=512 è esatto? La risposta si calcola dai parametri del crate, non si indovina, e
distingue **due** quantità che è facile confondere: la banda **pre-PBS** (resto del keyswitch più
drift del modulus switch, che scala come 1/Δ) e il **rumore in uscita** dal blind rotate (piatto,
invariante in Δ).

| set | n | k | N | pbs_base_log | σ_glwe rel. | banda prevista (Δ=2^51) | σ in uscita | margine col bit a 2^55 |
|---|---|---|---|---|---|---|---|---|
| 2_2 | 834 | 1 | 2048 | 23 | 2^−48,3 | **12** | 2^49,2 | 57σ |
| 2_1 | 857 | 2 | 1024 | 23 | 2^−48,3 | **24** | 2^49,2 | 57σ |
| 1_1 | 781 | 4 | 512 | 23 | 2^−48,3 | **49** | 2^49,1 | 60σ |
| 2_0 | 775 | 3 | 512 | **17** | **2^−35,6** | 48 | **2^55,0** | **1,0σ** |
| 1_0 | 720 | 6 | 256 | **17** | **2^−35,6** | 89 | **2^54,9** | **1,1σ** |

Le bande previste per 2_2, 2_1 e 1_1 (12 / 24 / 49) **combaciano con quelle misurate** in F46
(12 / ~30 / ~50): il modello è validato dove sappiamo la risposta. E dice una cosa netta: **2_0 ha
la stessa banda di 1_1**, quindi non fallisce per la banda. Fallisce perché ha `pbs_base_log=17` con
`pbs_level=1` **e** una chiave GLWE 2^12,7 volte più rumorosa (con k·N=1536 i 128 bit richiedono
σ_rel = 2^−35,6): i due termini del rumore del prodotto esterno si bilanciano a **σ_out = 2^55**,
che è **esattamente l'ampiezza con cui `LOG_DO = 56` codificava il bit**. Il bit usciva annegato nel
proprio rumore, con **1σ di margine** — errori casuali, cioè quel quinto di confronti sbagliati.

Verificato anche che a ℓ=1 `base_log=17` è **già l'ottimo** per quei set (minimo di σ_out su tutti i
base_log): non è aggiustabile lì, e salire a ℓ=2 raddoppia il lavoro e annulla il guadagno.

**Due indizi che confermano che si tratta di errori uniformi e non di una banda.** Primo: la mediana
di |s−T| degli errori scende da 1878 a 344 passando da Δ=2^51 a Δ=2^53, ma 1878/344 = 5,459 e il
rapporto fra i **range dei punteggi** delle due scene è 3562/653 = 5,455 — quel numero misura il
range, non una banda, ed è proprio ciò che ci si aspetta se gli errori sono indipendenti da |s−T|.
Secondo: il **tasso** d'errore non scende quadruplicando Δ (2_0: 20,7% → 19,0%; 1_0: 17,5% → 17,2%)
ed è costante in N.
Se fosse una banda in ingresso, il tasso dovrebbe scendere ~4×.

**Una spiegazione alternativa che sembra funzionare e non funziona.** Verrebbe da attribuire il
crollo alla *box size* dell'accumulatore (N / `message_modulus`), e la regola «box ≥ 256»
classifica correttamente tutti e cinque i set osservati. È però una coincidenza: il nostro
accumulatore è un **polinomio costante** (`varco_leveled.rs`), quindi il PBS negaciclico guarda solo
in quale metà del toro cade il valore — `message_modulus` non entra nel circuito e di scatole non ce
ne sono. Vale la pena registrarlo perché è un caso di scuola: **una regola che classifica bene i
dati non è per questo la causa**.

**Non è il segno a sbagliare: è la lettura del risultato.** Il bit d'esito era codificato a 2^56
(`LOG_DO = 56`) per lasciare 8 bit di franco alle somme dell'uscita compatta a blocchi di 64, cioè
un margine di decodifica di 2^55 — contro il σ_out = 2^55 della tabella. È una scelta di codifica,
non un limite dei parametri.

**Verificato, ed è un guadagno.** Basta alzare il margine: `--log-do 60 --blocco 8` (blocchi da 8
invece che da 64 → servono 4 bit di franco invece di 8 → il bit può stare a 2^60, margine 2^59).
Misurato sulla stessa scena, N=128, macchina scarica:

| set | prima (`log-do 56`, blocco 64) | **ora (`log-do 60`, blocco 8)** | PBS/thread | errori |
|---|---|---|---|---|
| 1_1 | 0,100 s, 0 errori | 0,089 s | 10,8 ms | 0/16.384 |
| 2_1 | 0,134 s | 0,119 s | 14,5 ms | 0/16.384 |
| 2_0 | 0,083 s, **3.118 errori** | **0,072 s** | 8,7 ms | 1/16.384 (a d=22) |
| **1_0** (N=256) | 0,072 s, **2.824 errori** | **0,064 s** | **7,8 ms** | **0/16.384** |

**Il varco più veloce non è quello che credevamo: è il set 1_0, con N=256, a 0,062 s a N=128** —
un altro **28%** sotto il minimo di F46, e con l'uscita compatta corretta 128/128.
E regge a scala, con zero errori dove il set "buono" ne faceva tre:

| N | 1_1 (il preteso muro) | **1_0 (`--log-do 60 --blocco 8`)** | guadagno | errori 1_0 |
|---|---|---|---|---|
| 128 | 0,089 s | **0,062 s** | −30% | 2 / 16.384 (a d=4 e 22) |
| 1024 | 0,72 s | **0,505 s** | −30% | 0 / 131.072 |
| 4096 | 3,07 s | **2,073 s** | −32% | **0 / 524.288** |

Il costo per bootstrap scende da 12 ms a **7,6 ms**: il set 1_0 ha il polinomio più corto (N=256) e
la chiave più piccola (n=720), quindi FFT e keyswitch costano meno.

**Un vincolo che nasce proprio da lì, e va detto.** Questi numeri vengono da `varco_leveled.rs`, che
cifra il probe come 512 LWE separati. L'encoding **polinomiale** di F41 — quello che porta il probe
a 32,8 KB con il set 2_2 della demo — richiede invece un polinomio lungo almeno quanto l'embedding, e il
set 1_0 ha **N=256 < 512**: con lui il probe compatto non ci sta in un solo GLWE. Le vie sono due:
tenere il set 1_1 (N=512) e il probe da 20 KB a 0,089 s, oppure spezzare il probe in **due** GLWE da
256 coefficienti e sommare i due contributi estratti (28 KB, 0,064 s). Non è un problema di
principio, è una scelta di impacchettamento; la demo tiene 2_2 (imposto da F56) perché lì il collo di bottiglia è
l'embedding sul client (170 ms), non i 25 ms di differenza.

**C'è però una terza via, ed è la migliore: ridurre l'embedding a 256 dimensioni.** F23 lo diceva
già («512→128 quasi gratis») e qui è misurato nella configurazione finale (ResNet100, 3 bit,
N=1000 iscritti): a 256 dimensioni la DIR@FPIR=1% è **95,6% contro 95,7%** a frame singolo e
**99,1% contro 99,2%** con la fusione multi-frame — un decimo di punto. A 128 si perde 1 punto, e
non serve. Con dim = 256 il probe entra in **un solo** GLWE del set più veloce (N=256): probe da
**14,3 KB**, varco a **0,064 s**, accuratezza intatta. L'aritmetica regge anche al caso limite
dim = N: il prodotto negaciclico ha grado massimo 2·dim−2 = 510 < N+dim−1 = 511, quindi il
coefficiente dim−1 non riceve termini di wraparound — verificato su 200 prove casuali per ognuna
delle tre combinazioni (256/256, 512/512, 512/2048), sempre esatto.

**La configurazione consigliata che ne esce** *(valida solo contro un client honest-but-curious:
vedi F56, che contro un client malicious impone il set 2_2 e un Δ più conservativo)*: embedding
256-dim, quantizzazione a 3 bit, fusione 2+3 frame, set di parametri 1_0 con `--log-do 60 --blocco 8`. Probe 14 KB, **0,064 s a N=128** e
**0,5 s a N=1024** sul server, **99,1%** di DIR@FPIR=1%.
Il prezzo è la banda: 1_0 ha N=256, e per la regola di F50 (banda ∝ 1/N) la sua banda è il doppio
di quella di 1_1, ~22 unità invece di ~11 a Δ=2^53 — sempre due ordini di grandezza sotto i divari
reali (300-3600 unità), come conferma lo 0/16.384 misurato. L'altro prezzo è la banda passante
dell'esito: blocchi da 8 invece che da 64 significa ~4,5× più cifrati in uscita (1 MB invece di
229 KB a N=128), che resta molto meno degli N bit separati.

**Cosa resta valido di F46/F47 e cosa no.** Resta vero il fatto misurato (con `LOG_DO=56` quei set
sbagliano) e resta valido tutto F50, che misura il rumore **in ingresso** al PBS e da cui viene la
banda: sono due fenomeni distinti che convivono — la banda in ingresso sfoca la decisione *vicino
alla soglia*, il rumore in uscita rompe la *lettura del bit* ovunque. Cade invece la spiegazione
(la box size) e cade la conclusione ("1_1 è il più piccolo set che tiene", "sotto non si scende").
Il minimo vero, su questo hardware e con questa libreria, è **0,064 s a N=128**.

**Nota di metodo, che vale quanto il numero.** Il finding sbagliato era proprio quello che
raccontava di aver trovato "il meccanismo". È il rischio tipico di una spiegazione che *classifica
correttamente i dati osservati* (box ≥ 256 separava i set buoni dai cattivi) senza essere la causa:
cinque punti, due classi, tante regole che li separano. L'inferenza si smonta con
un rapporto fra numeri già presenti nei file, senza rifare un solo esperimento.

## 🔴 F56 — Una vulnerabilità vera: il client malicious apre il varco in una query (e il costo della difesa)
La stessa revisione critica ha trovato una cosa più seria: **un difetto di
sicurezza nel sistema**, non un errore di racconto. Verificata end-to-end, e qui c'è anche la
difesa, con il suo prezzo misurato.

**Il difetto.** Il punteggio viaggia codificato come (s−T)·Δ sul toro a 64 bit, e Δ lo sceglievamo
*guardando i punteggi dei probe della scena* (`varco_leveled.rs` scorre tutti i probe per trovare
il massimo |s−T|). È un iperparametro tarato sul test set, e lascia un margine minimo: sulla scena
a 4 bit il massimo osservato è 3561 contro un **precipizio di wrap a 4096** — l'87% del budget.
Oltre quel valore (s−T)·Δ avvolge modulo 2^64 e il PBS di segno legge la **metà sbagliata del
toro**: risponde "match".

E un client malicious ci arriva senza sforzo, perché non manda un volto: manda un vettore. Basta
sceglierlo con s−T dentro la finestra [periodo/2, periodo), dove periodo = 2^64/Δ. Sui dati veri,
con valori tutti dentro il dominio legale a 3 bit:

| probe costruito | s−T | sotto soglia **in chiaro** | esito del **varco cifrato** |
|---|---|---|---|
| bersaglio 0 | 1026 | **0 iscritti** | accettato |
| bersaglio 5 | 1037 | **0 iscritti** | accettato |
| bersaglio 17 | 1027 | **0 iscritti** | rifiutato |

Tre probe che in chiaro non somigliano a nessuno, e il varco ne accetta **due su tre**, con
discrepanze di 1027 e 1037 unità — cento volte la banda (≈11). **Una query, nessun oracolo, nessuna
foto**: il cancello si apre.

**Perché è grave anche per F40.** Il modello di minaccia (F35) diceva che il client malicious non
può fare di meglio che tentare, e F40 aggiungeva che senza una foto dell'iscritto l'oracolo a un bit
è muto. Con il wrap, l'attaccante ottiene qualcosa di molto più forte: **spazzolando la finestra**
può misurare s_i(v) per un v qualunque, cioè un oracolo sul *punteggio*, non sul bit — e F40 misura
che con il punteggio l'embedding si ricostruisce in **513 query**, non 30.000, e **senza partire da
una foto**. La frase di F35 «con l'esito a soglia questo attacco non c'è» era quindi troppo forte.

**La difesa: Δ da un bound indipendente dal probe.** L'unico Δ difendibile è quello che copre tutto
ciò che un client *qualunque* può produrre. Il caso peggiore secco, |s−T| ≤ 2·dim·q² + max‖g‖² + |T|,
vale 10.168 sulla scena a 3 bit → Δ = 2^49. Ma si può stringere di **4×** senza perdere nulla,
perché il server **conosce la galleria** (è il Mondo 1) e i template quantizzati sono sparsi: il
bound vero è

    |s − T| ≤ 2·q · max_i ‖g_i‖₁ + max_i ‖g_i‖² + |T|  =  3.646  →  Δ = 2^51

(la norma ℓ1 media dei template è 426, non 1536 come nel caso peggiore). Resta **indipendente dal
probe** purché q sia il dominio *dichiarato* del client e non il massimo osservato (, quindi il wrap è impossibile per costruzione. Non è gratis, perché la banda è σ_assoluto/Δ e
quindi si allarga di 16×. Misurato:

| set | banda a Δ=2^51 | discrepanze su 16.384 | genuini / impostori accettati | tempo a N=128 | sotto attacco |
|---|---|---|---|---|---|
| 1_1 (N=512), il veloce | 44 unità | 6 | 58/64 · **4/64** | 0,095 s | 0/3 |
| **2_2 (N=2048)** | **10 unità** | **0** | 57/64 · **0/64** | **0,152 s** | **0/3** |

Il set piccolo **non sopravvive**: con la banda a 44 unità accetta 4 impostori su 64 (FPIR al 6%
invece dell'1% tarato) — il varco decide male vicino alla soglia. Il set grande regge perfettamente:
**zero discrepanze su 16.384 confronti**, zero impostori accettati, e i 57/64 genuini riconosciuti
sono *esattamente* il risultato del calcolo in chiaro. E con lui l'attacco è **bloccato**: 0 su 3.

Il conto vero del prezzo, quindi, è più preciso di come sembrava: **la difesa in sé non costa
nulla** (con il set 2_2, il Δ onesto dà gli stessi 0,152 s e la stessa accuratezza del Δ tarato sui
dati); quello che costa è **non poter usare il set piccolo con questa galleria**, cioè
0,064 → 0,152 s, **2,4×**. F58 mostra però che quel 2,4× è convertibile: limitando la norma ‖g‖₁
della galleria all'iscrizione il Δ guadagna due bit, il set piccolo torna utilizzabile **restando
difendibile**, e il prezzo diventa 0,4-0,9 punti di DIR invece che 2,4× di tempo.

**La configurazione sicura, quindi:** set 2_2 (N=2048), Δ = 2^63 / (2·q·max‖g‖₁ + max‖g‖² + |T|),
quantizzazione a 3 bit, fusione 2+3 frame. **0,152 s a N=128**, accuratezza identica al calcolo in
chiaro, e nessun probe costruito ad arte riesce ad aprire. Resta due ordini di grandezza sotto i 10 s dell'incontro: il
prezzo della sicurezza si paga senza uscire dal budget.

**La curva completa della configurazione sicura** (set 2_2, Δ = 2^51 dal bound onesto, 16 thread,
scena reale ResNet100/VGGFace2 a 3 bit, `--log-do 60 --blocco 8`):

| N | prodotto scalare | KS + PBS | **totale** | per PBS | discrepanze |
|---|---|---|---|---|---|
| 128 | 0,003 s | 0,150 s | **0,152 s** | 18,7 ms | 0 / 16.384 |
| 256 | 0,006 s | 0,291 s | **0,296 s** | 18,2 ms | 0 / 32.768 |
| 512 | 0,012 s | 0,581 s | **0,593 s** | 18,2 ms | 0 / 65.536 |
| 1024 | 0,020 s | 1,184 s | **1,204 s** | 18,5 ms | 0 / 131.072 |
| 2048 | 0,039 s | 2,330 s | **2,369 s** | 18,2 ms | 1 / 262.144 |
| 4096 | 0,082 s | 5,099 s | **5,181 s** | 19,9 ms | 0 / 524.288 |

Log: `experiments/14_pipeline_tfhe_rs/results/varco_sicuro_2_2.txt` (il file riporta anche il carico
della macchina al momento del run). ⚠️ **La dispersione fra run è del 3-5%** — una rilevazione
precedente dava 0,153 / 0,315 / 0,605 / 1,258 / 2,463 / 4,950 s — quindi questi numeri vanno citati
con una cifra significativa in meno di quante ne hanno, e i confronti fini vanno fatti dentro lo
stesso run.

**Dove va il tempo dentro la colonna «KS + PBS»**, misurato strumentando il ciclo (tempo-thread
cumulato, N=128): **keyswitch 890 ms (9,9%), blind rotate 8.119 ms (90,1%)**. Serve a chiudere una
scorciatoia che sembra ovvia: il keyswitch esiste perché il prodotto scalare è calcolato sotto la
chiave *grande* mentre il PBS vuole quella *piccola*, e verrebbe da cifrare il probe direttamente
sotto la chiave piccola per saltarlo. Il tetto di quel guadagno è **1,11×** — e si pagherebbe con il
rumore più alto della chiave piccola amplificato su 512 termini. Non vale: il costo è il blind
rotate, e il blind rotate non si sconta.

Lineare esatta (il tempo per PBS resta 19 ms a ogni scala: i thread non si saturano), e
**1 errore su 1.032.192 confronti**, a |s−T| = 4 (in un run precedente 3 errori, tutti a |s−T| ≤ 4) — cioè dentro la banda di ~10 unità, dove
il modello di rumore di F50 dice che devono stare. A N=4096 il varco sicuro sta in **5 secondi**,
dentro il budget dei 10 s dell'incontro con la galleria più grande che abbiamo.

**Verifica sulla demo end-to-end.** Ho rimesso il Δ onesto stretto (2^51, dal bound della galleria
sintetica: 3.455) nel servizio Docker e riprovato con volti passati dalla pipeline completa
(48 iscritti, ResNet100, fusione 2+3 frame): **6 iscritti su 7 aperti, 4 estranei su 4 negati**,
~90 ms lato server. L'unico caso non aperto è un *ambiguo* (due iscritti sotto soglia insieme),
cioè un limite di accuratezza della galleria sintetica — DigiFace ha identità molto simili tra
loro — non un errore del cifrato.

Uno sweep di Δ sulla stessa demo conferma il modello di rumore di F50 dal lato opposto: a **2^47**
un iscritto genuino con margine 127 unità viene *negato*, perché a quel Δ la banda vale ~64 unità e
127 non basta; da 2^49 in su lo stesso probe passa. Il Δ non è quindi solo una questione di
sicurezza: sotto il bound onesto si perde accuratezza, sopra si apre l'overflow. Il bound stretto
mette il sistema **esattamente sul massimo consentito**, che è anche il punto di rumore minimo.

**Perché una prova ZK di *range* non servirebbe a niente.** Verrebbe da pensare che il modo pulito
di riavere il Δ stretto sia far allegare al client una prova a conoscenza zero che il probe sta nel
dominio dichiarato (tfhe-rs ha il modulo `zk`, che prova esattamente il range del messaggio). Non
serve: l'attacco qui sopra usa un probe con **tutti i valori già legali** — è tarato, non fuori
range — e il bound onesto assume *già* che ogni coefficiente stia in [−q, q]. Una prova che
certifica ciò che il bound assume non toglie e non aggiunge nulla, e F58 mostra col conto che
nemmeno una prova sulla *norma* sposterebbe il Δ.

Il che non vuol dire che la norma sia irrilevante: **serve, ma contro un altro attacco** (F61), dove
è l'unica difesa completa. Le due cose vanno tenute distinte — il Δ si difende con il bound, il
punteggio si difende con la norma.

**Cosa correggere nei finding precedenti.** F37 dice che Δ è scelto «senza guardare nessun probe»:
è falso, il codice li guarda tutti. F35 dice che con l'esito a soglia l'attacco per gradiente «non
c'è»: vero solo se Δ è onesto. F55 elegge il set 1_0 come il più veloce: vero, ma solo nel modello
di minaccia *honest-but-curious sul client*; contro un client malicious il campione è il 2_2. La
lezione di metodo, di nuovo: **un iperparametro tarato sul test set non è solo un peccato
statistico — qui era un buco di sicurezza.**

---

## 🔵 F57 — La cascata: l'accuratezza dell'argmin al costo del varco (8× meno)

La demo mi ha messo davanti un caso che avevo sempre contato come sconfitta: il varco risponde
`(conteggio, indice)`, e su un iscritto genuino ha risposto **conteggio 2** — due iscritti sotto
soglia contemporaneamente, quindi «ambiguo», nessuna identità. Finora, nella metrica DIR, l'ambiguo
è un fallimento: chiedo che sia sotto soglia *esattamente uno* e che sia il proprio.

Ma l'ambiguo è esattamente il caso che l'argmin a torneo di F52 sa risolvere: fra i due sotto
soglia, quale ha il punteggio minore. La domanda giusta non è quindi «varco **o** argmin», è
**quanto spesso serve l'argmin** — perché il varco costa 0,15 s a N=128 e l'argmin 1,3 s.

**La misura** (ResNet100, VGGFace2 reale, 3 bit, fusione 2+3, soglia tarata a FPIR=1%, 10 semi):

| N | DIR col solo varco | DIR con la cascata | probe genuini ambigui | probe impostori ambigui |
|---|---|---|---|---|
| 128 | 98,6% | **99,4%** | **0,8%** | 0,0% |
| 1024 | 97,8% | **98,9%** | **1,2%** | 0,0% |

L'ambiguità è **rara** — meno dell'1,2% dei probe genuini, e quasi mai sugli impostori (0,0% a N=128, 0,02% a N=1024: un impostore
fatica già a scendere sotto soglia una volta; due volte quasi non capita). E risolverla vale **+0,8 / +1,1
punti** di DIR, che è esattamente l'accuratezza che si otterrebbe eseguendo l'argmin *sempre*: la
cascata non è un'approssimazione dell'argmin, gli è **equivalente**, perché quando il conteggio è 1
l'unico accettato *è* il minimo.

⚠️ Con una precisazione che va fatta qui e non altrove: il secondo stadio della cascata è l'argmin
di F52, e **con il Δ onesto l'argmin non è esatto al 100%** — su 32 probe l'indice è corretto 136
volte su 160. Quello che conta però è *quali* casi sbaglia: sui probe in cui il minimo è davvero
sotto soglia — gli unici in cui la cascata invoca il secondo stadio — l'indice è corretto **68 volte
su 68**, e a N=128 32/32. La cascata è quindi affidabile nel regime in cui viene usata, ma la parola
«equivalente» va intesa in quel senso, non come esattezza incondizionata.
Log: `experiments/14_pipeline_tfhe_rs/results/argmin_torneo_onesto.txt`.

**Il conto del costo atteso**, con i tempi misurati su questa macchina (varco: set 2_2 con Δ onesto,
F56; argmin: F52 a N=128, estrapolato con la retta 0,216 + 0,0086·N a N=1024):

| N | argmin sempre | **cascata** = varco + p·argmin | risparmio |
|---|---|---|---|
| 128 | 1,32 s | **0,16 s** | **8,3×** |
| 1024 | 9,02 s | **1,31 s** | **6,9×** |

Cioè: **la precisione dell'argmin esatto al prezzo del varco**, perché il caso costoso capita una
volta su cento.

**Cosa si paga in riservatezza, detto con precisione.** Il secondo giro rivela al server **un bit
per query**: «questo probe era ambiguo» — che succede ~1% delle volte. Non rivela chi, non rivela il
punteggio, non rivela se il probe è di un iscritto. È una perdita reale e va dichiarata, non
nascosta; chi non la vuole ha due uscite, entrambe già disponibili: pagare l'argmin sempre (1,32 s),
oppure il giro finto — mandare comunque la seconda richiesta anche quando non serve, che riporta il
costo a quello dell'argmin sempre. **Il risparmio 8× e il bit di leak sono la stessa cosa vista da
due lati**, ed è una scelta che va lasciata a chi installa il sistema.

**La variante a un giro solo, senza leak** (non implementata, e con un conto da verificare). I bit
di soglia b_i sono cifrati e valgono 0 oppure 2^60. Si possono usare per *mascherare* i punteggi
prima del torneo: s'_i = s_i + BIG·Δ − b_i·(BIG·Δ / 2^60), dove la moltiplicazione per una costante
intera è leveled — nessun bootstrap. Il torneo su s' trova allora il minimo **fra i soli accettati**,
perché i respinti sono stati spinti fuori scala, e il server non impara niente.

Il vincolo vero è aritmetico: BIG deve superare l'**intervallo** dei punteggi (non solo essere
grande), altrimenti un respinto può ancora battere un accettato; e BIG·Δ/2^60 deve essere intero,
cioè BIG multiplo di 2^9. Sulla scena reale l'intervallo è 1.371, quindi BIG = 1.536 e il fattore
scalare è **3**; se si vuole coprire anche un client malicious, l'intervallo da coprire è quello del
bound onesto (2 × 3.646), quindi BIG = 7.680 e il fattore è **15**. Il rumore cresce dello stesso
fattore: da +1,6 a +3,9 bit. È **plausibile** che stia nel budget — la banda del set 2_2 è 10 unità
su un intervallo di 1.371 — ma **non l'ho misurato**, e finché non lo misuro resta una proposta, non
un risultato. Costa comunque l'argmin sempre: la stessa spesa dell'opzione conservativa, col
vantaggio di non fare due giri di rete.

**Perché conta per la tesi.** Il consuntivo dell'incontro (F53) opponeva due risposte diverse alla
richiesta del prof — il varco a soglia (veloce, ma risponde «uno / nessuno / ambiguo») e l'argmin
esatto (risponde «chi», ma costa 10×). Non sono alternative: sono **il caso comune e il caso raro
dello stesso protocollo**, e messi in cascata danno la risposta dell'argmin al costo del varco.

---

## 🔴 F58 — Stringere il bound onesto: due bit, limitando la norma della galleria — e bastano

F56 lascia una domanda: la sicurezza contro un client malicious sembra costare **2,4×**
(0,064 → 0,153 s a N=128) perché obbliga al set 2_2 invece del set piccolo 1_1. Il collo di
bottiglia è uno solo — il Δ deve coprire il bound |s−T| ≤ 2q·max‖g_i‖₁ + max‖g_i‖² + |T| = 3.646,
mentre i punteggi veri stanno dentro ±757. **Un fattore 4,8 di margine sprecato.** Se si potesse
recuperarlo, il Δ salirebbe da 2^51 a 2^53, la banda di rumore in unità di punteggio si
dividerebbe per 4, e il set veloce tornerebbe utilizzabile. Ho provato tre leve.

**Leva A — prova ZK di range: per il Δ non serve a niente.** L'attacco di F56 manda un probe con **tutti i coefficienti già legali**:
è un vettore tarato, non fuori dominio. Il bound onesto assume *già* che ogni coefficiente stia in
[−3, 3] — è esattamente da lì che esce il fattore 2q. Una prova che certifica ciò che il bound
assume già non stringe nulla. Vale la pena averlo scritto: era una risposta plausibile alla domanda
sbagliata.

**Leva B — prova ZK di norma: misurata, guadagno zero.** La versione sensata è provare che il probe
ha norma da embedding vero, ‖a‖₂ ≤ A, e usare Cauchy-Schwarz al posto della disuguaglianza ℓ1:
|2g·a| ≤ 2‖g‖₂‖a‖₂. Sulla scena reale (‖g‖₂ = 26,3, ‖a‖₂ = 25,8):

| ipotesi sul probe | bound | Δ |
|---|---|---|
| caso peggiore secco 2·dim·q² | 10.081 | 2^49 |
| coefficienti in [−3,3] (quello che usiamo) | 3.613 | **2^51** |
| + prova ZK di norma ‖a‖₂ ≤ 25,8 | 2.219 | **2^51** — *zero bit guadagnati* |
| range osservato sui probe veri (indifendibile) | 850 | 2^53 |

La prova di norma stringe il bound del 39% e **non cambia il Δ**, perché il logaritmo si arrotonda
allo stesso intero. Una macchina crittografica in più per zero bit.

**Leva C — limitare la norma della galleria: due bit, e sono quelli che servono.** Il termine che domina è 2q·‖g‖₁, e
‖g‖₁ è una proprietà della *galleria*, che il server conosce e può modificare all'iscrizione. Primo
fatto, che non sapevo: **i template a 3 bit sono già sparsi** — 331 coefficienti non nulli su 512.
Secondo: i coefficienti a ±1 sono la maggioranza in numero ma portano poco segnale. Azzerandoli
(cioè tenendo solo |g| ≥ 2, ~86 coefficienti su 512) su 10 semi e il protocollo completo:

| N | soglia | non nulli | bound | Δ | DIR@FPIR=1% |
|---|---|---|---|---|---|
| 128 | tutti | 331 | 3.652 | 2^51 | 99,4% |
| 128 | \|g\| ≥ 2 | 86 | **1.806** | **2^52** | 99,2% |
| 1024 | tutti | 331 | 3.630 | 2^51 | 98,9% |
| 1024 | \|g\| ≥ 2 | 85 | **1.812** | **2^52** | 98,6% |

Il bound si **dimezza** e il Δ guadagna un bit, al prezzo di ~0,2 punti di DIR.

**Ma la soglia sul modulo è lo strumento sbagliato: quello giusto è un tetto sulla norma.** Invece
di azzerare i coefficienti sotto un modulo fisso, si azzerano i più piccoli **finché ‖g‖₁ scende
sotto un tetto scelto** — è la stessa operazione, fatta all'iscrizione e in chiaro, ma controlla
direttamente la quantità che entra nel bound. Misurato col protocollo completo
(`benchmark/norma_limitata.py`, ResNet100 su VGGFace2, 3 bit, fusione 2+3, 10 semi):

| N | tetto su ‖g‖₁ | non nulli | bound | Δ | DIR@FPIR=1% | costo |
|---|---|---|---|---|---|---|
| 128 | nessuno | 331 | 3.652 | 2^51 | 99,4% | — |
| 128 | 200 | 104 | 1.793 | 2^52 | 99,2% | −0,2 |
| **128** | **110** | **50** | **1.008** | **2^53** | **99,0%** | **−0,4** |
| 1024 | nessuno | 331 | 3.630 | 2^51 | 98,9% | — |
| 1024 | 200 | 105 | 1.762 | 2^52 | 98,6% | −0,3 |
| **1024** | **110** | **50** | **991** | **2^53** | **98,0%** | **−0,9** |

**Due bit, al prezzo di 0,4 punti di DIR a N=128 e 0,9 a N=1024.** E due bit sono esattamente quelli
che servivano: con Δ = 2^53 la banda in unità di punteggio si divide per quattro, e i set piccoli
tornano utilizzabili **restando nel modello di minaccia malicious**, perché il Δ continua a uscire
da un bound indipendente dal probe. Misurato sul cifrato, N=128, galleria con ‖g‖₁ ≤ 110:

| set | totale | discrepanze su 16.384 | |s−T| degli errori |
|---|---|---|---|
| **2_0** | **0,081 s** | **1** | 2 |
| 1_0 | 0,081 s | 3 | 0, 14, 40 |
| 1_1 | 0,111 s | 2 | 0, 2 |
| 2_2 (il set "sicuro" di F56) | 0,192 s | 1 | 2 |

Il set 2_0 fa **0,081 s con un solo errore, a |s−T| = 2**, cioè dentro la banda, contro i **0,152 s**
del set 2_2 sulla galleria non limitata.

⚠️ **Sul fattore di velocità serve cautela**: i due numeri vengono da run a carico di macchina
diverso, e la dispersione documentata è del 3-5% — ma qui il divario apparente è 1,9×, e una
rimisura del set 2_0 a N=512 su macchina carica ha dato 24,6 ms per PBS contro i 9,9 ms della prima
rilevazione, cioè un fattore 2,5 di solo carico. **Il guadagno di velocità va rimisurato a macchina
scarica prima di essere citato.** Quello che invece NON dipende dal carico, ed è il risultato solido
di questo finding, è: il bound scende a 1.008 → Δ = 2^53 (due bit), la DIR costa 0,4-0,9 punti, e
sul cifrato gli errori restano dentro la banda.

**Il che riscrive il prezzo della sicurezza.** F56 conclude che difendersi da un client malicious
costa 2,4× perché obbliga al set grande. Non è così: costa **0,4-0,9 punti di DIR**, e in cambio si
tiene un set piccolo. Le due grandezze sono scambiabili, e l'installatore può scegliere dove stare.
Il tetto vero non è un bit — è che sotto ‖g‖₁ ≈ 90 la DIR comincia a cedere davvero (97,5% a
N=1024) senza guadagnare un altro bit.

**E il guadagno si compone: anche l'argmin diventa più accurato.** Il Δ più grande dimezza due volte
il rumore in unità di punteggio, e l'argmin a torneo di F52 — che soffre proprio di quello — ne
beneficia direttamente. Stesso binario, stessi 32 probe, unica differenza la galleria limitata
(log: `results/argmin_torneo_cap110.txt` contro `results/argmin_torneo_onesto.txt`):

| | galleria intera (Δ=2^51) | **galleria con ‖g‖₁ ≤ 110 (Δ=2^53)** |
|---|---|---|
| indice esatto | 136/160 (85%) | **146/160 (91%)** |
| indice esatto quando il divario > 20 | 117/136 (86%) | **99/99 (100%)** |
| minimo sotto soglia | 68/68 | 66/66 |
| rumore sul punteggio dopo log N CMUX | 3,5-11,8 unità | **1,1-1,6 unità** |

La riga che conta è la seconda: **con la galleria limitata il torneo non sbaglia mai un confronto
non ambiguo**. Gli errori residui sono tutti su quasi-pareggi, dove sbagliare non ha conseguenze
operative. La stessa leva che rende difendibile il set piccolo rende esatto l'argmin: è il rumore
in unità di punteggio a governare entrambi, e il Δ lo governa.

**Un bug latente trovato per strada.** `varco_leveled` calcolava il q del bound dalla **galleria**
invece che dal dominio dichiarato del **probe**. Qui coincidono (entrambi 3) e il risultato non
cambia, ma è sbagliato in principio: se la galleria fosse più stretta del dominio che il client può
usare, il bound risulterebbe troppo piccolo e il wrap tornerebbe possibile — cioè la stessa
vulnerabilità di F56 da un'altra porta. Corretto: ora prende il massimo fra galleria e probe, e
`--q-probe K` lo forza esplicitamente.

---

## 🔴 F59 — Tutta l'uscita del varco in una GLWE: 112× meno banda con un packing keyswitch

Un costo che avevo sempre riportato di sfuggita e mai attaccato: **quanto pesa la risposta**. Il
varco produce N bit cifrati, uno per iscritto, e ogni bit è un LWE sotto la chiave grande — 2049
u64, cioè 16,4 KB *l'uno*. A N=4096 sono 67 MB per una singola interrogazione. L'uscita compatta di
F43 (conteggio + indice locale in binario, per blocchi di B iscritti) li somma e scende a 7,3 MB con
B=64, ma è stretta fra due vincoli opposti: le somme accumulano il rumore in uscita dal PBS — è la
trappola descritta in F55, che obbliga a blocchi *piccoli* — mentre la dimensione vuole blocchi
*grandi*. Non c'è una scelta buona, solo un compromesso.

**Il vincolo era finto.** Un LWE si può spostare dentro un *coefficiente* di una GLWE con un
**packing keyswitch** (`par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext`): 2048 bit
entrano in **una sola** GLWE da 2·2048 u64 = 32 KB. Niente somme, quindi niente accumulo di rumore,
quindi nessun vincolo su LOG_DO e nessun blocco da tarare. Misurato sulla scena reale, set 2_2 con
Δ onesto, decomposizione del packing 2^23 × 1 livello:

| N | KS+PBS | packing | GLWE | **uscita** | uscita a blocchi 64 | guadagno | bit sbagliati |
|---|---|---|---|---|---|---|---|
| 128 | 0,156 s | 0,024 s | 1 | **0,03 MB** | 0,23 MB | 7× | 0 / 1.024 |
| 512 | 0,600 s | 0,084 s | 1 | **0,03 MB** | 0,92 MB | 28× | 0 / 4.096 |
| 1024 | 1,171 s | 0,171 s | 1 | **0,03 MB** | 1,84 MB | 56× | 0 / 8.192 |
| 2048 | 2,399 s | 0,353 s | 1 | **0,03 MB** | 3,67 MB | **112×** | 1 / 16.384 (|s−T| = 3) |
| 4096 | 4,966 s | 0,707 s | 2 | **0,07 MB** | 7,34 MB | **112×** | 0 / 32.768 |

Fino a N=2048 **l'uscita è costante: una GLWE, 32 KB**, qualunque sia la galleria. L'unico bit
sbagliato in 62.464 misurati sta a |s−T| = 3, cioè dentro la banda di ~10 unità che il varco ha
già per conto suo (F56: errori a |s−T| = 3, 4, 4): **il packing non aggiunge rumore percepibile**.

**Il prezzo, per intero.** Il packing costa **+14/15% di tempo** (0,024 s su 0,156 a N=128; 0,707 s
su 4,966 a N=4096) e una **chiave di packing da 67 MB**, che si consegna una volta insieme a quella
di valutazione. La decomposizione grossolana è la scelta giusta: con 2^15 × 3 livelli la chiave sale
a 201 MB e il packing è **2,8× più lento**, con zero bit guadagnati — perché il margine di decodifica
qui è 2^61, enorme, e non serve precisione.

**Due conseguenze oltre alla banda.** Primo: l'uscita compatta a blocchi **non serve più**, e con lei
sparisce il compromesso di F55 fra LOG_DO e dimensione del blocco — qui LOG_DO vale 62 perché non
c'è nessuna somma che possa traboccare. Secondo: il client riceve il **vettore completo** degli
accettati invece del solo conteggio+indice, il che non è una perdita di riservatezza (quei bit sono
informazione *sua*: è lui che ha la chiave) ed è esattamente ciò che serve alla cascata di F57 —
sa subito se il caso è ambiguo e quali iscritti sono coinvolti.

Codice: `experiments/14_pipeline_tfhe_rs/src/bin/uscita_impacchettata.rs`.

**Quando conviene davvero (e quando no).** La chiave di packing è un costo *una tantum* di 67 MB, il
risparmio è *per interrogazione*. A N=128 si risparmiano 0,2 MB a query, quindi il pareggio arriva
dopo ~335 query: per la demo, che ha 48 iscritti e si usa a mano, non vale la pena cambiarla. A
N=4096 si risparmiano 7,3 MB a query e il pareggio arriva alla **nona**. È una tecnica che va accesa
quando la galleria è grande, che è esattamente il caso in cui la banda diventava insostenibile.

---

## 🔵 F60 — Il PBS multi-bit non aiuta: 6-9% più lento a ogni scala

Ultima leva di pura velocità rimasta sul tavolo prima della GPU: il set di parametri **multi-bit**
(`V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2`), che raggruppa 3 bit di chiave per iterazione del
blind rotate e in teoria taglia il numero di iterazioni, in cambio di una chiave di bootstrap più
grande e di parallelismo *interno* al singolo PBS. Stesso message/carry del set sicuro, quindi
confrontabile direttamente. Sulla stessa scena e con lo stesso Δ onesto:

| N | classico (set 2_2) | multi-bit | |
|---|---|---|---|
| 128 | **0,153 s** | 0,173 s | +13% |
| 256 | **0,315 s** | 0,325 s | +3% |
| 512 | **0,605 s** | 0,669 s | +11% |
| 1024 | **1,258 s** | 1,329 s | +6% |
| 2048 | **2,463 s** | 2,674 s | +9% |

Sempre più lento, mai più veloce (per PBS: 20,6 ms contro 18,9).

**Obiezione ovvia, chiusa con la misura**: il multi-bit ha un parallelismo *interno* al singolo PBS,
e lasciarlo al valore di default può farlo competere con rayon invece che aiutarlo. Ho quindi
spazzato il numero di thread interni a N=128 (`--mb-threads`), sulla stessa scena e con lo stesso
Δ onesto:

| configurazione | totale | per PBS | discrepanze |
|---|---|---|---|
| multi-bit, 1 thread interno | 0,193 s | 23,7 ms | 0 / 16.384 |
| multi-bit, 2 | 0,175 s | 21,4 ms | 0 / 16.384 |
| multi-bit, 4 | 0,160 s | 19,6 ms | 2 / 16.384 (|s−T| = 4, **28**) |
| multi-bit, 8 | 0,165 s | 20,2 ms | 1 / 16.384 |
| **PBS classico** | **0,153 s** | **18,8 ms** | 0 / 16.384 |

Il minimo del multi-bit (4 thread interni, 0,160 s) resta **sopra** il classico, e per giunta con
una banda un po' peggiore — la discrepanza a |s−T| = 28 è fuori dalle ~10 unità che il set TUniform
ci dà, coerente col fatto che il set multi-bit disponibile è Gaussian. La leva non esiste in nessuna
taratura. La ragione è la stessa che rende il
nostro carico *facile*: i N PBS sono **già indipendenti** e saturano i 16 thread da soli. Il
parallelismo interno del multi-bit non ha core liberi da usare, e resta solo il suo costo. È un set
pensato per il caso opposto al nostro — pochi PBS da fare in fretta, non tantissimi da fare in
parallelo. Registrato come **negativo**, così non lo si riprova.

---

## 🔴 F61 — Il probe non è un volto: un vettore legale apre il varco in una query (e la difesa è la norma)

Una revisione critica indipendente ha rimesso in discussione il punto 2 di F40 — «il bit non parte
da zero: senza un punto già accettato l'oracolo è muto» — e aveva ragione. Peggio: il difetto non è
nell'attacco, è **nello script che lo misurava**. `attacco_oracolo.py::da_fuori` faceva due cose che
un attaccante non farebbe: perturbava sempre lo **stesso** punto rifiutato (la variabile `v` non
veniva mai aggiornata, quindi erano 20.000 campioni i.i.d. attorno a un punto fisso) e interrogava
**una sola identità a caso**, mentre l'uscita vera del varco dà l'esito su **tutti** gli N iscritti.
Con quei due vincoli l'attacco falliva 0/10, e da lì la conclusione sbagliata.

**Rifatto senza i due vincoli, e restando dentro il protocollo** (interi in [−q, q], esattamente ciò
che il client è autorizzato a mandare), sulla scena a 4 bit di F40:

| attacco | esito |
|---|---|
| bipolari casuali, leggendo l'uscita completa | **200/200 aperti, query mediana 1** |
| bipolari casuali, mirati su un iscritto | 10/10 aperti, query mediana 43 |
| come nello script originale (punto fisso, un iscritto) | 0/10 |

**E colpisce la configurazione attuale, non solo quella vecchia.** Sulla scena a 3 bit con il set
sicuro, provando 2.000 vettori bipolari ±3:

| N | il bipolare apre | con la norma vincolata a quella di un embedding vero |
|---|---|---|
| 128 | **15,2%** (≈ 7 tentativi) | **0,00%** |
| 1024 | **67,7%** (≈ 1,5 tentativi) | **0,00%** |
| 4096 | **98,2%** (**una query**) | **0,00%** |

**Perché funziona, in una riga.** Il punteggio s_i = ‖g_i‖² − 2 g_i·a è un **semispazio**: illimitato
nella direzione di g_i. Un vettore con tutti i coefficienti a ±q ha norma q·√dim = 67,9, cioè
**2,7× quella di un embedding vero quantizzato** (25,2); il prodotto g_i·a ha allora deviazione
q·‖g_i‖₂ ≈ 79, e serve g_i·a ≥ (‖g_i‖²−T)/2 per aprire. È un evento a ~3σ per *singolo* iscritto,
ma con N iscritti basta che **uno** ci arrivi — e la probabilità che nessuno ci arrivi crolla con N.
**L'attacco migliora con la dimensione della galleria**, che è esattamente il contrario di quello
che si vorrebbe.

**Non è l'overflow di F56.** Lì il punteggio era calcolato male (wrap mod 2^64). Qui il cifrato fa
tutto correttamente: è il **punteggio stesso** a scendere sotto soglia. Nessun Δ onesto lo ferma,
perché non c'è niente da fermare — il circuito sta rispondendo alla domanda giusta. Il problema è
che la domanda presuppone che `a` sia un volto, e niente lo impone.

**Le difese, misurate.**

1. **Vincolare la norma del probe: risolutiva.** Ripetendo lo stesso attacco con i vettori
   rinormalizzati alla norma di un embedding vero: **0 successi su 2.000 tentativi, a ogni N**.
   ⚠️ Va detto con precisione cosa questo dimostra e cosa no: 0/2.000 è un **limite superiore dello
   0,18%** al tasso di successo, non uno zero; e l'attacco misurato è a **ricerca casuale**, mentre
   un attaccante adattivo che sfrutta l'esito delle query precedenti non è stato provato. Quindi
   l'enunciato sostenuto dai dati è «la ricerca casuale con norma vincolata non apre in 2.000
   tentativi», non «la norma risolve il problema». È la difesa più promettente che ho trovato, e
   resta da verificare contro un attaccante adattivo. Attenzione a non confonderla con la prova ZK di *range* di F58,
   che per il bound su Δ non serve a niente: qui serve una prova sulla **norma**, che è un'altra
   cosa e difende da un altro attacco. Non è però disponibile a scaffale: il
   modulo `zk` di tfhe-rs prova il range del messaggio, cioè un vincolo per coefficiente, mentre
   ‖a‖₂ ≤ A è una forma quadratica. Resta lavoro futuro, ma ora con una ragione precisa.
2. **Un pavimento sul punteggio (accetta sse T_basso ≤ s ≤ T): non funziona.** Sembrava naturale —
   il bipolare spinge s molto sotto — e costerebbe solo un secondo PBS di segno, gratis come
   struttura. Ma i tentativi che *riescono* atterrano fra −373 e 0 rispetto a T, cioè **più vicini
   alla soglia dei genuini** (mediana −340): la ricerca casuale trova le soglie che si attraversano
   di poco, non quelle che si sfondano. Il pavimento taglia il lato sbagliato. Misurato e scartato.
3. **Stringere la soglia: parziale, e il prezzo cresce con N.** Con un offset di −200 unità:

   | N | DIR genuini | attacco bipolare |
   |---|---|---|
   | 128 | 100% (invariata) | 14,7% → **0,1%** |
   | 1024 | 100% → 85,7% | 68,3% → 0,5% |
   | 4096 | 96,9% → 82,8% | 98,0% → 1,8% |

   A N=128 è **gratis** e chiude l'attacco; a N=4096 costa **14 punti** di DIR. Esattamente il
   contrario di come dovrebbe scalare una difesa.
4. **Rate limiting**: da F40 era una nota, va promosso a **requisito**; ma con una query su quattro
   che apre a N=1024 non basta da solo.

**La lettura onesta per la tesi, ed è quella che regge.** Il modello di minaccia va detto con
precisione, e allora tutto torna: nel **varco fisico** — che è lo scenario del lavoro — il client
non è una parte arbitraria, è **la telecamera al cancello**, hardware che l'installatore controlla e
che produce embedding veri per costruzione. Lì l'attacco è fuori modello, e il sistema è sano.
Diventa reale quando lo stesso servizio è esposto come **API remota** a client qualunque: in quel
caso servono, insieme, una prova di buona formazione del probe e il rate limiting. Non è una
scappatoia: è la differenza fra i due deployment, e va scritta nel capitolo del modello di minaccia
invece di essere lasciata implicita.

**Da citare, perché ci arriva addosso.** Rahimi, Osadchy, Dunkelman, IJCB 2025 (arXiv `2601.17620`):
l'attaccante che osserva **solo accettato/rifiutato** ricostruisce il template con perdita
trascurabile e, per inversione generativa, ottiene immagini che passano **oltre il 98%** delle
volte; gli autori dichiarano esplicitamente che vale «for any protection mechanism that maintains
the accuracy of the recognition», FHE inclusa. Sostituisce Adler 2003/04 e Galbally 2010 come
citazione di riferimento di F40 e **conferma dall'esterno** ciò che qui è misurato.

---

## 🔴 F62 — Dove siamo nella letteratura, e cosa significa davvero «parametri a 128 bit»

Due cose che valgono per tutto il documento: l'enunciato preciso dell'affermazione di sicurezza, e
il posizionamento del lavoro rispetto allo stato dell'arte, normalizzato in modo che regga a un
revisore. Entrambi vengono da revisioni indipendenti condotte sul repo e sulle fonti primarie.

### L'affermazione di sicurezza, detta con precisione (una volta sola, vale per tutto il documento)

Dove nel documento si legge «parametri standard a 128 bit», va inteso così:

1. **La sicurezza IND-CPA c'è, ed è quella dei set standard di tfhe-rs.** Il varco usa
   `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` (e gli altri set `V0_11_*` nei confronti),
   presi dalle chiavi dell'API alta via `into_raw_parts`, con chiave e distribuzione di rumore
   invariate. Le operazioni che aggiungiamo — somme e moltiplicazioni per costanti in chiaro — non
   cambiano né la dimensione della chiave né la distribuzione: la riduzione di sicurezza è quella
   della libreria, senza asterischi.
2. **La p-fail 2⁻⁶⁴ NON si trasferisce.** È calcolata per il carico *shortint* (un input con
   `max_noise_level` fra 1 e 5); da noi l'ingresso al PBS ha attraversato **512 termini** leveled,
   quindi quella cifra non dice nulla sul nostro circuito. Il sostituto legittimo è la **misura**:
   F50 dà il modello di rumore in forma chiusa e F56 conta **3 errori su 1.032.192 confronti**,
   tutti a |s−T| ≤ 4, cioè dentro la banda prevista. Va citata quella, non la p-fail della libreria.
3. **Due punti dove «128 bit» è proprio falso**, e vanno detti: `experiments/13/src/bin/basso_livello.rs`
   usa `LweDimension(1024)` con `StandardDev(4·10⁻¹⁴) ≈ 2⁻⁴⁴`, che a quella dimensione vale **~70
   bit** — è un microbenchmark di costo, non un pezzo del sistema, e come tale va etichettato; e il
   set `LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS` di F52 è dichiarato dalla libreria stessa
   «security between **123 and 128** bits» e non espone `log2_p_fail`.

Il sistema che proponiamo — varco leveled, set 2_2, Δ onesto — sta interamente dentro il punto 1.
- ~~**F32/F42 «a parità di macchina»**~~ — **chiuso da F64**, e non togliendo la frase ma
  rendendola vera: Concrete ora gira sul Mac, e il confronto rifatto sullo stesso hardware dà
  **105× a N=4 e 94× a N=8**.
- ~~**F49**~~ — **chiuso**: i quattro numeri sono ora prodotti da `benchmark/soglia_dominio.py` e
  i tempi client sono attribuiti correttamente. Resta valido il rilievo che «4/4 e 3/3» è una prova
  di funzionamento, non una misura (Wilson 95% su 4/4: [51%, 100%]).

### Il posizionamento, normalizzato

Il solo numero che rende confrontabili macchine e thread diversi è il **costo per template per
core** (tempo × core / N). Con la configurazione **sicura** (set 2_2, Δ onesto, 1,258 s a N=1024):

| lavoro | schema | modello di minaccia | costo per template per core |
|---|---|---|---|
| Zuber & Sirdey, PoPETs 2021 (`10.2478/popets-2021-0020`) | TFHE, δ-matrix O(N²) | probe cifrato, galleria in chiaro | ~9.300 ms·core |
| Cong et al., SAC 2024 (`2023/852`) | tfhe-rs, top-k O(N log²k) | idem | 672 ms·core |
| Azogagh et al., PoPETs 2025 (`2024/1894`) | tfhe-rs, blind counting sort | idem | 139 ms·core |
| **questo lavoro** | tfhe-rs, soglia con PBS di segno | idem (+ galleria cifrata, F51) | **19,7 ms·core** |
| HyDia, PoPETs 2025 (`10.56553/popets-2025-0146`) | CKKS, soglia polinomiale | entrambe cifrate | 1,6-9,7 ms·core |

⚠️ **Attenzione: quella tabella confronta operazioni diverse.** Zuber-Sirdey fa un *argmin*, Cong
un *top-k*, Azogagh un *sort*: tutti risolvono un problema **strettamente più difficile** di N test
di soglia indipendenti. La riga nostra confrontabile con loro non è la soglia ma **l'argmin a
torneo di F52** (~159 ms·core), e su quella «7× meglio di Azogagh» diventa **1,15× peggio**. Il
claim difendibile va detto così: **facciamo un lavoro più piccolo, e per quel lavoro costiamo meno**
— non «siamo 7× più veloci a parità di compito». La tabella andrebbe riportata con due colonne in
più: operazione risolta, e CPU/anno della macchina.

**La rivendicazione più forte non è la soglia, è la galleria cifrata.** Zuber-Sirdey scrivono in
§1.2 che cifrare query *e* database insieme è «within reach but not yet attainable due to a high
noise propagation issue». Il prodotto esterno GGSW⊡GLWE ha crescita di rumore **additiva**, e F51 lo
misura a costo quasi nullo: è la risposta a un problema che il prior art più vicino dichiara aperto.

**Dove siamo alla pari o peggio, senza girarci intorno.**
- Contro HyDia siamo **2-12× peggio** per template per core, ma a parità di modello di minaccia e
  con confronto esatto e profondità 1 invece di κ=10 livelli di approssimazione polinomiale.
- **Sopra N ≈ 10⁴ perdiamo e basta**: IDFace fa 1M in 0,126 s (arXiv `2507.12050`), perché uno slot
  CKKS impacchettato costa ordini di grandezza meno di un PBS. Il regime operativo da dichiarare è
  **N ∈ [10², 10³]**, e la questione si chiude lì.
- **L'argmin a torneo non è un progresso sullo stato dell'arte**: Chakraborty & Zuber (`2022/622`)
  fanno l'argmin di 128 valori in 17 s **single-thread su un i7-6600U del 2016**; i nostri 1,3 s ×
  16 thread sono 20,8 s·core su M4 Max. Normalizzando siamo **peggio**. La difesa vera è di
  *applicabilità*: loro sono esatti su interi a 4 bit, noi operiamo sul punteggio leveled a
  larghezza piena senza rappresentazione radix e senza ponte.

**Cosa NON è nostro, e va citato invece che rivendicato.**
- Il **PBS di segno con accumulatore costante come test di soglia parallelo è il neurone di
  FHE-DiNN** (Bourse, Minelli, Minihold, Paillier, CRYPTO 2018, `2017/1114`): pesi in chiaro, somma
  con sole addizioni omomorfe, bias assorbito come costante — cioè la nostra soglia — segno dal test
  vector, profondità 1, neuroni indipendenti. Uno strato DiNN con pesi = template e bias = −T **è il
  nostro varco**. Rivendichiamo l'istanziazione biometrica, che nessuno ha fatto; non la primitiva.
- **L'uscita compatta senza punteggi, motivata dagli attacchi di ricostruzione, è HyDia**, con la
  stessa motivazione scritta quasi con le stesse parole. È la nostra F40/F43, pubblicata prima.
- **«Per il varco basta la soglia, l'argmin non serve»** è l'argomento di Funshade
  (`10.56553/popets-2023-0096`), Monchi (`2024/654`) e del deployment World ID (`2024/705`).
- Il setting probe-cifrato/galleria-in-chiaro risale a **Erkin et al., PETS 2009**.
- La baseline negativa da citare per giustificare «leveled + 1 PBS» è **Pradel & Mitchell**
  (arXiv `2111.12372`): 34.308 s per un match **1:1** con gate bootstrapping bit-a-bit.

**Confronti da NON fare.** L'accuratezza non va confrontata con nessuno: il nostro 97-99%
DIR@FPIR=1% è open-set, il 99,63% rank-1 di Blind-Match è closed-set, il TAR@FAR di CryptoMask è
verifica 1:1. Tutte quelle cifre misurano il **modello di riconoscimento**, non la crittografia.
E vanno esclusi anche CryptoFace (i 22 minuti sono la CNN cifrata, il matching è 0,3 s), IDFace
(query **in chiaro**, il Key Server decifra ogni punteggio), Funshade/Monchi (2PC interattivo con
non-collusione — su cui però vedi sotto, perché escluderli senza il loro numero non basta), HERS e Blind-Match (l'argmax lo fa il client dopo aver visto tutti i punteggi),
CryptoMask (**non pubblica tempi assoluti**).

**Il confronto scomodo, che va fatto e non evitato: Funshade.** *Funshade* (Ibarrondo, Chabanne,
Önen, PoPETs 2023(4), `10.56553/popets-2023-0096`) calcola **esattamente la nostra funzione** —
prodotto scalare più confronto con una soglia fissa, motivato proprio come controllo accessi
biometrico — e lo fa in **9,3 µs per decisione di soglia** contro i nostri **18,9 ms**: 5.000
iscritti in **47,9 ms su un core**. È ~2000× più veloce di noi, e non è una svista: non è FHE, è
**function secret sharing** fra due server.

L'esclusione è corretta, ma va argomentata sul modello di minaccia e non sulla velocità: Funshade
richiede **due server che non colludano**, un round di comunicazione online e materiale di
preprocessing per ogni query. Il nostro sistema ha **un solo server**, è **non interattivo**, e non
assume nessuna non-collusione. Sono garanzie diverse, e il prezzo di quelle garanzie è quel fattore.
Scritto così il confronto è difendibile; scritto senza il loro numero accanto, è una domanda evitata.
Vale anche per Monchi (`2024/654`, 1000 passeggeri in meno di un secondo), che è il seguito applicato
di Funshade.

---

## 🔴 F63 — Verifica di novità sulle fonti primarie: cosa possiamo davvero rivendicare

F62 dice dove siamo nella letteratura; questo dice cosa possiamo **rivendicare come nuovo**, con le
citazioni verificate sui PDF originali e non su riassunti.

### (a) La galleria cifrata via GGSW⊡GLWE — **nuova, se formulata dentro CGGI**

Due frasi, verificate verbatim sui PDF, reggono la rivendicazione. La prima è del prior art più
vicino, **Zuber & Sirdey, PoPETs 2021(2) §1.2 p. 114**:

> «Achieving encryption for **both the query and the database** is within reach but **not yet
> attainable due to a high noise propagation issue**.»

La seconda è più forte, perché è del loro **successore diretto**, sulla **stessa libreria**, nel
**2025** — Azogagh, Killijian, Larose-Gervais, PoPETs 2025(3), §2.2.1:

> «**Absorption**: (★, ⟦★⟧GLWE) → ⟦★⟧GLWE. This operation multiplies a **plaintext value m** with a
> GLWE ciphertext […] Note that **this is the only multiplication that can be performed in TFHE**
> (i.e. the multiplication of two GLWE ciphertexts is not supported).»

Cioè: nel 2025, nella stessa linea di ricerca, si scrive come **fatto dello schema** ciò che F51
misura. Tecnicamente è una semplificazione — il prodotto esterno *è* una moltiplicazione
cifrato×cifrato, solo asimmetrica — ed è esattamente il varco che abbiamo attraversato.

**Cosa è prior art e va citato, non rivendicato.** L'encoding polinomiale negaciclico per ⟨f,m⟩ con
sample extract è di Zuber, Carpov, Sirdey (ICICS 2020, `10.1007/978-3-030-61078-4_23`); lo split
‖f‖² − 2⟨f,m⟩ + ‖m‖² con un lato precalcolato è della stessa linea; il PBS di segno per la soglia
loro lo chiamano «sign bootstrapping» (§3.4). **«Probe e galleria entrambi cifrati» non è nuovo in
sé**: è la norma in CKKS/BFV, dove ct×ct è nativa (HERS, Blind-Match, IDFace, De Micheli). E il
prodotto esterno contro un database cifrato **esiste** — Onion Ring ORAM (`2019/736`), Panacea — ma
lì la GGSW cifra sempre un **bit di selezione**, mai i dati. Infine la GGSW a messaggio polinomiale
**è già definita** (CGGI Def. 3.8 ammette µ ∈ R; Joye, `2021/1402`, definisce TGGSW_s(m) per m
polinomio) — e subito dopo si legge «the main application of the external product in TFHE is the
"controlled" multiplexer». La primitiva c'è: **nessuno ci aveva messo dentro dei dati densi.**

Ricerche full-text a supporto: `"GGSW" "polynomial message"` → **0**; `"GGSW" "Euclidean distance"`
→ 0; `"external product" "biometric"` → 0; `"circuit bootstrapping" "biometric"` → 0; contro
`"external product" "TFHE"` → 48 (tutte CMux/bootstrapping), che è il controllo che l'indice
funzioni.

**Il rischio residuo era uno solo, ed è chiuso.** Wang, Ha, Shen, Lu, Chen, Wang, Lee, *Refined TFHE
Leveled Homomorphic Evaluation and Its Application*, **CCS 2025** (`2024/1318`) era il posto più
plausibile per una tecnica sovrapposta sul CGGI leveled, e non era stato leggibile durante la
ricerca (eprint rispondeva 429). L'ho letto: è un lavoro sul **circuit bootstrapping più veloce**
(pre-processing + split FFT, fino a 12,1× su WWL+, chiave 33× più piccola). Nel testo:
«polynomial message» **0** occorrenze, «dot product» 0, «encrypted database» 0. **Nessuna
sovrapposizione** — anzi, è un regalo per il punto (b).

**Tre cautele nella formulazione**, che vanno rispettate o la rivendicazione si sgonfia: (1)
delimitare **allo schema** — «in CGGI», mai «nessuno cifra entrambi i lati»; (2) dire che la GGSW
polinomiale è nella **Definizione 3.8 di CGGI**, cioè abbiamo implementato una primitiva *definita e
non esposta*, non inventato un costrutto; (3) mettere il **rumore** al centro: la crescita del
prodotto esterno scala con ‖µ‖ del messaggio GGSW, e un messaggio denso a 512 coefficienti è
precisamente il caso che si dava per perso — quindi la quantizzazione a 3 bit che limita ‖µ‖ va
presentata come **nucleo tecnico** con il bound esplicito, non come un dettaglio dei tempi.

### (b) L'argmin a torneo — **ripresa di una via scartata, non algoritmo nuovo**

Il torneo è di **Chakraborty & Zuber, WAHC 2022** (`10.1145/3560827.3563375`, `2022/622`), §3.1
«Tournament Method» — e il loro nodo è **diverso dal nostro**: un bootstrap funzionale *privato* con
vettore di test **cifrato**, che impacchetta (x_i, x_j, i/b, j/b) in quattro quarti del polinomio e
con una sola blind rotation produce minimo **e** indice. Niente circuit bootstrapping, niente GGSW,
niente CMUX.

**Ma nello stesso lavoro, §1.2, scrivono** (verbatim):

> «We omit the solution using **levelled CMUX gates** from [6]: although they allow for a **very fast
> comparison of 2 integers (much faster than any other solution presented here)** their performance
> decreases dramatically […] **This is due to the necessary use of the circuit bootstrapping
> operation.**»

Non possiamo quindi rivendicare di esserci arrivati per primi. Ma **la loro obiezione ha due gambe e
si sono rotte entrambe dopo il 2022**:

1. **Il costo del CB**: 137 ms (CGGI 2020) → 88,6 ms NTT / 44,4 ms AVX-512 (Eurocrypt 2024,
   `2024/323`) → **13,3-19,4 ms** (CCS 2025, `2024/1318`, misurato proprio su tfhe-rs). Fino a 65×.
2. **La scalabilità**: il criterio lo danno loro — «whether the computation is fully homomorphic
   (**the parameters do not depend on the number of inputs**) or levelled is important». Ciò che
   scartano è la soluzione **leveled e bit-a-bit** di CGGI §5 (automa det-WFA, 5d CMUX su d bit, il
   rumore si accumula). **Il nostro non è quella**: un PBS di segno su un LWE largo, **un solo**
   circuit bootstrap per nodo, e il PBS di ogni livello **rinfresca**. I parametri non dipendono da
   N: per la loro stessa definizione, è fully homomorphic. **La loro obiezione, letteralmente, non
   ci tocca.**

La formulazione onesta è quindi **«ripresa di una via scartata + prima implementazione + prima
misura»**, che è molto più difficile da attaccare di «algoritmo nuovo», e trasforma la frase di
Chakraborty-Zuber da minaccia in motivazione.

**RevoLUT e il Blind Counting Sort sono ortogonali, non concorrenti** (e sono **due lavori diversi**,
`2024/1935` con 5 autori, non pubblicato, e `2024/1894` con 3 autori → PoPETs 2025). La loro
primitiva è blind rotation su LUT impacchettata: niente confronti — «the first known sorting
algorithm for encrypted data that does not rely on comparisons» — e con un limite dichiarato in
§4.3: «**p has to be lower than 2⁸**», «**we cannot natively process arrays larger than 256**», e gli
errori «may accumulate throughout the tournament and could result in an **incorrect top-k result**».
Su punteggi a 13-14 bit e gallerie oltre 256 **non è applicabile**: regimi disgiunti.

### (c) Due cose concrete che ne escono

**C'è probabilmente un 2-3× ancora sul tavolo nel torneo.** `tfhe-rs 0.11.3` espone solo il circuit
bootstrapping **classico** CGGI (`circuit_bootstrap_boolean` in `fft_impl::fft64::crypto::wop_pbs`),
cioè ℓ_cb PBS **più** (k+1)·ℓ_cb private functional packing keyswitch per bit — non la versione
raffinata di CCS 2025. Il conto teorico del nostro torneo a N=128 su 16 thread è
Σ_livelli ⌈nodi/16⌉ = 4+2+1+1+1+1+1 = **11 round**: con un CB da ~19 ms verrebbe **~0,35 s**, con il
CB classico da 40-60 ms per nodo **0,44-0,66 s**. Ne misuriamo **1,27**. Vale la pena profilare: il
sospettato numero uno è la **coda del torneo**, dove gli ultimi 4 livelli usano 1-8 core su 16.

**Provato subito, e il 2-3× non è lì.** La prima ipotesi era la decomposizione del circuit
bootstrap (il binario la espone con `--cbs BASE LIVELLI`, default 2^5 × 3 = 4 PBS per confronto).
Scendere a 2 livelli toglie un PBS per nodo e si vede:

| gadget CB | PBS/confronto | torneo a N=128 | indice esatto (8 probe, N=8/16/32) |
|---|---|---|---|
| **2^5 × 3** (default) | 4 | 1,249 s | **8/8 · 8/8 · 8/8** |
| 2^6 × 3 | 4 | 1,25 s | 8/8 · 7/8 · 6/8 |
| 2^4 × 4 | 5 | 1,6 s (stimato da N≤32) | 7/8 · 7/8 · 7/8 |
| 2^7 × 2 | 3 | **0,882 s (−29%)** | 6/8 · 7/8 · 7/8 |
| 2^9 × 2 | 3 | 0,88 s | 6/8 · **4/8** · 5/8 |

A 2 livelli il torneo è **29% più veloce e sbaglia di più**, e con base grossa l'indice decifrato
finisce anche **fuori range** (il binario ora lo conta come errore invece di andare in panic:
prima esplodeva, ed è un difetto di robustezza che era rimasto nascosto). **Il default 2^5 × 3 è
già la scelta giusta**: non c'è margine gratis nella decomposizione. Quello che resta è la coda del
torneo — un problema di *occupazione dei core*, non di parametri — e si aggredisce con il batching
fra query, non ritoccando il CB.

**E il numero di testa, con l'avvertenza accanto.** 1,27 s a N=128 sarebbe l'argmin TFHE esatto più
veloce pubblicato a quella taglia, e con **13-14 bit** di precisione contro i **2-4 bit** di
Chakraborty-Zuber — che è più interessante del tempo. Ma loro girano **single-thread su un ultrabook
del 2015**: senza le colonne CPU, thread, bit ed esattezza il confronto non regge, e con quelle
regge. Resta comunque il design: nella configurazione sicura il varco fa 0,153 s contro 1,27 s,
**~8×**, e l'argmin esatto va
offerto come l'opzione che toglie il conteggio dall'uscita, col prezzo scritto accanto — come in
F45, solo che ora il prezzo è 14× invece di 150×.

---

## 🔴 F64 — Concrete funziona sul Mac: i numeri non riproducibili, rifatti (e il 100× finalmente dimostrato)

F62 chiudeva con una lista di cifre che nessuno script sapeva più produrre. Elencarle non è
risolverle, quindi le ho affrontate una per una — e la prima cosa che ho trovato è che il muro non
era dove credevamo.

**Il muro era un percorso sbagliato, non una libreria.** Da F25 in poi il progetto dà per assodato
che *Concrete non gira su questa macchina*: qualunque compilazione FHE muore con
`ld: library 'System' not found`, e per questo tutti i benchmark Concrete sono stati fatti
sull'home server Linux — che è poi il motivo per cui i confronti Concrete/tfhe-rs **non erano a
parità di macchina** (l'accusa di F62). Guardando l'errore per esteso, Concrete invoca `ld` con
`-L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib`, che su questo Mac **non esiste**:
l'SDK sta dentro `Xcode.app`. Un wrapper di `ld` che sostituisce quel percorso con
`xcrun --show-sdk-path` risolve tutto — niente sudo, niente modifiche a `/Library`, reversibile
togliendo una directory dal PATH (`tools/ldfix`, con le istruzioni in `tools/README.md`).

Non è un dettaglio di comodità: **rende confrontabili sulla stessa macchina due anni di misure che
erano su macchine diverse.**

### Il ~100× di F32, ora dimostrato

Stesso circuito (DIM=64, valori in [−2,2], argmin sequenziale), stessa macchina (M4 Max), tutti
gli indici verificati contro il chiaro:

| N | Concrete (`bench_struttura.py`) | tfhe-rs (`argmin_tfhe_rs`) | rapporto |
|---|---|---|---|
| 4 | 47,35 s | **0,45 s** | **105×** |
| 8 | 98,29 s | **1,05 s** | **94×** |

Il ~100× che F32 rivendicava **era giusto**, semplicemente non era dimostrato: i 78 s e 180 s
venivano dal server Linux. Ora il confronto è pulito, e la frase «a parità di macchina» si può
scrivere davvero (F62 diceva di toglierla: si può invece tenerla, dopo averla resa vera).

### Ma il torneo di F27 non regge senza dataflow

Nella stessa esecuzione ho misurato anche la variante a torneo:

| N | sequenziale | torneo |
|---|---|---|
| 4 | **47,35 s** | 63,31 s |
| 8 | **98,29 s** | 102,44 s |

**Il torneo è più lento**, non 2,2× più veloce come dice F27. La spiegazione è nella colonna che su
macOS non esiste: `Dataflow parallelism is not available in macOS`. Il vantaggio del torneo è la
**profondità**, e la profondità si incassa solo se c'è parallelismo che la sfrutti; senza, restano
solo i suoi confronti in più. Quindi F27 va letto così: **il 2,2× era del dataflow, non della
struttura**. (Il che, di rimbalzo, rafforza F52: il nostro torneo in tfhe-rs guadagna perché rayon
esegue davvero i livelli in parallelo.)

### Il breakdown di F33, rifatto

`benchmark/breakdown_query.py` **esiste** — la revisione diceva che 4 righe su 6 non avevano un
file, e su questo si sbagliava (come si sbagliava su `experiments/08_cnn/costo_modelli.py`, anch'esso
presente). Rieseguito qui:

| tappa | F33 (home server) | **rifatto (M4 Max)** |
|---|---|---|
| embedding ResNet100 | 167 ms (135 ms/img batch) | **84 ms (26 ms/img batch)** |
| quantizza e cifra | 16 ms | **15 ms** |
| prodotto scalare, N=8 | 0,07 s (0 PBS) | **0,07 s (0 PBS)** |
| prodotto scalare, N=64 | 0,06 s | **0,04 s** |
| decifra | 1 ms | **1 ms** |
| argmin N=8 | 455 s (108 PBS) | **207 s (57 PBS)** |

Quattro righe su sei combaciano. L'embedding è 2× più veloce (macchina diversa) e **l'argmin è
diverso in modo sostanziale**: 207 s contro 455 s, ma soprattutto **57 PBS contro 108** — un
conteggio di PBS diverso significa che il *circuito* è diverso, non solo la macchina, quindi c'è di
mezzo anche una versione diversa di Concrete. La conclusione qualitativa di F33 non cambia e anzi si
rafforza: tutto tranne la selezione sta sotto i 0,2 s, e il prodotto scalare è gratis (0 PBS).

### Lo sweep per dimensione, ricostruito da zero

Questo era il buco vero: `compressione_tradeoff.csv` riportava 457 / 542 / 586 s a 512 / 128 / 64
dimensioni citando tre script (`argmin_verifica.py`, `dim_sweep.py`, `argmin_dim.py`) che **non
esistono né nel repo né nella storia git** — i numeri c'erano, il codice mai. L'ho riscritto
(`benchmark/argmin_dimensione.py`, PCA + stesso circuito CHUNKED, 4 bit, N=4):

| dim | compila | **argmin** | PBS | bit del punteggio | esito |
|---|---|---|---|---|---|
| 512 | 29,5 s | **158,7 s** | 44 | 14 | OK |
| 128 | 55,4 s | **237,9 s** | 81 | 12 | OK |
| 64 | 18,1 s | 74,8 s | 22 | 12 | **ERRATO** |

La conclusione di F23/F31 — «comprimere non è una leva FHE» — **regge, e più forte dei numeri
perduti**: scendere da 512 a 128 dimensioni non fa risparmiare, fa costare **1,5× di più**
(158,7 → 237,9 s), perché il circuito che ne esce ha quasi il doppio dei PBS. E a 64 dimensioni il
risultato cifrato **non coincide col chiaro**: più economico e sbagliato, che non è un punto
operativo. Il vecchio 457/542/586 raccontava una crescita lenta e monotona; il dato vero è
**non monotono**, e la lezione resta la stessa — la leva è la **precisione per valore**, non la
dimensione.

### Stato della lista di F62

Chiusi: esperimento 13 (rieseguito, `results/argmin_tfhe_rs.txt`, indici verificati a ogni N fino a
64), F33, F23/F31, F32/F42 («a parità di macchina» ora è vero), F19 (lo script c'è). Restano
**davvero** senza codice solo le righe di `costo_reale.csv` che citano `argmin_512.py` e
`soglia_scala` (59,5 s a N=4 e i 15,1 / 29,7 s della soglia a N=16/32): quelle vanno lette come
*registrazioni d'archivio*, non come misure riproducibili, e nella tesi non vanno usate — tanto più
che il percorso è passato a tfhe-rs, dove gli stessi numeri sono misurati e riproducibili.

---

## 🔵 F65 — Il bootstrapping ammortizzato non ci salva, e il motivo è strutturale (non di velocità)

Restava una leva algoritmica non esplorata: gli N PBS del varco sono **indipendenti e identici**
(stesso accumulatore costante, stessa funzione segno), che è esattamente la forma che la letteratura
sul **bootstrapping ammortizzato** promette di far pagare meno di N volte. Se funzionasse sarebbe la
cosa più grossa rimasta, perché attaccherebbe l'unico termine che conta: N × PBS.

**Il fatto strutturale che chiude la direzione, e va capito prima dei numeri.** In TFHE la LUT è
**gratis**: l'accumulatore viene inizializzato col polinomio di test e *tutto* il costo è la blind
rotation, cioè n prodotti esterni che dipendono **solo dalla maschera dell'input**, non dalla
funzione. Quindi il fatto che i nostri N bootstrap usino tutti lo stesso accumulatore costante non
fa risparmiare **niente** nell'algoritmo standard — l'intuizione «stessa LUT per tutti, quindi
qualcosa si condivide» è sbagliata alla radice. Ne segue che qualsiasi tecnica che scenda sotto
N × PBS deve fare una di due cose: **(a)** impacchettare gli N input in un unico cifrato
RLWE/BFV/CKKS e valutare la decrittazione LWE in SIMD, oppure **(b)** costringere gli N input a
**condividere la maschera**.

**Il duale di multi-value non esiste.** Le tecniche «molte LUT» — Carpov, Izabachène, Mollimard
(CT-RSA 2019, `2018/622`) e PBSmanyLUT — sono «molte funzioni, **un** input», che è il problema
opposto al nostro. *(Correzione di attribuzione utile per la tesi: **PBSmanyLUT è di Chillotti,
Ligier, Orfila, Tap, Asiacrypt 2021** (`2021/729`), non di Chillotti-Joye-Paillier CSCML 2021.)*

**La via (b) esiste, ed è la sola davvero «una blind rotation, molti messaggi»**: *Sharing the Mask:
TFHE Bootstrapping on Packed Messages*, Bergerat et al., TCHES 2025(4) (`2025/2112`), con cifrati a
maschera comune sotto Matrix-LWE. Due motivi per cui non ci serve, e il secondo è definitivo:

1. **I numeri non tengono**, misurati dagli autori *su tfhe-rs*: 2× a 2 bit di precisione, ma
   **+16% a 4 bit con w=2**, più lenta della sequenziale a w=8, e a 8 bit **30% peggio** con w=6-8.
2. **Il vincolo è incompatibile con il nostro circuito.** La tecnica richiede che i w messaggi
   **condividano letteralmente la maschera a**. I nostri N punteggi sono
   x_i = (‖g_i‖² − T)·Δ − 2Σ_j g_ij·enc(a_j): **combinazioni lineari diverse** dello stesso probe,
   quindi con maschere **diverse per costruzione**. Non è un problema di ingegneria, è che il
   requisito e la nostra struttura si escludono. (Questo l'ho verificato da me sul circuito, non
   sulla letteratura: basta guardare come si formano gli x_i.)

**E la via (a), i numeri.** Tutte le costruzioni ammortizzate pubblicate, con il loro costo
ammortizzato migliore, il batch che serve per ottenerlo e la latenza minima (**tutte
single-thread**):

| tecnica | ammortizzato | batch | latenza |
|---|---|---|---|
| Micciancio-Sorrell, ICALP 2018 (`2018/532`) | mai implementato | — | — |
| Guimarães, Pereira, van Leeuwen, Asiacrypt 2023 (`2023/014`) | 851 ms | 1024 | 871 s, 76 GiB |
| Liu & Wang, Asiacrypt 2023 (`2023/910`) | 4,7-6,7 ms | **32.768** | 155-220 s |
| De Micheli et al., PKC 2024 (`2023/112`) | mai implementato | — | — |
| Guimarães & Pereira, CCS 2025 (`2025/686`) | 4,01-4,28 ms | 2048 | 8,2 s |
| Paiva et al., TCHES 2025 (`2025/696`) | 584,7 ms | 1024 | 599 s, 50 GB |
| BatchBoot, USENIX Sec 2026 | **3,71 ms** | 512-1024 | **2,11-3,86 s** |

**La lettura onesta, che è meno trionfale di come verrebbe da scriverla.** Il nostro PBS costa
**18,8-19,0 ms di tempo-thread** nella configurazione sicura (il numero si ricava dalla colonna
«PBS/thread» di F56: 0,150 s × 16 thread / 128 = 18,8 ms, e resta 19,0 ms fino a N=4096) — quindi
*per costo ammortizzato* le tecniche migliori (3,7-4,3 ms) sono **~5× più economiche della nostra**,
e sarebbe disonesto nascondersi dietro il totale. (Col set veloce 1_1, quello che F56 ha dovuto
scartare per sicurezza, saremmo a 12 ms e il divario sarebbe 3×.) Quello che le rende
inutili qui è la **latenza** e il **batch**: la nostra galleria a N=1024 nella configurazione sicura
fa **1,258 s di parete su 16 thread**, mentre BatchBoot — la migliore — chiede un batch di 512-1024
e paga 2,11-3,86 s **di latenza su un thread**. ⚠️ Il confronto va fatto sul **tempo-CPU**, che è
il metro che F67 elegge come equo, e lì perdiamo: 3,71 ms × 1.024 = **3,8 s·core** contro i nostri
1,258 × 16 = **20,1 s·core**, cioè **5,3× a loro favore** — coerente col «~5× più economiche» già
ammesso sopra. Quello che ci salva non è il costo, è che il loro guadagno si incassa solo
riempiendo un batch da 512-1024, e in un varco il batch è una query. Il nostro carico parallelizza in modo banale (N PBS indipendenti, 16 thread, efficienza
misurata costante a 19 ms/PBS fino a N=4096); il loro è un guadagno *per core* che va incassato
riempiendo un batch, e in un varco il batch è **una query**. Sotto il migliaio di iscritti non c'è
nemmeno abbastanza lavoro per riempirlo.

**Verdetto**: direzione chiusa, e chiusa per il motivo giusto — non «sono lenti», ma **il requisito
di maschera condivisa è incompatibile col nostro circuito**, e l'ammortizzazione SIMD compra costo
per core in cambio di latenza, che è esattamente lo scambio sbagliato per un cancello. Va scritto in
tesi come direzione *valutata e scartata con i numeri*, perché è la prima cosa che un revisore
chiederebbe.

**La minaccia specifica segnalata dalla revisione della letteratura, verificata sul paper.**
*Bootstrapping Bits with CKKS* (Bae, Cheon, Kim, Stehlé, `2024/767`) dichiara una **«winning
threshold» di 162-262 gate in parallelo** oltre la quale conviene loro — e a N=1024 noi ci siamo
ampiamente sopra, quindi andava guardata. Ho letto la loro Tabella 2: la soglia è
`T_boot / T_gate`, con T_boot = **1,70 s** per un lotto da 2¹⁴ slot, e i 162/262 escono confrontando
con gate DM/CGGI da 10,5 ms e 6,49 ms. La formula si riproduce esattamente, quindi la posso
applicare a noi: con il nostro PBS sicuro da **18,9 ms** di tempo-thread la soglia scende a
**1700/18,9 ≈ 90** bootstrap. A N=1024 siamo 11× sopra: **per costo-core hanno ragione loro.**

**Precisazione, dopo aver confrontato con la riga giusta.** L'argomento sopra è corretto ma non è il
più tagliente. La «winning threshold» di 2024/767 misura un `GateBoot`, cioè il **rinfresco di un
cifrato il cui plaintext è già un bit**: una porta booleana. La primitiva che serve a noi — valutare
sign(x) su un LWE largo 13-14 bit — ha un suo benchmark pubblicato, ed è **Alexandru, Kim, Polyakov,
CRYPTO 2025 (`2024/1623`)**: segno a **12 bit** su 65.536 slot, **63,8-147 s**. A N=1024 riempiremmo
l'1,6% degli slot e pagheremmo 63,8 s contro i nostri 1,26 s. La frase da usare in tesi è quindi:
*il varco è N PBS **funzionali** su messaggi larghi, non N gate booleani; sulla primitiva che ci
serve il pavimento CKKS è 6,4 s (4 bit, `2024/1637`) o 63,8 s (segno a 12 bit), non 1,70 s.*

Cade però su due cose concrete. **La latenza**: i loro 1,70 s sono per *un* lotto, mentre il nostro
N=1024 completo sta in **1,258 s di parete** su 16 thread — siamo già sotto, e per giunta il loro
lotto sarebbe pieno al 6% (1.024 slot su 16.384), perché in un varco le query arrivano **una alla
volta** e non c'è niente con cui riempirlo. **Il formato**, che è il blocco vero: BinBoot fa
bootstrap di **bit**, valuta porte binarie. Il nostro PBS non è una porta binaria — è l'estrazione
del **segno di un punteggio leveled a 13-14 bit**. Per dargli in pasto i nostri punteggi servirebbe
il ponte leveled→radix, che F45 costa fra **~7,3 s** (con la bit extraction del WoP-PBS, stima) e
**60-70 s** (con un PBS largo per cifra, misurato). In entrambi i casi il ponte costa più di quello
che la tecnica farebbe risparmiare, e il conto non si chiude.

Registrato così perché è la domanda che un revisore farebbe per prima, e la risposta non è «non
l'abbiamo provato» ma «ecco la loro soglia applicata ai nostri numeri, ed ecco perché il formato
non combacia».

---

## 🔴 F66 — La GPU è l'unica leva di velocità rimasta, e sublineare in N non si scende

### La GPU: la leva più grande rimasta, e le API sono già lì

`tfhe-0.11.3` contiene già `src/core_crypto/gpu/algorithms/` con **tutta** la pipeline del varco —
`lwe_programmable_bootstrapping.rs`, `lwe_keyswitch.rs`, `glwe_sample_extraction.rs`,
`lwe_linear_algebra.rs` e perfino `lwe_packing_keyswitch.rs` (cioè anche F59) — dietro la feature
`gpu = ["dep:tfhe-cuda-backend"]`. E la firma è **nativa a lotto**, che è esattamente la forma del
nostro carico:

```rust
pub fn cuda_programmable_bootstrap_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>, output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>, …, num_samples: LweCiphertextCount, …)
```

Numeri Zama: **945 µs di latenza** per un PBS a 4 bit su H100 e **189.000 PBS/s su 8×H100**
(~42 µs ammortizzati per GPU), contro i nostri **0,70-0,78 ms effettivi** per PBS a 16 thread → un
fattore ~18 sulla carta. Stima onesta su una GPU da Colab: **5-15× a N ≥ 512**, poco o niente a
N=128 dove il trasferimento domina.

**E va detto perché F25 non contraddice questo.** Lì la GPU risultava *più lenta* della CPU, ma era
Concrete con un argmin **sequenziale**: una catena di confronti dipendenti, cioè il caso peggiore
possibile per un acceleratore. Il varco è l'opposto esatto — N bootstrap indipendenti, nessuna
dipendenza, una sola LUT — ed è il carico per cui quelle API sono scritte. **È l'unica leva di
velocità rimasta aperta dopo che ammortizzato (F65), multi-bit (F60), decomposizione del CB (F63),
compressione (F64) e keyswitch (F56) sono stati misurati e chiusi.**

### Sublineare in N: non si scende, e il motivo non è il lower bound del PIR

Non si scende sotto il lineare, e il motivo **non** è il lower bound del PIR: Beimel-Ishai-Malkin
parla di *retrieval* con indice segreto del client, mentre qui la galleria il server **la conosce**.
L'inquadramento giusto è **RAM-FHE** (Lin, Mook, Wichs, `2022/1703`, §1.1 caso 1, «encrypted queries
over a public database») e la barriera è il **modello a circuiti**, non la privacy: il problema è
risolto in teoria (preprocessing O(N^{1+ε}), query polylog, RingLWE + circular security) e **mai
implementato**. Nessuna struttura «blind» scende sotto il lineare: RevoLUT è lineare e limitata a
p ≤ 2⁸; IDFace lo scrive («grows linearly with respect to the number of enrolled identities»);
Tiptoe clusterizza in √N ma **scandisce tutto**. I sistemi che sono davvero sublineari rompono un
vincolo: Wally usa **differential privacy**, Pacmann fa scaricare il database, Compass mette i dati
dal client. Nessuno dei tre è accettabile qui.

---

## 🔴 F67 — Il confronto con CKKS, con la baseline giusta: ci battono sul tempo-CPU

Il confronto di F39 usava per CKKS un packing ingenuo. Con il packing corretto per questa forma il
quadro cambia, e non a nostro favore: va misurato bene proprio perché è il confronto su cui poggia
la scelta dello schema.

### Il packing: eravamo depotenziati fino a 7,6×

La baseline di F39 replica il probe R = slot/dim = 32 volte e fa pagare a **ogni blocco** il suo
rotate-and-sum: log₂(512) = 9 rotazioni, più una maschera e una rotazione di compattamento. Le
rotazioni sono quindi ~10·⌈N/32⌉, **lineari in N**. Esiste un layout migliore — lo stesso di
Halevi-Shoup in versione ibrida: si danno a ogni iscritto W = slot/N slot contigui, si ruota il
**probe** di W·j per j = 0…ρ−1 con ρ = N·dim/slot (e quelle rotazioni sono **condivise da tutti gli
iscritti**), si moltiplica per la galleria riordinata, e si chiude con log₂(W) rotazioni di
collasso. Rotazioni: ρ + log₂(W).

Misurato da me, stessa macchina, stessa scena, stessi parametri, **stesso errore sui punteggi e
stesso livello d'uscita** (`experiments/15_ckks_confronto/ckks_packing_forte.py`):

| N | rotazioni ora | tempo ora | rotazioni giuste | **tempo giusto** | guadagno | chiavi di Galois |
|---|---|---|---|---|---|---|
| 128 | 40 | 3,529 s | 11 | **0,963 s** | 3,7× | 2.099 MB |
| 256 | 80 | 7,094 s | 14 | **1,304 s** | 5,4× | 3.229 MB |
| 512 | 160 | 14,352 s | 21 | **2,101 s** | 6,8× | 5.651 MB |
| 1024 | 320 | 28,827 s | 36 | **3,772 s** | **7,6×** | 10.656 MB |

Il guadagno **cresce con N**, perché il costo giusto è quasi piatto mentre quello a blocchi cresce
lineare. Ne segue che i 4,25 s che F39 riporta sono un artefatto del packing a blocchi, **non una
proprietà dello schema**: il numero da usare per CKKS è quello della colonna «tempo giusto».

### Il confronto, con i due numeri messi sullo stesso piano

Aggiungendo il segno (0,71 s, indipendente da N) la baseline CKKS **corretta** costa **1,67 s a
N=128** e **4,48 s a N=1024**, single-thread. Il nostro varco sicuro costa 0,153 s e 1,258 s su
**16 thread**, cioè 2,45 e 20,1 s·core.

| | CKKS corretto (1 thread) | varco TFHE (16 thread) | tempo-CPU | parete |
|---|---|---|---|---|
| N=128 | 1,67 s | 0,153 s (2,45 s·core) | **CKKS 1,5× meglio** | noi 11× meglio |
| N=1024 | 4,48 s | 1,258 s (20,1 s·core) | **CKKS 4,5× meglio** | noi 3,6× meglio |

**Sul tempo-CPU perdiamo già dentro il regime del varco**, e il pareggio sta intorno a N≈60. La ragione è strutturale e va scritta senza girarci intorno: la soglia CKKS costa **O(1) in
N** — una sola valutazione del segno per tutti gli iscritti insieme — mentre i nostri PBS costano
**O(N)**. Non è un dettaglio di implementazione, è la differenza fra SIMD e non-SIMD.

### Cosa regge davvero, e sono tre cose misurate

1. **La profondità, che è l'unico asse dove il vantaggio cresce con la macchina invece di
   consumarsi.** La nostra decisione è **un** PBS di segno, 18,9 ms, con N istanze indipendenti: la
   latenza scende linearmente coi core fino a un pavimento di 19 ms, e lo scaling misurato è quasi
   perfetto (128 × 18,9/16 = 151 ms previsti contro 153 misurati). Il CKKS ha una catena
   **sequenziale irriducibile** — le log₂(slot/N) rotazioni di collasso più le 12-16 moltiplicazioni
   ct×ct del polinomio di segno — che nessun numero di core accorcia. In latenza vinciamo a **ogni
   N misurato**, ma con vantaggio che si consuma: 11× a N=128, 3,6× a N=1024, e l'asintoto è ~2,6×
   perché la loro catena sequenziale è un pavimento fisso mentre il nostro costo cresce con N.
2. **Il materiale di chiave, misurato qui sopra: 2,1 GB a N=128 e 10,7 GB a N=1024** di sole chiavi
   di Galois, contro i nostri 130 MB di chiave di valutazione più 67 MB di packing. È **10-50× a
   nostro favore**, non dipende da nessuna ottimizzazione dell'avversario, e per un varco che deve
   girare su hardware ordinario conta quanto il tempo.
3. **La parte lineare**: le nostre distanze leveled costano 3 ms su 153 (il 2%), le loro 0,96-3,77 s.
   ~100× a nostro favore e robusto a qualunque ottimizzazione. **Il nostro punto debole non sono le
   distanze, è la soglia** — ed è meglio dirlo noi.

### La formulazione da mettere in tesi

> Il confronto con CKKS non si decide su un numero: si decide su una metrica e su un intervallo.
> Con la baseline CKKS scritta col packing corretto per questa forma, sul **tempo-CPU** il varco
> perde già a N=128 (2,45 s·core contro 1,67 s) e il pareggio sta a N≈60, perché la soglia CKKS è
> O(1) in N e i nostri PBS sono O(N). Sulla **latenza a parità di hardware ordinario** il varco
> vince in tutto il regime rivendicato, ma il motivo non è che TFHE sia più veloce: è che la nostra
> operazione non lineare ha **profondità uno**, quindi la latenza si compra coi core fino a 19 ms,
> mentre CKKS ha una catena sequenziale di ~20 operazioni che nessun core accorcia. A questo si
> aggiungono due argomenti indipendenti dalla velocità e misurati: il materiale di chiave (2,1-10,7
> GB contro 197 MB) e la natura dell'uscita (un bit esatto contro un valore graduato). Per un varco
> fisico — poche centinaia di iscritti, una query alla volta, latenza come specifica, chiavi che
> devono stare sulla macchina — la scelta giusta è il varco TFHE. Per gallerie da migliaia di
> iscritti, o dove conta il costo per query invece della latenza, la scelta giusta è CKKS.

---

# Appendice A — Registro delle revisioni

I finding qui sopra riportano i numeri **finali**. Questo registro dice quali sono stati rivisti e
perché, perché un relatore ha diritto di sapere che una misura è cambiata e per quale motivo — ma
non serve per leggere i finding, che sono autosufficienti.

| finding | cosa è stato rivisto | perché |
|---|---|---|
| F14 | «~63 ms» → **151,9 ms** per il match a dim 512 | era il numero di dim **128**, usato come se fosse quello a piena dimensione (`velocita_dimensione.csv`). Le stime che lo riusano — F15, F19, F22 — vanno lette con questa avvertenza |
| F19/F20 | il tetto ~95-96% è quello **a frame singolo** | con la fusione multi-frame (F48) lo stesso protocollo arriva a 99,2% |
| F22/F23/F24 | tabelle pre-CHUNKED; «comprimere è la leva» → **non lo è** | rimisurato: l'argmin a 128 dim costa *più* che a 512 (237,9 s contro 158,7 s) |
| F27 | il torneo vale 2,2× **solo col dataflow** | su macOS, dove il dataflow non esiste, il torneo è più lento del sequenziale |
| F28 | aggiunta la riga a N=64/128 dim, prima omessa | quella riga (93,4% contro 92,5%) contraddice la conclusione originale |
| F32/F42 | «a parità di macchina» reso vero, non tolto | Concrete sbloccato sul Mac (F64): 105× a N=4 e 94× a N=8, stesso hardware |
| F33 | breakdown rimisurato | i numeri venivano dall'home server con un'altra versione di Concrete (57 PBS contro 108: circuito diverso, non solo macchina) |
| F37 | Δ non era «scelto senza guardare i probe» | il codice li guardava tutti: è la vulnerabilità di F56 |
| F39 | campione bilanciato per gli impostori; packing corretto | `P[:32]` prendeva solo genuini; e il packing a blocchi costava fino a 7,6× di troppo (F67) |
| F40 | l'attacco «da fuori» rifatto | lo script perturbava un punto fisso e interrogava un solo iscritto: rifatto, apre alla prima query (F61) |
| F45 | il costo del ponte è una **stima pessimistica** | costato con un PBS largo per cifra; con la bit extraction del WoP-PBS sarebbe ~10× meno (domanda aperta B1) |
| F46/F47 | il meccanismo del crollo dei set piccoli | non è la box size (l'accumulatore è costante: `message_modulus` non entra nel circuito), è il rumore in uscita contro `LOG_DO` — modello quantitativo in F55 |
| F48 | «+8,7 punti» → **+3,9** | il +8,7 è misurato contro una baseline a una foto per iscritto, che non è mai stata la nostra |
| F49 | quattro numeri ora prodotti da uno script; tempi client riattribuiti | `benchmark/soglia_dominio.py`; i «10/8 ms» cronometravano `subprocess.run`, non la crittografia |
| F51 | rimisurato nella configurazione **sicura** | era misurato col set 1_1 e Δ=2^53, che F56 dichiara inutilizzabili: 0,192 s invece di 0,094 s |
| F52 | tabella riallineata all'artefatto; Δ onesto | il Δ=2^52 lasciava viva la vulnerabilità di F56 nell'argmin; col Δ onesto l'accuratezza dell'indice cala |
| F58 | la prova ZK di **range** non serve, quella di **norma** sì | servono contro due attacchi diversi: il Δ si difende col bound, il punteggio con la norma (F61) |
| F62 | la tabella normalizzata confronta **operazioni diverse** | argmin/top-k/sort sono più difficili di N soglie: sull'operazione giusta il vantaggio si inverte |
| F65 | il confronto col bootstrapping ammortizzato non era normalizzato sui thread | la direzione resta chiusa, ma perché manca il **batch**, non perché siamo più veloci |

---

# Appendice B — Domande aperte

Cose che non sappiamo, dichiarate come tali. Non sono correzioni in attesa: sono misure che non
abbiamo fatto e la cui risposta potrebbe cambiare un numero.

**B1. Il ponte con la bit extraction del WoP-PBS.** F45 chiude la strada del ponte a 60-70 s, ma
quel numero viene da un PBS largo per cifra. `extract_bits_from_lwe_ciphertext_mem_optimized` è già
in tfhe-rs e farebbe *b* PBS piccoli: stima ~7,3 s, un ordine di grandezza meno. La conclusione
operativa non cambia (resta ~47× il varco), il margine sì.

**B2. I parametri WOPBS del torneo (F52) non sono stati scelti, sono stati ereditati.** Il crate ne
contiene 43, tutti dichiarati a 123-128 bit. Cambiare la sola geometria vale ~2× stimato. Va fatto
lo sweep, importando le costanti dalla libreria invece di ricopiarle a mano.

**B3. La coda del torneo.** F63 calcola 11 round paralleli × 19-60 ms = 0,35-0,66 s e ne misura
1,27: resta un ~2× non spiegato, di cui la coda (gli ultimi livelli usano 1-8 core su 16) spiega
solo 1,4×. Va profilato per stadio prima di ottimizzare.

**B4. ~~Funshade non è prezzato~~ — chiuso**: il confronto è ora scritto in F62 col loro numero
accanto (9,3 µs per decisione contro i nostri 18,9 ms, ~2000×), e l'esclusione è argomentata sul
modello di minaccia — due server non colludenti e un round di comunicazione contro il nostro server
unico e non interattivo — invece che sulla velocità.

**B5. La baseline CKKS può essere ancora più veloce.** Usiamo il polinomio di segno di
Cheon-Kim-Kim; il minimax composito di Lee-Lee-No-Kim (`2020/834`) è la versione a complessità
ottima e varrebbe 19 → ~13 livelli, cioè un altro ~1,8× **a favore di CKKS**. E la misura è fatta con
SEAL su ARM senza HEXL: un fattore 1,5-2× rispetto a x86 con HEXL è plausibile e non è stato
verificato. Entrambe le cose peggiorano il nostro confronto, quindi vanno fatte.

**B6. La GPU.** È l'unica leva di velocità rimasta (F66). Le API a lotto ci sono già in tfhe-0.11.3;
serve una macchina CUDA.

**B7. La dispersione delle misure singole.** I numeri di testa dei binari tfhe-rs sono esecuzioni
singole, e F52 dichiara esso stesso una dispersione di 1,7× fra macchina scarica e carica — più
grande di parecchi degli effetti che confrontiamo. I ~8 numeri destinati alla tesi vanno rifatti con
5 ripetizioni, riportando mediana e min-max a carico dichiarato.
