# Findings — diario del progetto

Diario in ordine cronologico di cosa abbiamo fatto e capito, dal primo "hello world"
FHE fino al sistema che riconosce volti reali.

I pallini nei titoli segnano il filone: 🔵 riconoscimento (la scaletta delle tecniche),
🔴 lato FHE (cifratura, match cifrato, argmin privato sul server). I due filoni si intrecciano.

## Concetti di base

**FHE** (cifratura completamente omomorfica). Permette di fare *calcoli su dati
cifrati* senza decifrarli: il server elabora il cifrato e produce un risultato
cifrato, che solo chi ha la chiave può aprire. Noi usiamo Zama **Concrete**, che si
basa sullo schema **TFHE** e lavora su interi (niente float: i valori vanno
quantizzati). Si definisce una funzione Python e Concrete la compila in un
circuito che opera sul cifrato.

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
cifrato×chiaro, non cifrato×cifrato.

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
privacy l'argmin (e in prospettiva la soglia open-set) deve stare sul server, sotto FHE, così
il client apprende solo l'esito.

Chiamiamo **N** il numero di iscritti in galleria: a ogni query si calcolano N distanze (il
probe contro le N facce note) e l'argmin sceglie la più vicina. L'argmin cifrato non è nativo
in Concrete (`np.argmin` non supportato), quindi si fa a riduzione: N−1 confronti cifrati a
coppie, ognuno con un select di indice/valore e un PBS. Il costo dipende da due cose, la
larghezza in bit dei punteggi e N, e le misuriamo entrambe.

La prima leva sono i bit. A N=10 fisso, il tempo dell'argmin raddoppia ~a ogni bit di
punteggio (di nuovo la leva di F1–F3, ora sull'argmin):

| larghezza punteggi | 5 bit | 6 bit | 7 bit | 8 bit | 9 bit | 10 bit |
|---|---|---|---|---|---|---|
| run argmin | 4,2 s | 5,8 s | 12,7 s | 34 s | 82 s | 172 s |

La seconda leva è N, ed è il prima/dopo: quanto rallenta spostare l'argmin dal client al
server al crescere della galleria (prototipo PCA su Olivetti; figura
`experiments/06_argmin_soglia/results/prima_dopo.png`):

| N (iscritti in galleria) | prima (argmin client) | dopo (argmin server, FHE) | fattore |
|---|---|---|---|
| 2 | 51 ms | 293 ms | 6× |
| 8 | 37 ms | 1.357 ms | 36× |
| 16 | 37 ms | 3.264 ms | 87× |
| 32 | 37 ms | 7.043 ms | 190× |

Il client è piatto a ~37 ms/query (decifra gli N punteggi + un argmin numpy, nessun PBS); il
server cresce con N (i confronti cifrati sono ~N−1), da 6× a 190× il costo del client nonostante N sia ancora molto basso. E
attenzione: il "dopo" è a precisione ridotta (8 componenti, 3 bit, quindi punteggi ~6 bit) per
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

Esito. Al punto di lavoro sicuro (FPIR=1%), su volti reali il meglio è ~2%: il
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
np.max, np.minimum, np.maximum, np.sum, np.where`, ma non `np.argmin`/`np.argmax`. Ha
il *valore* minimo, non l'*indice*: coerente col modello a circuito/LUT (un indice non
è un'operazione naturale sul cifrato). Quindi l'argmin si costruisce da `<` + select
(`np.where`/aritmetica), in `core/matching.py`.

2. Il rifiuto "nessun match" funziona, ma serve l'inputset giusto. Il circuito
completo (`circuito_distanza_argmin_soglia`) ritorna `(indice, è_match)` dove la
soglia confronta la distanza² vera `val_min + ‖a‖²` (il termine `‖a‖²` scartato per
il ranking va rimesso per una soglia assoluta). All'inizio il ramo "nessun match" non
si attivava mai: causa = inputset troppo stretto. Concrete inferisce la larghezza
in bit dei valori cifrati *dall'inputset*; passando solo le righe della galleria, il
range era insufficiente e il confronto della soglia andava in overflow silenzioso
(il valore gira modulo a un numero piccolo, quindi sempre "sotto soglia" e sempre "match").
L'argmin restava giusto (i suoi valori erano nel range); solo la soglia sballava: un
bug subdolo, niente errore, solo risultato sbagliato.

Con un inputset rappresentativo dei probe reali, il circuito è corretto: verificato
10/10, con i "nessun match" che si attivano davvero (4/10 nel test a soglia stretta).

Lezione (cugina di F3/F6): l'inputset definisce il range valido del circuito. Va
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
Terzo gradino della scaletta (CNN), partendo dalla bassa profondità:
MobileFaceNet (InsightFace `buffalo_s`, `w600k_mbf`, linea ArcFace, embedding
512-dim, 13 MB), eseguito in chiaro sul client. Stesso protocollo 1:N open-set e stessa
figura dei pre-CNN (`benchmark/results/tecniche_1n.png`, gradino
`experiments/08_cnn/`).

| | | Rank-1 | DIR@FPIR=1% |
|---|---|---|---|
| DigiFace (sintetico) | migliore pre-CNN (HOG) | 42,2% | 10,4% |
| | CNN MobileFaceNet | 99,6% | 94,2% |
| VGGFace2 (reale) | migliore pre-CNN (HOG) | 14,4% | 2,2% |
| | CNN MobileFaceNet | 97,8% | 96,0% |

Il salto. Su volti reali (VGGFace2), al punto di lavoro sicuro (FPIR=1%) si passa da
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
MobileFaceNet (DigiFace, dim 512):

| | risultato |
|---|---|
| quantizzazione a 6 bit | non perde: DIR@FPIR=1% 89,3% (float) = 89,3% (quant) |
| match cifrato (dim 512, N=25–50) | ~63 ms/query, punteggi esatti (cifrato == quant) |

Più economico del gradino 07 (descrittori, dim 3776, ~75–95 ms): l'embedding CNN è
più piccolo, quindi la distanza cifrata costa meno. Conferma l'intuizione: la potenza del
modello (in chiaro sul client) non tocca l'FHE, conta solo la dimensione dell'embedding.

La pipeline completa è coerente e interattiva: client calcola l'embedding CNN in
chiaro, quantizza (senza perdita), cifra; server calcola la distanza cifrata in
~63 ms; il riconoscimento funziona (89–96% DIR@FPIR, F13). Resta aperto il solo
argmin cifrato sul server (F6), da rendere praticabile con `truncate_bit_pattern`
o tenendo l'embedding a pochi bit (qui 6 bit bastano e non costano accuratezza).

## 🔵 F15 — CNN profonda (ResNet50): un ritocco, e a costo FHE invariato
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

3. DigiFace (sintetico) è più duro di VGGFace2 (reale) per la CNN, controintuitivo
   ma logico: i modelli sono addestrati su volti reali (WebFace600K), quindi il sintetico
   è fuori-distribuzione e fa da stress test. È il caveat di onestà sui numeri alti:
   VGGFace2 è *in-distribuzione*; gallerie enormi (migliaia), condizioni out-of-domain e
   non-cooperative abbasserebbero ancora il DIR. Entro ciò che possiamo testare, però, il
   sistema è forte e scala.

## 🔵 F17 — Scaling su larga scala: a migliaia di iscritti il DIR scende davvero
Spinto oltre i 500 iscritti (richiesta di scalare ancora). Scaricata la parte DigiFace
a 33.333 identità (×5 img), sweep fino a 8000 iscritti (sintetico = stress test
out-of-distribution, F16). Figura `benchmark/results/scaling_grande.png`.

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
## 🔵 F19 — Modelli più grandi: si sale, ma poco — il 99% non è di questo protocollo
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
degli embedding CNN a 512 dimensioni troviamo un limite netto. Diario dei tentativi.

Il problema. Il punteggio `‖b‖² − 2·a·b` su 512 dimensioni quantizzate a 6 bit è
largo ~18 bit. Il confronto cifrato di Concrete 2.11 è limitato a ~16 bit:
l'argmin sui punteggi CNN non compila (`this 18-bit value is used as an operand to a
comparison operation`). E i ~18 bit nascono dall'accumulatore su 512 dimensioni, non
dalla precisione per-valore, e non si abbassano facilmente.

Cosa abbiamo provato (e perché non basta):
1. `round_bit_pattern` (arrotonda via i bit bassi dei punteggi prima del confronto).
   *No.* Azzera i bit bassi ma non riduce il range: il valore resta a 18 bit, quindi
   il confronto è ancora su 18 bit ed è rifiutato. Lo strumento serve a far seguire una
   tabella a precisione ridotta, non a stringere un confronto.
2. Dividere i punteggi (`// 2^k`, per tagliare il range alla metà). *No.* L'operazione
   stessa prende in input il valore a 18 bit, cioè una tabella su 18 bit, quindi non compila. Qualunque
   manipolazione *a valle* del punteggio largo è bloccata dallo stesso limite.
3. Comprimere l'embedding (PCA a meno dimensioni + meno bit), per stringere i
   punteggi alla sorgente. È l'unica leva che funziona, ma: per rendere l'argmin
   *veloce* (secondi) serve comprimere così tanto (≤16-32 dim, 2-3 bit) da distruggere
   l'accuratezza che la CNN ci aveva dato. Più che un'ottimizzazione è un trade-off:
   o accuratezza piena e argmin intrattabile, o argmin veloce e riconoscimento a pezzi.

Conclusione (onesta). Non esiste un calo progressivo coi miglioramenti: l'argmin
cifrato sul server non scala agli embedding CNN ad alta dimensione: è un limite
(limite di bit-width del confronto in Concrete), non una discesa. Estende ed è il
contraltare di F6: lì il costo cresceva ~2×/bit; qui i bit sono troppi a priori.

Come farlo davvero (da esplorare): (a) un punto di compromesso dimensione/accuratezza,
cioè PCA dell'embedding a ~128-256 dim, argmin tractabile ma lento (~minuti/query) con qualche
punto di accuratezza in meno; (b) privacy a livello di protocollo invece che di
circuito, per esempio il server mescola i punteggi così il client vede solo distanze
anonime + l'identità vincente, senza argmin cifrato; (c) un argmin a torneo/gerarchico
che non materializzi mai il punteggio pieno. Il client-argmin (~100 ms) resta solo come
*baseline funzionante ma non privata*, non come soluzione.

## 🔴 F21 — L'argmin server serve davvero? Dipende dal modello di minaccia
Ripensando: con l'argmin sul client (la demo funzionante, ~100 ms) il server calcola
i punteggi cifrati e li rimanda senza mai decifrare. Quindi il server non impara
nulla: né il volto, né i punteggi, né l'esito. L'unico a vedere le distanze è il
client (che ha la chiave). Conseguenza importante:

- Sotto il modello di minaccia naturale del varco (server honest-but-curious, client
  fidato, il terminale è del gestore) il sistema client-argmin a ~100 ms è già
  privacy-preserving: protegge il volto e l'esito dal server. Niente argmin cifrato.
- L'argmin (e soglia) sul server serve solo se il client non è fidato (un
  client malevolo non deve poter sondare la galleria imparando le distanze). È un
  irrobustimento extra, ed è quello che incontra il limite FHE (F20).

Quindi "l'argmin cifrato sul server è necessario" non è assoluto: dipende da quanto
si fida il client. Il contributo della tesi può legittimamente fermarsi al sistema
client-argmin (funziona, è privato verso il server, ~100 ms con ResNet100 al ~95%), e
trattare il server-argmin come hardening per il caso untrusted-client (fattibile solo a
dimensione ridotta, vedi F22).

## 🔴 F22 — Comprimere l'embedding: a 128 dim quasi gratis (la leva per l'FHE)
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
nella dimensione). NB: per rendere l'argmin cifrato *tractabile* serve 128 dim +
quantizzazione bassa (~4 bit), quindi punteggi ~14 bit e argmin lento (~minuti/query) ma non
intrattabile. È l'operating point del server-argmin privato: lento, per basso throughput.

Velocità del match cifrato vs dimensione (`velocita_dimensione.py`, figura
`velocita_dimensione.png`): 512→152 ms, 256→65, 128→63, 64→59, 32→57. Il match
(cifrato×chiaro, no PBS) è economico e quasi piatto sotto 256 (~60 ms): dominano i
costi fissi, non la dimensione. Ridurre l'embedding aiuta poco il *match* (già a terra),
ma è la leva per rendere l'*argmin* cifrato fattibile (F20/F22). Quadro completo: la
dimensione 128 è il punto dolce, accuratezza ~94% (ResNet50), match ~63 ms, e punteggi
abbastanza stretti da avvicinare l'argmin privato al fattibile.

## 🔴 F23 — Ottimizzare l'argmin server: niente hardware-lever, e la compressione aiuta al margine
Tentativo di "ottimizzare fortissimo" l'argmin cifrato sul server. Due fatti duri.

Niente leve hardware su questa macchina. Il parallelismo dataflow di Concrete
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
dove è veloce (16 dim) l'accuratezza è inutile. Niente operating point buono.

La compressione migliore aiuta, ma non rompe la frontiera. Abbiamo usato la PCA;
provata anche la LDA (supervisionata, `compressione.py`, figura `compressione.png`):
a dim bassa la LDA batte la PCA (dim 16: 25% vs 14%; dim 32: 65% vs 56%), sopra 64 la
PCA torna avanti (la LDA si sovra-adatta agli iscritti). Ma anche con LDA, dim 32 = 65%
(tractabile ma lento) e dim 64 = 84% (RAM esplode), e la compressione sposta i punti di
qualche punto, non sposta il limite.

Conclusione (definitiva su questo hardware). L'argmin cifrato sul server con
embedding CNN di qualità è non praticabile ottimizzando software/compressione: serve
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
operations are supported"*). Ma combinandolo con una dimensione ridotta, così che i punteggi
stiano sotto i 16 bit, l'argmin sul server finalmente compila e gira, dove con la strategia di
default esplodeva la RAM (F23):

| dim PCA | accuratezza | argmin cifrato (N=8) |
|---|---|---|
| 128 | ~90% | 123 s |
| 256 | ~93% | 130 s |

Il limite, quindi, era la strategia sbagliata e non un limite della FHE: con CHUNKED l'argmin
sul server funziona, a circa 90-93% di accuratezza. Resta il problema del tempo: circa due
minuti su CPU per N=8, perché ogni confronto CHUNKED costa una quindicina di secondi. Non sono
i 2-3 secondi che vorremmo, ma il sistema funziona, ed è privato anche verso il client.

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

La misura, stesso circuito di F24 (argmin 1:N, N=8, CHUNKED, Q=±2, punteggi 8-10 bit):

| dim | bit | GPU T4 (run) |
|---|---|---|
| 64 | 8 | 629 s |
| 128 | 9 | 1082 s (18 min) |
| 256 | 10 | 1267 s (21 min) |

Per riferimento, l'M4 Max (F24) faceva dim 128 in ~123 s, e il baseline CPU sulla stessa VM
Colab girava da oltre 17 minuti senza finire. Cioè: la T4 è ~9× più lenta della CPU desktop,
e non dà speedup nemmeno rispetto alla CPU debole della sua stessa macchina. L'ipotesi di
F24 è falsa.

Conta capire il perché. L'accelerazione GPU di TFHE serve al throughput in batch: tante
bootstrap indipendenti che riempiono insieme i core. Il nostro argmin è l'opposto, una
riduzione sequenziale (N−1 confronti dipendenti) su una singola query, niente da
parallelizzare, e ogni PBS minuscolo paga solo l'overhead di lancio del kernel. La GPU
servirebbe a fare molte persone insieme (throughput), non la latenza del singolo al varco.

E non è una congettura nostra. Zama stessa scrive che la GPU di TFHE-rs privilegia un
tradeoff latenza/throughput perché "i casi reali raramente calcolano un singolo bootstrap"
([Zama](https://www.zama.org/post/bootstrapping-tfhe-ciphertexts-in-less-than-one-millisecond),
[TFHE-rs GPU docs](https://docs.zama.org/tfhe-rs/hardware-acceleration/run-on-gpu)); e la
letteratura sugli acceleratori FHE-GPU dà il meccanismo preciso: l'overhead di lancio dei
kernel (~2-10 µs) serializza le tante operazioni piccole, e il rimedio è il batching in
un'unica chiamata ([Theodosian](https://arxiv.org/abs/2512.18345),
[Chameleon](https://arxiv.org/abs/2410.05934)). Il nostro argmin è batch ≈ 1, fuori dal
regime in cui la GPU conviene. (I numeri assoluti dipendono dalla build GPU 2024.12.19 e da
CHUNKED; cambierebbero con un backend più recente, ma non l'asse del problema.)

Conclusione: non c'è una scorciatoia hardware ai 2-3 s del riconoscimento privato-verso-il-
client. Le leve vere restano algoritmiche (meno confronti, batch tra query, torneo
parallelo) o di protocollo. Il sistema veloce-e-accurato resta quello con argmin sul client
(F21); il server-argmin privato funziona (F24, ~90% a ~2 min) ma non è realtime, e, ora
verificato, la GPU non lo rende tale.

## 🔴 F26 — Cosa fa la letteratura: non è tutto CKKS, e quasi nessuno fa l'argmax sul server
Dopo aver incontrato il limite dell'argmin siamo andati a vedere come lo risolvono gli altri. La
rassegna completa, 16 sistemi con le fonti lette direttamente, sta in `letteratura.md`; qui il
succo.

Gli schemi. CKKS è il più diffuso per la similarità (Blind-Match, GROTE, CryptoFace, BSGS,
Mazzone): lavora su vettori di reali e fa packing SIMD, cioè una sola operazione cifrata agisce
su centinaia di slot in parallelo, così impacchetta le similarità della galleria in un
ciphertext e batcha i confronti. TFHE, il nostro, è l'opposto: ottimo per le funzioni
non-lineari arbitrarie via PBS, ma ogni confronto è un'operazione a sé, quindi l'argmin è una
riduzione sequenziale lenta (F24), peggio su GPU (F25). Non è però tutto CKKS: c'è il BFV/FV per
gli interi esatti (HERS, Boddeti, che poi scaricano l'argmax al client), e c'è una linea TFHE
sul nostro stesso problema (Blind Counting Sort e Blind Top-k di PoPETs'25, RevoLUT, k-NN
simmetrico di PSD'22, che fanno argmin e top-k via LUT e counting-sort). Quindi nello schema non
eravamo fuori strada.

La cosa importante: quasi nessuno calcola un argmax cifrato vero sul server. Lo evitano in
quattro modi. Lo scaricano sul client, che decifra tutti gli score e fa l'argmax in chiaro
(HERS, Blind-Match, CryptoFace; è il nostro F21). Lo riducono a una soglia, un solo bit "c'è un
match?" (CryptoMask) o i soli indici senza score (BSGS). Lo approssimano sul server con polinomi
(GROTE col group testing, confronti K→2√K; Mazzone con un vettore one-hot, argmin di 128 in
~13 s). Oppure usano due server, dove un Key Server decifra gli score (IDFace, 1M template in
126 ms).

Ordini di grandezza per il related-work: IDFace 1M in 126 ms (CKKS, due server); Blind-Match LFW
99,63% in 0,74 s (CKKS); BSGS 99,99% su 44K, sub-secondo su GPU (CKKS); HERS 100 M in 500 s
(BFV); GROTE 14,6 s a K=16.384 (CKKS); Mazzone argmin di 128 in 12,8 s (CKKS); Blind Counting
Sort k-NN in ~2,4 s (TFHE).

Dove siamo noi. Quasi tutti cifrano anche la galleria (enc×enc); il nostro Mondo 1 (galleria in
chiaro, solo probe cifrata, quindi enc×plaintext senza PBS sul prodotto scalare) è più leggero,
ma assume che il server veda la galleria. L'unico parente stretto è il k-NN TFHE simmetrico di
PSD'22 (probe cifrata, galleria in chiaro, non-interattivo, identico a noi, ma con costo PBS
quadratico). È un punto distinto e poco esplorato dello spazio, e va dichiarato.

La lezione per il varco: spesso l'argmin non serve. A un controllo accessi basta "c'è qualcuno
sotto soglia? apri o non aprire", più economico e con meno leakage (il client non impara né gli
score né chi sei). La soglia ce l'abbiamo già (F11); l'argmin serve solo per dire quale
identità. Il nostro lavoro non è scoprire CKKS in ritardo, ma aver costruito e misurato un 1:N
privacy-preserving su Concrete/TFHE nel setup galleria-in-chiaro, poco battuto, e aver situato
il risultato nello stato dell'arte: il limite è intrinseco all'operazione su TFHE, gli altri lo
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

L'ottimizzazione che conta è il torneo: 2,2× più veloce a N=4, 2,6× a N=8, e il vantaggio cresce
con la galleria (il sequenziale scala ×2,3 per raddoppio, il torneo ×1,9). La catena paga
anche l'indice accumulato che si allarga, mentre l'albero no. Il dataflow invece non è la leva:
inutile sul sequenziale (niente da parallelizzare), solo ~8% sul torneo a N=4, e a N=8 fa
crashare il compilatore (un bug, assertion MLIR).

Ma c'è un limite inferiore. La config migliore, torneo a N=8, è 69 s per soli 8 iscritti, perché
il singolo confronto cifrato costa ~26 s a 8 bit, e nessuna struttura scende sotto ~log(N)
volte quel costo. Quindi: ottimizzare la struttura aiuta sul serio (un passo avanti verso
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

Tutti corretti (conteggio = atteso), e il dataflow non aiuta (31,2 vs 32,0 s a N=8). Ma
conta lo scaling: 8→64 iscritti (×8) porta 31→348 s (×11), cioè ~lineare in N. La
parallelizzazione dà solo un fattore costante (≈ numero di core), non spezza la linearità.
La soglia quindi abbassa il costante (è più economica dell'argmin, è il primitivo giusto,
fa trapelare un solo bit) ma non cambia la legge: a un ufficio (decine di iscritti) è
plausibile, qualche minuto; estrapolando, N=256 ≈ 23 min, N=1024 ≈ 1,5 h. In più il keygen
esplode con N: a N=64 il processo usava 27 GB di RAM, e oltre va in OOM su questo box,
quindi è un secondo limite, sul setup più che sulla query.

Il verdetto chiude la domanda "il varco a soglia è realtime?": no, a scala reale. In TFHE
restano N PBS indipendenti, tempo lineare in N, e la parallelizzazione è solo un fattore
costante. Operativamente: varco TFHE con galleria in chiaro è pratico solo per gallerie
piccole (decine di iscritti, latenza minuti); per centinaia o migliaia serve il packing SIMD
di CKKS (F26: IDFace, 1M in 126 ms), che batcha gli N confronti invece di pagarli uno per
uno. È la conferma sperimentale, dal lato giusto del problema, della conclusione di F24→F27:
su TFHE il match privato 1:N non è realtime a scala: lo è solo nel caso piccolo, o
spostando la decisione fuori dal server (client, F21) o su un altro schema (CKKS).

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

Nota metodologica, perché senza non saremmo arrivati a 48000. L'embedding girava una
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
Validato: carica strict 917/917 chiavi, 1:1 su DigiFace 98,9% (d'=4,98), quindi caricamento
e preprocessing sono corretti.

Sul sintetico AdaFace non stacca. L'ho aggiunto a tutto lo sweep DigiFace fino a 48000,
quindi la figura `scaling_grande.png` ora ha quattro curve. AdaFace traccia vicino ai due
modelli profondi, un soffio sopra a galleria piccola e media (93,9% a 250 contro 92,3% di
ResNet50, 78,3% contro 77,4% a 8000) e converge al fondo scala (66,8% contro 67,1% a 48000).
Mediando su 8 seed (per non confondere il vantaggio col rumore di seed, che a N piccolo è
±1,5 punti) il margine su ResNet50 è ~+0,6 punti, costante e mai negativo ai size grandi a
bassa varianza (4000, 8000): satura insieme agli altri. Conferma F29, sul sintetico la
ricetta di addestramento, come la profondità, cambia poco.

Sul reale (VGGFace2, estende F19 a quattro modelli):

| iscritti | MobileFaceNet | ResNet50 | ResNet100 | AdaFace |
|---|---|---|---|---|
| 250 | 93,3% | 96,3% | 96,7% | 96,3% |
| 1000 | 90,2% | 95,8% | 96,5% | 96,0% |
| 4300 | 86,0% | 94,2% | 95,5% | 95,0% |

AdaFace pareggia ResNet100 sui piccoli N e gli scende appena sotto a scala, restando sempre
sopra ResNet50. ResNet100 rimane il migliore. AdaFace è progettato per i volti reali di
bassa qualità (sfocati, bassa risoluzione), e né VGGFace2 (volti web puliti) né DigiFace
(render puliti) lo mettono alla prova, quindi resta alla pari con ResNet100. Per vederlo
staccare servirebbe un set reale difficile, tipo TinyFace o IJB-C hard, che non abbiamo.

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
MobileFaceNet). E la leva per renderlo più forte non è una rete diversa ma allineare il
test al dominio d'uso reale. Quello che ancora manca è il reale a grande scala (MegaFace,
1M), fermo sulle credenziali di download.

Nota tecnica: embeddare AdaFace su tutte le 500k immagini DigiFace richiede attenzione alla
memoria. Convertire l'intero array immagini in float32 in un colpo arriva a ~150 GB e manda
in OOM; va fatto in streaming, caricando ed embeddando poche migliaia di immagini per volta
(picco ~2 GB). Sui set più piccoli (VGGFace2 reale, ~50k crop) non si nota.

## 🔴 F31 — Ottimizzare Concrete il più possibile: il limite è l'API, non TFHE
Dopo F26 e F27 abbiamo voluto ottimizzare ancora l'argmin sul server e leggere bene la
letteratura su come si fa l'argmin cifrato veloce. Il risultato corregge una cosa che avevamo
detto sbrigativamente (F26: "il limite è TFHE").

Cosa dice la letteratura. Il TFHE può fare l'argmin molto più veloce di noi. Chakraborty e
Zuber (WAHC 2022, eprint 2022/622) fanno un argmin a torneo su 64 interi a 8 bit in 10,8 s
single-thread su un laptop del 2016, cioè ~0,17 s per confronto, con un bootstrap che emette
minimo e indice insieme in ~2 PBS. Azogagh et al. (Blind Counting Sort, PoPETs 2025) fanno
argmin e sort senza confronti, via counting-sort su LUT (k-NN ~2,4 s a piccola scala). Ma
entrambi sono scritti a mano sulle primitive TFHE a basso livello — Chakraborty sulla libreria
TFHE originale in C/C++, Azogagh su tfhe-rs — non in Concrete-python. Per la scala vera
resta CKKS con packing SIMD (IDFace, 1M in 126 ms), che è un altro schema.

Cosa abbiamo provato su Concrete, e i verdetti:
- Quantizzazione aggressiva. Sugli embedding CNN veri (ResNet50, DigiFace, N=1000) la
  quantizzazione a 3 bit è quasi gratis: DIR@FPIR 86,2% contro 86,7% del float; a 2 bit crolla
  a 61%. Ma non dà velocità: l'argmin a N=8 resta ~135-180 s per q = 2, 3, 4, persino
  non-monotòno. E a 512 dimensioni la quantizzazione a ≤4 bit è obbligatoria per compilare,
  perché il confronto cifrato di Concrete è limitato a 16 bit e i punteggi a 6 bit lo superano (circa 17).
- Riduzione di dimensione. Comprime i punteggi (meno bit) ma uccide l'accuratezza 1:N: da 512
  a 64 dim il DIR scende da 86% a 68%. È la dimensione, non i bit per elemento, a guidare sia
  il costo FHE (larghezza del punteggio) sia l'accuratezza, quindi non c'è un punto operativo
  veloce e accurato insieme.
- Strategie di confronto e min (ONE_TLU_PROMOTED, THREE_TLU_CASTED). Più lente del CHUNKED di
  default (28,9 s contro 20,9 s a N=8) o crashano, per un bug interno di Concrete su un assert
  di bit-width dentro `np.minimum`.
- Rounding approssimato (`round_bit_pattern`). Aggiunge un PBS suo che annulla il risparmio,
  rumoroso, e crasha anch'esso con `np.minimum`.
Già fatte prima: torneo 2,6× (F27), soglia (F28), GPU 9× più lenta (F25), argmin sul client
(F21).

Il numero che spiega tutto. Il nostro argmin sequenziale su 8 elementi compila in ~210
bootstrap (PBS), ~30 per confronto, e gira in ~180 s, cioè ~0,85 s per bootstrap (misurato
ricompilando il circuito e leggendo `programmable_bootstrap_count`). Chakraborty fa lo stesso
su 8 elementi con ~14 PBS a ~0,09 s l'uno, ~1,2 s in tutto. Il divario di ~150× viene da due
cose insieme: facciamo ~15× più bootstrap, e ognuno è ~10× più lento.

Il perché. Concrete-python compila una funzione Python qualsiasi in automatico: scriviamo
`p[i] < val`, `np.minimum`, i select, e lui mette un PBS generico per ognuno. È comodo (si
scrive Python, compila da solo, ottimo per uno studio di fattibilità), ma non lascia scrivere
il bootstrap a mano. Chi nella letteratura va veloce ha fatto il contrario: ha scritto a mano
il circuito TFHE in Rust, fondendo minimo e indice in un solo functional bootstrap e tarando i
parametri. Quella leva in Concrete-python non c'è: decide il compilatore come implementare `<`
e `min`, non noi. Le nostre manopole (strategia, quantizzazione, rounding) stanno sopra questo
collo di bottiglia, quindi non possono chiuderlo.

La conclusione, che corregge F26 e F27. Il limite che abbiamo misurato non è il limite inferiore di TFHE,
è il limite inferiore di Concrete-python: la sua API ad alto livello, non lo schema. La frase giusta
per la tesi è che il match 1:N privato in Concrete-python è classe-minuti, mentre lo stesso in
TFHE scritto a basso livello (C/C++ originale o tfhe-rs) è classe-secondi a questa scala
(Chakraborty: ~1 s a N=8, ~11 s a N=64), e in CKKS sub-secondo a un milione (IDFace); portarlo
lì è ingegneria crittografica fuori dallo scopo di questa tesi. Le sole
vie viste e non provate restano la delta-matrix one-hot (O(N²) confronti paralleli, serve il
dataflow di Linux, comunque fattore costante) e `fhe.multivariate` (fonde compare e select ma
vuole operandi a 4-5 bit, i nostri punteggi sono 10-14), e nessuna delle due spezza il
lineare-in-N.

Nota infra. Concrete ora compila e gira sul Mac, che prima falliva sul linker (macOS beta, SDK
fuori posto). Un wrapper di `ld` in PATH riscrive il path SDK cablato verso quello di Xcode,
senza sudo e tutto in sessione, quindi questi esperimenti li abbiamo fatti in locale.
