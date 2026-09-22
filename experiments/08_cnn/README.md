# Gradino 08 - CNN (embedding pre-addestrato)

Il passaggio modificato è **foto allineata → vettore numerico del volto**.
Il gradino 07 costruiva il vettore contando texture e orientamenti locali;
qui lo produce una **CNN**, una rete neurale convoluzionale già addestrata
su immagini di volti. Non si addestra una nuova rete in questo esperimento.
Il suo output, chiamato *embedding*, alimenta lo stesso calcolo dei punteggi
cifrati dei gradini precedenti.

L'esperimento valuta MobileFaceNet, il modello `w600k_mbf` di InsightFace
`buffalo_s`: usa la funzione di addestramento ArcFace, produce embedding a
512 dimensioni e occupa circa 13 MB. La CNN viene eseguita in chiaro sul
client; il circuito della distanza in `core/matching.py` è quello dei
prototipi precedenti.

La rete non viene eseguita sotto FHE: il client fidato vede l'immagine,
calcola il vettore e lo quantizza in interi. Il server del prototipo
confronta il vettore cifrato con la galleria in chiaro e restituisce i
punteggi cifrati. Le misure storiche Concrete di questa pagina non sono
tempi del [runtime TFHE mantenuto](../../runtime/README.md), che esegue
anche la selezione del vincitore descritta nella
[guida al confronto](../../docs/come-funziona-il-confronto.md).

## Accuratezza in chiaro

**1:N** significa cercare una persona fra le voci della galleria;
**open-set** aggiunge probe di persone non iscritte, da rifiutare.
*Rank-1* conta i probe noti il cui primo candidato ha l'identità corretta,
senza applicare la soglia. *DIR@FPIR=1%* conta invece i noti identificati
correttamente e accettati, con soglia tarata sul quantile degli ignoti
del campione per il punto operativo indicato. Non garantisce quel tasso
di falsi ingressi su nuove popolazioni.

Stesso protocollo 1:N open-set dei pre-CNN (`benchmark/identificazione_1n.py`), stessa
figura (`benchmark/results/tecniche_1n.png`):

| | | Rank-1 | DIR@FPIR=1% |
|---|---|---|---|
| DigiFace (sintetico) | migliore pre-CNN | 42,2% | 10,4% |
| | CNN MobileFaceNet | 99,6% | 94,2% |
| VGGFace2 (reale) | migliore pre-CNN | 14,4% | 2,2% |
| | CNN MobileFaceNet | 97,8% | 96,0% |

Su VGGFace2 il DIR al punto operativo indicato passa da circa 2% a 96%.
Si tratta di accuratezza sul protocollo di prova, non di una garanzia di
sicurezza del varco. Dettagli in `findings.md`, F14.

## Allineamento del volto

ArcFace/MobileFaceNet richiedono un volto allineato sui 5 landmark a 112×112.
Su VGGFace2 ridimensionato senza allineamento l'accuratezza era 10,4%; con
detection e allineamento di InsightFace sale a 97,8%. Le immagini DigiFace
sono già allineate.

## File

| file | ruolo |
|---|---|
| `embedding.py` | carica MobileFaceNet/ResNet; `embedding()` (volti già allineati, es. DigiFace) e `embedding_allineato()` (volti grezzi → detect+align+embed, es. VGGFace2) |

La valutazione 1:N è in `benchmark/identificazione_1n.py` (la CNN è una tecnica come le
altre). I modelli si scaricano da soli al primo uso (`~/.insightface/models/`).

## Costo FHE (F15)

Match cifrato a dim 512: ~63 ms/query (< gradino 07, dim 3776), quantizzazione 6
bit senza perdita (DIR=1% 89,3% float = quant). `costo.py`.

Qui la notazione abbreviata `DIR=1%` indica il DIR al punto FPIR=1%.
Il tempo riguarda soltanto l'esecuzione del circuito dei punteggi, con
input già cifrato: non comprende la rete neurale, la cifratura, la
decifratura o l'argmin cifrato.

## 08b - Confronto con ResNet50 (F16)

Sullo stesso protocollo ResNet50 (`buffalo_l`) ottiene risultati lievemente
superiori a MobileFaceNet: DIR@FPIR=1% su VGGFace2 97,0% contro 96,0%; Rank-1
98,8% contro 97,8%. Entrambi producono vettori a 512 dimensioni e usano lo
stesso circuito FHE. La differenza maggiore osservata resta quella tra
descrittori locali e CNN.
