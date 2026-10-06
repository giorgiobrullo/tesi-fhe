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
| `adaface.py` | carica il checkpoint esterno CVLface AdaFace IR101 WebFace12M; estrae embedding sul client |
| `_adaface_net.py` | backbone AdaFace incorporato, con [licenza MIT](LICENSE.AdaFace-MIT) |

La valutazione 1:N è in `benchmark/identificazione_1n.py` (la CNN è una tecnica come le
altre). I modelli si scaricano da soli al primo uso (`~/.insightface/models/`).

<a id="costo-fhe-f15"></a>

## Costo FHE degli score

La [serie per dimensione](../../benchmark/results/velocita_dimensione.csv)
misura **151,9 ms/query a 512 dimensioni** e **62,7 ms a 128 dimensioni**,
con punteggi cifrati uguali al calcolo quantizzato in chiaro. Il valore a
128 dimensioni non va usato come costo del vettore completo a 512 dimensioni.
In questa serie il costo a piena dimensione supera i circa 75–95 ms dei
descrittori del gradino 07; non è un confronto appaiato fra le due costruzioni.

La prova di quantizzazione MobileFaceNet su DigiFace, descritta in
[F14](../../docs/risultati/diario/f00-f14.md#f14), usa 100 identità con 12 foto
ciascuna, metà in galleria: a sei bit la DIR al punto empirico FPIR=1%
è 89,3% sia float sia quantizzata. L'assenza di perdita vale per quel
campione e non per ogni configurazione. Il diario distingue anche le altre
serie temporali storiche (63,8 e circa 102–111 ms) e i richiami successivi
che avevano confuso le dimensioni.

Il timer riguarda soltanto l'esecuzione del circuito dei punteggi, con
input già cifrato: esclude rete neurale, cifratura, decifratura e argmin
cifrato. I programmi sono [costo.py](costo.py) e lo sweep
[velocita_dimensione.py](../../benchmark/velocita_dimensione.py); questo
prototipo restituisce gli score al client, non l'uscita cifrata 0/ID del
runtime mantenuto.

## 08b - Confronto con ResNet50 (F16)

Sullo stesso protocollo ResNet50 (`buffalo_l`) ottiene risultati lievemente
superiori a MobileFaceNet: DIR@FPIR=1% su VGGFace2 97,0% contro 96,0%; Rank-1
98,8% contro 97,8%. Entrambi producono vettori a 512 dimensioni e usano lo
stesso circuito FHE. La differenza maggiore osservata resta quella tra
descrittori locali e CNN.

## Confronto opzionale con AdaFace

Il confronto successivo di [scaling_modelli.py](../../benchmark/scaling_modelli.py)
affianca MobileFaceNet, ResNet50, ResNet100 e AdaFace IR101. Anche AdaFace
produce il vettore sul client in chiaro. Per riprodurre questo confronto
servono i dati e le cache descritti dallo script, oltre ai seguenti prerequisiti:

- PyTorch, già presente nel lockfile del progetto, e **`safetensors`**, che
  il caricatore importa separatamente e che non è incluso nel lockfile.
  La versione storicamente usata di quest'ultimo pacchetto non è fissata
  dalle istruzioni del prototipo.
- Il file `model.safetensors` della
  [distribuzione CVLface dell'autore](https://huggingface.co/minchul/cvlface_adaface_ir101_webface12m),
  salvato come `datasets/adaface/cvlface_adaface_ir101_webface12m.safetensors`.
  Il caricatore locale legge questo percorso, senza scaricare automaticamente
  il checkpoint; i pesi restano esterni al repository. Per provenienze e
  condizioni dei materiali si veda [THIRD_PARTY.md](../../THIRD_PARTY.md).

Dalla radice, un'invocazione opzionale del confronto con la dipendenza
aggiuntiva è:

```bash
uv run --with safetensors python benchmark/scaling_modelli.py
```

Questo comando avvia il benchmark biometrico e può creare o riusare cache;
non è un passaggio di installazione o di avvio del runtime TFHE. La risoluzione
corrente di `safetensors` non ricostruisce da sola l'ambiente storico: una nuova
prova deve registrarne la versione e identificare il checkpoint usato.

**Erratum del commento sulla distillazione.** Il
[commento iniziale dello script](../../benchmark/scaling_modelli.py#L13-L15)
non è un risultato sperimentale: questa campagna non valuta la distillazione
e non stabilisce un ordine necessario `student ≤ teacher`, né che la sua
utilità sia limitata all'esecuzione della rete sotto FHE. Il sorgente storico
rimane conservato; i risultati descrivono soltanto i modelli effettivamente
confrontati.

I riferimenti di **ArcFace, MobileFaceNets, AdaFace, VGGFace2, DigiFace-1M e
LFW** sono raccolti nella sezione
[modelli e dataset della bibliografia annotata](../../docs/letteratura/fonti.md#modelli-in-chiaro-e-dataset-biometrici),
con chiavi per la [bibliografia canonica](../../docs/letteratura/bibliografia.bib).
Il riferimento metodologico di un modello non identifica automaticamente
il checkpoint usato e non trasferisce i risultati del paper al protocollo
1:N locale.
