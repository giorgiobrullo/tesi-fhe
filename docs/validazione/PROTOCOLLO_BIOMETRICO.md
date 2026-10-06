# Validazione biometrica della baseline

Protocollo definito il 2 ottobre 2026. Una [prima verifica su nuova galleria](BIOMETRIA_VGGFACE2_20261002.md)
è stata eseguita in chiaro, con provenienza condizionata e foto originali:
non completa la verifica dell'interfaccia o della webcam. Il successivo
[confronto della preparazione UI](BIOMETRIA_UI_20261002.md) valuta una
sensibilità sugli stessi input, già consultati, senza ritarare la soglia.
Il protocollo
serve a misurare su acquisizioni separate l'accuratezza della regola attuale.
Le [precisazioni storiche](../risultati/prototipi-e-correzioni.md#precisazioni-del-2-ottobre-2026)
spiegano perché i risultati precedenti non sostituiscono questa verifica.

La valutazione biometrica si svolge prima in chiaro: chiede se la persona
restituita è corretta. Un controllo FHE successivo chiede se il circuito
restituisce lo stesso esito dell'oracolo intero. Un circuito può concordare
perfettamente con l'oracolo anche quando il modello riconosce la persona
sbagliata. Nessuna delle due verifiche empiriche, da sola, stabilisce la
probabilità formale di fallimento del circuito, ancora aperta nei
[limiti](../limiti.md).

## 1. Congelare la regola da valutare

Per ogni query intera `q` e voce della galleria `g_i`, calcolare:

```text
score_i = ||g_i||² − 2<g_i,q>
j = primo indice che minimizza score_i
esito = j+1 se score_j <= T_j, altrimenti 0
```

Il minimo usa gli score originali, prima di applicare qualunque soglia.
Se il vincitore non passa la propria soglia, si restituisce zero: non si
sceglie un candidato più lontano che ne abbia una più permissiva. A parità
passa la prima voce nell'ordine della galleria. Questa è la regola di
[validate_input](../../demo/web/engines.py), descritta con due candidati
nella [guida al confronto](../come-funziona-il-confronto.md).

La soglia è un limite dello **score**, non una percentuale di somiglianza.
Il termine `||q||²` è comune ai candidati e non cambia il minimo, ma varia
fra query quantizzate: una soglia fissa di score non equivale a una soglia
fissa di distanza euclidea.

Prima di estrarre o valutare il test, salvare un manifest con:

- hash del codice, configurazione, pesi del modello e detector;
- modello, allineamento, normalizzazione, dimensione, quantizzazione e
  comportamento se un frame non contiene un volto;
- preparazione nell’interfaccia prima dell’invio: resize, ricodifica,
  orientamento e limiti; distinguere foto originali dai byte inviati;
- foto/frame usati per iscrizione e per ogni richiesta, metodo di fusione,
  ordine della galleria e mappa `indice_template → persona`;
- soglia comune o metodo per assegnare soglie diverse, punto FPIR scelto e
  criteri di esclusione dei dati.

Il riferimento locale è [runtime/config.json](../../runtime/config.json):
ResNet100, dimensione 512, scala `0,04098006`, componenti fra −3 e 3 e norma
quadratica della query al massimo 1024. La
[preparazione del client](../../runtime/client/embedding.py) rileva e
allinea il volto più grande, media gli embedding disponibili, normalizza
la media e poi quantizza; l'
[iscrizione](../../demo/dual_view/enrollment.py) segue la stessa sequenza.
L’[interfaccia web](../../demo/dual_view/static/shared.js) riduce il lato
maggiore a 1280 pixel e ricodifica in JPEG con qualità 0,9 prima dell’invio.
Eseguire solo detector/embedding sugli originali non include questa fase.
Il manifest deve precisare se usa una foto caricata o tre frame acquisiti,
e quanti frame sono effettivamente rilevati. La vecchia calibrazione 2+3
foto e la galleria web con un ritratto per persona sono condizioni diverse.

Congelare anche i controlli di ammissibilità del servizio. Un fallimento
di estrazione o un vettore fuori dominio è un esito da contare, non un
probe da eliminare dopo aver visto il risultato. Le soglie storiche 4 e
273 nella configurazione sono riferimenti delle rispettive calibrazioni,
non garanzie di accuratezza su una nuova coorte.

## 2. Separare sviluppo, calibrazione e test

Il manifest elenca persona, sessione, immagine/frame e ruolo di ogni
acquisizione. Dividere i dati prima di stimare parametri o scegliere una
configurazione:

| Insieme | Uso consentito |
|---|---|
| Sviluppo | Scegliere modello, fusioni, eventuale PCA e scala di quantizzazione |
| Calibrazione | Scegliere la soglia o i parametri delle soglie usando una galleria e richieste dichiarate |
| Test riservato | Misurare una sola configurazione già congelata |

Per valutare la configurazione attuale, si può conservare la scala già
fissata; il test deve però usare dati che non siano stati impiegati per
sceglierla o scegliere quella configurazione. Risuddividere il vecchio
pool dopo averne osservato i risultati non crea un test indipendente.
Se si vuole ristimare scala o PCA, farlo solo sullo sviluppo e dichiarare
la nuova configurazione come variante separata.

Nel test, le foto d'iscrizione e le richieste genuine della stessa persona
devono essere diverse; per qualificare l'uso della webcam preferire anche
sessioni diverse. Gli sconosciuti usati per calibrare la soglia devono
avere identità disgiunte dagli iscritti e dagli sconosciuti del test.
Una persona usata nello sviluppo non deve ricomparire nel test riservato
di una valutazione su nuove identità. Documentare anche ciò che si sa,
o non si sa, dell'eventuale sovrapposizione con il training del modello
pre-addestrato.

Due domande richiedono protocolli differenti. Per una **galleria fissa**,
si può iscrivere la coorte di test e calibrare la soglia con sconosciuti
di sviluppo contro quella stessa galleria; la conclusione sarà condizionata
a quella galleria e riguarderà nuovi probe. Per misurare il trasferimento
a **nuove gallerie**, scegliere i parametri su gallerie di sviluppo e
valutarli su persone iscritte diverse. Dichiarare quale domanda si misura.
In entrambi i casi, non usare i probe riservati per scegliere parametri.

La separazione deve valere anche attraverso tutti gli split: una persona
usata per selezionare la configurazione in uno split non diventa un test
indipendente soltanto perché cambia ruolo nel successivo. Se si riportano
split ripetuti con persone condivise, presentarli come sensibilità alla
suddivisione, conservare le sovrapposizioni e non sommare le osservazioni
come se fossero soggetti indipendenti.

## 3. Calibrare la decisione completa

Con una soglia comune, calcolare il minimo degli score di ciascuna ricerca
di uno sconosciuto della calibrazione. Tra i valori osservati, scegliere
il massimo intero T per cui la quota di minimi `<= T` non supera il punto
FPIR prefissato. Se nessun valore osservato lo consente, scegliere il
minimo osservato meno uno.
La funzione [soglia_inclusiva](../../demo/calibra.py) mostra questo calcolo:
gestire i pareggi è necessario, perché un percentile seguito da `<=` può
accettare più richieste del previsto.

Bloccare T prima del test e applicarlo a tutte le richieste riservate.
La calibrazione è **globale per la configurazione dichiarata**: un'unica
T, oppure una procedura completamente fissata per ottenere i `T_i`.
Non scegliere la soglia dopo aver letto la FPIR del test e non scegliere
retrospettivamente il miglior seed. La mediana di soglie ricavate da
più split è una procedura possibile di sviluppo; richiede poi un test
separato della singola soglia ottenuta.

Con soglie per template, congelare il metodo di assegnazione e verificare
sulla calibrazione la decisione **primo argmin originale, poi soglia del
vincitore**. Non sostituirla con `min(score_i−T_i)` o con «almeno un
template passa»: sono altre regole. Registrare e verificare la FPIR
aggregata della galleria, soprattutto se contiene soglie di domini diversi.
Cambiare il numero o la composizione degli iscritti può cambiarla.

## 4. Contare ricerche, identità e sessioni

Riportare `N_id`, persone iscritte, e `N_template`, vettori confrontati.
Se una persona ha più template, convertire l'indice del vincitore nella
sua identità prima di calcolare le metriche. Una ricerca che sceglie una
foto diversa della persona corretta resta un'identificazione corretta.
Una media di più frame produce un solo probe, non più ricerche indipendenti.

| Metrica | Numeratore e denominatore |
|---|---|
| Rank-1 senza soglia | Ricerche genuine il cui primo minimo appartiene alla persona corretta / ricerche genuine con vettore ammissibile |
| TPIR, qui equivalente al DIR a rank 1 | Ricerche genuine con identità corretta e vincitore accettato / ricerche genuine ammissibili |
| FNIR a rank 1 | `1 − TPIR`, con lo stesso denominatore |
| FPIR | Ricerche di sconosciuti che restituiscono qualsiasi ID nonzero / ricerche di sconosciuti ammissibili |

Le definizioni di ricerca con e senza identità corrispondente seguono
[NIST FRTE 1:N](https://pages.nist.gov/frvt/html/frvt1N.html), applicate qui
all'unico candidato restituito e all'ordinamento crescente dello score.
FPIR riguarda le **ricerche**, non tutte le coppie probe/template.
Il progetto non replica il benchmark NIST.

Riportare separatamente, fra le ricerche genuine, i rifiuti e gli accessi
con identità errata. Per tutte le acquisizioni tentate, riportare anche
fallimenti di estrazione e rifiuti di dominio, numero di frame utilizzati
e quota di identificazioni corrette sul totale dei tentativi. Questo
evita che una buona metrica condizionata ai volti estratti nasconda
fallimenti dell'acquisizione. Conservare ogni conteggio, non solo le
percentuali, e la FPIR effettiva del test accanto al punto scelto in
calibrazione.

Per l'incertezza, trattare persona e sessione come unità: fotografie o
frame ripetuti della stessa persona non sono osservazioni indipendenti
della popolazione. Fissare prima se si pesa ogni persona ugualmente o ogni
tentativo e usare intervalli o ricampionamenti coerenti con questa scelta.
Un intervallo binomiale per ricerca è appropriato solo se l'indipendenza
è giustificata. Per esempio, zero falsi accessi su 500 ricerche indipendenti
dà ancora un limite superiore unilaterale al 95% di circa 0,6%: non
qualifica una FPIR dello 0,01%.

## 5. Separare quantizzazione e correttezza FHE

Sul medesimo split riservato, confrontare float e intero senza ristimare
parametri sul test. Per isolare l'effetto della quantizzazione, il
riferimento float deve usare la stessa regola dello score; esprimere
gli score float nelle unità intere dividendo per `scala²`. Dichiarare
se la soglia è quella comune congelata oppure se ogni rappresentazione
è stata calibrata separatamente sullo sviluppo. Sono confronti diversi.
Registrare cambi di vincitore, cambi di accettazione e variazioni delle
metriche biometriche. Un confronto con la distanza euclidea completa
può essere una diagnostica aggiuntiva, ma non sostituisce questa misura.

L'oracolo intero usa esattamente vettori, ordine, soglie e regola della
baseline, con aritmetica senza overflow. Solo dopo la valutazione in
chiaro, scegliere un sottoinsieme FHE preregistrato con query positive,
sconosciuti, pareggi e casi vicini alla soglia; conservare gli ID di tutti
i casi, anche quelli falliti. Per ogni cifrato riportare esito atteso,
esito decifrato e identità del codice/binario, parametri e famiglia di
chiavi. Il conteggio di concordanza risponde alla correttezza aritmetica
sui casi provati, non all'accuratezza biometrica o a un bound formale.

## 6. Artefatti necessari prima di dichiarare la validazione

Conservare manifest delle partizioni con hash dei file, configurazione
congelata prima del test, hash dei vettori prodotti, tabella per ricerca
con persona/sessione/esito e conteggi aggregati. Per i tempi, usare un
report separato con CPU, thread e fasi misurate. Non sovrascrivere CSV,
cache o figure delle campagne precedenti: ogni nuova valutazione ha una
cartella datata e un collegamento alle condizioni che misura.

La [galleria di 120 ritratti](../../demo/web/gallery/README.md) permette
di provare il percorso del servizio; le prove con la fotografia già
iscritta non soddisfano questo protocollo. Questo documento definisce
la verifica; il [primo risultato](BIOMETRIA_VGGFACE2_20261002.md) conserva
separatamente condizioni, fallimenti e limiti. Nessuna garanzia generale
di accuratezza della demo deriva dal protocollo.
