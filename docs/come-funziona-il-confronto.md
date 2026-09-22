# Dallo score al risultato: un esempio

La selezione parte da uno **score cifrato per ogni candidato** della galleria.
Lo score è il numero usato per ordinare i candidati: più è basso, migliore
è il candidato. Non è una percentuale di somiglianza. Il motore trova il
minimo, controlla la soglia di quel candidato e restituisce il suo ID oppure
zero. Con FHE, cioè calcolo su dati cifrati, questi passaggi avvengono senza
decifrare gli score o la scelta intermedia.

Qui partiamo dagli score già calcolati; l'acquisizione della foto e la
produzione degli score precedono l'esempio. I numeri sono illustrativi,
non risultati di un nuovo esperimento. Li mostriamo in chiaro per seguire
il calcolo; durante l'esecuzione restano cifrati.

| Candidato | Score | Soglia massima accettata |
|---|---:|---:|
| ID 1 | 26 | 24 |
| ID 2 | 21 | 24 |

## 1. Estrarre le cifre dello score

Il circuito sottrae agli score un offset pubblico comune `L`, poi
rappresenta `score − L` con tre cifre in base 16. Sottrarre lo stesso
valore mantiene l'ordine dei candidati. Nell'esempio scegliamo `L = 0`.
È lo stesso principio della scrittura decimale, ma ogni posizione vale
16 volte quella precedente. Scrivendo dalla cifra bassa alla più alta:

- `26 = 10 + 16 × 1 + 256 × 0` → `[10, 1, 0]`;
- `21 = 5 + 16 × 1 + 256 × 0` → `[5, 1, 0]`.

**Head Start** estrae le cifre a partire dalla più significativa. I
normalizzatori sistemano gli intermedi separando cifra e riporto: per
esempio, un intermedio `r = 21` diventa cifra `5` e riporto `1`. Questo
esempio del riporto descrive l'operazione, non un intermedio misurato
per i due score della tabella. Il normalizzatore condiviso ricava le due
uscite riutilizzando la stessa operazione cifrata costosa.

## 2. Confrontare i due candidati

Si confrontano le cifre dalla più alta. Qui le prime due sono uguali;
decide la cifra bassa: `5 < 10`, quindi vince ID 2. Anche la decisione resta
cifrata. Con più candidati si ripete il procedimento in un **torneo**:
ogni coppia produce un vincitore, poi i vincitori si confrontano fra loro.
A parità di score passa il primo candidato nell'ordine della galleria.

## 3. Portare avanti i dati del vincitore

Il **selettore** usa la decisione cifrata per conservare insieme score,
ID e soglia del vincitore. Dopo questo nodo rappresentano `21`, `2` e `24`.
Non basta conservare lo score: il risultato deve restare associato alla
persona e alla sua soglia.

Gli ID usano la base 15: ID 1 e ID 2 sono `[1, 0, 0]` e `[2, 0, 0]`.
Gli ID e le soglie dei candidati sono pubblici al server, ma la scelta del
vincitore è cifrata. Una cifra uguale in entrambi i rami resta nota anche
dopo la scelta: qui gli zeri degli ID e la soglia comune `24`.

Restano da selezionare tre cifre dello score e una dell'ID. Il **packing**
le raccoglie nello stesso gruppo `[score₀, score₁, score₂, ID₀]` per
selezionarle con una sola rotazione cifrata del gruppo. “Quattro” indica
quattro cifre, non quattro persone. La preparazione di ciascuna cifra
e la rigenerazione del controllo restano necessarie. Con soglie diverse
possono servire altre cifre e altri gruppi.

## 4. Applicare la soglia e restituire l'esito

Si controlla la soglia **del vincitore**: `21 ≤ 24`, quindi l'esito è ID 2.
La soglia è inclusiva: anche `24 ≤ 24` sarebbe accettato. Se il controllo
fallisce, l'esito è `0`, cioè nessun riconoscimento.

Il motore restituisce l'esito cifrato; il client con la chiave segreta lo
decifra. Nell'attuale formato, ID 2 è codificato come tre cifre base 15,
`[2, 0, 0]`. Questa è la divisione dei ruoli del protocollo; nella demo web
pubblicata anche il ruolo client gira sul server che ospita la pagina.

Due variazioni chiariscono la regola:

| Caso | Esito |
|---|---|
| Entrambi hanno score 21 e soglia 24. | ID 1: a parità passa il primo. |
| ID 1 ha score 21 e soglia 20; ID 2 ha score 26 e soglia 30. | 0: vince ID 1, ma non passa la propria soglia. Non si ripiega su ID 2. |

## Dove intervengono le ottimizzazioni

Ogni documento collegato mostra il riferimento precedente, la modifica
e i risultati misurati. Le percentuali dei diversi confronti non si sommano.

| Passaggio | Intervento | Dettagli |
|---|---|---|
| Estrazione e primo torneo | Head Start e selezione PFKS. | [Esperimento 17](../experiments/17_head_pfks_tfhe17/README.md) |
| Normalizzazione | Una rotazione condivisa per cifra e riporto. | [Esperimento 20](../experiments/20_normalizzatori_carry/README.md) |
| Selezione | Evitare il lavoro sulle cifre note e parallelizzare le operazioni indipendenti. | [Esperimento 21](../experiments/21_costanti_pubbliche_parallelismo/README.md) |
| Selezione | Raggruppare fino a quattro cifre, mantenendo il controllo corretto. | [Packing a quattro cifre](validazione/PACK4_VALIDATION.md) |
| Esecuzione sulla CPU | Configurare FFT, compilatore e thread. | [Esperimento 19](../experiments/19_runtime_cpu/README.md) |

## Termini usati nei README

| Termine | Significato nel circuito |
|---|---|
| LWE / GLWE | Due rappresentazioni dei dati cifrati. LWE trasporta un valore, per esempio uno score, una cifra o un controllo. GLWE cifra un polinomio e permette di organizzare le cifre in un gruppo. |
| PFKS | *Private functional key switching*: trasforma i dati cifrati da LWE a GLWE applicando la funzione prevista. Nel selettore prepara le differenze tra i dati dei due candidati. |
| LUT | Tabella che associa a ciascun ingresso un'uscita, per esempio il riporto. |
| Blind rotation | Rotazione di una tabella controllata dall'ingresso cifrato, senza rivelarlo. È una delle operazioni costose conteggiate negli esperimenti. |
| PBS | *Programmable bootstrapping*: valuta una funzione descritta da una LUT e riduce il rumore crittografico. La blind rotation ne è una parte. |
| Rumore / refresh | Il rumore è la perturbazione presente nella rappresentazione cifrata, distinta da variazioni di foto o score. Il refresh rigenera il controllo del selettore per aumentare il margine disponibile. |
| FFT | Trasformata veloce di Fourier, usata per accelerare i calcoli sui polinomi delle operazioni crittografiche. |
| Thread / CGU | I thread eseguono lavoro in parallelo. Le CGU sono le unità in cui il compilatore divide la generazione del codice: CGU1 non significa eseguire con un solo thread. |

La [guida del runtime](../runtime/README.md) riporta la versione attuale
e rimanda alle istruzioni di avvio. I README degli esperimenti conservano
le versioni e le misure storiche di ciascun confronto.
