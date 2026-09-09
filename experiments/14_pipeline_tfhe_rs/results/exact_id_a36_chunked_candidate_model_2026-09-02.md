# A36: chunk da quattro valido, fusione interlacciata `B=13` respinta

Data: 2026-09-02. Questo e' un audit statico e un modello clear separato: non e' stato eseguito
alcun workload FHE/Cargo e non e' stato modificato il core A33 congelato.

## Esito

La fusione proposta al confine del chunk, con peso `B=13`, accumulatore raw `p=32` ed estrazioni
ai gradi `0` e `N/32`, e' esatta nei punti centrali ma **non ha il margine di input dichiarato**.
Va quindi respinta.

Resta invece valida nel modello strutturale la variante **non fusa**:

- stato attivo `2`, inattivi in `0,-2,...,-8`;
- aggiornamento lineare `state <- state + z - a`, con `z=2` solo per
  `state=2, bit=0` e `a=OR(z)` alla stessa scala;
- bit `b7..b0` pesati `[-2,-2,-2,-2,-2,8,-4,-2]` a partire dagli output A33
  `[1,1,1,1,1,8,4,2]`;
- un canonicalizzatore separato dopo `b4` che riemette `0/2` e uno dopo `b0` che emette
  il Booleano `0/1` richiesto dallo scan A33 invariato.

Questa sostituzione usa `8N` zero-PBS e `2N` canonicalizzatori invece di `8N+4N`: a `N=127`
risparmia strutturalmente **254 blind rotation, 254 key switch e 254 marginali di output**. Applicata
senza altre modifiche al candidato A33 da `4.273 PBS / 3.892 KS`, la proiezione e'
`4.019 PBS / 3.638 KS`. Non e' ancora una misura FHE ne' uno snapshot promosso.

## Perche' la fusione raw `p=32` non passa

Dopo `b4`, lo stato clear e' `2` per un candidato attivo e appartiene a
`{0,30,28,26,24}` modulo 32 per un inattivo. Con `B=13`, i due casi attivi di `b3` sono:

| stato | bit | input modulo 32 | canonical | `z` | centri raw `p=32` |
|---:|---:|---:|---:|---:|---:|
| 2 | 0 | 2 | 2 | 2 | 4, 5 |
| 2 | 1 | 15 | 2 | 0 | 30, 31 |
| 0 | 0 | 0 | 0 | 0 | 0, 1 |

Un codice a `Delta_bool` occupa un centro pari della griglia `p=32`. Le estrazioni `0` e `N/32`
leggono quindi due box adiacenti, separati nel dominio di input da `Delta_bool/2`.

Gli offset pubblici distinti delle due uscite non risolvono il problema. Se rendono uguali i due
coefficienti raw necessari per la coppia inattiva `(0,0)`, la coppia attiva `(2,0)` deve usare due
coefficienti diversi; se rendono uguale quest'ultima, diventa diversa la coppia inattiva. Almeno un
input raggiungibile richiede dunque valori raw diversi in due centri adiacenti. Il miglior margine
simultaneo e' al massimo meta' della loro distanza, cioe' **`Delta_bool/4`**, non `Delta_bool`.

Anche usando il conto ottimistico della proposta (`L1=10` all'ingresso fuso), quel margine equivale
a 20 unita' rispetto al mezzo-slot `p=16`, contro `max_noise_level=5`.

Il modello contiene inoltre una ricerca finita a granularita' di grado polinomiale. Sono stati
enumerati:

- tutti i pesi non nulli `B mod 32` (`1..31`);
- tutti i secondi gradi di estrazione raw `1..2047`;
- tutte le `64^2` coppie di offset pubblici sulla griglia `Delta_bool/2`, sufficiente per le
  equazioni di compatibilita' con uscite `0/2` e negaciclicita';
- tutti gli stati attivi/inattivi raggiungibili al confine dopo `b4`, entrambi i valori di `b3`
  e i loro antipodi.

Non esiste alcun layout raw a due estrazioni con margine aperto `Delta_bool`. La conclusione negativa
e' limitata a questa **sample extraction raw interlacciata**. Una costruzione universale multi-value
basata su moltiplicazione polinomiale, PFKS o vertical packing non e' stata valutata e non viene
esclusa da questo controesempio.

## LUT non fusa compatibile

Il fallback usa una LUT raw `p=16` a uscita singola. Nel corpo firmato di 2.048 coefficienti:

- il test intermedio `state==2` vale `2` nell'intervallo di rotazione semiaperto
  `[N/16,3N/16)`, `-2` sull'antipodo e zero altrove;
- il finalizzatore usa lo stesso intervallo e lo stesso margine, ma vale `1`/`-1`, cosi' l'uscita
  torna alla scala Booleana A33 `0/1` senza un'altra operazione;
- l'OR step-two vale `2` in `[N/16,9N/16)`, `-2` sull'antipodo e zero altrove.

Le transizioni cadono nei codici dispari inutilizzati. Tutti i centri raggiungibili conservano il
risultato per `|errore| < N/16`, equivalente a un margine aperto `Delta_bool`; il codice antipodale
18 del target 2 non e' mai raggiungibile. I range clear restano fra `-8` e `10`, quindi non si
introducono collisioni modulo 32.

Questo `Delta_bool` e' il margine nominale di 128 bin sulla griglia della blind rotation per
`N=2048`. Nel toro continuo resta la convenzione di arrotondamento di mezzo bin del modulus switch;
il successivo run FHE e l'accounting p-fail devono quindi validare il caso senza trasformare questo
audit L1 in una garanzia probabilistica.

La compatibilita' con gli output esistenti e' soltanto lineare:

| bit | peso A33 | peso A36 | adattamento clear | peso L1 del bit |
|---:|---:|---:|---:|---:|
| `b7..b3` | 1 | -2 | moltiplica per -2 | 2 |
| `b2` | 8 | 8 | riuso diretto | 1 |
| `b1` | 4 | -4 | negazione | 1 |
| `b0` | 2 | -2 | negazione | 1 |

Per non assumere una nuova uscita dall'accumulatore precedente, il modello scala inoltre il
candidato A33 fresco `0/1` per due: il primo chunk parte quindi conservativamente da `L1=2`.

## Bound strutturale del rumore

Ogni `z` e ogni uscita dell'OR dedicato sono trattati come una marginale fresca. L'OR radix-4 usa
al massimo quattro marginali. Con margine doppio rispetto al mezzo-slot standard, il bound viene
normalizzato dividendo `L1` per due:

| ingresso | `b7` | `b6` | `b5` | `b4` | canon. `b4` | `b3` | `b2` | `b1` | `b0` | canon. `b0` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `L1` | 4 | 6 | 8 | 10 | 10 | 3 | 4 | 6 | 8 | 9 |
| equivalente mezzo-slot | 2 | 3 | 4 | **5** | **5** | 1,5 | 2 | 3 | 4 | 4,5 |

Il massimo e' esattamente cinque: la route e' compatibile col bound locale conservativo, ma non ha
slack in `b4`. Come per gli audit precedenti del core low-level, questo e' un conto geometrico/L1 e
non una derivazione della `p-fail` end-to-end.

## Verifica clear riproducibile

Artefatti:

- `benchmark/a36_chunked_candidate_model.py`;
- `tests/test_a36_chunked_candidate_model.py`.

Comandi eseguiti:

```text
python3 -m unittest tests.test_a36_chunked_candidate_model
python3 benchmark/a36_chunked_candidate_model.py \
  --random-patterns-per-size 2 --exhaustive-through 4 --skip-max-gallery-pairs
```

Esito unit test: `8/8`. La matrice clear aggiuntiva passa `17.364/17.364` casi:

- 128 gallerie all-reject e 128 tie completi;
- tutte le 8.256 posizioni di vincitore su `N=1..128`;
- 8.256 casi no-resurrection con l'unico candidato attivo deliberatamente peggiore degli inattivi;
- 256 pattern pseudocasuali deterministici;
- 340 combinazioni esaustive a quattro stati per template fino a `N=4`.

La prova semantica confronta i sopravvissuti dopo ogni scan completo con l'insieme degli iscritti
inizialmente attivi aventi suffisso minimo, e applica poi il tie-first. Non valida ancora accumulatore
Rust eseguito, distribuzione reale del rumore o latenza.

## Prototipo Rust isolato materializzato

E' stato materializzato anche `tmp/a36-chunked-candidate-prototype`, un crate separato che dipende
dal source snapshot A33 congelato tramite la feature diagnostica, senza modificarlo. Il prototipo:

- rifiuta l'avvio se `private_argmin.rs` non conserva lo SHA-256
  `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d`;
- riusa dal trace A33 i candidati cifrati dopo `b8` e gli otto ciphertext pesati di `b7..b0`, senza
  decrypt-then-reencrypt nel circuito;
- applica soltanto il fallback non fuso raw `p=16`, con refresh `0/2` dopo `b4` e finalizzazione
  `0/1` dopo `b0`;
- confronta, per ogni livello, stato, peso, ingresso LUT, `z`, OR, aggiornamento lineare e refresh
  decifrati con la fixture clear e confronta l'uscita finale anche con A33;
- conta separatamente blind rotation, key switch e marginali di output; ciascun nodo A36 ha una
  sola estrazione, quindi i tre conteggi coincidono per costruzione verificata;
- include fixture mirate da `N=1` a `N=128`, con all-reject, no-resurrection, tie-first, scala di bit,
  tail dispari `N=127` e codice massimo `127`.

In questa fase il file e' stato soltanto formattato e auditato staticamente. Non e' stato eseguito
alcun comando Cargo, non sono state generate chiavi e non e' stato lanciato alcun PBS/FHE. Quindi il
prototipo materializza il prossimo test, ma **non** converte ancora la proiezione `4.019/3.638` in un
risultato misurato o promovibile.
