# A29 exact-ID: contabilita' condizionale della p-fail

Data: 2026-09-02. Runtime: TFHE-rs 0.11.3. Circuito: A29 ManyLUT, galleria uniforme
`N=127`, 4.965 blind rotation/PBS osservate.

## Risultato

Il vecchio limite «le operazioni sono dipendenti, quindi non si puo' usare una union bound» non e'
corretto. L'indipendenza **non serve**. Se, lungo ogni prefisso eseguito correttamente, si riesce a
dimostrare per l'evento successivo

\[
P(F_i\mid \neg F_1,\ldots,\neg F_{i-1})\le p_i,
\]

allora

\[
P(\text{almeno un fallimento})\le\sum_i p_i.
\]

Applicando soltanto in modo **condizionale** il valore nominale del parameter set,

\[
p=2^{-71.625}=2.74616457523\cdot10^{-22},
\]

si ottiene:

| contabilita' ipotetica | eventi | limite per query | log2 |
|---|---:|---:|---:|
| una failure-event per blind rotation | 4.965 | `1,36347071160e-18` | `-59,347422` |
| una marginale per LWE estratto da una rotazione/PBS, due per ManyLUT | 5.473 | `1,50297587202e-18` | `-59,206884` |

Questi numeri sono corretti aritmeticamente, ma **non sono ancora un bound end-to-end di A29**.
Il lavoro aperto non e' l'unione delle probabilita': e' provare che il valore nominale sia
applicabile, con un limite condizionale valido, a tutti gli ingressi raggiungibili delle LUT custom,
alle due sample extraction ManyLUT e alla decodifica finale.

## Cosa significa il numero del parameter set

Il file dei parametri usato dal binario dichiara:

- sicurezza stimata: 132 bit;
- `lwe_dimension=879`, `glwe_dimension=1`, `polynomial_size=2048`;
- TUniform(46) per LWE e TUniform(17) per GLWE;
- decomposizione PBS `base_log=23`, `level=1`;
- decomposizione KS `base_log=3`, `level=5`;
- message modulus 4, carry modulus 4, `max_noise_level=5`;
- `log2_p_fail=-71.625`.

La documentazione inclusa in TFHE-rs chiama il target una «bootstrapping failure probability» e
spiega che i parametri predefiniti appartengono al modello IND-CPA. Sicurezza 132 bit e p-fail
`2^-71.625` misurano cose diverse: la prima non trasforma la seconda in una garanzia di
affidabilita' del circuito.

Il core A29 usa direttamente le primitive `core_crypto`, scale torus e accumulatori propri. Non
costruisce `shortint::Ciphertext` con il relativo tracker `NoiseLevel`. Di conseguenza il campo
`log2_p_fail` non certifica automaticamente ogni chiamata solo perche' BSK e KSK hanno la geometria
giusta.

## Inventario strutturale a N=127 uniforme

La formula del core e i gate osservati danno:

| stadio | blind rotation/PBS | key switch |
|---|---:|---:|
| score lineare | 0 | 0 |
| estrazione split4 + bridge | 1.905 = `15N` | 1.524 = `12N` |
| selezione dell'argmin sui 12 bit | 2.675 | 2.675 |
| scan first-minimum | 222 | 222 |
| confronto col threshold uniforme | 13 | 13 |
| codifica ID cifrato | 150 | 150 |
| **totale** | **4.965** | **4.584** |

I 508 ManyLUT sono esattamente quattro per template: il bit globale 3 nel bridge low-to-full e i
bit globali 4, 5 e 6 nell'estrattore high. Ciascuno esegue una blind rotation e due sample
extraction. Le altre 4.457 rotazioni producono una uscita; quindi il conteggio conservativo delle
marginali e'

\[
4457+2\cdot508=5473.
\]

Il bit 7 non aggiunge una marginale: riusa byte-per-byte la stessa correction LWE. Le 4.584 key
switch non vengono sommate come altrettante failure-event. Nel percorso shortint `KS_PBS` previsto
dal parameter set, il rumore del KS entra nell'ingresso del PBS associato; finche' non si prova
l'applicabilita' alle primitive raw custom, neppure questo implica che `log2_p_fail` le copra tutte,
ma aggiungere automaticamente ogni KS una seconda volta non e' giustificato. Il DAG ha inoltre
fan-out diffuso: riusa small LWE, winner e `accept_tag`, le due uscite ManyLUT condividono una GLWE
ruotata e tutti gli eventi condividono BSK/KSK. Queste dipendenze non invalidano la union bound,
pero' il limite di ogni evento deve restare valido condizionando sul prefisso corretto.

La scomposizione e' riproducibile dal codice:

```text
extract  = 15*127                                      = 1905
select   = 17*127 + 12*OR4(127), con OR4(127)=43      = 2675
scan     = first_one_scan(127)                         =  222
threshold uniforme                                     =   13
output_code                                             =  150
totale                                                  = 4965
```

## Perche' i due conti restano condizionali

Per promuovere `1,50e-18` a limite della query servono ancora almeno cinque obblighi separati.

1. **Ingressi di ogni PBS.** Per ogni stato raggiungibile sotto un prefisso corretto bisogna
   mostrare distanza dalla discontinuita' della LUT e distribuzione/supporto del rumore dopo
   cifratura iniziale, prodotto GLWE-per-plaintext, sample extraction degli score, somme,
   sottrazioni, shift e KS. Le 254 estrazioni lineari delle due score-lane non sono failure-event
   PBS aggiuntive: il loro rumore deve essere assorbito nella prova dell'ingresso del primo PBS.
   I commenti del core limitano il fan-in Booleano a `max_noise_level=5`, ma il tracker shortint non
   viene eseguito.

2. **Estrazione split4 e fusione A29.** La coda `~2^-609` dell'audit A28 riguardava la correzione
   split4 separata e non puo' essere attribuita alla fusione A29. Per l'ingresso fused peggiore, il
   modello engineering che somma le varianze e usa un'approssimazione Gaussiana fornisce circa
   `2^-154,938` per score (`2^-150,623` includendo separatamente la varianza di modulus switch).
   La sensibilita' alternativa con somma triangolare degli RMS scende fino a circa `2^-38,548`.
   Nessuno di questi tre numeri e' un bound TUniform formale, e il primo non va presentato come
   worst case.

3. **ManyLUT.** Le 508 rotazioni producono due LWE correlate dalla stessa GLWE ruotata. Si puo'
   limitare l'evento comune di rotazione oppure unire due limiti marginali; in nessun caso e'
   lecito assumerle indipendenti. Lo stress FHE 198/198 ha misurato questa correlazione e verificato
   792 coppie, ma non stima una coda di ordine `10^-18`.

4. **Somma finale non rinfrescata.** Il core somma fino a tre `code_groups` freschi e restituisce
   direttamente il risultato a `Delta=2^56`. Serve un termine esplicito per la probabilita' che
   questa somma attraversi il confine di rounding del client; non esiste un PBS successivo che la
   riporti automaticamente al budget nominale.

5. **Modello d'ingresso e implementazione.** Il ragionamento richiede probe onesto e bounded,
   template validi e chiavi corrispondenti. Il server controlla geometria della chiave, forma del
   probe e template clear, ma non puo' provare che il plaintext cifrato rispetti `[-3,3]` o che la
   evaluation key sia legata alla secret key del client. Errori FFT/implementativi vanno inoltre
   distinti dal modello analitico del rumore.

Sia `A` l'insieme esplicito delle assunzioni: client onesto e bounded, template validi, chiavi
generate onestamente e abbinate, evaluator/server onesto, software, hardware, serializzazione e
trasporto corretti. Dentro questo modello il bound dovra' avere la forma:

\[
P(\text{output errato}\mid A)
\le
\sum_i P(F_i\mid A,\text{prefisso corretto})
+P(F_{\mathrm{decode\ finale}}\mid A,\text{tutti i PBS corretti}).
\]

Fuori da `A` non viene dichiarata alcuna garanzia probabilistica. Un termine `P(A^c)` si puo'
aggiungere soltanto introducendo e giustificando una distribuzione sulle violazioni delle
assunzioni; non e' corretto inventare `P(F_assunzioni)` senza quel modello.

## Cosa dicono davvero gli esperimenti

La suite primaria vincolata registra 632 risposte decifrate, zero discrepanze semantiche e zero
errori operativi. Sotto un modello Bernoulli iid, il limite
esatto unilaterale al 95% per zero fallimenti e'

\[
1-0.05^{1/632}=0.00472886625,
\]

cioe' circa 0,473% per query. Non e' vicino a `10^-18`; inoltre le query riusano una sola chiave e
non sono iid in senso crittografico. Le 198 boundary, le 198 semantic, le 80 frontier e le sei
Docker sono evidenza funzionale complementare, non vanno fuse meccanicamente in un campione iid.

Quindi:

- `0/632` sostiene la correttezza empirica sul campione;
- la union bound condizionale chiarisce l'aritmetica del target;
- nessuno dei due certifica ancora la p-fail del sistema.

## Percorso per chiudere il gate

1. Estrarre dal core un inventario machine-checkable di ogni famiglia di LUT: codici raggiungibili,
   fan-in, scala, KS precedente, numero di chiamate e margine minimo.
2. Propagare il rumore lungo il prefisso corretto con le formule ufficiali TUniform, mantenendo
   separati bound dimostrati e approssimazioni Gaussiane.
3. Trattare le due uscite ManyLUT come marginali correlate o come unico evento geometrico di blind
   rotation, senza ipotesi di indipendenza.
4. Derivare il termine della somma/decode finale a `Delta=2^56`.
5. Eseguire un audit indipendente delle formule e scegliere soltanto allora il linguaggio della
   tesi: `bound condizionale`, `stima engineering` o `problema aperto`.

## Riproducibilita' e provenienza

Comando:

```sh
uv run python benchmark/a29_pfail_accounting.py \
  --output benchmark/results/exact_id_manylut_pfail_accounting_2026-09-02.json
```

Lo script non riceve override per conteggi o `log2_p_fail`: estrae il core A29 completo dal membro
new-file della patch congelata, senza dipendere dal `private_argmin.rs` vivo; ricostruisce lo stage
breakdown per `N=127`, verifica `ManyLUT=4N` e `KS=PBS-3N`, legge
success/query/errori/discrepanze dal JSON primario e fallisce se uno degli hash congelati cambia.
Non inserisce un timestamp di generazione; due esecuzioni canoniche consecutive hanno prodotto
byte identici anche dopo l'avanzamento del worktree ad A33.

SHA-256:

- core A29 `private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- patch sorgente A29:
  `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54`;
- JSON/CSV della suite primaria:
  `328964c860919cfce2ae09ec3ac1e2ab1f3efcc7d25c1a9781ee1ee7dafa0b34` /
  `7337057cc97eeafe102cd330df154f31656e142a97029ac388dbd8aefd8eed5b`;
- parameter file TFHE-rs 0.11.3:
  `14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6`;
- README TFHE-rs 0.11.3:
  `c224297542eff2e6bae585b320144be02b6475dd43656be2c59aaed41d704052`;
- script:
  `5e68a2eeb89d3725b742c870e780cebf1a34abc2c99c89cd8420829baf443292`;
- JSON:
  `f18da093a5b611d04bc5cdc1f3da931246ac5f7acb723780f6496c71a9e6672b`.

Fonti locali vincolate:

- parametro: `tfhe-0.11.3/src/shortint/parameters/classic/tuniform/`
  `p_fail_2_minus_64/ks_pbs.rs:8-25`;
- definizione del modello di sicurezza: `tfhe-0.11.3/README.md:188-203`;
- formula di costo, accumulatori ManyLUT, score, estrazione, quattro fusioni per template, gate e
  assert dei conteggi: core A29 congelato SHA-256
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`, ricostruibile dalla patch
  `benchmark/patches/a29_manylut_source_2026-09-02.patch`; le righe del sorgente vivo possono
  spostarsi con gli esperimenti successivi;
- percorso shortint KS -> PBS: `tfhe-0.11.3/src/shortint/server_key/mod.rs:812-826`; scelta
  `EncryptionKeyChoice::Big` -> `KS_PBS`: `tfhe-0.11.3/src/shortint/parameters/mod.rs:185-193`;
- scale custom e somma finale: stesso core A29 congelato;
- rounding client: funzione `encode_probe_coefficients` dello snapshot `src/bin/varco_demo.rs`
  incluso nella stessa patch.

Il JSON porta lo stato esplicito
`conditional_accounting_not_end_to_end_certificate`; il suo valore principale non deve essere
rinominato in `p-fail A29` finche' gli obblighi sopra non sono chiusi.
