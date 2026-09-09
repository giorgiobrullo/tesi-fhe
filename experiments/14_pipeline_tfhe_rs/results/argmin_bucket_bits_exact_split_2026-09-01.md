# Argmin exact a bit: evidenza del percorso Delta51 + modulo16

Data: 2026-09-01. Host Apple Silicon, tfhe-rs 0.11.3, parametri
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` (`log2_p_fail=-71.625`, valore nominale
della primitiva del parameter set, non un bound del circuito composto).
I tempi escludono generazione delle chiavi e compilazione. Ogni invocazione genera chiavi nuove.

Contratto verificato: un solo LWE di uscita, `0=rifiuto`, `indice+1=match`; nessuna distanza
decifrata o restituita. L'argmin esatto seleziona il primo indice in caso di parita'.

## Tentativi scartati

### Correzioni Delta51 ridimensionate per tutti i tredici bit, input non centrato

Comando:

```text
RAYON_NUM_THREADS=8 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --cases adversarial --low-bit 0 --bool-log 60 \
  --capture-from-bit 0 --sizes 64
```

Risultato: `6.261593 s`, ma indice `9` anziche' `32`. I rami 12..3 erano corretti;
i bit 2 e 0 ridimensionati hanno invertito la selezione. Le correzioni dei bit bassi non hanno
margine sufficiente dopo l'amplificazione pubblica.

### Correzioni alte + ricodifica Delta51 dei bit 2..0, input non centrato

N=64: indice e decisione finali corretti in `7.306344 s`, ma il controllo globale ha trovato
un errore al bit 2 e due al bit 1 su template gia' esclusi. N=128: output corretto in
`14.635399 s`, ma tre errori al bit 2 e tre al bit 1. Il requisito finale e' zero errori su tutti
i template, quindi questa variante e' scartata anche se gli errori inattivi non cambiarono questi
due output.

### Input centrato con `+Delta/2`

La centratura suggerita dall'algebra del confronto periodico non e' compatibile con il residuo
dell'estrattore sequenziale:

- correzioni catturate 0..11: N=64 `6.755849 s`, errori a partire dal bit 7 e indice `2` invece
  di `32`;
- ricodifica di tutti e tredici gli output piccoli: N=64 `7.761313 s`, errori ai bit 5..1 e
  indice `0` invece di `32`.

Entrambe le codifiche centrate sono scartate.

## Soluzione esatta: canale alto Delta51 + residuo modulo16 Delta60

Il punteggio traslato `x=score-L` viene valutato due volte sotto la stessa chiave:

- `x * 2^51`: l'estrattore completo produce i bit 12..3; le correzioni grandi dei bit 11..3
  alimentano direttamente le LUT e soltanto il bit 12 viene ricodificato;
- `(x mod 16) * 2^60`: un estrattore a quattro bit produce correzioni esatte per i bit 2..0,
  gia' negli slot booleani 8, 4 e 2 con `Delta_bool=2^59`.

La selezione lessicografica usa tutti i bit 12..0. Il controllo di soglia e' una macchina
booleana sullo stesso cammino scelto. Per il percorso reale i due encoding sono impacchettati in
un solo GLWE: coefficienti 0..511 a Delta51 e 1024..1535 a Delta60; con il polinomio galleria di
supporto 0..511, i prodotti occupano 0..1022 e 1024..2046 e non si sovrappongono.

### Sintetico avversario, N=64, 8 thread

```text
RAYON_NUM_THREADS=8 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --cases adversarial --low-bit 0 --bool-log 59 \
  --capture-from-bit 3 --sizes 64
```

```text
RESULT,1,synthetic,bit_boundaries_first_bucket_tie,64,32,32,true,true,0.006250,2.397288,4.520877,0.581373,0.141837,7.647624,true,true,true,true,true
DIAG,bit_errors_by_position=[(12,0),(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],actual_candidates=[32,33],expected_candidates=[32,33]
SUMMARY,all_correct=true,all_under_10s=true
```

### Sintetico avversario, N=128, 8 thread

```text
RAYON_NUM_THREADS=8 target/release/argmin_bucket_bits_periodic --run --keys 1 \
  --cases adversarial --low-bit 0 --bool-log 59 --capture-from-bit 3 --sizes 128
```

```text
RESULT,1,synthetic,bit_boundaries_first_bucket_tie,128,reject_sentinel,reject_sentinel,false,false,0.013151,4.672315,7.833086,0.932673,0.345445,13.796670,true,true,true,true,false
DIAG,bit_errors_by_position=[(12,0),(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],actual_candidates=[64,65],expected_candidates=[64,65]
SUMMARY,all_correct=true,all_under_10s=false
```

### Sintetico avversario, N=128, 16 thread

```text
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic --run --keys 1 \
  --cases adversarial --low-bit 0 --bool-log 59 --capture-from-bit 3 --sizes 128
```

```text
RESULT,1,synthetic,bit_boundaries_first_bucket_tie,128,reject_sentinel,reject_sentinel,false,false,0.012254,4.096964,6.154582,0.755663,0.203490,11.222954,true,true,true,true,false
DIAG,captured_extract_s=3.884806,bridge_s=0.212158,recode_pbs_per_score=1,bit_errors_by_position=[(12,0),(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],active_bits_correct=true,decision_bits_correct=true,candidate_bits_correct=true,threshold_decision_correct=true,actual_candidates=[64,65],expected_candidates=[64,65]
SUMMARY,all_correct=true,all_under_10s=false
```

### Un solo GLWE impacchettato, probe reale

Comando N=64/N=128 (una chiave nuova per ogni N):

```text
RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --cases real --real-probes 1 --low-bit 0 --bool-log 59 \
  --capture-from-bit 3 --sizes both
```

N=64:

```text
RESULT,1,scene,real_probe_0,64,reject_sentinel,reject_sentinel,false,false,0.006112,3.363310,5.613597,0.638081,0.265949,9.887049,true,true,true,true,true
DIAG,bit_errors_by_position=[(12,0),(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],actual_candidates=[38],expected_candidates=[38]
```

Il processo combinato ha superato il timeout di cattura dopo l'intestazione N=128, quindi N=128
e' stato ripetuto isolatamente con una nuova chiave:

```text
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic --run --keys 1 \
  --cases real --real-probes 1 --low-bit 0 --bool-log 59 --capture-from-bit 3 --sizes 128
```

```text
RESULT,1,scene,real_probe_0,128,reject_sentinel,reject_sentinel,false,false,0.049686,8.355840,8.605778,0.748321,0.215677,17.975303,true,true,true,true,false
DIAG,captured_extract_s=7.801984,bridge_s=0.553856,recode_pbs_per_score=1,bit_errors_by_position=[(12,0),(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],active_bits_correct=true,decision_bits_correct=true,candidate_bits_correct=true,threshold_decision_correct=true,actual_candidates=[38],expected_candidates=[38]
SUMMARY,all_correct=true,all_under_10s=false
```

Quest'ultimo tempo e' stato misurato mentre altri benchmark TFHE giravano sulla stessa macchina
(la generazione chiavi era anch'essa circa 2x piu' lenta) e non va confrontato come misura isolata
con il sintetico a 16 thread. E' invece evidenza di correttezza del percorso GLWE impacchettato.

## Stato di questa evidenza

- rappresentazione e ordinamento sono aritmeticamente esatti; nei run cifrati a N=64 e N=128,
  inclusi tie al primo indice, accettazione e rifiuto, sono stati osservati zero errori su tutti i
  bit di tutti i template;
- questi run non stimano ne' limitano il `p-fail` del circuito composto;
- canale reale impacchettato in un solo GLWE verificato end-to-end;
- N=64 sotto 10 secondi;
- N=128 ha prodotto l'output corretto nel run ma resta sopra il tetto: migliore misura isolata
  `11.222954 s` a 16 thread.
