# Argmin TFHE esatto N=128 sotto 10 s: dominio a 12 bit

> **Storico: prova di fattibilita' precedente all'integrazione e ai tre hardening del rumore.** La
> prova dell'esattezza del dominio a 12 bit e le diagnostiche di estrazione restano valide per la
> revisione misurata. Il titolo "sotto 10 s" descrive soltanto alcuni run isolati di quel circuito:
> non e' un gate del core corrente. Lo stato canonico e' in `../../../README.md` e
> `../../../status.md`; la cronologia tecnica degli hardening e' in
> `../../../benchmark/results/exact_id_noise_hardening_2026-09-01.md`.

Data: 2026-09-01. Host Apple Silicon, 16 thread Rayon, tfhe-rs 0.11.3, parametri
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` (`log2_p_fail=-71.625`, valore nominale
della primitiva del parameter set, non un bound del circuito composto).
Ogni `--keys` genera chiavi nuove. I tempi `total_s` escludono generazione chiavi e compilazione.

## Perche' il dominio e' esatto

Per il template pubblico `g_i` e il probe quantizzato `q`, il punteggio usato dal sistema e'

```text
s_i = ||g_i||^2 - 2 <g_i,q>.
```

Il client fidato rifiuta il probe prima della cifratura se `sum_j q_j^2 > 1024` (oltre al bound
coordinata gia' esistente). Cauchy-Schwarz implica quindi

```text
|<g_i,q>| <= sqrt(||g_i||^2 * 1024).
```

Poiche' il prodotto scalare e' intero, il bound implementato usa conservativamente
`ceil_sqrt(||g_i||^2 * 1024)`. Per ogni iscritto:

```text
L_i = ||g_i||^2 - 2 ceil_sqrt(||g_i||^2 * 1024)
U_i = ||g_i||^2 + 2 ceil_sqrt(||g_i||^2 * 1024).
```

Il dominio pubblico della galleria e' `[min_i L_i, max_i U_i]`. Sulla scena q3 corrente:

```text
N=64:  L=-984, U=2293, width=3278
N=128: L=-986, U=2314, width=3301
```

Entrambi stanno in 4096 valori: `x=s-L` usa esattamente dodici bit con `Delta=2^52`. Non c'e'
quantizzazione o perdita di ordinamento. L'enrollment deve ricalcolare il bound e rifiutare una
mutazione della galleria se la larghezza supera 4096.

L'audit empirico separato conferma che il limite client ha margine: massimo `norm2=696` su 17.262
campioni VGGFace2 fusi, `684` su 2.000 probe DigiFace e `671` nella galleria corrente. Questi dati
motivano operativamente il limite 1024; la correttezza deriva comunque dal controllo client, non
dall'osservazione empirica.

## Circuito

- canale alto: punteggio traslato a `Delta=2^52`, estrazione completa di 12 bit; si usano i bit
  11..3;
- canale basso: lo stesso punteggio modulo16 a `Delta=2^60`, estrazione a 4 bit; le correzioni
  grandi forniscono esattamente i bit 2..0 negli slot booleani pesati;
- i due canali del probe reale sono impacchettati in un solo GLWE (coefficienti 0..511 e
  1024..1535); i supporti convoluti 0..1022 e 1024..2046 non si sovrappongono;
- selezione lessicografica cifrata dei dodici bit, primo indice in caso di parita'; macchina
  booleana per `min<=soglia`; output unico `0=rifiuto`, `indice+1=match`; nessuna distanza.

La validazione isolata del canale modulo16, in
`results/score_mod16_lowbits_2026-09-01.md`, conta tre chiavi fresche e quattro probe a N=128:
6.144/6.144 bit raw e 4.608/4.608 bit ricodificati corretti. Sull'intera batteria modulo16/modulo8/
packed: 20.025 raw + 16.506 ricodificati, zero errori.

## Gate di latenza isolato, N=128

```text
RAYON_NUM_THREADS=16 cargo run --release --bin argmin_bucket_bits_periodic -- \
  --run --keys 1 --cases adversarial --low-bit 0 --bool-log 59 \
  --capture-from-bit 3 --probe-norm2-max 1024 --sizes 128
```

```text
KEY,key=1,N=128,generation_s=0.515497,domain_L=-986,domain_U=2314,domain_width=3301,padded_width=4096
RESULT,1,synthetic,bit_boundaries_first_bucket_tie,128,reject_sentinel,reject_sentinel,false,false,0.012258,3.164964,5.257123,0.808592,0.245336,9.488273,true,true,true,true,true
DIAG,captured_extract_s=2.980535,bridge_s=0.184429,recode_pbs_per_score=1,bit_errors_by_position=[(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],active_bits_correct=true,decision_bits_correct=true,candidate_bits_correct=true,threshold_decision_correct=true,actual_candidates=[64,65],expected_candidates=[64,65]
SUMMARY,all_correct=true,all_under_10s=true
```

## Stress a due chiavi fresche, N=64 e N=128

```text
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic --run --keys 2 \
  --cases adversarial --low-bit 0 --bool-log 59 --capture-from-bit 3 \
  --probe-norm2-max 1024 --sizes both
```

```text
RESULT,key1,N64,expected=32,actual=32,match=true,total_s=6.596045,bits_correct=true,correct=true,under_10s=true
RESULT,key1,N128,expected=reject,actual=reject,match=false,total_s=10.745427,bits_correct=true,correct=true,under_10s=false
RESULT,key2,N64,expected=32,actual=32,match=true,total_s=4.792402,bits_correct=true,correct=true,under_10s=true
RESULT,key2,N128,expected=reject,actual=reject,match=false,total_s=10.109244,bits_correct=true,correct=true,under_10s=false
SUMMARY,all_correct=true,all_under_10s=false
```

Tutti i 12 bit di tutti i template sono corretti in ogni run. I due N=128 della sequenza lunga
superano il tetto rispettivamente di 0,745 e 0,109 s; la misura isolata sopra e il probe reale
isolato sotto restano sotto 10 s. La latenza ha quindi sensibilita' osservabile al carico/ordine
delle run e il tetto non va ancora presentato come worst-case garantito.

## Probe reale, un solo GLWE impacchettato, N=128

```text
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic --run --keys 1 \
  --cases real --real-probes 1 --low-bit 0 --bool-log 59 --capture-from-bit 3 \
  --probe-norm2-max 1024 --sizes 128
```

```text
KEY,key=1,N=128,generation_s=0.511248,domain_L=-986,domain_U=2314,domain_width=3301,padded_width=4096
RESULT,1,scene,real_probe_0,128,reject_sentinel,reject_sentinel,false,false,0.007009,3.291804,5.013661,1.004072,0.337151,9.653697,true,true,true,true,true
DIAG,captured_extract_s=3.109483,bridge_s=0.182320,recode_pbs_per_score=1,bit_errors_by_position=[(11,0),(10,0),(9,0),(8,0),(7,0),(6,0),(5,0),(4,0),(3,0),(2,0),(1,0),(0,0)],active_bits_correct=true,decision_bits_correct=true,candidate_bits_correct=true,threshold_decision_correct=true,actual_candidates=[38],expected_candidates=[38]
SUMMARY,all_correct=true,all_under_10s=true
```

## Stato

- gate funzionale del percorso aritmeticamente esatto: superato nei run osservati (zero errori
  osservati, chiavi fresche, tie/boundary, accept/reject, percorso sintetico e reale impacchettato);
- questi run non stimano ne' limitano il `p-fail` del circuito composto;
- gate N=64: superato con margine;
- gate N=128 isolato: superato (`9.488 s` sintetico, `9.654 s` reale);
- worst-case sotto carico/sequenza: non ancora garantito, massimo osservato in questa batteria
  `10.745 s`;
- il contratto non espone la distanza: soltanto rifiuto oppure identita'.
