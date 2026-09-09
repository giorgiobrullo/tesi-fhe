# Canale esatto dei bit bassi: mod 16, mod 8 e packing in un GLWE

Data: 2026-09-01

Harness: `src/bin/score_mod16_lowbits.rs`

## Esito

Il bridge e' risultato strettamente corretto in tutti i test eseguiti:

- 3 chiavi TFHE generate da zero;
- 149 valori avversari per chiave, inclusi tutti i residui modulo 8 e 16, valori negativi e punti a distanza 0, 1 e 2 dai principali confini binari;
- 4 probe reali x 128 identita' per chiave;
- canale GLWE fresco modulo 16 a `Delta=2^60`;
- canale GLWE fresco modulo 8 a `Delta=2^61`;
- layout packed con canale completo a `Delta=2^51` e canale modulo 16 a `Delta=2^60` nello stesso GLWE.

In totale sono stati verificati 20.025 bit grezzi `{0,q/2}` e 16.506 bit bassi ricodificati `{0,2^60}`, senza errori. I test unitari verificano inoltre l'identita' toroidale per ogni intero in `[-65536,65535]`.

Il layout packed usa:

- probe completo nei coefficienti `0..511`, sample al grado 511;
- probe modulo 16 nei coefficienti `1024..1535`, sample al grado 1535;
- polinomio galleria `p[511-j] = -2g[j]` condiviso.

I supporti del prodotto sono rispettivamente `0..1022` e `1024..2046`: non si sovrappongono e non fanno wrap negaciclico con polynomial size 2048. Un solo ciphertext GLWE e un solo prodotto producono quindi entrambi i punteggi, senza riscalare il ciphertext a `Delta=2^51` e senza aumentarne la dimensione.

## Comandi di verifica

```text
rustfmt --edition 2021 src/bin/score_mod16_lowbits.rs
cargo clippy --bin score_mod16_lowbits -- -D warnings
cargo test --bin score_mod16_lowbits
cargo run --release --bin score_mod16_lowbits -- --run --keys 3 --n 128 --probes 4
```

Clippy passa con `-D warnings`; i 3 test unitari passano.

## Output completo del benchmark

```text
CONFIG,params=V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64,log2_p_fail=-71.625,keys=3,N=128,probes=4,domain_L=-2038,domain_U=3357,domain_width=5396,direct_points=149,recode=official_q_over_2_to_bool_q_over_16_shift,packed=delta51_at_0_511_delta60_at_1024_1535
RESULT,key,mode,source,values,raw_bits,raw_errors,low_bits,low_errors,encrypt_s,score_s,bridge_s,input_phase_error_max,input_half_step,input_headroom,recode_phase_error_max,correct
KEY,key=1,generation_s=0.531735,polynomial_size=2048,large_lwe_dimension=2048,small_lwe_dimension=879
RESULT,1,fresh_mod16,direct,149,596,0,447,0,0.008544,0.000000,1.826663,130832,576460752303423488,576460752303292656,2130658113617920,true
RESULT,1,fresh_mod8,direct,149,447,0,447,0,0.007083,0.000000,1.350110,128204,1152921504606846976,1152921504606718772,1731663637774336,true
RESULT,1,fresh_mod16,leveled_real,512,2048,0,1536,0,0.001064,0.029867,5.013769,12321266,576460752303423488,576460752291102222,2047912380989440,true
RESULT,1,fresh_mod8,leveled_real,512,1536,0,1536,0,0.001060,0.029728,4.547872,9730020,1152921504606846976,1152921504597116956,1979854429880320,true
RESULT,1,packed_dual_mod16,leveled_real,512,2048,0,1536,0,0.001058,0.043079,7.970169,11478722,576460752303423488,576460752291944766,2280535292379136,true
PACKED_FULL,key=1,values=512,phase_error_max=10322770,half_step=1125899906842624,headroom=1125899896519854,correct=true
KEY,key=2,generation_s=0.304456,polynomial_size=2048,large_lwe_dimension=2048,small_lwe_dimension=879
RESULT,2,fresh_mod16,direct,149,596,0,447,0,0.014194,0.000000,2.231608,130292,576460752303423488,576460752303293196,1994866011668480,true
RESULT,2,fresh_mod8,direct,149,447,0,447,0,0.007184,0.000000,2.017587,130966,1152921504606846976,1152921504606716010,2050663139770368,true
RESULT,2,fresh_mod16,leveled_real,512,2048,0,1536,0,0.001332,0.100625,8.827759,12415484,576460752303423488,576460752291008004,2117751585898496,true
RESULT,2,fresh_mod8,leveled_real,512,1536,0,1536,0,0.001784,0.078945,7.759996,11514750,1152921504606846976,1152921504595332226,2297282242281472,true
RESULT,2,packed_dual_mod16,leveled_real,512,2048,0,1536,0,0.001341,0.035023,6.392310,11957824,576460752303423488,576460752291465664,2424960882573312,true
PACKED_FULL,key=2,values=512,phase_error_max=11853796,half_step=1125899906842624,headroom=1125899894988828,correct=true
KEY,key=3,generation_s=0.267550,polynomial_size=2048,large_lwe_dimension=2048,small_lwe_dimension=879
RESULT,3,fresh_mod16,direct,149,596,0,447,0,0.007040,0.000000,1.660970,130594,576460752303423488,576460752303292894,1862037034500096,true
RESULT,3,fresh_mod8,direct,149,447,0,447,0,0.007417,0.000000,1.747307,130519,1152921504606846976,1152921504606716457,1930667860426752,true
RESULT,3,fresh_mod16,leveled_real,512,2048,0,1536,0,0.001097,0.053477,6.416270,13312250,576460752303423488,576460752290111238,2015992821579776,true
RESULT,3,fresh_mod8,leveled_real,512,1536,0,1536,0,0.001087,0.081866,7.195063,11966204,1152921504606846976,1152921504594880772,2183471204139008,true
RESULT,3,packed_dual_mod16,leveled_real,512,2048,0,1536,0,0.001080,0.037102,8.694156,15451644,576460752303423488,576460752287971844,2080940998262784,true
PACKED_FULL,key=3,values=512,phase_error_max=11139662,half_step=1125899906842624,headroom=1125899895702962,correct=true
SUMMARY,correct=true
```

## Interpretazione

- Il canale modulo 16 recupera esattamente `x[3:0]`; dopo la ricodifica sono usati `x[2:0]` per completare l'argmin esatto.
- Il canale modulo 8 recupera direttamente `x[2:0]` e ha un half-step di `2^60`, esattamente doppio rispetto a quello modulo 16 (`2^59`). Il massimo errore di fase del punteggio osservato resta dello stesso ordine nei due canali.
- Nel layout packed, il massimo errore di fase osservato sul canale basso e' 15.451.644 contro un half-step di 576.460.752.303.423.488. Sul canale completo e' 11.853.796 contro 1.125.899.906.842.624.
- La ricodifica piu' rumorosa osservata ha errore di fase 2.424.960.882.573.312, ancora molto inferiore al margine decisionale booleano `2^59`.
- Per 128 identita', il solo bridge ufficiale piu' ricodifica dei tre bit bassi richiede empiricamente circa 1,14-2,21 secondi per probe in queste esecuzioni. Non e' un tempo end-to-end dell'argmin.

## Limiti e failure mode rimasti

- La correttezza cifrata e' evidenza empirica su tre chiavi, non una prova formale del failure probability dell'intero circuito.
- Il layout packed e' intenzionalmente vincolato a embedding 512 e polynomial size 2048; il binario fallisce esplicitamente se questi parametri cambiano.
- Il test packed verifica per decrittazione la correttezza del canale completo a `Delta=2^51`, ma applica l'estrattore ufficiale soltanto al canale basso. L'estrazione dei bit alti resta responsabilita' del circuito argmin principale.
- Il modulo 8 massimizza il margine ma non fornisce una copia indipendente di `x[3]`; il modulo 16 permette anche quel controllo. Il layout packed provato usa modulo 16.
- I tempi mostrano variabilita' da contesa CPU. Il vantaggio principale del packing e' evitare un secondo ciphertext probe e un secondo prodotto galleria nel sistema completo; non riduce il numero di PBS del bridge basso.
