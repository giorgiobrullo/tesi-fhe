# A29 ManyLUT: replay diagnostico DigiFace probe 87

Data: 2026-09-02. Core A29 congelato, tfhe-rs 0.11.3,
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`, Apple M4 Max arm64,
`RAYON_NUM_THREADS=16`.

## Esito

**PASS.** Il replay cifrato N=127 del probe DigiFace 87 ha attraversato tutti i checkpoint
diagnostici senza errori e ha restituito il codice exact-ID atteso `88`:

```text
CONFIG,N=127,domain_lower=-987,domain_upper=2329,winner=87,min_score=-269,threshold=4,expected_code=88
SUMMARY,total_checkpoint_mismatches=0,diagnostic_correction_rounding_mismatches=0,pbs=4965,final_phase=6341166383463661568
```

Il codice `88` significa identita' all'indice zero-based `87`; non e' un bit di membership. Poiche'
il punteggio minimo `-269` e' sotto la soglia `4`, il vincitore viene accettato. Il replay verifica
anche che il tie-break e la soglia restino nel core condiviso, mentre il client vede soltanto il
codice finale.

Tutti i checkpoint riportavano `mismatches=0`, inclusi:

- punteggi full e low-mod16;
- dodici bit del punteggio, correzioni e bit fused/reused;
- riduzione dei candidati e vincitore one-hot;
- selezione cifrata della soglia del solo vincitore;
- confronto di soglia, codifica e ricomposizione del codice finale.

Il massimo errore di fase normalizzato osservato fra i checkpoint Booleani di correzione e' stato
`0,397532 delta`, sotto la frontiera di arrotondamento `0,5`; non e' un bound di `p-fail`. Il tempo
wall osservato dal comando diagnostico e' stato circa `9,7 s`, ma include decifratura e analisi di
tutti i checkpoint e non e' una misura della latenza del servizio.

## Provenienza

Il binario e' stato compilato dallo snapshot sorgente A29 identificato dagli hash seguenti.
Il replay utilizza quindi A29; gli artefatti di compilazione precedenti appartenevano ad A28.

- core `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- harness `src/bin/exact_id_replay_trace.rs`:
  `724a5a515a6258c26657bc8a70b210893d972209accfacabed7eb7fbe04cd08c`;
- binario diagnostico congelato:
  `26cdacfa8c88cb5637f2c9f835c6a5f4463052d563810be913340d9eda66051b`;
- cache DigiFace:
  `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99`;
- galleria testuale estratta:
  `0e3f170cf8660f352ad021598f3d8ef5c276ecd5f32a1094a15d2b303cd366ae`;
- probe testuale estratto:
  `ad9a3d60433f1878a45aaa2d5c0233fb0d61b30933536a02dfb06e9a19565346`;
- probe ciphertext fresco, 32.840 byte:
  `682794eca67247d9c3900a76df5f3c22a8d6ce6031595d3cd1575b90f78af276`.

La coppia client/server e la cifratura del probe sono materiale effimero generato apposta per
il gate, senza riuso di chiavi storiche.

## Limiti

Questo e' un replay profondo di un singolo probe reale. Non sostituisce la regressione di
frontiera, la suite primaria da 632 query, l'E2E HTTP/Docker, il confronto paired A28/A29 o un
bound composto della probabilita' di errore.
