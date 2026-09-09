# Audit del ponte punteggio -> bit di bin

Data: 2026-09-01  
Macchina: Apple M4 Max, 16 core  
Parametri: `V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64`  
Sorgente: `src/bin/bucket_bit_periodic.rs`

Scopo: verificare separatamente tre modi di ottenere i dieci bit alti di un punteggio intero
traslato in `[0,8191]`. I dieci bit 12..3 identificano un bin di ampiezza 8. Il test usa
ciphertext freschi; non e' una stima formale della probabilita' di fallimento composta.

## 1. Segno periodico diretto: negativo

Comando:

```text
cargo run --release --bin bucket_bit_periodic
```

Risultato boundary-rich sull'intero dominio:

```text
points=5120,pbs=51200,extract_s=81.075294
SUMMARY,correct=false,failures=72,tested_bits=51200
```

Il modello chiaro del segno periodico e' esatto, ma il ciphertext non lo e': il margine minimo
di mezzo punto, dopo la riscalatura dei bit alti, puo' essere inferiore alla risoluzione/noise del
modulus switch del PBS. Gli errori compaiono soprattutto attorno alle discontinuita' periodiche.
Questa scorciatoia a un PBS per bit e' quindi esclusa.

## 2. Estrattore ufficiale a 13 bit + recoder: positivo sul campione

L'estrattore `extract_bits_from_lwe_ciphertext_mem_optimized` riceve il punteggio a
`Delta=2^51`, estrae tutti i tredici bit e li restituisce come small-LWE in `{0,q/2}`. Un PBS
unario, con shift `q/8`, ricodifica soltanto i dieci bit alti in booleani large-LWE.

Comando finale ripetuto dopo `cargo clippy -- -D warnings`:

```text
cargo run --release --bin bucket_bit_periodic -- --official
```

Risultato:

```text
points=71,pbs=1633,key_s=0.543364,extract_s=2.815505
SUMMARY,correct=true,failures=0,tested_bits=710
```

I 71 valori includono estremi e vicini delle frontiere dei bit. Il risultato sostiene il ponte
usato dal prototipo completo, ma 710 bit corretti non costituiscono da soli una p-fail formale.

## 3. Estrarre direttamente dieci bit a Delta=2^54: negativo

Chiedere all'estrattore dieci bit con `DeltaLog(54)` evita tre round, ma tratta i tre bit bassi
come parte frazionaria e arrotonda vicino ai confini del bin. Senza bias il test ha dato 24 valori
errati su 71 (710 bit controllati); con un bias centrato di 3,5 punti ne ha dati 40. I fallimenti
includono `x=7,15,31,...`, cioe' proprio il lato alto dei bin.

Conclusione: per una semantica deterministica `floor(x/8)` occorre partire dall'estrazione completa
a tredici bit. L'ottimizzazione successiva deve riusare i ciphertext intermedi dell'estrattore,
non cambiare `DeltaLog` e accettare un arrotondamento non dichiarato.
