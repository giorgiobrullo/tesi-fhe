# Head-to-head del 100×: lo stesso match 1:N in tfhe-rs vs Concrete-python

Confronto controllato, stessa macchina (Apple M4 Max), dello stesso match 1:N cifrato (prodotto
scalare più argmin sequenziale): una volta in Concrete-python (i nostri esperimenti, findings
F31/F32) e una in tfhe-rs (la libreria TFHE nativa in Rust, qui). Stessa config del circuito
Concrete: DIM=64, valori in [-2,2], punteggi signed via `FheInt16` (più bit dei ~9-10 di
Concrete, quindi semmai conservativo). Build `--release` con `target-cpu=native`, keygen 0,6 s,
indice verificato contro il chiaro a ogni N.

## Misure

Argmin (la riduzione non lineare, la parte che conta):

| N | argmin Concrete | argmin tfhe-rs | rapporto |
|---|---|---|---|
| 4  | 78 s  | 0,68 s | ~115× |
| 8  | 180 s | 1,78 s | ~100× |
| 64 | (non misurato) | 15,5 s | — |

Pipeline intero in tfhe-rs (prodotto scalare più argmin):

| N | dot+argmin | di cui argmin |
|---|---|---|
| 8  | 100,6 s | 1,78 s |
| 64 | 673,4 s | 15,5 s |

## Lettura

1. Sull'argmin il divario è ~100× a parità di macchina e schema (tfhe-rs *è* TFHE), e tutto
   corretto. Quindi i ~180 s di Concrete a N=8 non sono colpa dell'hardware né di TFHE, ma di
   come Concrete-python compila in automatico la riduzione.
2. Basta l'alto livello di un'altra libreria: gli 1,78 s vengono dall'API `FheInt16`/`min`/`lt`,
   non da primitive tarate a mano. I numeri combaciano con Chakraborty–Zuber (N=8 ~1,2 s, N=64
   ~10,8 s, eprint 2022/622), quindi la letteratura era riproducibile.
3. Ma il pipeline intero racconta una cosa in più: in tfhe-rs ad alto livello il prodotto scalare
   è carissimo (a N=8 il dot+argmin è 100,6 s, di cui l'argmin 1,78 s, quindi il dot product ~99
   s), perché le somme intere propagano i riporti via bootstrap. In Concrete è l'opposto, il
   prodotto scalare enc×plaintext è leveled e gratis (0 PBS, ~0,07 s). I due profili sono
   specchiati, e il pipeline naïf intero in tfhe-rs è solo ~1,8× più veloce di Concrete, non
   100×. Il sistema davvero veloce scrive a basso livello, dove sia le somme sia il confronto
   sono economiche.

## Riprodurre

```
cargo run --release
```

Su macOS beta, se il linker fallisce, anteporre un wrapper di `ld` (`PATH=/tmp/ldfix:$PATH`).
