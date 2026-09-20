# Confronto storico tra tfhe-rs e Concrete-python

Il report confronta il prodotto scalare e l'argmin sequenziale cifrati in
Concrete-python (`findings.md`, F31/F32) e tfhe-rs. La prova tfhe-rs usa Apple
M4 Max, DIM=64, valori in [-2,2] e punteggi signed `FheInt16`, contro circa
9–10 bit nel circuito Concrete. Build `--release` con `target-cpu=native`,
keygen 0,6 s; l'indice è confrontato con il risultato in chiaro a ogni N.

Il testo originale descriveva il confronto come eseguito sulla stessa macchina.
I tempi Concrete di 78 e 180 s coincidono però con quelli arrotondati del
[report 10](../10_argmin_struttura/RISULTATI.md), che indica un server Linux.
Finché non è risolta questa attribuzione, i rapporti sotto vanno letti come
confronti storici riportati, non come una misura controllata a parità di hardware.

## Misure

Tempo della riduzione non lineare argmin:

| N | argmin Concrete | argmin tfhe-rs | rapporto |
|---|---|---|---|
| 4  | 78 s  | 0,68 s | ~115× |
| 8  | 180 s | 1,78 s | ~100× |
| 64 | (non misurato) | 15,5 s | - |

Pipeline completa in tfhe-rs (prodotto scalare più argmin):

| N | dot+argmin | di cui argmin |
|---|---|---|
| 8  | 100,6 s | 1,78 s |
| 64 | 673,4 s | 15,5 s |

## Lettura

1. I tempi riportati dell'argmin differiscono di circa 100×, con indici corretti
   nei casi tfhe-rs provati. L'incertezza sull'hardware del riferimento Concrete
   impedisce di attribuire tutto il rapporto alla libreria o al compilatore.
2. Gli 1,78 s provengono dalle API `FheInt16`/`min`/`lt`. Il report li confrontava
   con le stime estrapolate dal costo per confronto di Chakraborty–Zuber
   (N=8 ~1,2 s, N=64 ~10,8 s, eprint 2022/622). Queste stime costituiscono un
   riferimento di ordine di grandezza, non una riproduzione di quel lavoro.
3. Nella pipeline tfhe-rs ad alto livello il prodotto scalare domina il tempo:
   a N=8 il totale è 100,6 s, di cui 1,78 s per l'argmin e circa 99 s per il
   prodotto scalare. Le somme intere propagano i riporti via bootstrap.
   Il circuito Concrete cifrato×chiaro usa invece operazioni leveled
   (0 PBS, circa 0,07 s). Il rapporto storico della pipeline completa è
   circa 1,8×; vale la stessa riserva sull'hardware. Il seguito valuta
   il prodotto scalare sulle primitive a basso livello.

## Riprodurre

```
cargo run --release
```

Su macOS, per l'errore del linker `library 'System' not found`, consultare le
[istruzioni del wrapper SDK](../../tools/README.md).

## Prove a basso livello del 30 agosto 2026 (F34)

`basso_livello.rs`: lo stesso prodotto scalare scritto sulle primitive `core_crypto` (LWE
grezzi, combinazione lineare a coefficienti in chiaro, zero bootstrap), DIM=64, valori in [−2,2].

| N | dot (tutti i punteggi) | esito |
|---|---|---|
| 4 | 0,1 ms | OK |
| 8 | 0,2 ms | OK |
| 16 | 0,3 ms | OK |
| 32 | 1,1 ms | OK |
| 64 | 2,0 ms | OK |

Rispetto ai circa 99 s dell'alto livello (`FheInt16`, riporti propagati via bootstrap): la lentezza del
prodotto scalare in F32 era dell'API radix, non di TFHE. Limite: parametri LWE scelti a mano
(n=1024, rumore ~2^−44) per 12 bit leveled, non un set validato a 128 bit; l'esperimento 14 ripete
la misura con i parametri standard di tfhe-rs.

`correttezza.rs`: l'argmin cifrato (lt + select + min) contro il chiaro su 208 casi (N = 4, 8,
16, 32; 15 vettori casuali su tre range, 12 bit / largo / estremi di i16, più 7 casi avversari
per N: tutti uguali, pareggio al minimo, crescente, decrescente, minimo in coda, in testa,
alternato): 208/208 corretti, pareggi risolti come in chiaro (vince il primo), 462 s.

```
cargo run --release --bin basso_livello
cargo run --release --bin correttezza
```

Il seguito (pipeline completa con parametri standard, torneo, soglia leveled) è in
`experiments/14_pipeline_tfhe_rs/`.
