# A28 split4: validazione FHE dei confini

Data: 2026-09-02. Harness: `split4_boundary_trace`, core reale
`private_argmin_with_trace`, galleria `N=1`, dominio largo 4096.

## Esito

Tre processi separati hanno generato ciascuno una nuova coppia di chiavi in memoria e hanno
eseguito gli stessi 66 casi. Tutti i checkpoint, il codice finale e il modello di costo hanno
coinciso con l'atteso.

| run | thread Rayon | casi corretti | mismatch | keygen (s) | validazione (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | non registrato | 66/66 | 0 | ~0.513 (`0.512695`) | `13.527430` |
| 2 | 16 | 66/66 | 0 | `0.597414` | `13.458183` |
| 3 | 16 | 66/66 | 0 | `0.488344` | `13.484801` |
| totale | — | **198/198** | **0** | — | — |

La griglia baseline di ogni run copre 40 valori distinti di `x`, cioe' 120 coppie `(chiave, x)`;
le scene rumorose aggiungono 78 esecuzioni su valori in parte ripetuti, per 198 casi complessivi.
Per ogni caso il risultato decifrato e' stato `code=1` e il contatore e' stato esattamente
`53 PBS`. I casi con template non nullo e rumore reale del canale score sono 26 per chiave. Il
massimo errore di fase annotato nei tre riepiloghi osservati e' stato `0.260839 Delta`, inferiore
al confine di decodifica `0.5 Delta`; e' un massimo campionario, non un bound sul rumore.

## Copertura

Il punteggio chiaro di ogni scena e' `score`; scegliendo `domain.lower = score - x` e
`domain.upper = domain.lower + 4095`, il core riceve esattamente il punteggio tradotto `x` senza
usare un estrattore alternativo.

- `zero_baseline`: template e probe nulli; tutti `0..15`, ogni terna
  `2^j-1, 2^j, 2^j+1` per `j=4..11`, e `4095` (40 valori distinti).
- `noisy_boundary_16`: `g=q`, norma 1018 (`113*3^2 + 1^2`), `x=15,16,17`.
- `noisy_boundary_32`: `g=q`, norma 1012 (`112*3^2 + 2^2`), `x=31,32,33`.
- `noisy_boundary_64`: `g=q`, norma 1002 (`111*3^2 + 3*1^2`), `x=63,64,65`.
- `noisy_high_boundaries`: `g[0]=1`, `q=0`; `x=64,65` e le terne attorno a
  `2^j` per `j=7..11` (17 casi). `x=4095` resta nel baseline perche' un dominio largo 4096
  centrato in quel modo non coprirebbe tutto l'intervallo di Cauchy del template unitario.

Per ogni caso sono stati decifrati e verificati: score full e modulo 16, i 12 bit globali
`full_small`, le 11 correzioni globali, i checkpoint low, il codice finale e il conteggio PBS.
Il checkpoint `high_residual`, preso dopo la sottrazione delle quattro correzioni low e prima
dell'estrazione high, ha sempre decodificato `x >> 4` a `Delta=2^56`. Questo mostra direttamente
che il nibble basso viene ricostruito e sottratto correttamente e che l'estrattore high riceve il
multiplo di 16 atteso; il solo codice finale corretto non sarebbe sufficiente a dimostrarlo.

## Limiti dell'evidenza

- E' evidenza empirica su tre chiavi, non una prova o una stima del `p-fail` crittografico.
- Il baseline nullo non contiene rumore del calcolo score; i 26 casi non nulli per chiave coprono
  appositamente questo limite, ma riusano lo stesso ciphertext all'interno di ciascuna scena.
- `N=1` isola l'estrazione split4: non valida da solo torneo, tie-breaking o selezione a `N>1`.
- `code=1` esercita il percorso di accettazione ma non aggiunge copertura di rifiuto o altri ID.
- Ogni accettazione usa `score == threshold`; l'accettazione strettamente sotto soglia non e'
  coperta da questo harness.
- I tempi appartengono a un harness diagnostico con decifratura dei checkpoint e non sono evidenza
  di performance del servizio. Le run 2 e 3 usavano `RAYON_NUM_THREADS=16`; per la run 1 il numero
  di thread non e' stato registrato esplicitamente.
- I transcript completi stdout/stderr non sono stati conservati come file; questo documento
  conserva soltanto i riepiloghi osservati, quindi non consente una ri-analisi indipendente di
  tutte le singole righe.

## Riproduzione e provenienza

Comandi di controllo e riproduzione:

```bash
cargo fmt -- --check
cargo check --release --features diagnostic-trace --bin split4_boundary_trace
cargo clippy --release --features diagnostic-trace --bin split4_boundary_trace -- -D warnings
cargo run --release --features diagnostic-trace --bin split4_boundary_trace
RAYON_NUM_THREADS=16 target/release/split4_boundary_trace
```

Ambiente osservato: `rustc 1.97.1`, `cargo 1.97.1`, branch
`thesis-evidence-audit-2026-09`, base Git `6611c185adc9a658a075519b4316386f0bb48656`
con working tree modificato. Gli hash, non il commit base, identificano quindi gli input attuali.

| file | SHA-256 |
| --- | --- |
| `src/bin/split4_boundary_trace.rs` | `27fd4ec54e20c61d0d21cec2b01a60e85aa85c4ae0ea718b0bf12249272ddc03` |
| `src/private_argmin.rs` | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| `src/lib.rs` | `3fc09f32ff149ff103d38820727246f37ed068c5256b0ba71840610b65a2ecf1` |
| `Cargo.toml` | `676635518edecf7ff1d395036074914f4398bb23ea1d16b93f2e47f12e7d4501` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |
| `target/release/split4_boundary_trace` | `4751a1c5682962958156ecad133bc1ab330f8f95d08a341a87c78250a1be3166` |

Il binario hashato misura 2,061,888 byte ed e' stato generato il
`2026-09-02T04:55:02+0200`, dopo gli input elencati. Nessuna chiave e' stata scritta su disco.
