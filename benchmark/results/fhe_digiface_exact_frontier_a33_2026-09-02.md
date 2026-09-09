# A33: regressione FHE exact-ID sulla frontiera DigiFace

Data: 2026-09-02. Stato: **PASS sul run finale immutabile**.

## Che cosa verifica

La galleria contiene 127 identita' DigiFace e usa la soglia uniforme calibrata `T=4`. Il server
non restituisce un bit di membership: restituisce un solo LWE che decodifica `0` per il rifiuto o
`indice+1` per la prima identita' col punteggio minimo, se quel minimo e' sotto soglia.

I cinque probe storici di frontiera hanno minimi clear `2, 3, 4, 5, 7`: coprono quindi
accettazione stretta, uguaglianza alla soglia e rifiuto appena oltre soglia. Ciascun probe e' stato
cifrato 16 volte con randomness fresca, per 80 query totali. Una sola coppia di chiavi, generata in
una directory temporanea, e' stata usata nel run; la directory e' stata rimossa prima di chiudere
l'artefatto.

## Risultato

- 80/80 righe registrate e 80/80 ciphertext del probe distinti;
- 48 accettazioni attese e 48 osservate;
- zero errori operativi;
- zero discrepanze sull'intero risultato exact-ID, non soltanto sulla decisione;
- contratto HTTP sempre `exact-open-set-id-v2`;
- percorso sempre `a33_aligned_sparse`;
- dominio Cauchy stretto `[-987, 2329]`, larghezza 3.317;
- dominio di esecuzione A33 `[-1019, 2329]`, larghezza 3.349;
- esattamente 4.273 PBS in ogni query;
- core, servizio, libreria, binario, harness, configurazione, cache e manifest Cargo immutati fra
  inizio e fine del run.

Il tempo server mediano e' stato 8.272,6 ms, con media 8.381,1 ms e p95 9.544,5 ms. La macchina
era fortemente caricata: questi valori assoluti documentano il run ma **non** sono usati per
stimare il guadagno rispetto ad A29. Quel confronto richiede lo schema paired sugli stessi byte
cifrati e ordine A/B bilanciato.

## Provenienza congelata

| Artefatto | SHA-256 |
|---|---|
| CSV finale | `e72dd64db5751ee49ca2016908698f583e1f7d16c33c44d77beb3d9a7e68e98d` |
| JSON finale | `d15933731a313ed82445e03ca37e999178cdf18c2f7953c86e8b38b9d7cd3e15` |
| `varco_demo` | `13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59` |
| core `private_argmin.rs` | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| servizio `varco_demo.rs` | `ae23024c8cbcb3269db14d816da44fb035f72b8ba00d83b5a5c2cb1aaca4c5ca` |
| libreria `lib.rs` | `c6fbdd61636f6335e6547ed17aa73cdea7c69c2a7c26f74980bb99c52a2e6f53` |
| harness | `b54fbc7ef278e53a08ad08eed4429833a7fba62b15ba810bc12c31af4904e79d` |
| patch A33 ricostruibile | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |

Comando del run finale:

```text
python3 benchmark/fhe_digiface_validation.py --run --skip-build \
  --binary experiments/14_pipeline_tfhe_rs/target/release/varco_demo \
  --regression-repetitions 16 \
  --output-stem fhe_digiface_exact_frontier_a33_final_2026-09-02 --timeout 900
```

## Run contaminato conservato, non promosso

Il precedente artefatto senza suffisso `_final` contiene anch'esso 80/80 risposte corrette e
4.273 PBS/query, ma ha `success=false`: durante la misura e' stata aggiunta la voce del nuovo
harness diagnostico in `Cargo.toml`. Il controllo di immutabilita' ha rilevato il drift e ha
invalidato l'intero run. Quei tempi non fanno parte dell'evidenza promossa.

## Limite

Questo stress empirico aumenta la confidenza funzionale sui confini e sul risultato esatto, ma non
certifica una probabilita' di fallimento end-to-end nell'ordine della `p-fail` nominale del
parameter set. Uscite multi-output correlate, accumulatori raw e somma finale del codice restano
obblighi separati della contabilita' conservativa.
