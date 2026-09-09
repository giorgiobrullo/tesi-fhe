# Sweep CBS del torneo periodic-fold (2026-09-01)

Artefatto sperimentale negativo. Il comparatore periodic-fold rende affidabili i predicati
pairwise, ma il circuit bootstrapping + CMUX non conserva il punteggio selezionato con precisione
sufficiente per un argmin open-set. Questi run usano una chiave fresca per configurazione, sette
casi sintetici avversariali e una probe reale, sia a N=64 sia a N=128 (16 osservazioni per riga).

Sorgente: `src/bin/argmin_torneo_periodic_fold.rs`.

## Comandi

```text
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 5 --cbs-levels 3
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 6 --cbs-levels 3
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 7 --cbs-levels 3
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 5 --cbs-levels 4
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 6 --cbs-levels 4
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 5 --cbs-levels 5
```

Configurazione comune stampata dal binario:

```text
params=LEGACY_WOPBS_MESSAGE_2_CARRY_2
periods=32|512
pfpksk=2^15x2
predicate=final_fold
security=legacy_wopbs_documented_123_to_128_bits
```

## Sommari osservati

```text
CBS 2^5x3  SUMMARY,total=16,correct=5,under_5s=14,under_10s=16,median_s=2.806,max_s=5.487
CBS 2^6x3  SUMMARY,total=16,correct=5,under_10s=15,median_s=6.316,max_s=11.957
            DIAG_SUMMARY,median_abs_score_units=0.625,max_abs_score_units=19.524
CBS 2^7x3  SUMMARY,total=16,correct=6,under_5s=16,under_10s=16,median_s=1.418,max_s=2.788
            DIAG_SUMMARY,median_abs_score_units=1.717,max_abs_score_units=10.148
CBS 2^5x4  SUMMARY,total=16,correct=6,under_5s=16,under_10s=16,median_s=1.583,max_s=3.555
            DIAG_SUMMARY,median_abs_score_units=0.297,max_abs_score_units=9.344
CBS 2^6x4  SUMMARY,total=16,correct=4,under_5s=16,under_10s=16,median_s=1.809,max_s=3.992
            DIAG_SUMMARY,median_abs_score_units=1.107,max_abs_score_units=13.145
CBS 2^5x5  SUMMARY,total=16,correct=7,under_5s=16,under_10s=16,median_s=1.817,max_s=4.329
            DIAG_SUMMARY,median_abs_score_units=0.255,max_abs_score_units=19.898
```

Per `2^5x3` il primo run non stampava ancora il riepilogo aggregato del rumore; i risultati per
caso sono stati usati per la conta di correttezza e latenza qui sopra. Le metriche di rumore sono
diagnostiche interne sul punteggio selezionato e non fanno parte del contratto di output.

## Variante con predicato precomputato

È stata avviata anche:

```text
cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 1 --real-probes 1 --cbs-base 5 --cbs-levels 5 --precompute-match
```

Il run è stato interrotto dopo l'evidenza sufficiente per scartare la route: a N=64 il bit di
match selezionato restava spesso errato; a N=128 comparivano alcuni casi corretti ma senza una
correttezza consistente, con tempi parziali nell'intervallo ~6-10 s. Non esiste quindi un summary
completo per questa configurazione e non viene ricostruito artificialmente.

## Conclusione sperimentale

L'aumento della precisione gadget riduce talvolta l'errore mediano, ma non quello di coda e non
porta nessuna configurazione vicino a 16/16 risultati completi. La velocità di alcune righe è
compatibile con il target, la correttezza no. Il torneo CMUX non è pertanto una route consegnabile
con questi parametri; il seguito deve evitare la selezione omomorfa del valore del punteggio.
