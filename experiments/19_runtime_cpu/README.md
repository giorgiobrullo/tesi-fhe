# 19 — Runtime CPU, FFT, thread e compilatore

Questo esperimento fissa e registra il piano FFT prima di creare o caricare
le chiavi Fourier, quindi confronta compiler, numero di thread, PGO e due
modifiche runtime. La scelta finale è opt 3/CGU 1,16 thread, CPU generica,
senza LTO/PGO e senza le feature copie PFKS/cache LUT.

Il [runtime a FFT fissa](source/runtime-fixed-fft/Cargo.toml) e il
[controllo precedente](source/runtime-candidate/Cargo.toml) conservano sorgenti,
core locale, lockfile e artefatti incorporati. Le feature negative
`opt-owned-pfks` e `opt-lut-cache` rimangono leggibili nel codice.
Il Cargo.toml congelato ha il profilo del confronto: la configurazione CGU 1
selezionata è documentata sotto [configs/historical](configs/historical),
non ottenuta modificando retroattivamente quel file. Questi config contengono
percorsi della campagna originale e sono ricevute, non comandi di avvio portabili.

[Risultati](RESULTS.json):18,368730% nella conferma rispetto a FFT fissa/8
thread;16,63% nel confronto distinto con il vecchio riferimento adattivo/8.
Non si sommano. Native e CGU 1/8 non confermano un vantaggio. PGO è 1,53% più
lento nello screening separato; copie/cache non vengono selezionate.
L'intervallo finale usa due medie per chiave, non 48 chiavi indipendenti.

**Questa copia non è stata compilata o eseguita.** I risultati sono quelli
accettati nelle posizioni originali, elencate con hash in
[PROVENANCE.json](PROVENANCE.json). Sono conservati tutti i flag di carico
nei risultati d'origine; nessuna causa hardware viene dedotta dalle sole
percentuali. Non sono copiati chiavi, ciphertext, profili PGO binari, modelli,
log dei processi o target di compilazione.
