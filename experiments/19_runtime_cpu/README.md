# 19 - Runtime CPU, FFT, thread e compilatore

L'esperimento confronta piano FFT, numero di thread, profilo di compilazione,
PGO e due opzioni runtime sul core Head/PFKS. La configurazione selezionata
è **opt3, CGU1, 16 thread, CPU generica, FFT Dif4 fissa**, senza LTO, PGO
o feature di copia/cache.

## Metodo e risultati

Il [runner a FFT fissa](source/runtime-fixed-fft/README.md) installa il piano
prima di generare o caricare le chiavi Fourier. Il [riferimento adattivo](source/runtime-candidate/README.md)
conserva la scelta del piano a runtime. Le opzioni `opt-owned-pfks` e
`opt-lut-cache` confrontano rispettivamente spostamento degli intermedi PFKS
invece della copia e riuso dei corpi immutabili delle LUT.

La conferma su due nuove famiglie misura **18,368730% di riduzione** per
CGU1/16 thread rispetto a FFT fissa/8 thread. Il confronto distinto con il
vecchio riferimento adattivo/8 thread dà **16,63%**. Questi effetti non si
sommano. Native e CGU1/8 non confermano un vantaggio; PGO è **1,53% più lento**
nello screening separato. Copie/cache non vengono selezionate.

L'intervallo finale usa due medie per chiave, non 48 chiavi indipendenti.
Tutte le coppie conservano segnalazioni di carico esterno e contabilità
parzialmente incerta. Sedici thread software non dimostrano affinità a
specifici core fisici. La FFT fissa consente confronti dei ciphertext tra
processi, ma i piani adattivi precedenti non erano registrati: non si
attribuisce retroattivamente ogni differenza alla FFT. [Risultati completi](RESULTS.json).

## Compilazione e uso

I due workspace contengono runner, core e lockfile TFHE-rs 1.7.0. Il profilo
Cargo predefinito conserva 16 unità di compilazione; per compilare il profilo
selezionato a CGU1, da questa cartella:

```sh
env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS= \
  CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=false \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  cargo build --release --locked \
  --manifest-path source/runtime-fixed-fft/Cargo.toml \
  --target-dir .local/target-fixed
```

Le feature runtime sono disattivate per default. Per studiarle usare target
di compilazione separati e gli stessi input, chiavi e condizioni nel confronto;
il protocollo del runner è documentato nelle due cartelle. Il successivo
[servizio 22](../22_demo_composita/README.md) incorpora la configurazione selezionata.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
