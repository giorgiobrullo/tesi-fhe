# 19 - Runtime CPU, FFT, thread e compilatore

L'esperimento modifica le impostazioni di esecuzione e compilazione del
motore, mantenendo le stesse operazioni logiche. Per orientarsi nel calcolo,
vedere l'[esempio con due candidati](../../docs/come-funziona-il-confronto.md).

La configurazione selezionata è **opt3, CGU1, 16 thread, CPU generica,
FFT Dif4 fissa**: livello di ottimizzazione 3, una unità di generazione del
codice, sedici thread di esecuzione e un algoritmo FFT prestabilito.
FFT significa trasformata veloce di Fourier; qui accelera i calcoli sui
polinomi. Non sono attivi LTO (ottimizzazione in fase di collegamento),
PGO (ottimizzazione guidata da profili di esecuzione) o le opzioni di copia/cache.

## Passaggio modificato

Score cifrati → estrazione delle cifre → torneo (confronto e selezione) →
controllo della soglia → esito cifrato 0/ID.

Qui non si sostituisce una fase del circuito: si cambia **come il motore
esegue le operazioni sulla CPU**. La FFT entra nei calcoli sui polinomi
delle primitive crittografiche; i thread eseguono parti indipendenti del
lavoro; il compilatore genera il codice macchina dell'intero motore.
I tempi escludono la fotocamera e l'interazione con la pagina web.

## Prima e dopo

| Impostazione | Prima | Dopo, nella configurazione selezionata |
|---|---|---|
| Piano FFT | Nel riferimento originale, la libreria sceglie il piano a runtime. Il controllo successivo ha già la FFT fissa. | Piano Dif4 fisso installato prima di generare o caricare le chiavi Fourier. |
| Compilazione | Profilo con 16 unità di generazione del codice. | Una sola unità, CGU1, mantenendo livello di ottimizzazione 3 e CPU generica. |
| Thread | Otto thread nei riferimenti temporizzati. | Sedici thread. |
| Circuito | Estrazione, confronto, selezione e controllo della soglia Head/PFKS. | Stesse operazioni logiche e stesso risultato 0/ID. |

Il risparmio cercato è nel tempo di esecuzione, non nel numero di
confronti del torneo. CGU1 indica un'impostazione del compilatore, non un
limite a un solo thread. Il piano FFT fisso rende ripetibile la scelta
numerica; la sua adozione da sola non dimostra un'accelerazione.

## Metodo e risultati

Il [runner a FFT fissa](source/runtime-fixed-fft/README.md) installa il piano
prima di generare o caricare le chiavi Fourier. Il [riferimento adattivo](source/runtime-candidate/README.md)
conserva la scelta del piano a runtime. Le opzioni `opt-owned-pfks` e
`opt-lut-cache` confrontano rispettivamente spostamento degli intermedi PFKS
invece della copia e riuso dei corpi immutabili delle LUT.

La conferma su due nuove famiglie seleziona CGU1 con 16 thread e FFT fissa.

| Riferimento | Cosa cambia | Riduzione del tempo |
|---|---|---:|
| FFT fissa, 8 thread | Compilazione e numero di thread | 18,37% |
| Piano adattivo, 8 thread | Compilazione, thread e piano FFT | 16,63% |

Sono confronti distinti: le percentuali non si sommano e non isolano
l'effetto della FFT. Native e CGU1/8 non confermano un vantaggio; PGO è
**1,53% più lento** nello screening separato. Copie/cache non vengono selezionate.

L'intervallo finale usa due medie per chiave, non 48 chiavi indipendenti.
Tutte le coppie conservano segnalazioni di carico esterno e contabilità
parzialmente incerta. Sedici thread software non dimostrano affinità a
specifici core fisici. La FFT fissa consente confronti dei ciphertext tra
processi, ma i piani adattivi precedenti non erano registrati: non si
attribuisce retroattivamente ogni differenza alla FFT. [Risultati completi](RESULTS.json).

<a id="misure-salvate-integrazione-del-6-ottobre-2026"></a>

Le [misure della prima famiglia](evidence/confirmation-key1.json)
e della [seconda](evidence/confirmation-key2.json) documentano la
conferma; gli screening [runtime](evidence/runtime-screen.json) e
[PGO](evidence/pgo-heldout.json) conservano anche le varianti non
selezionate. L'[analisi del contesto CPU](evidence/context-analysis.json)
riporta le condizioni osservate.

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
I risultati qui restano quelli storici su TFHE-rs 1.7; per versione e
configurazione attualmente adottate vedere il [runtime mantenuto](../../runtime/README.md).

## Provenienza

La [provenienza dei sorgenti e delle misure](PROVENANCE.json) lega i file
alle fonti originali e dichiara le selezioni dei dati. Le impronte delle
copie pubbliche sono distinte da quelle degli originali.
