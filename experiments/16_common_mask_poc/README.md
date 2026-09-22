# Esperimento 16 - common-mask TFHE: primitive e piano del prototipo

La domanda qui riguarda il costo di un'operazione elementare del calcolo
cifrato: **si possono elaborare più valori condividendo parte della loro
rappresentazione?** Un ciphertext LWE ordinario rappresenta un valore
mediante una *maschera*, un vettore di coefficienti, e un *body*, un'altra
componente cifrata. Nel formato **common-mask** più body condividono una
maschera. Un body non è un valore lasciato in chiaro.

Il riferimento elabora ciphertext LWE ordinari separati, anche in parallelo.
La variante li raggruppa e misura operazioni sul formato comune. Il
**packing** converte gli ingressi nel gruppo; il **key switch** cambia la
chiave a cui sono riferiti senza decifrarli; il **PBS** applica una funzione
tabulata ai valori cifrati. La tabella, detta **LUT**, qui è l'identità:
l'uscita attesa rappresenta lo stesso valore dell'ingresso.

L'ingresso è quindi un insieme di valori sintetici cifrati, non una foto;
l'uscita delle primitive è ancora cifrata, non un'identità riconosciuta.
Si vuole capire se valga la pena costruire un **POC**, cioè un prototipo
che dimostri la fattibilità del passaggio successivo. I tempi da soli non
dimostrano che le uscite siano corrette: il programma non le decifra.
Questo packing common-mask è distinto dal raggruppamento delle cifre nel
selettore della [guida al confronto](../../docs/come-funziona-il-confronto.md).

Questa directory conserva il microbenchmark usato il 2 settembre 2026 per valutare le
primitive common-mask LWE sperimentali di `tfhe-rs 1.7.0`. La dipendenza è bloccata
esattamente a `=1.7.0`; i due `Cargo.lock` conservano anche la risoluzione transitiva usata.

Il risultato riguarda queste condizioni: su questa macchina, con precisione p=2 e quattro
body per maschera, uno stage di 128 PBS logiche ha margine sufficiente per giustificare un
POC. Non è ancora un argmin common-mask, non misura la pipeline completa e non dimostra
la correttezza dell'identificazione.

Questa è una linea sperimentale storica; per la configurazione effettivamente
mantenuta partire dal [README del runtime](../../runtime/README.md).

## Contenuto

- [src/main.rs](src/main.rs): microbenchmark common-mask semanticamente identico al sorgente
  eseguito nelle misure; l'unica trasformazione è `cargo fmt`.
- `ordinary_baseline/`: sorgente del benchmark ordinary/Rayon usato come baseline. Il solo
  cambiamento funzionale rispetto al sorgente misurato è il pin del manifest da `1.7.0`
  a `=1.7.0`; anche questo sorgente è stato soltanto formattato con `cargo fmt`.
- `results/2026-09-02_common_mask_primitives.txt`: ambiente, comandi di riproduzione, misure
  conservate e limiti metodologici.

Il programma common-mask accetta `<width>x<precision>`: per esempio `4x2` seleziona
`CM_PARAM_4_2_MINUS_64`, cioè quattro body e precisione plaintext di due bit. Genera le
chiavi, costruisce una LUT identità e misura:

1. packing di quattro LWE indipendenti in una CM-LWE;
2. common-mask key switch;
3. common-mask PBS;
4. 32 gruppi in parallelo, equivalenti a 128 slot logici.

Le misure per singolo gruppo usano 25 campioni; quelle N=128 usano sette ripetizioni. La
baseline ordinary usa tre ripetizioni e il valore confrontato è `scalar_parallel_s`, non la
batch PBS seriale stampata dallo stesso programma.

## Riproduzione

Per misure confrontabili, usare una CPU libera da altri benchmark. Dalla presente directory:

```sh
RAYON_NUM_THREADS=16 cargo run --release --locked -- 4x2
RAYON_NUM_THREADS=16 cargo run --release --locked -- 4x4
RAYON_NUM_THREADS=16 cargo run --release --locked \
  --manifest-path ordinary_baseline/Cargo.toml -- 1x1
RAYON_NUM_THREADS=16 cargo run --release --locked \
  --manifest-path ordinary_baseline/Cargo.toml -- 2x2
```

`1x1` nella baseline seleziona message=1 bit e carry=1 bit, quindi precisione totale p=2;
`2x2` seleziona message=2 e carry=2, quindi p=4. I comandi sopra sono gli equivalenti
riproducibili dei run conservati; non è stato mantenuto il transcript originale completo
della shell.

## Cosa non misurano questi programmi

- Il common-mask benchmark non decifra né confronta gli output: il campo `check` impedisce
  soltanto che il compilatore elimini interamente il lavoro.
- Tutti i gruppi riusano lo stesso ciphertext di prova e una LUT identità. Si misura il costo
  della primitiva, non una distribuzione di query reali.
- La baseline usa una LUT `x & 1`; è un confronto di costo a uguale classe di parametri, non
  un confronto di semantica applicativa identica.
- `packing + KS + PBS` è una somma di mediane di run separati, non la mediana di uno stage
  fuso.
- Le dimensioni delle chiavi sono i payload dei container calcolati dal programma, non il
  picco RSS o la dimensione serializzata. Escludono chiavi segrete, accumulatori, ciphertext,
  allocator e la BSK standard eliminata dopo la conversione Fourier.
- Queste misure non stabiliscono un'accelerazione dell'intero argmin esatto.

## Limiti dei parametri p=2

Il circuito exact-ID usato come riferimento il 2 settembre usa LUT a 16 stati per OR a fan-in quattro, transizioni del
comparatore, aggiornamenti del candidato e output raggruppato. `CM_PARAM_4_2_MINUS_64` offre
solo quattro stati: prima di riusare i numeri di questo benchmark, tali LUT devono essere
scomposte in microstep a due bit e lo stato deve restare common-mask fra gli stage.

Inoltre, in `tfhe-rs 1.7.0`:

- l'helper dell'accumulatore replica la stessa funzione su tutti i body e contiene un TODO per
  LUT distinte per slot;
- packing, key switch, PBS e algebra lineare componente per componente sono disponibili;
- non c'è una API pronta per le permutazioni/riduzioni cross-slot richieste da OR, prefix scan
  e first-one.

Il packing ripetuto a ogni livello può consumare il vantaggio osservato. Anche la memoria
delle sole chiavi valutative misurate è sostanziale: circa 435,7 MiB per p2/w4.

## Piano del prototipo al 2 settembre 2026

I criteri seguenti documentano il piano successivo al microbenchmark.
Il lavoro successivo è descritto nell'esperimento [24](../24_frontiere_common_mask_bgv/README.md).

### POC A - stage senza comunicazione fra slot

Implementare quattro aggiornamenti booleani/2-bit indipendenti per gruppo, con packing una
sola volta, CM key switch, CM PBS e output mantenuto in forma common-mask. Decifrare e
verificare tutti gli input della LUT per più chiavi fresche.

Criteri di successo:

- zero discrepanze;
- nessuna estrazione LWE per slot nel percorso misurato;
- almeno 1,5× rispetto alla baseline ordinary includendo il bridge iniziale;
- memoria delle chiavi e picco RSS registrati separatamente.

### POC B - riduzione cross-slot

Implementare almeno una OR/prefix reduction di quattro slot, conservando la rappresentazione
common-mask. Il criterio esclude la variante se occorre estrarre e reimpacchettare a ogni livello oppure
se packing e trasformazioni consumano il margine temporale rispetto alla baseline ordinary.
Solo dopo questo test ha senso tentare l'intero first-argmin con soglia del vincitore e ID
cifrato.

## Fonti primarie

- Bergerat et al., *Sharing the Mask: TFHE Bootstrapping on Packed Messages*, TCHES 2025:
  <https://doi.org/10.46586/tches.v2025.i4.925-971>
- Release sperimentale `tfhe-rs 1.7.0`:
  <https://github.com/zama-ai/tfhe-rs/releases/tag/tfhe-rs-1.7.0>
- Parametro p2/w4 conservato:
  <https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.7.0/tfhe/src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_params.rs#L116-L142>
- API common-mask PBS:
  <https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.7.0/tfhe/src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_programmable_bootstrapping/cm_fft64.rs#L12-L67>
- Packing di LWE indipendenti:
  <https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.7.0/tfhe/src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_packing.rs#L12-L116>
- Helper LUT e TODO per funzioni distinte:
  <https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.7.0/tfhe/src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_programmable_bootstrapping/mod.rs#L11-L51>

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
