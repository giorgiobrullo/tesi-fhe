# Passaggio a TFHE-rs 1.8.1 — 22 settembre 2026

Il runtime mantenuto passa da TFHE-rs 1.7.0 a **1.8.1**. La compilazione e
i controlli funzionali descritti sotto passano. Il pilot CPU non mostra
un vantaggio di velocità: nei tre casi il tempo della 1.8.1 è circa il
3–6% maggiore. Questa prova breve non stabilisce una regressione generale.
L’aggiornamento dei sorgenti è locale; non attesta un deploy dei servizi.

## Modifica e compatibilità

Restano gli stessi parametri espliciti
`V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, la geometria delle
chiavi, il KS corretto, la correzione della media e il selettore pack4.
L’audit mirato dei sorgenti upstream non ha trovato modifiche delle
primitive KS/PFKS, rounding e FFT usate. TFHE-FFT resta 0.10.1; il CSPRNG
passa da 0.9.2 a 0.10.0 e aggiorna il backend AES.

Sono aggiornati i due pin Cargo, il lockfile, i nomi di versione e i binding
del circuito. Il fingerprint dei parametri include il numero di versione
e quindi cambia anche a parametri numerici invariati. Il formato wire resta
9. Servono nuove chiavi in una directory distinta: non sono stati alterati
gli header di chiavi o ciphertext precedenti, né verificata interoperabilità
fra versioni. La guida in [BUILD_AND_RUN](../../BUILD_AND_RUN.md) descrive
compilazione e generazione delle chiavi.

## Controlli eseguiti

- 119 test Rust ordinari, 32 test Python di client/configurazione e 107 test
  Python delle demo passati.
- Regressione FHE con una famiglia nuova in memoria: tre query N2 per
  pareggio, soglia inclusiva e rifiuto secondo la soglia del primo vincitore.
- Quattro query HTTP aggiuntive sul candidato: N127 → ID127, N128 → ID128,
  N225 → ID225 e N226 → 0 per un pareggio in cui il primo vincitore rifiuta.
  Coprono il passaggio fra percorso generale e allineato e la terza cifra
  dell’ID in base 15.
- Tutte le 24 query del confronto, warmup inclusi, restituiscono l’ID previsto
  dall’oracolo intero indipendente. Conteggi, galleria e binding coincidono
  con il rispettivo contratto.
- Avvio del vero adattatore `CurrentEngine` della demo con il runtime
  aggiornato, caricamento delle chiavi e stato verificati. Il worker
  temporaneo è poi arrestato; nessuna query aggiuntiva in questo controllo.

In totale: 31 valutazioni cifrate corrette, 19 sul candidato e 12 sulla
1.7, con tre famiglie di chiavi complessive. Questi casi non sono una prova
generale di correttezza, una stima di accuratezza biometrica o un limite
numerico della probabilità di fallimento del circuito.

## Misura breve

Apple M4 Max, macOS ARM64, stesso Rust 1.98.0 Homebrew, profilo release
opt3/CGU1 senza LTO o PGO, 16 thread, FFT Dif4/base1024, G4 disattivato.
Due eseguibili compilati dai sorgenti, nessuna build concorrente al timing.
La baseline parte dal commit `53579721e13da416334bb0bba48fd03307c95f81`.

La galleria ha 120 elementi e vettori di 512 coordinate. Si usano tre query
fisse da fotografie già presenti nell’iscrizione. Ciascuna versione ha una
famiglia nuova indipendente e una cifratura per scena, riusata nei suoi
blocchi. Il confronto tiene uguali plaintext e parametri, non i bit delle
chiavi o dei ciphertext. Il caricamento reale verifica il roundtrip e la
validità di ogni bundle.

Ordine dei processi: **1.7, 1.8.1, 1.8.1, 1.7** in due blocchi AB/BA.
Ogni processo esegue tre warmup esclusi e una misura per ciascuna scena;
nel secondo blocco l’ordine delle scene è invertito. Sono 12 warmup e
12 misure, sei per versione. Le quattro query di frontiera precedono il
confronto e sono escluse da ogni stima temporale.

Il timer HTTP `X-Tempo-Ms`, arrotondato a 0,1 ms, copre il calcolo del
servizio, inclusi decode del probe, pianificazione e serializzazione della
risposta. Esclude caricamento delle chiavi, trasporto HTTP e decifratura.
Non coincide con i confini del timer del grafico storico a N127.

| Scena | TFHE-rs 1.7.0 | TFHE-rs 1.8.1 | Variazione per blocco |
|---|---:|---:|---:|
| Einstein | 1,758 s | 1,814 s | +3,2% |
| Curie | 1,757 s | 1,862 s | +6,0% |
| Turing | 1,796 s | 1,885 s | +4,8% |

I tempi sono mediane di due misure per scena/versione. La variazione è
la mediana dei due rapporti 1.8.1/1.7 calcolati dentro ciascun blocco,
meno uno; non è il rapporto delle mediane mostrate.

Il carico esterno non era controllato. In 31 snapshot distanziati di circa
2,1 secondi, la contabilità parziale del tempo CPU fuori dagli evaluatori
va da 1,34 a 3,49 core equivalenti. Gli intervalli sovrapposti alle misure
1.8.1 del secondo blocco sono più carichi di quelli della 1.7 successiva
(circa 2,70–3,49 contro 2,10–2,53). Sono inclusi harness e campionatore;
processi nuovi/scomparsi e tempo CPU quantizzato rendono la contabilità
incompleta. Non attribuiamo causalità e non correggiamo o escludiamo tempi
a posteriori.

Con un solo host, una famiglia per versione e due ripetizioni non si
distingue in modo affidabile l’effetto della versione dalla variabilità di
carico, chiavi e blocco. Non sono riportati intervalli di confidenza,
claim di accelerazione o una prova di equivalenza prestazionale. L’adozione
locale aggiorna la libreria e si basa sui controlli funzionali superati.

I [24 campioni](../../benchmark/tfhe-181-20260922/samples.csv) consentono
di ricalcolare le statistiche; il [riepilogo](../../benchmark/tfhe-181-20260922/SUMMARY.json)
registra metodo, contatori, hash di sorgenti/eseguibili e gate. Le chiavi e
i ciphertext completi rimangono negli artifact locali e non sono inclusi.
Il CSV consente il ricalcolo, non da solo il replay crittografico.

Le [campagne pack4](PACK4_VALIDATION.md) e le figure precedenti restano
misure dei loro sorgenti sulla 1.7: i loro tempi non sono riattribuiti alla
1.8.1. Il bound di fallimento del circuito completo resta aperto.

## Nuova campagna del 4 ottobre

Il [confronto più ampio](TEMPI_181_20261004.md) usa lo stesso Rust 1.98.1
per entrambe le versioni, tre famiglie di chiavi per versione e 144 misure.
Sono corrette tutte le 216 risposte, warmup compresi. Nei tre casi la
1.8.1 richiede circa 0,9–2,1% di tempo in più. È una nuova osservazione con
condizioni proprie; non modifica i dati del pilot sopra o dei grafici 1.7.
La [demo reale misurata a parte](DEMO_SSE_20261004.md) richiede 2,10–2,24 s
dal POST al risultato SSE, con una foto per richiesta e avvio escluso.
