# Prova composita binaria N2

Il test ignorato `binary_pipeline_probe::fresh_key_composite_n2_common_and_mixed_preserves_ids_without_timing`
si esegue da solo, in un nuovo processo, con `--ignored --exact --test-threads=1`.
Il launcher deve usare il nome completo del test mostrato dal binario. Le impostazioni composite
sono globali; le sei query sono serializzate dentro un pool Rayon fisso da 16 thread.
Questa prova non misura tempi.

`BINARY_PIPELINE_OUTPUT_DIR` deve indicare un percorso assoluto **non esistente**, il cui parent
esiste già. Il test crea la directory, `rows.jsonl`, gli envelope e `COMPLETE.json` esclusivamente.
Il root lega separatamente sorgenti, compiler e binario; può incorporare l'identità del compiler
con `BINARY_PIPELINE_BUILD_RUSTC` durante la build. La dichiarazione `[59,55,55]` nel metadata
descrive la configurazione prevista e non sostituisce la revisione del sorgente compilato.

Una sola famiglia Standard fresca: preset TFHE-rs 1.8.1 M1/C3, small-LWE 859,
GLWE size 2/N2048, FFT Dif4/base1024 impostato prima di generare le chiavi. Il normale
`service::generate_bundle` genera Head e PFKS; l'ordinary server key contiene i normalizzatori.
Nessuna chiave salvata viene caricata, nessun resampling o scelta di una famiglia favorevole.

Tutti i vettori hanno dimensione 512 e sono zero oltre le due coordinate riportate. Coordinate
di query/template in [−3,3], norma quadratica query ≤1024 e norme template verificate dal planner.
L'oracolo è `norm2(template) − 2·dot(query,template)`, poi `clear_private_argmin` corrente:
primo minimo e soltanto la sua soglia inclusiva. Ogni fixture viene ammessa prima delle chiavi.

| Caso | Query | Template 1 / 2 | Score 1 / 2 | Soglie | ID |
|---|---|---|---|---|---|
| comune inclusivo | (3,0) | (2,0) / (1,0) | −8 / −5 | −8 / −8 | 1 |
| comune rifiuto | (3,0) | (2,0) / (1,0) | −8 / −5 | −9 / −9 | 0 |
| comune pareggio distinto | (1,1) | (1,0) / (0,1) | −1 / −1 | −1 / −1 | 1 |
| Mixed minimo rifiutato, altro accettabile | (1,1) | (1,0) / (0,−1) | −1 / 3 | −2 / 3 | 0 |
| Mixed primo pari rifiutato, altro accettabile | (1,1) | (1,0) / (0,1) | −1 / −1 | −2 / −1 | 0 |
| Mixed inclusivo, ID2 | (3,0) | (1,0) / (2,0) | −5 / −8 | −6 / −8 | 2 |

I tre casi comuni devono usare `CompareSentinel`, senza shortcut. Il primo normalizza i due
score a 1023/1026 e la sentinella a 1024; il secondo mette il vincitore a 1024, pari alla
sentinella sinistra: il rifiuto deve prevalere. Questo attraversa carry/top senza cifre artificiali.
I tre casi Mixed devono usare `MixedWinnerThreshold` e soglie interne al dominio.
Il callee completo esegue scoring, Head, middle/low55, comparatore, refresh, PFKS e verifica finale.
I contatori osservati e la verifica del ledger del service restano distinti dalla correttezza ID.
Il probe richiede anche i costi pubblici letterali `(BR,KS,marginali,PFKS,initial)`:
prime tre query `(16,16,24,6,2)`, quarta `(17,16,26,8,2)`, ultime due `(17,16,25,7,2)`.
Ogni riga conserva `classic_batch::report`: esattamente due `binary2_comparisons`,
zero `batch3_merges` e zero `parallel3_merges`. Sono obblighi del percorso selezionato,
non una simulazione o un bound del rumore; nessuna query aggiuntiva.

Massimo sei query, una nuova cifratura GLWE ordinaria per caso. La decifratura riguarda soltanto
le tre cifre finali ID a delta59; cifre non canoniche sono una divergenza scientifica, non filtrate.
Nessuna fase non arrotondata, bit segreto, indirizzo, spettro o checkpoint interno viene riportato.

`rows.jsonl` contiene metadata, i casi effettivamente eseguiti e un complete; ciascuna riga viene
flushata. Alla prima divergenza conserva query e tre output cifrati, scrive `CANDIDATE_REJECTED`
anche in `COMPLETE.json`, poi termina il test con panic scientifico: i casi successivi sono omessi.
Un successo scrive `COMPOSITE_N2_PASS_6_CASES`. Gli errori controllati di ammissione, API,
ledger o I/O hanno prefisso `CONFIG_OR_IO_FAILURE`; un panic interno inatteso può non averlo.
L'assenza di COMPLETE è quindi un esito inatteso/config/API/I/O/internal panic, distinto dal
rifiuto scientifico. Il launcher distingue i casi leggendo gli artifact, non dal solo exit
nonzero del test harness: il panic scientifico non è un exit2 dedicato.

Le chiavi proprie sono conservate in envelope locali opachi: magic `BPN2ENV1`, lunghezza LE
dell'header JSON pubblico, header, payload bincode 1.3.3. Gli envelope sono legati da byte/SHA256;
non vengono deserializzati o ispezionati. Nessun dato viene caricato altrove.
Un eventuale PASS riguarda questi sei casi/famiglia; non è un bound di fallimento, un benchmark,
una qualificazione N120 o una garanzia per tutta la pipeline.
