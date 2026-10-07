# Head e confronto dei due score pari

Test ignorato esatto: `service::stage_probe::fresh_head_and_equal_score_stages_without_timing`.
Output: `BINARY_STAGE_OUTPUT_DIR`, percorso assoluto ancora inesistente; directory, rows.jsonl,
COMPLETE.json ed envelope vengono creati in modo esclusivo. Nessun caricamento di chiavi.

Prima della chiave, il fixture pubblico viene validato: query(1,1), template distinti e0/e1,
soglie−2/−1, score−1/−1, modo Mixed. Il dominio effettivo deve dare score normalizzati62/62;
i nibble attesi sono top0/middle3/low14. Una sola famiglia fresca ordinaria+Head+PFKS, una sola
query GLWE alle scale51/60, piano FFT1024/Dif4/base1024, pool16. Il bundle PFKS viene generato
come nel servizio, ma nessuna selezione PFKS viene eseguita nella prova.

Tre record stage al massimo, in questo ordine:

1. Head: lo stesso `mixed::hybrid_bridge` restituisce i tuple originali. Si arrotondano soltanto
   le sei cifre score alle Delta59/55/55; tutti i valori devono essere nibble0..15 e uguali0/3/14.
2. C_same: la prima foglia e una sua copia identica entrano nel confronto reale; attesi
   top0, lower−1, combined−1. Nessuna nuova cifratura o canonicalizzazione delle cifre Head.
3. C_distinct: confronto tra i due tuple Head distinti e non modificati; stessi simboli attesi.

Il confronto restituisce i due veri output PBS e C della stessa chiamata: due callback diverse,
top raw59 e lower55 mean-only→59. Il refactor è condiviso col producer del percorso Mixed;
non duplica PBS. configure_level(1,true) riproduce Parallel2. I contatori actual devono essere
binary2=0/1/2, binary2_parallel=0/1/2 e legacy Batch3/Parallel3=0 nelle tre righe.

L'osservazione è decrittazione ordinaria dell'output e rounding alla Delta, senza conservare
fasi grezze o residui. I simboli signed59 sono interpretati modulo32, quindi31→−1. Top ammette
−1/0/+1, lower−1/+1, C−3/−1/+1/+3; ogni altro simbolo o cifra non canonica causa stop.
Gli oggetti Head osservati sono soltanto presi in prestito e poi riusati immutati.

rows.jsonl contiene metadata, massimo3 righe `record=stage`, poi complete. Successo:
`STAGE_PASS_3_CHECKS`; prima divergenza semantica: `STAGE_REJECTED`, COMPLETE prima del panic,
numero di stadi non eseguiti e `failed_envelopes` opachi del primo output fallito (anche i tuple
Head di ingresso se fallisce un confronto). Query e chiavi nuove
sono conservate in envelope locali opachi con header pubblico/hash; non sono ricaricate.
Errori di fixture/I/O/configurazione o dei contatori hanno prefisso distinto e non producono
un successo scientifico. `BINARY_STAGE_BUILD_RUSTC` è metadata compilato opzionale.

Il profiling viene esplicitamente disabilitato. Nessun clock/timing, indirizzo MS, secret bit,
spettro, fase sub-Delta, selettore o finale.
ALL-PASS non qualifica G e non isola la causa della vecchia famiglia. G e le sue evidenze
restano immutati. Root solo può compilare e lanciare dopo review e liveness.
