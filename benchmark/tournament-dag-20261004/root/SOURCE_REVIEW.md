# Scheduler DAG: revisione prima della build

**SOURCE_PASS.** Nessun blocco concreto nel sorgente finale letto. Gate statico per la copia isolata: non attesta compilazione, test eseguiti, correttezza FHE universale o guadagno. Nessun build/native/modello/payload privato eseguito o letto dal reviewer.

## Scheduler e integrazione

`reduce` costruisce coppie adiacenti dagli stessi livelli; `Promote` clona esattamente una volta per promozione. N120 conserva ready60/30/15/7/4/2/1,119 merge e radice64/56. Non è una bisezione60/60. I figli completano prima del proprio padre; i log sono ordinati `(level,index)`.

La guardia nasce nello stesso worker immediatamente prima del merge, dopo il join dei figli. `PhantomData<Rc<()>>` impedisce Send/Sync; Cell::replace/Drop conserva il contesto precedente anche su reentrancy/unwind. Classic e selector catturano la policy una volta prima dei task interni; figli PBS/PFKS/gruppo non rileggono READY. Il fallback globale resta al percorso con barriere. Nessun configure_level avviene durante i nodi DAG; il finale lo usa dopo il ritorno della radice.

La comparazione statica dei sei file modificati con W mostra solo scheduling/interfaccia: stessi figli e argomenti di confronto/selezione, gruppi/piani `(level,index)`, costanti ripristinate e fold metriche ordinato. Sentinel-left e soglia del vincitore Mixed restano distinti. La nota INVARIANTS descrive un contratto, senza dichiarare test anticipati.

DAG è inizialmente disabilitato. Profiling e cutoff nonzero sono respinti nel ramo DAG; il pilot imposta profilingoff, cutoff0 tramite PublicParallel e G4off. Rimane una sola valutazione sincrona: nessun supporto nuovo a query concorrenti. Cargo lega il helper alla copia locale e TFHE1.8.1; nuova sola importazione core `dag_scheduler`, nessun modello storico o Python-cache nel grafo nuovo.

## Pilot preregistrato

Una famiglia client/server/bundle fresca in RAM, una sola cifratura query e pool16. Query D512/valori±1 sui primi16 elementi, norma16; N120, primi minimi ID76/120. Oracle intero indipendente dal decoder. Cinque fixture verificano primo pari, soglia inclusiva−16, rifiuto−17 e Mixed che rifiuta76 anche se120 passerebbe; AllReject resta solo correttezza. Non vengono stampati ciphertext, fasi o segreti.

Programma:10 correttezza+4 warmup+16 misure=30 chiamate;4 coppie AB/BA alternate per Uniform/Mixed. Stessi input/chiavi, configurazione/oracle/decode fuori timer; evaluate dentro. Primo errore ferma la campagna; nessun rekey/retry. Counts/classic/selector ed esiti sono confrontati entro coppia. I due test nuovi controllano bracket/promotion e restore/unwind, ma qui sono soltanto letti. Il gate prestazionale preregistrato resta da applicare ai dati reali, senza esclusioni.

## Identità finali verificate

Percorsi relativi alla fase; byte/SHA256 effettivi:

| File | B | SHA256 |
|---|---:|---|
| runtime/core/src/dag_scheduler.rs |6862|94c1b9114a23bdba05a8bf232ee8858434a8425fb34b0627323597f7879e8159|
| runtime/core/src/classic_batch.rs |5337|101ceca17b40dfa96af8469e5782d021b967f04fc34456cad1f711af418d3e5f|
| runtime/core/src/selector_parallel.rs |10601|84638d8e4ed7917b12ca09271af3ee4cbb908dabb3355d2e2de1ef300d14e22e|
| runtime/core/src/wide_id.rs |20118|59e286f80efe34d9768d0f741d65d5817744581bb48a276f5769b4b3df98212e|
| runtime/core/src/mixed.rs |23215|c01b6cd60bf88b9babc81fbe450593864c7407c137108d2d9fa523d036501881|
| runtime/core/src/smallcuts.rs |16973|6cfef61c42bdb466eb39058d73f9d173569ff53783f02abaeced86443e225d93|
| runtime/core/src/lib.rs |4203|a3cd583854740a4cfd77afe4ae4959dcc2407f02b3df40b9ee7443a1bbadba8b|
| probe/src/main.rs |6539|f7db084f76b1e45812d1c030dd370101a6cbe4bda27cbfe3ff6f18585c8761ee|
| probe/Cargo.toml |372|63d2689b360e3b2ee1a7aa04ebc08901b7e6039ab0ea773e00f77e118897f0ea|
| root/CASEPLAN.json |725|343bc51a0052bfc8e1b91c065094d9b9cce00fc4dc8a052da6fddfef5a16785e|
| math/INVARIANTS.md |4171|c01714d6a30b2637fa8ba5e80be26d5d7a00a05bed623b39fc10c75726c6b498|
| PROTOCOL.md |2981|b83ff1674aaf846760ac21b93ab5d217d960f8ad0aebf34c7c4ca6099ec67eb3|
