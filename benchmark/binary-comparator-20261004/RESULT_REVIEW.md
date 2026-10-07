# Verifica indipendente del probe binario

**PASS dei record e PRIMITIVE_PASS_8_CASES.** Verifica mediante lettura, aritmetica ordinaria e digest; nessuna nuova esecuzione, compilazione o chiave.

Il JSONL contiene dieci record: una metadata, otto casi, un complete. Ordine esatto round0/case0..7, corrispondente alle otto coppie prefissate. Differenze integer z: `[0,−1,1,1,−1,255,−255,0]`. Oracoli binari e risultati candidate: `[−1,−1,1,1,−1,1,−1,−1]`. Entrambi i pareggi (case0 e7) restituiscono−1, come richiesto dal tie-left; l'oracolo ternario separato rimane0.

Tutti i **24** ternari reference Delta59 corrispondono alla differenza della propria cifra, e il primo nonzero corrisponde all'oracolo lessicografico. Ogni record è CANDIDATE_PASS con reference_correct/candidate_correct true e preserved vuoto. Tutti gli otto casi previsti sono completati, nessuno ineseguito. Il complete contiene true/rows8/PRIMITIVE_PASS_8_CASES; RUN e build hanno exit0. Non è una stima della frequenza d'errore.

Metadata coerente con il protocollo: gamma55/output59, LUT negativo0..3/zero4/positivo5..2047, un round, tre reference PBS e una candidate PBS per caso, mean-only stock correction+2^51 dopo KS, Standard/Classic859/GLWE2/N2048/FFT Dif4-base1024.

Verificati direttamente i cinque input SOURCE_BUILD, il suo digest nelle ricevute, l'identità completa Rust1.98.1 fra metadata/build/SOURCE_BUILD, binario, raw, ricevuta RUN e COMPLETE. Le due envelope client/server hanno byte e SHA256 conformi alla metadata; lette **solo per il digest**, senza deserializzazione, bit del segreto o fasi private. Fonte e metadata sono coerenti con una sola famiglia ordinaria propria fresca, senza caricamento o retry.

- raw `a569cf423703dd47b9aa43159d1b81f1d399bd85848e276830dbe95f05862c9a`;
- binario `15c8fcc48513f92cd60cfe764c992adf6b266674e9910e28880518c5633f8449`;
- COMPLETE `57f56eba2f2d252c8cf6b79a305c9872dd34a2564545328fef919b25dd035a29`.

I digest delle chiavi F differiscono da quelli E. Il raw del fallimento E è ancora `28d23a72131a9b7354e339dfab273d7e704bd89cc7f040f61b24eb891f66afd6`, invariato. **E/F non sono un confronto appaiato sulla stessa famiglia**, né una misura di guadagno; il precedente fallimento rimane valido per quella proposta e prova.

Il PASS riguarda soltanto questi otto casi del primitivo basso, con questa famiglia. Non qualifica top nonzero, composto2*top+b, refresh, ingresso Head, conversioni, PFKS, selettore, torneo, 0/ID, bound di rumore o runtime. La reference non attesta tutta la baseline; nessun tempo di processo è interpretato come latenza o speedup. Solo questa nota è stata scritta, senza modificare fonti o dati originali.
