# Verifica indipendente dell'esito del probe

**Verifica dei record PASS; esito scientifico CANDIDATE_REJECTED.** Solo lettura, aritmetica ordinaria e hash opachi: nessuna nuova valutazione, compilazione, chiave o replay.

`run01/rows.jsonl` contiene otto record: una metadata, sei casi, un complete. Ordine esatto round0/case0..5. I casi0..4 centered passano; il primo centered failure è case5, `[15,15]` contro `[0,0]`: z=255, oracolo+1, output decodificato0. Il programma si ferma lì come previsto. I casi6/7 del round0 e tutti i round1..3 **non sono stati eseguiti**: 32 era il massimo, non il numero completato.

| Caso | z | Oracolo | Reference `[top,middle,low]` | Raw | Centered |
|---:|---:|---:|---|---:|---:|
| 0 | 0 | 0 | `[0,0,0]` | −1 | 0 |
| 1 | −1 | −1 | `[0,0,−1]` | 0 | −1 |
| 2 | 1 | 1 | `[0,0,1]` | 1 | 1 |
| 3 | 1 | 1 | `[0,1,−1]` | 1 | 1 |
| 4 | −1 | −1 | `[0,−1,1]` | −1 | −1 |
| 5 | 255 | 1 | `[0,1,1]` | 0 | 0 |

Tutti i 18 ternari reference Delta59 corrispondono alle singole differenze; il primo nonzero corrisponde sempre all'oracolo. I tre raw failure osservati sono0/1/5, e il primo è preservato senza retry. Il centered failure è preservato separatamente. Questi conteggi **non sono stime di frequenza o probabilità**: la campagna si arresta alla prima sconfitta centered. La reference valida questi soli casi del primitivo, non tutta la baseline.

COMPLETE riporta sei casi, false/CANDIDATE_REJECTED/raw_failures3; RUN riporta native exit2 e la build exit0. Exit2 è il ramo scientifico previsto, distinto da exit1 per reference failure e dal panic101; non è una build fallita. Una sola famiglia propria fresca, senza resampling, coerente con fonte e metadata.

Verificati direttamente i cinque input SOURCE_BUILD, identità compiler Rust1.98.1 fra metadata/build/SOURCE_BUILD, hash del binario e della ricevuta RUN, più byte/SHA256 dei **sei** envelope: client/server e primi fallimenti raw/centered input/output. I file binari sono stati trattati esclusivamente come byte per il digest, senza deserializzazione, ispezione del segreto o fasi. Le impronte concordano con i record:

- raw `28d23a72131a9b7354e339dfab273d7e704bd89cc7f040f61b24eb891f66afd6`;
- binario `5941a2788cb9960a5b018e8b5cc0e392470185b20999bb7e0161db2a3d7f43a9`;
- COMPLETE `a68ff4dec6b9526bae9db8e5650ea458c4ada20bfe734e6f5562bb725fadc013`.

Conclusione circoscritta: il primitivo gamma55 con questi parametri Classic/Standard e questa correzione mean-only ha prodotto un errore reale nella singola famiglia provata. Nessuna integrazione Head/PFKS/refresh/tournament è stata verificata; nessuna misura di prestazione o bound formale. Il record non identifica da solo il canale d'errore e non esclude altri comparatori compressi. Nessuna nuova progettazione o modifica ai dati originali in questa revisione.
