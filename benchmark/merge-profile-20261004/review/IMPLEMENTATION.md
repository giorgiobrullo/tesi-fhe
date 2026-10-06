# Profilo optional di un merge N120

Solo `core/src/smallcuts.rs` e `wide_id.rs` nella nuova copia locale sono modificati. Il runtime mantenuto e la precedente copia profilata restano intatti. Nessuna compilazione, test, chiave o query eseguita dall'autore.

Il record `designated_merge`, schema interno `smallcuts-designated-merge.v1`, viene creato soltanto con profiling già attivo, ModeBoth, public digits Repack, N120, livello0 e indice0. Contiene solo contatori e wall time pubblici: candidates120, ready_merges60, level_index0, index0, payloads/group_count numerici, internal_parallel=false, completed, node_wall_ns, cinque timer e unassigned_wall_ns.

La guardia RAII è locale al worker e non Send. Inizia dopo il lookup del nodo e prima della costruzione dei gruppi; termina dopo restore_constants/metriche, al ritorno della closure. In Drop prende e cancella il thread-local **prima** di pubblicare una sola volta nel parent profile. Su panic il record è marcato incompleto e il TLS viene comunque eliminato; il guard del servizio scarta il profilo della query fallita. Altri merge non acquisiscono orologi o accumulano tempi.

Confini disgiunti:

- `comparison_wall_ns`: soltanto la chiamata compare del nodo designato.
- `prepare_control_wall_ns`: la chiamata esistente prepare_control, dopo i due fallback del selettore.
- `pfks_wall_ns`: inizializzazione del ledger/buffer, differenze, allocazioni e PFKS per tutte le lane selezionate.
- `packing_rotation_wall_ns`: per ogni gruppo, clone/take, offset, somme del packing, blind rotation e relativo incremento BR.
- `extraction_addback_wall_ns`: allocazione, estrazione, addback e deposito degli output del gruppo.

Gli ultimi due timer sommano intervalli sequenziali **sullo stesso worker**, non tempi di worker diversi. La configurazione esistente con60merge pronti esclude il parallelismo interno di comparatore e selettore; non viene alterata per ottenere questo profilo. I fallback restano precedenti ai timer interni.

Il gap è node_wall meno i cinque intervalli: include setup pubblico, restore, placeholder e overhead fra span. Pubblicazione del record e setup del contesto esterno restano nel livello padre. Il nodo è già incluso nel primo livello, quindi non va aggiunto ai tempi del livello o del torneo.

Ordine delle operazioni FHE, input/output, gruppi, primitive e aggiornamenti dei contatori sono identici. La lettura pubblica non contiene score, cifre, decisioni o dati di chiave. La patch è una diagnosi empirica, non un'ottimizzazione o una nuova garanzia di correttezza.
