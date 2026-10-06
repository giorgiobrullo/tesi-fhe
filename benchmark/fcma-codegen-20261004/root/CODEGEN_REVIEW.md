# FCMA: riscontro indipendente nel binario isolato

4 ottobre 2026. **PASS_CODEGEN_DISCRIMINATION**. Ispezione readonly nm/LLVM objdump del solo binario congelato; nessuna compilazione, esecuzione del target, aritmetica, chiave o timing del reviewer. La precedente REVIEW.md resta immutata.

Binario Z/bin/codegen-probe:454480B, SHA256 `a7276e4bccee81362779aaee551b2a559733cece450494b2e60f545d93dfc668`. Il receipt BUILD terminale exit0 e gli otto record SOURCE_BUILD corrispondono direttamente ai byte/hash attuali. `nm -m` identifica un solo `_fcma_update` a0x100000c98 e un solo `_neon_update` a0x100000de8. Disassembly indipendente ristretto a entrambi: i corpi sono direttamente nei wrapper, nessun thunk da inferire.

| Corpo di un loop, inclusa branch finale | Neon | FCMA |
|---|---:|---:|
| First, ciascuno dei due output1024 | 14 istruzioni | 9 istruzioni |
| MAC, ciascuno dei due output1024 | 15 istruzioni | 9 istruzioni |

Locatori: Neon First0e2c–e60/First1e74–ea8, MAC0eb0–ee8/MAC1efc–f34; FCMA First0cd0–cf0/First1d00–d20, MAC0d28–d48/MAC1d58–d78, tutti con prefisso0x100000. Ogni output copre1024 elementi: Neon termina all'indice0x400; FCMA avanza16 byte e termina a0x4000. Restano i controlli2048/2048/1024 del wrapper.

Le quattro preparazioni Neon mov/mov/dup/eor sono assenti nei quattro loop FCMA. First FCMA aggiunge una `movi.2d` per azzerare l'accumulatore a ogni complesso: il beneficio netto non è semplicemente quattro istruzioni. Le altre differenze di conteggio sono nell'indicizzazione: Neon ha shift e avanzamento separato del puntatore lhs, FCMA usa un offset in byte. First conserva due istruzioni FP (Neon FMUL+FMLA contro FCMLA0+FCMLA90); MAC conserva due operazioni seriali sullo stesso accumulatore. Nessun hot call o accesso allo stack è presente nei loop; salvataggi/assert/panic esterni non sono spill del loop. Questi sono conteggi statici di questo caller, non conteggi del servizio o una previsione di cicli.

La sola invocazione metadata registrata dal root, PID24694/driver24693, termina exit0. `logs/capabilities.stdout` coincide esattamente con il JSON del receipt; stderr è vuoto. Rust e le factory checked Neon/NeonFcma risultano disponibili. Gli indirizzi conservati nel main non sono chiamate ai wrapper: `arithmetic_called:false`, `timing_performed:false`, come il sorgente prebuild già revisionato. La fingerprint del binario resta invariata. Questo verifica la disponibilità dichiarata, non FPCR/RN/FMA/underflow eseguiti né correttezza aritmetica.

Il precheck di codegen ha dunque superato il discriminatore: la pista elimina realmente preparazioni e non introduce chiamate/spill evidenti in questi loop. Non stabilisce latenza, throughput, uguaglianza bit, cap dei prodotti, budget BR/0-ID o beneficio end-to-end. Un futuro test pubblico del kernel avrebbe scope e gate propri; nessuna integrazione nel runtime mantenuto è stata fatta.

Identità dei record letti: SOURCE_BUILD.json1252B `2dc4470f244a459eaa7e85256124d520c784875c6116702b8273423e4ab18b81`; BUILD.json819B `344b6ca517ff8d7c3c2d6f8dbebed82bd4ce93a831efdfe3e14ca82c12828728`; CAPABILITIES.json863B `91fcc03424fb9a30fd6932ad862bf6cb2e1c81635cb022dae5317af9f5c7d045`, stdout282B `f1dc969b23584be2994bcbb0f430dfd4ed45d8ff578895d257fae550376d959e`. Snapshot root FCMA.asm3946B `3de59a429f51e6f6eb73812f79b038fcf94d606667f3804cf3f3e599a0a0937b` e NEON.asm4766B `0676aa29834f6077d66fcaac0e944b26944cd43899c9ce31dc0926286a0f6f71` coincidono nel contenuto dei simboli con l'ispezione indipendente. Nessuna lettura di vecchi modelli o payload.
