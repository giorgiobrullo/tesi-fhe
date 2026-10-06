# Stesso torneo, diversa disponibilità dei nodi

Nota di contratto dalla lettura dei sorgenti mantenuti; non verifica della patch ancora in preparazione. Interfaccia comunicata da source: `NodePolicy{ready, requested_parallel}`, con ready del livello originale; `current_policy()->Option<NodePolicy>`. Comparator/selector mantengono il fallback globale quando il contesto è assente. Questi nomi sono ricevuti, non ancora verificati sulla patch.

## Bracket e dati pubblici

Il DAG deve essere costruito dalle coppie adiacenti dei livelli originali. Ogni merge conserva figli sinistro/destro, `(level,index)`, gruppi, cifre pubbliche, ripristino delle costanti e piano della soglia. Un ultimo elemento dispari viene **clonato e promosso in coda**, come nel codice corrente; non semplicemente ricollegato eliminando questa operazione. A N120 i livelli sono 120→60→30→15→8→4→2→1: il ramo degli indici 112..119 è promosso al livello con 15 candidati; la radice confronta 0..63 con 64..119, quindi 64/56. Ricorsione su metà 60/60 cambierebbe questo DAG.

Il comparator forma `left−right`; il controllo con bias negativo conserva il primo minimo nei pari. Il finale resta distinto: sentinel a sinistra, vincitore a destra, soglia inclusiva. Ordinare le foglie non basta: anche intermedi, metadati e selezioni devono restare quelli del bracket originale.

## Scheduling e policy

La disponibilità dinamica consente di avviare un padre dopo i propri figli, senza attendere gli altri rami. Non cambia `ready`: la policy usa il numero di coppie **del livello originale**, mai la lunghezza corrente della coda. Querymode e cutoff restano fissi.

Il contesto TLS deve essere installato nel worker che esegue il merge, dopo il join dei figli. La guardia RAII deve essere `!Send/!Sync`, salvare il contesto precedente e ripristinarlo anche su unwind. Un `rayon::join` può eseguire un altro nodo sullo stesso thread: le guardie annidate devono ripristinare il padre, non azzerare indiscriminatamente il TLS. Source comunica `PolicyGuard` con `PhantomData<Rc<()>>`, save tramite `Cell::replace` e restore in Drop.

Nei sorgenti letti `classic_batch::mode()` e `selector_parallel::maybe_select` decidono all'ingresso; i figli PBS, PFKS e gruppi usano la decisione catturata senza leggere nuovamente READY. G4 resta disabilitato: `g4_query::active()` legge comunque READY, ma con ENABLED falso non esegue il ramo. Durante i nodi non si scrivono i controlli globali del livello; il finale può configurarli soltanto dopo il join della radice. Profiling disabilitato, valutazioni serializzate, nessuna query concorrente.

Il fold delle metriche segue l'ordine originale `(level,index)`, non l'ordine di completamento. I contatori interi devono descrivere gli stessi lavori; nessun tempo sovrapposto viene sommato come durata del torneo.

## Perimetro

Questi invarianti motivano l'accoppiamento dei sorgenti, non attestano la patch finale, una prova completa del FHE rumoroso o un guadagno. Gate del codice compilato e preregistrazione precedono l'eventuale unico pilot su famiglia fresca; nessun build o native eseguito qui.

## Pin diretti

Radice dei sette sorgenti: `/workspace/maintained/runtime/core/src/`. SHA256, byte:

| File | Byte | SHA256 |
|---|---:|---|
| wide_id.rs | 19387 | 0e9639bddd7e268a91234fbb2d16614b39b2b36094003e50d86c4c8cc6ecf35d |
| mixed.rs | 21808 | 467492d764ae8b51c78b1bba531082cd401ce1b6d27e84d7e03cd61751916ec2 |
| public_digits.rs | 10712 | 5c402b3296a599640f8b91543ace8149707488e0114f518276e6dd1d7c508439 |
| classic_batch.rs | 5162 | c496e843f2909c616cae76e9f549846d496fa55e191cfd5d34930a9babfc886f |
| selector_parallel.rs | 10250 | 4e54015fc8ad82a7deb2d842c607bbd58a0dd8409113038e3d49f8a83f8078f4 |
| g4_query.rs | 13510 | 6311dbb40e266b31164d341e14613b34d0eb044f9d9861fa778c3ca9c3986c8e |
| smallcuts.rs | 16892 | aa25d4b8dd1df2c2b89d7b6b2242f381066d5127ebe629ff2cadc25e144aac3a |

Interfaccia prevista: `tmp/current-tournament-dag-20261004/PROTOCOL.md`, 2981 byte, SHA256 `b83ff1674aaf846760ac21b93ab5d217d960f8ad0aebf34c7c4ca6099ec67eb3`. I pin non descrivono le nuove patch isolate.
