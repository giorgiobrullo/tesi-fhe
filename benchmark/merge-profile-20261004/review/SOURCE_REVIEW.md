# Revisione sorgenti del profilo di un merge

Esito: nessun blocco materiale trovato nella patch letta. È una revisione statica, senza build, test, chiavi o query. La copia mantenuta non è stata modificata.

Confrontati integralmente i due diff con `tmp/current-core-profile-20261004/runtimes/profile`. Identità effettivamente verificate:

- `core/src/smallcuts.rs`: 21.600 byte, SHA256 `69b7d5d5cf89b2f7250ee8d5d439f7efde275d3e1e4aa10b911a7d4b8092aae9`.
- `core/src/wide_id.rs`: 19.713 byte, SHA256 `28443af60e3e66edc4e6ea2b0e7f9279a7f92c38728b35a799b451fd743a574f`.

La guardia di `smallcuts.rs:131–148` si attiva soltanto per N120, livello0, indice0, ModeBoth, Repack e profiling attivo. La closure indicizzata di `wide_id.rs:258–284` la crea e distrugge sullo stesso worker; PhantomData<Rc<()>> impedisce di spostarla. L'enumerazione del primo livello visita quell'indice una sola volta. La configurazione precedente al collect imposta60merge: `classic_batch.rs:37–47` conserva il comparatore scalare e `selector_parallel.rs:33–35` esclude il ramo interno parallelo. G4 è disabilitato dal PublicParallel corrente.

Il diff aggiunge soltanto guardia, record e letture temporali: operazioni FHE, ordine delle lane/gruppi, input/output e aggiornamenti dei contatori rimangono gli stessi. I cinque intervalli sono disgiunti; i gruppi di packing/rotazione ed estrazione vengono attraversati in serie da `smallcuts.rs:336–372`. **PackingRotation include la blind rotation**, oltre a copie, offset e somme: non può essere presentato come costo isolato delle allocazioni o del packing.

Drop prende e cancella il TLS prima di acquisire PROFILE, senza conservare un prestito RefCell o mutex durante FHE. Pubblica una sola volta; su panic marca completed=false. Il guard già presente in routes disabilita e scarta il profilo all'uscita dalla query, anche in errore. Begin/finish restano rispettivamente prima della validazione e dopo il controllo dei conteggi. Il parent profile conserva ModeBoth/narrow=true a N120.

Per consumare il risultato, richiedere completed=true, identità N120/level0/index0/ready60/internal_parallel=false e somma dei cinque span non superiore a node_wall_ns. `unassigned_wall_ns` usa saturating_sub: da solo non dimostra quest'ultima relazione. Il nodo è già incluso nel livello/torneo; non sommare o moltiplicare per60. Nessuna stima di risparmio segue dalla revisione.
