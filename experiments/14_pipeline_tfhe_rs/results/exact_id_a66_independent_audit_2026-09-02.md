# A66: audit indipendente del candidato latency-ready

Data: 2 settembre 2026. Ambito: confronto statico fra i prototipi A62 e A66.
I sorgenti specifici dei due prototipi non sono inclusi in questa distribuzione;
i nomi dei file sotto identificano le parti ispezionate. Questo rapporto non aggiunge
compilazione, esecuzione FHE o misure di latenza.

## Esito dell'audit

Non emerge una divergenza bloccante della semantica exact-ID sul percorso valido. A66 conserva il
grafo logico A62, il primo vincitore nei tie, i contatori `3390/3009/3930` a N=127 e il wire a due
radici p16 base 15. Il cambiamento osservato e' limitato alla preparazione degli accumulatori A53,
alla schedulazione dei peer indipendenti e ai contatori atomici.

Il claim strutturale e' corretto ma va formulato precisamente: **nel solo adapter A53**, a N=127,
A62 costruisce 136 GLWE triviali e A66 ne prepara 35. Sono 101 costruzioni in meno (-74,3%), non
101 PBS in meno, non un risparmio dimostrato di latenza e non una riduzione delle allocazioni
dell'intera query.

Questo audit statico non stabilisce type-check, esecuzione FHE o latenza; tali evidenze, anche se
prodotte separatamente, devono restare artefatti distinti. Il confronto causale corretto e'
**A62 contro A66**, non A44 contro A66.

## Superficie del cambiamento e provenienza

Il confronto ha coperto i 12 file del prototipo A62. La configurazione Cargo,
`src/lib.rs` e `src/a53_scan.rs` sono byte-identici in A66; rimane identico anche
il manifest degli input derivati.

Il `Cargo.lock` cambia soltanto il nome del package root. In `src/private_argmin.rs` le sole
modifiche operative sono il backend A53, i suoi contatori e la chiamata al nuovo adapter; score,
estrazione, A34-top e selezione A50 non cambiano. Il bin diagnostico cambia import e identificatori
di variante, non fixture o controlli. La parte sostanziale del candidato e' quindi
`src/a53_scan/fhe.rs`.

Il manifest A62 e' un buon vincolo statico, ma il gate runtime A66 continua a legare i sorgenti
A38/A44/A50/A53, non il proprio sorgente o il binario A66. Il futuro gate di compilazione e paired
deve quindi usare un `CARGO_TARGET_DIR` isolato, congelare sorgenti/lock/binario e stampare un
identificatore A66 specifico. Non va riutilizzato un shared target come prova che sia stato linkato
il sorgente atteso.

## Equivalenza semantica e tie-first

Per input validi il DAG cifrato resta equivalente ad A62:

1. `src/a53_scan.rs`, che definisce LUT, layout, radix 15 e modello clear, e' identico.
2. I candidati arrivano nello stesso ordine dal core A50 invariato.
3. Gli iteratori paralleli di slice sono indicizzati; i `Vec` raccolti conservano l'indice di
   galleria, non l'ordine di completamento dei thread.
4. Il prefix parallelo ricostruisce per ogni indice gli stessi `block_index`, `offset` e ingressi
   dell'algoritmo sequenziale A62. La ricorsione resta una barriera.
5. Ogni nodo somma i propri LWE nello stesso ordine sequenziale di A62; soltanto nodi indipendenti
   possono completare in ordine diverso.
6. Le riduzioni low/high conservano ordine dei chunk, livelli e forwarding dei singleton. Il
   `rayon::join` terminale separa due lane senza dipendenza reciproca.
7. Ogni selector possiede il layout dello stesso `group_index`; il relativo accumulatore viene
   mosso in un solo job e ruotato in-place.

Ne segue che prefix esclusivo, posizione locale e indice globale continuano a scegliere il primo
argmin ammesso. Il controllo statico composto A50+A53 conferma 512 fixture (reject, primo tie e
ultima identita' per ogni N=1..128), ma non sostituisce una replica FHE.

Per verificare l'equivalenza byte per byte, una replica dovrebbe confrontare i coefficienti delle due radici A62
e A66 sullo stesso input, oltre al codice decifrato. La valutazione server e' deterministica e gli
accumulatori triviali ricostruiti da A62 hanno gli stessi coefficienti di quelli riusati da A66;
una differenza byte-level sarebbe quindi un segnale da indagare, anche se il gate semantico minimo
resta `code=low+15*high` uguale all'oracolo clear.

### Differenza residua sul percorso di errore

A66 non conserva necessariamente la precedenza degli errori interni di A62: i due rami di un
`rayon::join` terminano entrambi e il codice propaga prima il risultato del ramo sinistro. A62
falliva invece alla prima chiamata sequenziale. Sul contratto valido gli errori interessati non
sono raggiungibili dopo i gate di geometria; il comportamento resta fail-closed, ma non va
dichiarata equivalenza perfetta delle diagnostiche per input/backend invalidi.

## Thread safety

La struttura e' plausibilmente thread-safe per costruzione Rust:

- il trait richiede `Backend: Sync`, `Lwe: Send + Sync`, `Accumulator: Send + Sync` ed
  `Error: Send`;
- server key, key-switch key, bootstrap key e accumulatori condivisi sono letti tramite riferimenti
  immutabili;
- output LWE, ciphertext switched e buffer sono locali al singolo job;
- l'unico accumulatore mutato dalla blind rotation e' il selector, passato per valore e quindi
  posseduto esclusivamente dal job;
- i contatori condivisi sono `AtomicU64` e vengono letti soltanto dopo le barriere Rayon.

Nel sorgente locale TFHE-rs 0.11.3, `programmable_bootstrap_lwe_ciphertext` e
`blind_rotate_assign` creano un `ComputationBuffers` locale a ogni invocazione; non e' stato
osservato scratch mutabile condiviso. Il primo type-check resta comunque il gate definitivo dei
vincoli auto-trait `Send/Sync`, seguito da FHE con piu' chiavi.

## Contatori, wire e riduzione GLWE

I contatori A53 non cambiano: ogni PBS incrementa un atomico comune per BR/KS, mentre la dual
extraction aggiunge un marginale extra. Dopo la barriera A66 ricostruisce quindi gli stessi
`136/136/168` della scan e gli stessi `3390/3009/3930` full a N=127. `src/a53_scan.rs` e
`src/lib.rs` identici mantengono due LWE p16, `Delta=2^59`, nessuna ricomposizione server e
`code=low+15*high` sul client.

La riduzione delle costruzioni GLWE e' verificabile direttamente:

| famiglia A53, N=127 | A62 | A66 | delta |
|---|---:|---:|---:|
| OR di gruppo + prefix | 64 | 1 condiviso | -63 |
| local-first | 32 | 1 condiviso | -31 |
| identity delle due riduzioni | 8 | 1 condiviso | -7 |
| selector, uno per gruppo | 32 | 32 esclusivi | 0 |
| **totale adapter** | **136** | **35** | **-101** |

Con `G=ceil(N/4)`, A66 prepara 1 accumulatore a N=1, 3 a N=2..4 e `G+3` da N=5. Ogni GLWE A44
contiene `glwe_size=2` per `polynomial_size=2048` coefficienti `u64`, circa 32 KiB di payload. A66
mantiene fino a 35 accumulatori contemporaneamente, circa 1,09 MiB, mentre A62 ne costruiva molti
di piu' nel tempo ma tipicamente uno per volta. Quindi diminuiscono costruzioni e copie, ma aumenta
la memoria GLWE viva dell'adapter. Inoltre ogni PBS parallelo alloca scratch locale TFHE: il paired
deve registrare peak RSS e non assumere che meno costruzioni significhi meno RAM.

## Perche' il baseline deve essere A62

A62 e A66 hanno stesso parametro A44, stesso contratto, stesso wire, stesso DAG logico e stessi
contatori; differiscono soltanto per preparazione/scheduling A53. Questo rende interpretabile il
rapporto temporale come effetto complessivo dell'implementazione latency-ready.

A44 non e' un controllo causale valido: usa selezione e scan precedenti, output base 16 e conta
`3655/3274/4206` invece di `3390/3009/3930`. Un A44/A66 mescolerebbe i risparmi algoritmici A50,
la scan/wire A53 e l'ottimizzazione di esecuzione A66. Puo' essere una comparazione secondaria
della linea evolutiva, mai la prova della velocita' di A66.

## Disegno preregistrato del paired A62/A66

### Artefatti e isolamento

1. Materializzare due binari di servizio con wrapper byte-identico, stesso protocollo A62 base 15
   e unica differenza nel path dependency A62 oppure A66. In alternativa, per il primo gate di
   componente, un solo binario dipende dai due crate rinominati e chiama entrambe le funzioni sullo
   stesso oggetto `ServerKey`, `Glwe` e slice di template.
2. Compilare locked/offline in un target temporaneo esclusivo. Congelare SHA-256 di lock, sorgenti,
   harness e binari; al runtime verificare gli ACK distinti A62/A66, il fingerprint A44 e gli anchor
   `3390/3009/3930`.
3. Fissare esplicitamente il numero di thread con un pool Rayon dedicato; non eseguire le due
   varianti contemporaneamente.

### Scena e coppie

Usare la scena DigiFace N=127 gia' congelata dal paired A33/A38 e gli stessi cinque probe di
frontiera `(265,2), (758,3), (211,4), (1943,5), (407,7)`. Evita i probe nulli/triviali del harness
di componente e mantiene galleria, nomi, soglia 4 e ordine byte-identici.

Per ogni key block:

- generare una sola coppia di chiavi A44 fresca;
- completare keygen, enrollment e tutte le cifrature prima del timing;
- per ogni riga creare un ciphertext fresco una sola volta e passare gli stessi byte immutabili a
  entrambe le varianti;
- escludere quattro coppie di warm-up;
- misurare quattro ripetizioni per ciascuno dei cinque probe, due in ordine A62->A66 e due in
  ordine A66->A62, mescolate con seed deterministico e bilanciate dentro ogni coppia
  `(key_block, probe)`.

Il disegno iniziale raccomandato e' 3 key block, 20 coppie misurate per blocco: 60 coppie piu' 12
warm-up. Se CI o effetto d'ordine non sono stabili, aggiungere una sola estensione preregistrata di
altri 3 blocchi, ottenendo al massimo 120 coppie piu' 24 warm-up senza mutare i dati iniziali.

### Endpoint e controlli

Il timing primario e' il solo core/server monotonic wall time; il wall end-to-end e le metriche di
stage (`scan.seconds`, `total_seconds`) sono diagnostiche secondarie. Ogni riga deve registrare:

- hash del ciphertext inviato alle due varianti e hash della galleria ordinata;
- ordine AB/BA, key block, probe, ripetizione e numero di thread;
- tempo A62/A66, stage scan e total, BR/KS/marginali;
- `low`, `high`, codice ricostruito e accordo con oracolo clear;
- RSS di picco per processo/blocco e failure/panic/OOM;
- hash delle due risposte cifrate come diagnostica di equivalenza byte-level.

Gate duri: stessi byte in input, stesso stato normalizzato di key/galleria, zero discrepanze
semantiche, due LWE p16, ricostruzione base 15, conteggi esatti e nessun record mancante/duplicato.
La decifratura va rimandata a dopo tutte le coppie timed del blocco.

### Separare riuso e parallelismo

L'A62/A66 multi-thread misura correttamente l'effetto **complessivo** del candidato, ma A66 unisce
due interventi. Per non attribuire causalita' al meccanismo sbagliato:

- eseguire uno strato `threads=1`, che misura riuso degli accumulatori piu' overhead fisso Rayon,
  senza speed-up da parallelismo;
- eseguire separatamente lo strato col numero di thread di produzione fissato, che misura l'effetto
  complessivo riuso+parallelismo;
- se serve un claim separato sul solo riuso, aggiungere un controllo seriale con accumulatori
  preparati (`A62`, `prepared-serial`, `A66-parallel`). Senza quel terzo braccio non separare i due
  effetti nel testo.

L'estimando primario e' `100 * (1 - geometric_mean(t_A66/t_A62))` sulle coppie. L'intervallo 95%
deve usare bootstrap gerarchico: ricampionare i key block, poi le righe nei relativi strati
probe-per-ordine a cardinalita' fissa. Riportare anche wins/losses, mediana del delta, risultati per
ordine AB/BA, per probe, per blocco, differenza prima/seconda meta' e CI. Una promozione temporale
richiede almeno limite inferiore del CI sopra zero e nessun segnale materiale di ordine/OOM; la
soglia pratica di speed-up va dichiarata prima dell'esecuzione.

## Esito e confronto necessario

A66 supera l'audit statico di equivalenza con le cautele sopra, ma nessun
claim di latenza e' ancora supportato da questo documento. Il prossimo confronto deve essere
A62/A66, con target isolato, input byte-identici, ordine bilanciato, strati a 1 thread e produzione,
RSS registrato e analisi paired gerarchica.
