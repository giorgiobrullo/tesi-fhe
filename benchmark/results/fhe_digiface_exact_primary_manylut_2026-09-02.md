# A29 ManyLUT: suite primaria exact-ID DigiFace

Data run: 2026-09-02T05:26:41Z--06:39:35Z. Durata wall: 4.373,064 s.

## Esito

**PASS: 632/632 risultati conformi al contratto**, zero errori operativi e zero discrepanze
rispetto all'oracolo clear intero.

| suite | query | autorizzazioni attese/osservate | errori | discrepanze |
|---|---:|---:|---:|---:|
| frontiera storica | 5 | 3/3 | 0 | 0 |
| genuine primarie | 127 | 127/127 | 0 | 0 |
| impostori primary-test | 500 | 1/1 | 0 | 0 |
| **totale** | **632** | **131/131** | **0** | **0** |

Le 131 accettazioni restituiscono il nearest ID esatto; i 501 rifiuti restituiscono il codice
`0`. Nei rifiuti l'argmin interno non e' osservabile dal client e non va descritto come direttamente
misurato. Tutti i 127 genuini restituiscono la propria identita'.

L'unico impostore autorizzato fra i 500 primary-test e' il probe `758`/identita' `1680`: score
minimo `3 <= T=4`, nearest gallery index `45`, identita' `1038`, codice `46`. E' un falso positivo
biometrico gia' previsto dall'oracolo e dalla calibrazione, non un errore FHE. Lo stesso probe
compare anche nella suite di frontiera, con una cifratura distinta.

La suite contiene nove righe con pareggio sul minimo, ma sono tutte rifiutate: non osserva quindi
direttamente il tie-break nell'output. La regola first-minimum resta validata dalla matrice semantica
A29 separata.

## Cifrature, costo e contratto

- 632/632 hash SHA-256 distinti dei probe ciphertext, 32.840 byte ciascuno;
- 632/632 hash SHA-256 distinti dei result ciphertext, 16.464 byte ciascuno;
- **4.965 PBS in ogni query**;
- contratto `exact-open-set-id-v2` in ogni risposta;
- coppia di chiavi client/server generata apposta in directory temporanea e rimossa a fine run;
- server terminato col SIGTERM previsto (`exit_code=-15`); PID e porta liberi sono stati verificati
  live dall'audit, ma non sono campi persistiti nel JSON;
- nessuna distanza, score o conteggio restituito dal decrypt.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server | 6.587,5 ms | 6.851,8 ms | 6.904,265 ms | 7.355,9 ms | 8.364,2 ms |
| HTTP | 6.588,137 ms | 6.852,517 ms | 6.904,940 ms | 7.356,593 ms | 8.365,286 ms |

Encrypt wall medio: 5,241 ms; decrypt wall medio: 5,691 ms.

Sul medesimo elenco di 632 casi, ma in un run A28 **separato**, si osservano:

- PBS/query: 5.600 -> 4.965, cioe' -635 e **-11,34%**;
- 401.320 blind rotation/PBS in meno sull'intera suite;
- media server: 7.522,258 -> 6.904,265 ms, cioe' -8,22%;
- mediana server: 7.451,75 -> 6.851,8 ms, cioe' -8,05%;
- A29 piu' veloce in 610/632 righe allineate per caso.

Questi ultimi numeri sono soltanto un confronto esplorativo: chiavi, ciphertext, ordine temporale e
carico non erano appaiati, e il load era alto/non stazionario. La stima causale va affidata al
benchmark paired A28/A29 sulla stessa chiave e sugli stessi byte cifrati.

## Provenienza

- base Git `6611c185adc9a658a075519b4316386f0bb48656`, worktree esplicitamente sporco;
- core A29 `src/private_argmin.rs`:
  `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- validator:
  `eabb803d3c8e85f4c38ac395a8907b7b0579fede89f9c23362006da675523398`;
- binario macOS congelato:
  `cb0d0c1736713ae7b7a36450456a6ea45cab5bd8ac63d0c08c78220b4aaba102`;
- patch sorgente A29 finale:
  `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54`;
- CSV:
  `7337057cc97eeafe102cd330df154f31656e142a97029ac388dbd8aefd8eed5b`;
- JSON:
  `328964c860919cfce2ae09ec3ac1e2ab1f3efcc7d25c1a9781ee1ee7dafa0b34`.

La patch contiene 19 file, si applica con `--index` al base e ricostruisce il tree
`00c9ee5f5c8c53c77dc38fca89cdb0ba75c000d8`; dal worktree ricostruito compilano sia i binari di
produzione sia quelli diagnostici. Tutti gli input registrati dal validator coincidono prima/dopo
il run e con i digest registrati nello snapshot congelato.

Artifact grezzi:

- [CSV](fhe_digiface_exact_primary_manylut_2026-09-02.csv)
- [JSON](fhe_digiface_exact_primary_manylut_2026-09-02.json)
- [patch sorgente A29](../patches/a29_manylut_source_2026-09-02.patch)

## Limiti

Il run usa una sola chiave, una galleria N=127 e la distribuzione DigiFace congelata. E' evidenza
empirica di correttezza sul campione, non una prova della `p-fail` end-to-end ne' della biometria
continua. Il gate E2E del demo Docker e il confronto paired restano artifact separati.
