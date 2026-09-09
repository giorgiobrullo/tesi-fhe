# A33 aligned-sparse: suite primaria exact-ID DigiFace

Data run: 2026-09-02T10:21:34Z--11:53:08Z. Durata wall: 5.493,303 s.

## Esito

**PASS: 632/632 risposte conformi all'oracolo clear intero**, senza errori operativi e senza
discrepanze sul risultato exact-ID.

| suite | query | autorizzazioni attese/osservate | errori | discrepanze |
|---|---:|---:|---:|---:|
| frontiera storica | 5 | 3/3 | 0 | 0 |
| genuine primarie | 127 | 127/127 | 0 | 0 |
| impostori primary-test | 500 | 1/1 | 0 | 0 |
| **totale** | **632** | **131/131** | **0** | **0** |

Il contratto `exact-open-set-id-v2` restituisce un solo LWE: dopo la decifratura del client,
`0` significa rifiuto e `i+1` identifica la prima identita' col punteggio minimo, purche' il
punteggio vincente sia sotto la soglia inclusiva. Le 131 accettazioni restituiscono il nearest ID
atteso; i 501 rifiuti restituiscono `0`. Nei casi rifiutati l'argmin interno non viene rivelato al
client e non va quindi descritto come osservato direttamente.

Tutti i 127 genuini restituiscono la propria identita'. L'unico impostore primary-test accettato e'
il probe `758`/identita' `1680`: minimo clear `3 <= T=4`, primo argmin all'indice `45`, identita'
`1038`, codice atteso e osservato `46`. Si tratta del falso positivo **biometrico** previsto
dall'oracolo e dalla calibrazione, non di un errore FHE. Lo stesso probe compare nella frontiera
storica, ma con una cifratura distinta.

Questa suite confronta l'intero codice con l'oracolo first-minimum; non e' pero' un test esaustivo
della regola di pareggio. I casi avversari di pareggio e i confini del codice appartengono agli
artifact semantici separati.

## Cifrature, percorso e costo

- 632/632 hash SHA-256 distinti dei probe ciphertext, 32.840 byte ciascuno;
- 632/632 hash SHA-256 distinti dei result ciphertext, 16.464 byte ciascuno;
- `exact-open-set-id-v2` e intestazioni di query verificate in ogni risposta;
- percorso A33 sempre `a33_aligned_sparse`;
- galleria DigiFace con `N=127`, soglia uniforme inclusiva `T=4`;
- dominio stretto `[-987, 2329]`, larghezza 3.317;
- dominio allineato di esecuzione `[-1019, 2329]`, larghezza 3.349;
- **4.273 PBS/blind rotation in ogni query**.

Il conteggio A29 congelato sulla stessa scena e' 4.965 PBS/query: A33 rimuove quindi 692 PBS,
ossia il 13,938%. Questo e' un confronto strutturale dei circuiti, non una stima di latenza; la
stima temporale relativa e' affidata all'artifact paired A29/A33.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server | 7.121,7 ms | 8.458,2 ms | 8.673,134 ms | 10.774,2 ms | 17.647,8 ms |
| HTTP | 7.122,619 ms | 8.459,052 ms | 8.674,172 ms | 10.775,704 ms | 17.651,724 ms |

Encrypt wall medio: 6,705 ms; decrypt wall medio: 6,998 ms. Il carico host era eccezionalmente
alto e non stazionario: load average 1/5/15 minuti `91,983/139,333/107,115` prima e
`262,212/330,999/279,250` dopo, su 16 CPU logiche. Le latenze assolute documentano dunque questo
run contaminato dal carico, non le prestazioni di A33 su una macchina idle e non un confronto
causale con un run A29 separato.

## Provenienza e riproducibilita'

Invocazione eseguita (l'`argv` interno e' persistito nel JSON):

```bash
uv run python benchmark/fhe_digiface_validation.py --run --primary-suite \
  --regression-repetitions 1 --skip-build \
  --binary tmp/a33-aligned-sparse-2026-09-02/varco_demo \
  --output-stem fhe_digiface_exact_primary_a33_2026-09-02 --timeout 900
```

| artefatto/input | SHA-256 |
|---|---|
| JSON finale | `e3ef7b5ae74c85e883d8ed3b2670fb6efbd20291775752fefe1ec56c0f1a9467` |
| CSV finale | `0d35640d7803969f4fb4781bac3975e367e477447ecbf6ffc9fb6a090669a011` |
| binario congelato A33 `varco_demo` | `13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59` |
| patch sorgente A33 | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| core `private_argmin.rs` | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| servizio `varco_demo.rs` | `ae23024c8cbcb3269db14d816da44fb035f72b8ba00d83b5a5c2cb1aaca4c5ca` |
| libreria `lib.rs` | `c6fbdd61636f6335e6547ed17aa73cdea7c69c2a7c26f74980bb99c52a2e6f53` |
| validator | `b54fbc7ef278e53a08ad08eed4429833a7fba62b15ba810bc12c31af4904e79d` |
| cache DigiFace | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| configurazione | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |

La provenienza Git registrata e' il branch `thesis-evidence-audit-2026-09`, base
`6611c185adc9a658a075519b4316386f0bb48656`, con worktree esplicitamente sporco. Il run ha usato
Python 3.12.11 e il binario congelato, senza ricompilarlo. Binario, sorgenti, harness, cache,
configurazione e manifest Cargo risultano identici prima e dopo. La coppia di chiavi era fresca e
temporanea; la directory e' stata rimossa e nessuna chiave client e' inclusa negli artifact.

Artifact grezzi:

- [CSV](fhe_digiface_exact_primary_a33_2026-09-02.csv)
- [JSON](fhe_digiface_exact_primary_a33_2026-09-02.json)
- [patch sorgente A33](../patches/a33_aligned_sparse_source_2026-09-02.patch)
- [validator](../fhe_digiface_validation.py)

## Limiti

Il run usa una sola chiave, una sola galleria DigiFace `N=127`, soglia uniforme `T=4` e il dominio
allineato che abilita il fast path A33. Non valida le scene che ricadono sul fallback A29, non
stima l'accuratezza biometrica della popolazione e non prova la correttezza su tutti i plaintext
ammissibili.

Zero errori in 632 query e' evidenza funzionale empirica, non una derivazione della probabilita' di
fallimento crittografico end-to-end. Il conteggio conservativo `p-fail`, l'uscita finale e la
circuit privacy richiedono argomenti separati. Questo artifact non sostiene claim di novita' o di
priorita' scientifica.
