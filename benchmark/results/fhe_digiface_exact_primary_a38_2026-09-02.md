# A38 combined: suite primaria exact-ID DigiFace

Data run: 2026-09-02T13:42:12Z--15:12:31Z. Durata wall: 5.419,370 s.

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

Tutti i 127 genuine restituiscono la propria identita'. L'unico impostore primary-test accettato e'
il probe `758`/identita' `1680`: minimo clear `3 <= T=4`, primo argmin all'indice `45`, identita'
`1038`, codice atteso e osservato `46`. E' il falso positivo **biometrico** previsto dall'oracolo e
dalla calibrazione, non un errore FHE. Lo stesso probe compare nella frontiera storica, ma con una
cifratura distinta.

La suite confronta l'intero codice con l'oracolo first-minimum. Non e' un test esaustivo della
regola di pareggio: tie interni, tie di coda e ID 127/128 sono coperti dalle fixture component A38,
non da questa popolazione primaria.

## Cifrature, percorso e costo

- 632/632 hash SHA-256 distinti dei probe ciphertext, 32.840 byte ciascuno;
- 632/632 hash SHA-256 distinti anche per i result ciphertext, 16.464 byte ciascuno;
- `exact-open-set-id-v2` e intestazioni di query verificate in ogni risposta;
- percorso integrato sempre `a38_combined`;
- stato server identico dopo enrollment e dopo tutte le query;
- galleria DigiFace con `N=127`, soglia uniforme inclusiva `T=4`;
- dominio stretto `[-987, 2329]`, larghezza 3.317;
- dominio allineato di esecuzione `[-1019, 2329]`, larghezza 3.349;
- **3.655 PBS/blind rotation in ogni query**.

Lo snapshot A33 usa 4.273 PBS sulla stessa scena: A38 rimuove quindi 618 PBS, ossia il 14,463%.
Rispetto ad A29 (`4.965`) ne rimuove 1.310 (`26,385%`); rispetto alla prima implementazione A23
completa (`7.804`) ne rimuove 4.149 (`53,165%`). Sono confronti strutturali del grafo, non misure
causali di latenza. Il confronto temporale valido A33/A38 e' l'esperimento paired separato sugli
stessi byte cifrati.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server | 5.664,3 ms | 8.327,75 ms | 8.552,109 ms | 11.039,5 ms | 16.174,7 ms |
| HTTP | 5.664,994 ms | 8.328,683 ms | 8.553,562 ms | 11.041,021 ms | 16.176,0 ms |

Encrypt wall medio: 7,921 ms; decrypt wall medio: 8,597 ms. Il carico host era alto e fortemente
non stazionario: load average 1/5/15 minuti `31,425/23,691/23,799` prima e
`263,235/320,065/345,909` dopo, su 16 CPU logiche. Le latenze assolute documentano questo run
contaminato e non vanno interpretate come prestazioni nominali su macchina idle. La mediana A33 di
un run separato era 8.458,2 ms, ma la differenza fra finestre non e' una stima causale.

## Provenienza e riproducibilita'

Invocazione eseguita (l'`argv` completo e' persistito nel JSON):

```bash
uv run python benchmark/fhe_digiface_validation.py --run --primary-suite \
  --regression-repetitions 1 --skip-build \
  --binary tmp/a38-combined-prototype/varco_demo \
  --output-stem fhe_digiface_exact_primary_a38_2026-09-02 --timeout 900
```

| artefatto/input | SHA-256 |
|---|---|
| JSON finale | `21b6a7db9e6eaa026cf3ea1fcc0264d942c56d6ead4d3f95a9fd4d76b9bc96e0` |
| CSV finale | `51b1539d894c3aa69cb4d91b77046dc741fee409685fa960d2cc84ba7653c610` |
| binario servizio congelato A38 `varco_demo` | `f4cdc28f92ffae8d34c207a06896299015aca2673fce14a959cc3bea34dc1e02` |
| core integrato `private_argmin.rs` | `5230f3863a5cad726aefe51a3c6a786899e4f1cdd47aeb0ff8f7141fcc3917ae` |
| servizio `varco_demo.rs` | `89eb3df057fd69e2ed3c96df94be9fdbd9e998eafe4401554da93ee168404f44` |
| libreria `lib.rs` | `855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532` |
| validator | `07a79bf92e409d67af3fcc003847eb28dba9041e753babca19ec66711053c559` |
| cache DigiFace | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| configurazione | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |
| `Cargo.toml` | `290b97cfd9af85685db419b5782d0e9ab073179b6ffe2c97ef9c8a33c4fddfb6` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Il processo osservato e il path atteso coincidevano col binario congelato. Il run ha usato
`--skip-build`; la copia sorgente conservata sotto `tmp/a38-combined-prototype/source/` coincide con
gli hash di core, servizio, libreria, manifest, validator e configurazione registrati dal run.

La provenienza Git e' il branch `thesis-evidence-audit-2026-09`, base
`6611c185adc9a658a075519b4316386f0bb48656`, con worktree esplicitamente sporco. Binario,
sorgenti, harness, cache, configurazione e manifest Cargo risultano identici prima e dopo. La
coppia di chiavi era fresca e temporanea; la directory e' stata rimossa e nessuna chiave client e'
inclusa negli artifact.

Artifact grezzi:

- [CSV](fhe_digiface_exact_primary_a38_2026-09-02.csv)
- [JSON](fhe_digiface_exact_primary_a38_2026-09-02.json)
- [component FHE A38](../../experiments/14_pipeline_tfhe_rs/results/exact_id_a38_combined_component_fhe_2026-09-02.md)
- [validator](../fhe_digiface_validation.py)

## Limiti e gate successivi

Il run usa una sola chiave, una sola galleria DigiFace `N=127`, soglia uniforme `T=4` e il dominio
allineato che abilita il fast path A38. Non valida il fallback A29 per soglie arbitrarie, non stima
l'accuratezza biometrica della popolazione e non prova la correttezza su ogni plaintext ammesso.

Zero errori in 632 query e' evidenza funzionale empirica, non una derivazione della probabilita' di
fallimento crittografico end-to-end. Restano separati il benchmark paired A33/A38, il gate Docker,
il formato terminale A41 a due LWE e il retuning A44. A38 ha quindi superato il gate primary, ma
non viene ancora promosso come configurazione finale. Questo artifact non sostiene claim di
novita' o priorita' scientifica.
