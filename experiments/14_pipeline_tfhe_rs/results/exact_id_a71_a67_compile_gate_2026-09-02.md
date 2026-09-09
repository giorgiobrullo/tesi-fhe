# A71 — gate indipendente di compilazione A67

Data: 2026-09-02.

## Esito

Il sorgente materializzato A67 compila e linka contro TFHE-rs 0.11.3 in modalita'
`--release --locked --offline` quando viene costruito in un target Cargo isolato. Il gate di
compilazione e' **PASS**:

- 13/13 test statici Python;
- audit statico `PASS_STATIC_ONLY_NOT_COMPILED_NOT_FHE_VALIDATED` (stato dichiarato dal manufatto
  A67 prima di questo gate);
- Ruff e `rustfmt --check` puliti;
- 31/31 pin degli input A62/A65 e 16/16 pin del sorgente materializzato verificati;
- libreria Rust: 23 test passati, 0 falliti, 3 ignorati perche' generano chiavi o eseguono FHE;
- binario `varco_demo`: 12 test passati, 0 falliti;
- build release del binario riuscita e smoke senza argomenti riuscito;
- `Cargo.lock` invariato, SHA-256
  `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a`.

Non e' stato modificato alcun sorgente A67. Restano non eseguiti keygen, FHE, rete, Docker e il
gate runtime completo dei reject cross-format. A67 non e' promosso da questo risultato.

## Collisione di provenienza nel target condiviso

Un primo tentativo nel target condiviso
`tmp/a38-combined-prototype/target` ha prodotto un risultato internamente incompatibile con il
sorgente A67: il test della libreria ha riusato il manufatto di un altro clone e il binario ha poi
fallito per simboli A62 non esportati, sebbene `lib.rs` A67 li esporti esplicitamente. I cloni
A65/A66/A67/A68 hanno lo stesso package Cargo `pipeline_tfhe_rs 0.1.0`; compilazioni concorrenti
nello stesso target non costituiscono quindi una prova affidabile della provenienza del crate.

I due log del tentativo condiviso sono conservati come evidenza negativa e **non** contano nel
gate. L'intera verifica e' stata ripetuta da zero in
`tmp/a67-a62-service-materialization/target-a71`, dove la libreria corretta espone anche i quattro
test A53 assenti nel manufatto riusato (23 test passati anziche' 19) e il binario compila.

## Binding del binario isolato

Il binario release ha SHA-256
`35dd29890573790158d1174f391b83c607693183f663e79fbdfc69f658819021`. Un controllo sul manufatto
ha confermato la presenza letterale dei quattro binding richiesti prima di qualunque futura prova
FHE:

```text
params_id          = tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64
params_fingerprint = b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1
variant_id         = a62-a50-a53-radix15-group4-two-p16-v1
circuit_sha256     = ee76afd8ad3f6ee48fb3da4806e52fee3edf9db773c4adbe2c986fe713789b79
```

Gli hash dei sorgenti core incorporati coincidono con i pin A62:

```text
lib.rs             6023d1ca3594897b54b216f85580897aef5c4fe12c7245278f4b12e90f25116b
private_argmin.rs  69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab
a53_scan.rs        81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5
a53_scan/fhe.rs    a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e
varco_demo.rs      8ad76dc073be4fbe82725afbfb85cc5c3c5fb38e6398ddba0d04ad01955069a8
```

La presenza delle stringhe nel binario e i pin del sorgente sono controlli di provenienza del
build; non sostituiscono il successivo test funzionale FHE del contratto base-15 a due LWE.

## Evidenza SHA-256

| Evidenza | SHA-256 | Uso |
|---|---|---|
| `exact_id_a71_a67_static_tests_2026-09-02.log` | `05beafd47ee27fd0d124d78284b36710fb73d62123653852b4c8f97a66ad469e` | 13/13 test Python |
| `exact_id_a71_a67_static_audit_2026-09-02.json` | `c9fc2283303fd2788a3406386ffe3be7f017e8a46e6128524789b6499b1aeb2b` | audit e pin dichiarati |
| `exact_id_a71_a67_ruff_2026-09-02.log` | `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18` | Ruff pulito |
| `exact_id_a71_a67_rustfmt_2026-09-02.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `rustfmt --check` pulito, log vuoto |
| `exact_id_a71_a67_source_inputs_manifest_2026-09-02.log` | `228f37bfac4b343efae6eec4d64e29004ec96c92938e5020eeb015e2cf118716` | 31/31 input A62/A65 |
| `exact_id_a71_a67_materialized_manifest_2026-09-02.log` | `0ec097539fc5b57f160efe301db520fb176aa035f10938e55f5f23db3a5d41dc` | 16/16 file materializzati |
| `exact_id_a71_a67_lib_tests_2026-09-02.log` | `4fb4522155f0bdfac807261bfc66504d2b6ef9a1e790bc7dc1da90f810eff111` | tentativo condiviso, evidenza rifiutata |
| `exact_id_a71_a67_bin_tests_2026-09-02.log` | `565b623ebd08a7a5f468355652824099c77c66f6ab0ad1d98fe43185efec7267` | collisione condivisa osservata |
| `exact_id_a71_a67_isolated_lib_tests_2026-09-02.log` | `3100851b9d3edf4c5222d460744bc9287dad1e054842362d8f008d0731853d07` | 23 pass, 3 FHE ignorati |
| `exact_id_a71_a67_isolated_bin_tests_2026-09-02.log` | `8ca5e5219d58945219ad9283e7e61c6c7a6ebf65e656004046795a701de23b59` | 12/12 test binario |
| `exact_id_a71_a67_isolated_release_build_2026-09-02.log` | `35be3f4149be9d437bffb42fba263fe66375b2e2887b6c8d3968608ee818641c` | build release |
| `exact_id_a71_a67_isolated_binary_smoke_2026-09-02.log` | `b0845daa3051947ba409171bd76a300a8a0db96d004627766a36fe63bfe29f6d` | avvio CLI senza keygen/rete |
| `exact_id_a71_a67_isolated_binary_binding_2026-09-02.log` | `b27719a60caa6eb2912b305075424c824e33517848d061c388a4a97e263b4bf9` | binding e hash del manufatto |

I warning Rust osservati riguardano esclusivamente helper/trace legacy non usati nel target
servizio; non sono presenti warning di feature o import nel build isolato riuscito.
