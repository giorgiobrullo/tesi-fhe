# A79 — gate `AuditedLwe` sul grafo A62

Data iniziale: 2026-09-02. Hardening: 2026-09-03. Stato: **PASS del
modello/replay dichiarativo; bound numerico end-to-end, truth table runtime e
attestazione restano aperti**.

## Risultato

A79 materializza un modello simbolico eseguibile e source-locked per il
percorso A62 exact `0/ID`. Ogni `AuditedLwe` porta esplicitamente:

- encoding torus, `delta`, dominio crittografico e ruolo LWE big/small;
- overapproximation dei plaintext raggiungibili e `Degree` shortint, se valido;
- `NoiseLevel` ufficiale oppure `None` per il raw non certificato;
- forma affine esatta dei contributi di rumore nominati;
- `blind_rotation_id` comune e grado di ogni sample correlato;
- obblighi di correttezza della LUT con stato open/discharged;
- evidenza tipata della derivazione, vincolata con SHA-256 allo stato completo.

Le origini ammesse sono cifratura fresca, output di PBS checked, plaintext
pubblico trivial, zero algebrico esatto e combinazione lineare ufficiale. Un
atomo ufficiale da solo non basta: copiare l'evidenza su un coefficiente, livello,
encoding, dominio, reachable set o lista di obblighi diversa viene rifiutato.
Due cifrature fresche distinte con la stessa label ricevono nonce interni
distinti, quindi non possono cancellarsi come se condividessero il rumore.

Questi seal e commitment sono guardrail di programmazione omission-resistant in
Python, non autenticazione crittografica contro codice che gira nello stesso
processo.

## Replay v3 e trust boundary

Il replay `a79.trace.v3` ricostruisce producer/consumer, reachable set,
operazioni lineari, KS, PBS raw/checked, geometria ManyLUT, sample correlati e
ledger. Il manifest `a79.manifest.v3`, fornito con digest atteso indipendente,
vincola:

- hash canonico della trace, graph ID, fingerprint A44, polynomial size,
  `max_noise_level` e ledger atteso;
- un binario, un parameter spec, un accumulator spec e almeno un sorgente via
  path esterno e SHA-256, rifiutando alias dello stesso file;
- per ogni accumulatore: modo PBS, encoding/dominio/wire/degree/reachable set
  dichiarati dell'input, margine e unità, stride checked, sample degree,
  encoding, reachable set e degree output.

Il replay confronta anche dinamicamente l'input effettivamente ricostruito con
il contratto dell'accumulatore. Riutilizzare lo stesso accumulator ID con un
input incompatibile viene rifiutato.

Il risultato resta intenzionalmente `PASS_DECLARATIVE_*` e riporta
`execution_attested=false`. Il digest non prova che il binario pin-nato abbia
emesso la trace. Inoltre l'accumulator spec descrive ancora metadata: non lega i
coefficienti effettivi del polinomio e non rivaluta indipendentemente la truth
table. Il bridge accumulator-runtime → mappa dichiarata resta quindi un obbligo
aperto, anche per una PBS checked.

## Ledger A62

| stadio | BR | KS | marginali conservative |
|---|---:|---:|---:|
| extract | 1651 | 1270 | 2159 |
| select | 1603 | 1603 | 1603 |
| scan/output | 136 | 136 | 168 |
| **totale** | **3390** | **3009** | **3930** |

Le `3930 - 3390 = 540` uscite aggiuntive sono marginali correlate, non prove
indipendenti. Il caso A53 conserva infatti la stessa blind rotation per i gradi
`0` e `1024`, ma due atomi marginali distinti. La ricostruzione client
`low + 15*high` mantiene entrambi nella provenance e non somma mai le varianze
come se fossero indipendenti.

Se, e solo se, tutte le 3930 marginali raw ereditassero il contratto del preset
A44:

```text
3930 * 2^-64.088 = 2^-52.14768640285403
                    = 2.00438981955565e-16.
```

Questa è ancora una union bound **condizionale**. Il bound end-to-end
incondizionato rimane `P_fail <= 1`, perché manca la premessa sulla coda
effettiva degli input raw dopo KS/modulus switching e sotto prefisso corretto.

## Verifiche

- 67/67 unit test Python 3.12: PASS;
- Ruff: PASS;
- nove famiglie di sorgenti/hash TFHE-rs/A62/A53 verificate: PASS;
- geometria checked ManyLUT (`<=8` funzioni, input max degree e stride generato)
  riprodotta e validata: PASS;
- `NoiseAtom` rifiuta NaN, infinito, booleani e identificatori/gradi mal tipati;
- reachable set generale dichiarato esplicitamente come overapproximation
  cartesiana; solo riferimenti allo stesso identico ciphertext vengono
  coalesciati relazionalmente, per esempio `x-x=0`;
- 364 mutazioni JSON-compatible del manifest: nessun crash non gestito e nessun
  falso accept nel fuzz indipendente;
- path illeggibili/troppo lunghi, op list/dict, alias di file, drift di hash,
  artifact role non stringa e riuso incompatibile di accumulatore sono
  trasformati in rifiuti controllati.

Comando riproducibile, con Python >=3.10:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover \
  -s tmp/a79-a62-audited-lwe-model -p 'test_*.py' -v
uv run --offline ruff check tmp/a79-a62-audited-lwe-model
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py
```

Il `python3` di sistema in questo host è 3.9 e non supporta
`zip(strict=True)`; non è il runner valido del gate.

## Limite e prossimo gate

A79 chiude gli invarianti tipati e la coerenza interna del replay dichiarativo,
non la semantica end-to-end/LUT né la correttezza numerica FHE completa. Restano
da fare:

1. emettere dal Rust tipato tutti i `3390 BR / 3009 KS / 3930` eventi, non solo
   trace rappresentative;
2. legare i byte/coefficienti reali degli accumulatori e verificarne
   indipendentemente le truth table;
3. attestare il legame fra esecuzione, binario e trace invece di verificarne
   soltanto la coerenza dei digest;
4. derivare un tail bound source-backed per ogni famiglia raw e propagare la
   dipendenza quando più sample della stessa blind rotation vengono ricombinati;
5. solo allora sostituire il bound incondizionato uno con un valore non banale.

Gli hash finali degli artefatti sono raccolti in
`tmp/a79-a62-audited-lwe-model/SHA256SUMS`.
