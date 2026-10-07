# A108: riesecuzione con log completi

Il 5 ottobre 2026 sono state rieseguite le cinque configurazioni del
componente packed PFKS A108: **40 casi, 295 record conservati**. Tutte le
configurazioni falliscono il gate; il riferimento scalare decodifica
correttamente tutte le 160 uscite. Il risultato negativo è confermato
con nuove chiavi, senza promuovere i tempi a uno speedup.

| PFKS | Casi che falliscono il gate / 8 | Decodifiche packed errate / 32 | Decodifiche scalari errate / 32 | Traccia completa |
|---|---:|---:|---:|---|
| 23x1 | 4 | 13 | 0 | [JSONL](runs/23x1/stdout.jsonl) |
| 24x1 | 3 | 5 | 0 | [JSONL](runs/24x1/stdout.jsonl) |
| 16x2 | 4 | 9 | 0 | [JSONL](runs/16x2/stdout.jsonl) |
| 12x3 | 5 | 10 | 0 | [JSONL](runs/12x3/stdout.jsonl) |
| 10x4 | 6 | 13 | 0 | [JSONL](runs/10x4/stdout.jsonl) |

Ogni configurazione usa un processo, una nuova famiglia di chiavi e un
thread Rayon, con le otto fixture e l'ordine packed/scalare originali.
Non sono stati ripetuti o scartati i casi falliti. L'uscita 1 del programma
segnala il gate negativo e segue il riepilogo completo: non è un crash.
Gli ingressi passano in tutti i casi.

## Codice e verifica

[Sorgente](source/src/main.rs), [manifest](source/Cargo.toml) e
[lockfile](source/Cargo.lock) sono identici agli originali: TFHE-rs 0.11.3.
La [compilazione](BUILD.json) usa Rust 1.98.1; il report di settembre
usava 1.97.1. Questa è una nuova campagna e non la ricostruzione delle
stesse chiavi casuali di settembre. La [provenienza](PROVENANCE.json)
lega sorgenti, tracce, ricevute di uscita e verifica.

Il [controllo indipendente dei log](review/validate_logs.py) ricalcola
fasi, decodifiche, gate e aggregati dai record salvati.
[Esito della verifica](VALIDATION.json).

Il campo originale `actual_control_degree` deriva dalla fase decifrata
arrotondata: **non certifica l'indirizzo effettivo della blind rotation
coefficiente per coefficiente**. I nuovi log documentano gli errori di
uscita; non autorizzano la vecchia attribuzione «errore dentro il supporto».
Il componente riceve già il controllo cifrato e non esegue comparatore,
torneo o identificazione completa. Una chiave per configurazione non
fornisce una stima della probabilità di fallimento.

## Ripetere la prova

Dalla cartella di questa scheda, compilare separatamente dall'esecuzione:

```sh
cargo build --release --locked -j 1 --manifest-path source/Cargo.toml --target-dir .local/target
mkdir -p .local/new-runs
A108_RUN_FHE=I_ACKNOWLEDGE_A108_PACKED_D2_K4_FHE \
A108_PREREGISTRATION_SHA256=b12dbbb9c2e81de20f54070dba2a48c9f5a6f64c351f26f2889a7e8d5d899ce6 \
RAYON_NUM_THREADS=1 \
.local/target/release/a108_packed_pfks_d2_k4 --run-authorized --pfks 23x1 \
> .local/new-runs/23x1.jsonl 2> .local/new-runs/23x1.stderr.log
```

Le altre configurazioni sono `24x1`, `16x2`, `12x3`, `10x4`, ciascuna in
un processo separato con file di uscita distinti. Conservare il primo
esito anche se negativo. Il [protocollo originale](PREREGISTRATION.json)
distingue questa diagnostica dalla qualifica su più chiavi e dai tempi.
