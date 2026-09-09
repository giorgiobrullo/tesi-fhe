# 21 — Selettore parallelo, cifre pubbliche, G4 e attraversamento PFKS

Quattro prototipi sono confrontati separatamente con i propri riferimenti,
già dotati di normalizzatore condiviso, confronto classico parallelo,
soglie pubbliche e tagli ID. Le percentuali misurano interventi aggiuntivi
su quei riferimenti.

| Prototipo | Esito | Coppie favorevoli |
|---|---:|---:|
| [Selettore parallelo](sources/selector-parallel/Cargo.toml) | 3,642326% di riduzione, due famiglie di conferma | 44/56 |
| [Propagazione cifre pubbliche](sources/public-digits/Cargo.toml) | 4,087594% di riduzione, due famiglie di conferma | 46/56 |
| [G4 composto](sources/g4-composite/Cargo.toml) | 2,323432% di riduzione, due famiglie di conferma | 45/56 |
| [Attraversamento PFKS condiviso](sources/pfks-stream/Cargo.toml) | 0,991443% più lento nello screening; nessuna conferma avviata | 11/28 |

Gli screening iniziali non entrano nelle conferme dei primi tre interventi.
Le perdite per scena e gli indicatori di carico restano nelle prove originali.
**Gli effetti non si sommano.** Nel confronto successivo della combinazione,
G4 è più lento della migliore variante pubblica/parallela e non viene incluso
nella [demo 22](../22_demo_composita/README.md). Questo non invalida il suo
precedente risultato contro un riferimento diverso.

[Risultati consolidati](RESULTS.json) e proiezioni delle conferme:
[selettore](evidence/selector-confirmation.json),
[cifre pubbliche](evidence/public-digits-confirmation.json),
[G4](evidence/g4-confirmation.json), [PFKS negativo](evidence/pfks-negative.json).
Ogni risultato resta legato alla propria sorgente e al proprio binario.

Le quattro copie contengono i workspace Rust, i lockfile e i file incorporati,
con dipendenza registry da TFHE-rs 1.7.0. Non sono state ricompilate o misurate
in questa posizione. [Origini delle copie](COPY_ORIGINS.json) e
[origini dell'evidenza](EVIDENCE_ORIGINS.json) permettono il confronto con gli
originali immutati. Nessuna chiave o query cifrata è inclusa.
