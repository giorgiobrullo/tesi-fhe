# A34/A36: validazione FHE isolata dei componenti

Data: 2026-09-02. Backend: TFHE-rs 0.11.3, parametri
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`, esecuzione locale arm64.

## Esito

Tre sostituzioni proposte dopo A33 sono state compilate ed eseguite su ciphertext reali:

| componente isolato | esito FHE | punto N=127 osservato | proiezione del core |
|---|---:|---:|---:|
| A34 classificatore/riduzione top | 24/24 casi, 25 valutazioni | 4.144 BR / 3.763 KS / 4.652 marginali | osservata direttamente dal core isolato |
| A34 scan/output a due nibble | 11/11 casi | blocco 210 BR / 210 KS / 253 marginali | 4.111 BR / 3.730 KS / 4.789 marginali |
| A36 selezione bassa a chunk di quattro livelli | 7/7 fixture su quattro key-run | blocco 1.614 / 1.614 / 1.614 | 4.019 BR / 3.638 KS / 4.654 marginali |

Tutti gli output coincidono con gli oracoli clear, compresi `0=reject`, ID 127, ID 128 e
tie-first. Le chiavi sono state generate in memoria dai tre harness e non serializzate.

Questi risultati validano i **componenti separati**. Non validano ancora il conto composto
`3.655 BR / 3.274 KS / 4.206 marginali`: serve un unico core Rust che colleghi A34-top, A36,
two-nibble e radix-5 senza decrypt/re-encrypt intermedio, seguito da test FHE propri.

## A34 top-category

Il prototipo parte dal core A33 congelato e sostituisce il filtro/riduzione superiore. Una LUT
classifica la categoria alta dello score riallineato, la riduzione sceglie la categoria minima e
gli otto bit bassi A33 completano l'argmin. Scan e output restano A33.

Il primo `cargo test` ha correttamente esposto un errore nell'asserzione clear del solo harness:
il test pretendeva che lo stadio top lasciasse gia' un unico minimo, mentre deve lasciare tutti i
candidati nella categoria alta minima. L'oracolo e' stato separato in:

1. candidati dopo la sola riduzione top;
2. candidati finali dopo gli otto bit bassi.

Dopo la correzione, `cargo fmt --check` e i quattro test Rust passano. Il run
`--run --small-only` passa 21 casi/22 valutazioni su una chiave fresca: tutte le 16 categorie,
frontiere 1023/1024, secondo ID, primo tie e all-reject. Il run completo successivo usa una nuova
chiave e passa 24 casi/25 valutazioni, aggiungendo le gallerie 64, 127 e 128:

| caso | codice | BR / KS / marginali | secondi del caso |
|---|---:|---:|---:|
| `n64_last_identity` | 64 | 2.076 / 1.884 / 2.332 | 6,108 |
| `n127_last_identity` | 127 | 4.144 / 3.763 / 4.652 | 10,292 |
| `n128_last_identity` | 128 | 4.174 / 3.790 / 4.686 | 10,268 |

Il comando del secondo run includeva `--case=n127_last_identity`, ma questo harness non implementa
un filtro `--case`; ha quindi eseguito l'intera matrice. Non e' stata selezionata una sottoserie a
posteriori.

## A34 scan/output a due nibble

Il prototipo consuma direttamente gli LWE dei candidati finali prodotti dalla trace A33. Non
decifra e non ricifra fra i due stadi. Una sola blind rotation del selector produce due sample,
low/high; le radici fresche sono pesate 1 e 16 e sommate linearmente, quindi la risposta wire resta
**un solo LWE** `0/ID`.

Il target dedicato compila; non contiene unit test Rust autonomi (`0 tests`), percio' il gate
sostanziale e' il suo harness FHE. Il run piccolo passa 5/5 casi; un secondo key-run completo passa
11/11:

| caso | codice | tie | nuovo blocco BR / KS / marginali | proiezione intero core |
|---|---:|---:|---:|---:|
| `n64_tie_id63_id64` | 63 | 2 | 108 / 108 / 130 | 2.068 / 1.876 / 2.410 |
| `n127_id127` | 127 | 1 | 210 / 210 / 253 | 4.111 / 3.730 / 4.789 |
| `n128_tie_id127_id128` | 127 | 2 | 212 / 212 / 255 | 4.140 / 3.756 / 4.823 |
| `n128_id128` | 128 | 1 | 212 / 212 / 255 | 4.140 / 3.756 / 4.823 |

## A36 chunked-candidate

A36 sostituisce otto aggiornamenti candidato indipendenti con due chunk di quattro livelli. Lo
stato interno usa `0/2`, i pesi signed
`[-2,-2,-2,-2,-2,8,-4,-2]`, una canonicalizzazione dopo `b4` e una finale `0/1` dopo `b0`.

La prima compilazione ha trovato un errore Rust nel solo audit statico: `flatten()` era applicato a
`&&[i64]` con il toolchain Rust 1.97.1. La sostituzione con
`flat_map(|values| values.iter())` non modifica LUT o circuito. Dopo la correzione,
`cargo fmt --check` e 2/2 test Rust passano.

Il run piccolo passa quattro fixture. Tre key-run ulteriori coprono il bit ladder, N=127 e N=128:

| caso | risultato | conteggio blocco | tempo sorgente A33 | tempo solo A36 |
|---|---:|---:|---:|---:|
| `n9_bit_ladder` | ID 1 | 122 / 122 / 122 | 0,931 s | 0,531 s |
| `n127_last_min` | ID 127 | 1.614 / 1.614 / 1.614 | 8,170 s | 3,100 s |
| `n128_last_two_tie` | ID 127 | 1.624 / 1.624 / 1.624 | 9,318 s | 3,650 s |

Nel caso N=127 il blocco A33 sostituito vale 1.868 nodi: il risparmio FHE strutturale osservato e'
254 BR, 254 KS e 254 marginali. I checkpoint di tutti gli otto livelli decifrano come il modello
clear e riportano zero mismatch.

## Tempi: cosa significano

I tempi sopra servono a rilevare regressioni macroscopiche e a mostrare che i circuiti vengono
effettivamente valutati. I componenti sono stati eseguiti in processi/key-run diversi e il carico
host non e' stato controllato: non costituiscono un benchmark appaiato e non vanno usati per
attribuire una percentuale di speed-up. La prova causale di latenza andra' eseguita soltanto sul
binario integrato congelato, contro A33, con gli stessi ciphertext per coppia.

## Provenienza congelata dopo i run

| artefatto | SHA-256 |
|---|---|
| A34-top `Cargo.toml` | `95952f1027654ca59211b9c5d0af875904a559c636c8d9e129274bc1937e2522` |
| A34-top `Cargo.lock` | `a957d1cea8f5a216280a799ed54cc63a937ab71455d6bfd1a86771d151789e51` |
| A34-top `src/lib.rs` | `40534f1df5e2cc9b9df8b21d25d0c80f5bd56604290e3064e663d627d1e565f6` |
| A34-top `src/private_argmin.rs` | `c52a525ca454478489a6cf57b44cc4a430318b50c51b018e8a80fd84f7a1149c` |
| A34-top harness corretto | `196d07ff15effe735daf426ed30eb354e864bf51042b24695150264e0a868fd3` |
| A34-top binario | `eb08f3f2b7ac0719a1f5f7370a55c85a7ed51af887e69ccb301d9d5110c0c6b7` |
| two-nibble `Cargo.toml` | `7d9d5c7c65a769f166ac5054fd57ccf8db9addce1a47fdfdb72cff11cd662bbd` |
| two-nibble `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |
| two-nibble core A33 | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| two-nibble harness | `1ebb13d244c7ac0b943e24e6db8aeba7c80d2e655908bd9cbea52a3446f20892` |
| two-nibble binario | `c11d2dce94fe4498bfcf1346b6da628c74b06bdab5262a32937105e43f4690c7` |
| A36 `Cargo.toml` | `443e1df88ef6f36aeb96f58b872f2fe26b5837831056a8e84bcb1f9222ed9e8b` |
| A36 `Cargo.lock` generato | `131e5cda4e131b3a62ae4ab264dad73e53a1b74e1b31e7690296cdf5a5627db2` |
| A36 sorgente corretto | `91a9cc206c059ee3806dc10d2ec6ef82b70fc7642bc9ac328a74884da58a2f0b` |
| A36 binario | `b8a0b75d1fac1545e7f50d04ef65876193bbe3fbb3c91bfbe2e251d38ea091c3` |

Gli hash identificano i prototipi isolati realmente eseguiti. Non trasformano le proiezioni
composte in conteggi osservati e non sostituiscono suite primaria, Docker, paired o accounting
`p-fail` del futuro core integrato.
