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

## Limite della composizione

Le proiezioni composte non sono conteggi osservati di un unico circuito.
Rimangono necessari suite primaria, test del servizio, confronto appaiato
e analisi `p-fail` dell'integrazione. I tre prototipi standalone non sono
inclusi in questa distribuzione.
