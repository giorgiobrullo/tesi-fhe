# Tuple con due cifre55: piano minimo delle interfacce

4 ottobre 2026. Solo sorgenti mantenute in W=`/workspace/maintained`; nessun codice/run. **Non servono doppie lane:** score `[top59,middle55,low55]`, ID59 e, per Mixed, soglia `[top59,middle55,low55]` codificata così fin dalla foglia pubblica.

**Selezione:** smallcuts.rs 238–278 e selector_parallel.rs 84–96, 148–183 sottraggono ciphertext, applicano PFKS, impacchettano con offset pubblici, fanno BR/extraction e add-back della stessa lane. Non leggono una Delta del payload. Scale diverse nello stesso gruppo non richiedono uno stride diverso, purché left/right della stessa lane coincidano come encoding. È compatibilità dell'interfaccia e del trasferimento ideale: la decomposizione PFKS e i residui rumorosi non diventano esattamente lineari né indipendenti dalla precisione richiesta. public_digits.rs 56–63 ripristina solo lane≥3: gli assert59 restano validi per ID e threshold-top; nel piano Mixed le lane7/8 richiedono assert55. I commenti all59 a124/141 vanno qualificati.

**Emissione senza nuove BR/extraction:**

1. shared_normalizers.rs 92–111: common Residual58→54 e common Carry59→55; fattori pubblici2/1 invariati. factor_pair/evaluate (158–200) mantengono una BR e due extraction per coppia in Both.
2. split.rs 82–85 e203–205/219–221: rendere coerenti cache e ramo Scalar: Residual `[low55, carry54]`, Carry `[middle55, carryTop55]`. Non cambiare `DELTA58`, Head4/Head5 o il feedback Head precedente (7,174–201).
3. split.rs217: usare una copia del carry Residual moltiplicata16 prima di sommarla a digits[1]. **Questo feedback è a58**, non59. A233, moltiplicare16 una copia di carryTop prima di completare top59. Restituire direttamente low55/middle55 a234. Sono due nuove moltiplicazioni pubbliche dell'intero LWE, con gestione delle copie; amplificano anche l'errore dei carry. Nessun BR/PFKS/sample aggiunto nell'ingresso.

**Uniforme:** wide_id.rs489–506 mantiene ID59. PAYLOAD_DELTAS (9) diventa `[59,55,55,59,59,59]` come esponenti: sentinella pubblica coerente (307–310). Sostituire compare (31–43) con C, senza vecchio offset−Delta/2; controllo/refresh59 invariati. Aggiornare conteggi/assert (service_selected.rs10–29,55), oggi riferiti al vecchio comparatore. Decodifica ID invariata.

**Due PBS eterogenee, non solo nuovi pesi:** classic_batch.rs58–90 esegue tre differenze con un unico callback/LUT; Batch3 costruisce tre accumulatori omogenei (94–129). I caller wide_id.rs34 e mixed.rs23 richiedono un percorso distinto a due operazioni: top-ternary59 può mantenere comparator::pbs_untraced raw (comparator.rs5–36); lower su `16*d_middle+d_low` a55 richiede **KS→mean-only→BR binaria→extraction**, con uscita59. Mean-only esatta: stock+2^51 (mean_center.rs15–26), come F/probe/src/main.rs68–74,145–146. LUT F55–58: body0..3 negativo,4 zero,5..2047 positivo. **Nessun bias lower o finaleC.** Servono callback distinti e scheduling a2; non riusare Batch3/Parallel3 invariati. La cache bool ternary/final di comparator.rs71–76 non rappresenta la terza LUT: aggiungere un'identità/cache binaria separata. Il percorso aggiunge una correzione pubblica per compare, con clone e scansione859mask/body-add, oltre ai carry×16. smallcuts::add_selection (289–304) conta oggi3KS/BR/sample/levels e solo le due mean del selettore: conteggiare2PBS e separatamente1mean del confronto; mantenere le2mean-selector nei suoi Metrics. Aggiornare anche ledger/report del dispatch.

**Mixed completo:** lasciare tutta la soglia59 bloccherebbe il finale356–357. Il blocco si evita al costruttore pubblico (mixed.rs468–486): ID e threshold-top59, threshold-middle/low55; rendere `digit(value)` sensibile alla posizione/Delta. Il profilo9 è `[59,55,55,59,59,59,59,55,55]` (const a10). `leaf_public_payloads` resta aritmetica pubblica: nessuna conversione cifrata. Adattare restore_constants (public_digits.rs56–63) alla Delta per posizione, incluse lane7/8 a55. Il ramo di omissione della soglia verifica solo mask-zero/uguaglianza dei byte (mixed.rs236–250), poi conserva quei ciphertext: non richiede59. Sostituire compare_scores (20–31), usato sia ai merge226 sia al finale357, con C sui due triple ora omogenei. Root_parts (198–199), gruppi, dimensione9 e PFKS/sample dei payload restano invariati; aggiornare i ledger del confronto. Tie-Left mantiene l'inclusività finale score≤soglia. Nessun demotion di una soglia cifrata né nuove BR/extraction per codificarla.

Nessuna impossibilità source individuata con questo profilo per posizione; precisione PFKS, carry×16 e composizione restano non validati. Un N2 uniforme sarebbe intermedio, non sostituirebbe Mixed. F8 resta solo il test del primitivo fresco.

## Impronte delle letture

File relativi a W/runtime/core/src; SHA256 completo, routine sopra citate.

| File | SHA256 |
| --- | --- |
| split.rs | `c145a703897dedd7be700d5e08c57d222bb8ddd45707612e9ac850f6963793d6` |
| shared_normalizers.rs | `9aad98bdf1d4b2954ca0c3ab3adb9ae7282158d275087c70ea0b2dbfd18672cc` |
| smallcuts.rs | `aa25d4b8dd1df2c2b89d7b6b2242f381066d5127ebe629ff2cadc25e144aac3a` |
| selector_parallel.rs | `4e54015fc8ad82a7deb2d842c607bbd58a0dd8409113038e3d49f8a83f8078f4` |
| public_digits.rs | `5c402b3296a599640f8b91543ace8149707488e0114f518276e6dd1d7c508439` |
| wide_id.rs | `0e9639bddd7e268a91234fbb2d16614b39b2b36094003e50d86c4c8cc6ecf35d` |
| mixed.rs | `467492d764ae8b51c78b1bba531082cd401ce1b6d27e84d7e03cd61751916ec2` |
| service_selected.rs | `88e59ecce0847bd5231109fa7775b295ea8c559823d76c4529455b4b9cc74026` |
| classic_batch.rs | `c496e843f2909c616cae76e9f549846d496fa55e191cfd5d34930a9babfc886f` |
| comparator.rs | `d22b803ac46c5ae100eab337971e5dd14602ab986e5a57c65e65660d7a753815` |
| mean_center.rs | `3f7f0205cc04c0aff6083d1040d8bc9e368e8ca07087507165a5f7b448a23de2` |

F=`/workspace/research/tmp/current-binary-comparator-20261004`; F/probe/src/main.rs SHA256 `b0067c1017f7233da4471c0d638ca29ccd0bb109e9fca61f2a34297b31c6b005`. Letti solo i confini LUT/mean/caller citati; F8 e i dati nativi restano immutati. Versioni precedenti conservate in HEAD55_PLAN.initial.md e HEAD55_PLAN.pre-review.md.
