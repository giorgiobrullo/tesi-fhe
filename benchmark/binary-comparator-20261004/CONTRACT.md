# Controllo binario e refresh corrente

4 ottobre 2026. Solo audit delle routine mantenute in W=`/workspace/maintained`; nessuna implementazione, esecuzione o prova del rumore.

**Il dominio proposto può entrare direttamente nel refresh, senza shift o riscalatura del messaggio**, condizionatamente al contratto del nuovo produttore: `C=2*s_top+b(z)` a Delta59, con `s_top∈{-1,0,1}` e `b(z)=-1` per z≤0, +1 per z>0. Le possibili fasi sono {-3,-1,1,3}*Delta59 e il segno mantiene Left sul pareggio completo.

`selector_refresh.rs` 28–46 non decodifica i pesi del vecchio confronto: esegue KS+mean-only, BR di una LUT costante `4*Delta59`, extraction e addizione pubblica `8*Delta59`. Con N2048/log12 i centri ideali sono:

| C/Delta59 | Indirizzo mod4096 | Uscita ideale del refresh/Delta59 |
| --- | --- | --- |
| -3 | 3712 | 4 |
| -1 | 3968 | 4 |
| +1 | 128 | 12 |
| +3 | 384 | 12 |

Le uscite 4/12 sono quelle già consumate dal secondo KS+mean-only (`prepare_control`, 49–57) e dal selettore PFKS con finestra centrata in1536 (11–14). `mean_center::apply` aggiunge la correzione stock **più** 2^51 (mean_center.rs 15–26): mantiene il centraggio mean-only richiesto, senza imporre al nuovo C un offset di mezzo Delta. Resta il contratto corrente sui residui d'indirizzo; questa geometria ideale non ne prova il rispetto né amplia i raggi63/127 dichiarati.

**Il produttore attuale è diverso:** `wide_id::compare` (31–43) calcola ancora `4*s_top+2*s_middle+s_low-1/2`, tutto a Delta59. Sostituirlo con C richiede rimuovere quell'assemblaggio, inclusa la sottrazione finale Delta59/2; non sommarla al nuovo C. Il caller ordinario passa il risultato direttamente a `prepare_control` (wide_id.rs 59; selector_parallel.rs 124). La sentinella mantiene l'ordine sentinel-left, il valore soglia+1 e ID0 (general.rs 34–46; wide_id.rs 302–316): la convenzione di pareggio Left resta necessaria anche lì.

Nessuna incompatibilità di scala o tipo è individuata **fra il futuro C già emesso a59 e il refresh**. Le cifre55, b(z) e la loro composizione non sono presenti nel runtime attuale e non sono validati da questa nota. Il primitivo8case è un obbligo distinto; non implica la composizione con Head/torneo, rumore, conteggi o prestazioni.

## Sorgenti effettivamente lette

Percorsi relativi a W; SHA256 del file completo. Letture limitate alle routine e ai caller citati; nessun payload acquisito.

| File | SHA256 |
| --- | --- |
| runtime/core/src/selector_refresh.rs | `2def89a65e9da264e26e86d6e58946213bb71eaaf5249478b55cf0043dd2905b` |
| runtime/core/src/mean_center.rs | `3f7f0205cc04c0aff6083d1040d8bc9e368e8ca07087507165a5f7b448a23de2` |
| runtime/core/src/wide_id.rs | `0e9639bddd7e268a91234fbb2d16614b39b2b36094003e50d86c4c8cc6ecf35d` |
| runtime/core/src/general.rs | `af61741b78548836b7939f51096470816dd6fe190e4bbce016d6d7644ddb58d3` |
| runtime/core/src/selector_parallel.rs | `4e54015fc8ad82a7deb2d842c607bbd58a0dd8409113038e3d49f8a83f8078f4` |
| runtime/core/src/lib.rs | `0cbae55764baab00f27acae946338a7e4960233982b636e6ed1240ee6dca7350` |
