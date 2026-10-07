# Ingresso delle due cifre e cambio di encoding

4 ottobre 2026. Audit solo delle sorgenti mantenute, senza implementazione o esecuzione. Radice W: `/workspace/maintained`.

**Oggi non esistono copie middle/low a 2^55.** `split::ingress` restituisce `[low, middle, top]` a 2^59; `wide_id::hybrid_bridge` le riordina `[top, middle, low, ID…]` (wide_id.rs 489–506). Il payload mantiene questa scala (lib.rs 50–52; wide_id.rs 9).

## Produzione attuale

- `split.rs` 174–201: due Head successivi, ciascuno con KS corretto, modulus switch, BR e sample a grado zero. Le uscite intermedie hanno scala 2^58; la sottrazione e la moltiplicazione pubblica aggiornano lo stato residuo.
- Residual (203–217): low=`r%16` a 2^59; carry=`r/16` a 2^58. Questo carry si somma alla seconda uscita Head per formare l'ingresso del normalizzatore successivo.
- Carry (219–234): middle=`v%16` e carry alto=`v/16`, entrambi a 2^59. Il carry alto completa top.
- Ogni coppia esegue un KS e un modulus switch comuni (104–141). In modalità Both, `shared_normalizers.rs` 92–111 e 158–200 esegue **una BR del carry**, applica le mappe pubbliche all'intero GLWE e poi **due sample extraction**. Il common Residual è a 2^58 e il common Carry a 2^59; il fattore pubblico 2 del Residual porta low a 2^59. Non sono due LUT arbitrarie gratuite. Le due Head restano distinte. Il ramo Scalar esegue invece due BR per coppia (split.rs 119–127).

## Cosa comporterebbero le copie a 2^55

Dividere per 16 i coefficienti degli LWE esistenti non è un'operazione lineare valida sul torus modulo 2^64. Non basta cambiare `SCORE_DELTA`, che serve anche payload e controllo.

Una possibile **modifica dell'emissione**, ancora non validata, è abbassare l'ampiezza dei due common LUT di quattro bit: Residual a 2^54 e Carry a 2^55. Le mappe pubbliche esistenti produrrebbero low/middle a 2^55. Clonare queste due uscite e moltiplicare una copia per 16 potrebbe ripristinare le scale richieste dal feedback e dal payload. Nel solo grafo di chiamate dell'ingresso non aggiungerebbe BR/PFKS/sample: riutilizzerebbe le due extraction già presenti per coppia. **Moltiplicherebbe però anche il loro errore per 16**; cambia il contratto del feedback Head e richiede una validazione specifica. Non equivale a output aggiuntivi già disponibili o a correttezza garantita.

Il torneo attuale seleziona solo il payload a 2^59. Per conservare anche due copie a 2^55 dopo ogni merge occorre estendere tuple/gruppi e selezionare quelle copie, oppure introdurre conversioni esplicite successive. Nel selettore corrente ogni lane selezionata ha un PFKS e una sample extraction; i gruppi richiedono BR (wide_id.rs 65–125). Cambiano anche sentinella finale e ripristino delle cifre pubbliche. Nessun costo aggiuntivo è automaticamente nullo.

Il confronto odierno usa tre differenze e tre ternary-PBS (classic_batch.rs 58–90), poi combina i risultati a 2^59 (wide_id.rs 31–43). Una PBS su `16*d_middle+d_low` a 2^55 richiede una LUT/contratto d'ingresso nuovi; può emettere il risultato ternario a 2^59, ma la LUT attuale è fissata in comparator.rs 57–68. Combinazione dei risultati e refresh del controllo vanno mantenuti coerenti (selector_refresh.rs 28–57). Nessuna promessa di guadagno o sicurezza segue da questa fattibilità sintattica.

## Identità delle fonti lette

Percorsi relativi a W; SHA256 del file completo. Letture limitate alle routine citate e ai loro confini, nessun payload acquisito.

| File | SHA256 |
| --- | --- |
| runtime/core/src/split.rs | `c145a703897dedd7be700d5e08c57d222bb8ddd45707612e9ac850f6963793d6` |
| runtime/core/src/shared_normalizers.rs | `9aad98bdf1d4b2954ca0c3ab3adb9ae7282158d275087c70ea0b2dbfd18672cc` |
| runtime/core/src/wide_id.rs | `0e9639bddd7e268a91234fbb2d16614b39b2b36094003e50d86c4c8cc6ecf35d` |
| runtime/core/src/comparator.rs | `d22b803ac46c5ae100eab337971e5dd14602ab986e5a57c65e65660d7a753815` |
| runtime/core/src/classic_batch.rs | `c496e843f2909c616cae76e9f549846d496fa55e191cfd5d34930a9babfc886f` |
| runtime/core/src/selector_refresh.rs | `2def89a65e9da264e26e86d6e58946213bb71eaaf5249478b55cf0043dd2905b` |
| runtime/core/src/lib.rs | `0cbae55764baab00f27acae946338a7e4960233982b636e6ed1240ee6dca7350` |
