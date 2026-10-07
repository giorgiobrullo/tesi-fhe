# Due cifre in una LUT: geometria condizionale

**Esito:** il nuovo encoding elimina la collisione precedente e ammette una LUT ternaria negaciclica. Il massimo raggio uniforme sugli indirizzi interi è **3 gradi**, compresi pareggio e wrap. Questo è un risultato sul messaggio e sulla tabella, non un certificato di rumore o una proposta già compatibile con il runtime.

## Messaggio e ordine

Poniamo `d_middle = left_middle − right_middle` e analogamente per low; le cifre base16 danno entrambe le differenze in `[-15,15]`. Il combinato `z = 16*d_middle + d_low` copre `[-255,255]`.

- Se `d_middle >= 1`, allora `z >= 16−15 = 1`; se `d_middle <= −1`, allora `z <= −1`.
- Se middle è pari, `z = d_low`.
- `z = 0` richiede entrambe le differenze zero, perché `|d_low| <= 15`.

Quindi `sign(z)` è esattamente il confronto lessicografico delle due cifre basse. Non occorre distinguere le diverse coppie che hanno lo stesso z.

Con torus nativo `q = 2^64`, `Delta' = 2^55` ha periodo512. Due z del dominio differiscono al massimo510, quindi non collidono modulo512. Per N2048 il grado torus vale `2^52`; il centro è dunque `r_z = 8*z mod4096`. I centri positivi sono8..2040; quelli negativi2056..4088. La coppia prima ambigua z=−1/31 ora ha centri4088/248 distinti.

## LUT ternaria e margine massimo

L'output torna all'encoding corrente `Delta = 2^59`. Una tabella possibile, espressa soltanto come valori pubblici del body, è:

`B[i] = +Delta` per `4 <= i <= 2043`, altrimenti `B[i] = 0`, per `0 <= i < 2048`.

La funzione estesa è `F(r) = B[r]` nella prima metà e `−B[r−2048]` nella seconda. Pertanto `F(r+2048) = −F(r)`, come richiesto dalla BR negaciclica. Non c'è add-back o bias sulla LUT ternaria.

| Centro nominale | Indirizzi con errore intero ±3 | Output |
|---|---|---|
| z=0, r=0 | 4093..4095 e0..3 | 0 |
| z=1, r=8 | 5..11 | +Delta |
| z=255, r=2040 | 2037..2043 | +Delta |
| z=−255, r=2056 | 2053..2059 | −Delta |
| z=−1, r=4088 | 4085..4091 | −Delta |

Tutti gli altri centri nonzero sono all'interno dei rispettivi plateau. La traslazione di2048 gradi accoppia z positivo con z−256 negativo: i segni richiesti sono opposti. Il partner di z=0 è la classe z=256, esclusa dal dominio; il suo valore zero è quindi compatibile.

Il raggio uniforme4 è impossibile: l'indirizzo4 è contemporaneamente centro0+4, che richiede zero, e centro8−4, che richiede +Delta. Il raggio3 è realizzato sopra ed è dunque massimo. Lo stesso vincolo compare negli altri bordi per negaciclismo/wrap. Si tratta dell'errore del **medesimo indirizzo effettivamente usato dalla BR**, misurato modulo4096 rispetto al centro; non è automaticamente un bound sulla sola fase LWE prima di KS/MS. Non segue alcuna probabilità di fallimento.

Un semplice sign PBS con bias per scegliere una direzione al pareggio non sostituisce questa ternary LUT: qui l'uguaglianza deve produrre zero, con un plateau protetto. La tabella attuale `comparator::body(false)` ha transizioni64/1984 e non è questa nuova tabella.

## Caller, refresh e condizioni ancora aperte

Il caller corrente ordina le cifre `[top,middle,low]` e sottrae right da left. Con `s_top` e `s_z` ternari, il nuovo messaggio di controllo è `(2*s_top + s_z − 1/2)*Delta`. Il peso2 domina la cifra bassa: top positivo rende il controllo positivo, top negativo lo rende negativo; top pari usa il segno di z. Il pareggio completo produce `−Delta/2` e conserva Left, quindi il primo minimo. La sentinella rimane Left con score normalizzato soglia+1: si mantiene il controllo inclusivo finale.

Il refresh esistente **rimane**: `selector_refresh::prepare_control` comprende due KS, una BR e l'estrazione. I nuovi centri del suo input vanno da−448 a320 gradi, a passi128; il più vicino alle transizioni0/2048 dista64 gradi. Questo conserva il suo raggio nominale63, a condizione che gli errori effettivi rispettino ancora il contratto. La BR del selettore/payload non è eliminata.

La struttura proposta è due ternary PBS (top e z) più lo stesso refresh, contro tre ternary PBS più refresh. Non ne segue un guadagno di tempo. Si assume qui che middle/low arrivino correttamente a Delta': le cifre attuali sono a Delta, e dividere/troncare le parole di un ciphertext non fornisce automaticamente questa conversione. Head, riporto/normalizzazione, PFKS, soglia, generazione dei payload e rumore sul combinato `16*d_middle+d_low` richiedono un audit separato. Non è stata acquisita alcuna chiave o tabella privata né modificato alcun sorgente.

Fonti primarie correnti: `runtime/core/src/lib.rs:43–51`, `classic_batch.rs:58–99`, `comparator.rs:57–105`, `wide_id.rs:31–43` e `315–334`, `general.rs:33–46`, `selector_refresh.rs:28–57`, nella copia W (`/workspace/maintained`). Solo lettura e nuova aritmetica su carta; nessun modello/checker, esecuzione FHE, test o build.
