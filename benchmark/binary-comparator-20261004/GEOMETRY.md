# Due cifre basse: il ternario non è logicamente necessario

Sia `z = 16*d_middle + d_low` e `b(z) = −1` per z≤0, +1 per z>0. Con top ancora ternario basta `C = 2*s_top + b(z)`, senza il precedente bias−1/2. Left vince per C<0, Right per C>0. I nove casi sono:

| s_top | z<0 | z=0 | z>0 |
|---:|---|---|---|
| −1 | −3, Left | −3, Left | −1, Left |
| 0 | −1, Left | −1, Left | +1, Right |
| +1 | +1, Right | +1, Right | +3, Right |

Il peso2 domina b quando top differisce. Con top pari si sceglie Right soltanto se le cifre basse Left sono maggiori. Il pareggio completo è C=−1: si conserva Left e quindi il primo minimo. Per la sentinella Left di score normalizzato T+1, un winner≤T rende C positivo e passa; winner=T+1 dà tie e sceglie ID0. La soglia resta inclusiva. Il refresh di segno esistente rimane necessario; non viene saltato.

## Geometria a Delta55/N2048

Restano periodo512, z∈[−255,255] e centri `r=8*z mod4096`. Una LUT pubblica possibile emette a Delta59, con body:

`B[0..3]=−Delta; B[4]=0; B[5..2047]=+Delta`.

L'estensione `F(r+2048)=−F(r)` è negaciclica. Nel cerchio completo: −Delta su0..3 e2053..4095, +Delta su5..2051; i soli zeri sono4 e2052. Il plateau negativo attraversa il wrap4095→0.

Tutti i centri legali hanno il valore binario richiesto con errore d'indirizzo intero±3: z=0 resta negativo anche attraversando il wrap; z=1 è positivo da5; z=−255 è negativo da2053. Il raggio uniforme4 resta impossibile: l'indirizzo4 appartiene sia a0+4, che richiede −Delta, sia a8−4, che richiede +Delta. Il massimo uniforme è dunque ancora3.

**C'è uno spostamento locale concreto del bordo:** il vecchio plateauzero2044..2051 sparisce e rimane lo zero2052. Il centro z=255 è2040 e ora ammette raggio simmetrico11, anziché3; z=−1 ottiene lo stesso miglioramento per negaciclismo. Non si può mettere zero sul centro255 stesso, che deve valere +Delta. z=0, +1 e−255 restano limitati a3: nessun miglioramento del margine minimo uniforme.

Conclusione: il ternario delle due cifre basse è superfluo per questo contratto; la LUT binaria è geometricamente compatibile e redistribuisce i margini, ma **non aumenta il margine uniforme**. Non corregge né riqualifica la prova E rifiutata: un output decodificato0 non rivela l'indirizzo effettivo e non prova che questa diversa LUT lo risolverebbe. Conversione55, rumore e pipeline restano aperti. Nessuna esecuzione, modello, nuovo parametro, probabilità o guadagno; il controllo su carta si ferma qui.

Riferimenti del caller già letti nella fase E: `wide_id.rs:31–43,315–334`, `general.rs:33–46`, `selector_refresh.rs:28–57`; geometria del messaggio in `math/GEOMETRY.md`. Nessun materiale C3–C34 importato o rieseguito.
