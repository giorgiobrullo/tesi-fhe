# Contratto ideale: una Head, due cifre base64

Questo documento conserva la proposta precedente al prototipo. Il
[controllo cifrato successivo](../../docs/validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md)
ha respinto la variante nei parametri provati: il quarto caso restituisce
4094 anziché 4095. Le condizioni ideali descritte sotto restano distinte
dall’esito della prova.

4 ottobre 2026. Nuova algebra pubblica, senza esecuzione, modello precedente, chiavi o ciphertext. **La proposta passa l'identità ideale sotto il lookup dichiarato; non è ancora una pipeline FHE corretta o un'ottimizzazione misurata.** Il riferimento pubblico nearest qui sotto non presume che l'indirizzo effettivo prodotto da KS/Head-MS coincida con esso.

## Tabella e wrap

Fissare q=2^64, N=2048, D=q/(2N)=2^52, A=2^51=D/2, B=2^56=16D, C=2^57=2B. Lo score normalizzato intero x appartiene a[0,4095], con messaggio xA. Sottrarre B prima della Head. La LUT ha128 valori

`V_m=floor(m/2)*B−O`, `O=63*2^55`, `m=0..127`.

Il layout proposto ripete ogni valore16 volte, nega i primi8 coefficienti e ruota a sinistra8, generalizzando **solo il layout pubblico** di [split.rs39–49](../../runtime/core/src/split.rs). La funzione di lookup è centrata: il centro16m ha cella intera `[16m−8,16m+7]`; la sua estensione soddisfa `F(j+2048)=−F(j)`.

Dopo l'addback O, V_0 dà0 e V_127 dà63B. Per il centro negativo−16, il lookup è−V_127; dopo O dà **0, non−B**. In generale il complemento negaciclico diventa `H(j+2048)=63B−H(j)`. Anche il bordo superiore è compatibile: il valore successivo all'ultima cella è−V_0, che dopo O resta63B. Questo controllo del bias è necessario: estendere direttamente `floor(m/2)` fuori dalla metà del torus darebbe il riferimento sbagliato.

Per il lookup ideale dichiarato prendere `J0(x)=floor(x/2−16+1/2)=ceil(x/2)−16`. Da cella e ramp segue, per tutti gli x,

`H(J0)=kB`, `k=max(0,floor((x−15)/64))`.

Scrivendo x=64h+l, con h,l in[0,63]: per h=0, k=0; per h>=1, k=h−1 se l<=14, e k=h se l>=15. Non occorre che la Head produca sempre h: il carry successivo corregge anche il primo caso.

## Dirty e ricostruzione

Sottrarre **2H** dallo score originale xA, quindi moltiplicare32. Poiché64A=2B e32A=B, il risultato ideale è

`32*(xA−2kB)=rB`, `r=x−64k`.

Il range esatto sotto J0 è r in[0,78]: se k=h, r=l; se k=h−1, r=l+64 con l<=14. Il caso inferiore clamped ha r=l. Il contratto dei normalizzatori copre comunque tutti gli stati[0,127], non soltanto quelli raggiunti nel riferimento nearest.

Le due LUT scalari, allo **stesso inputB** e con gli stessi128 centri, restituiscono `(r mod64)*C` e `floor(r/64)*C`. Il low è lC; il high finale `2H+carry` è `(k+floor(r/64))*C=hC`. In particolare x=0 usa k=r=0; x=4095 usa k=63,r=63. Ogni messaggio dirty rB resta nella metà positiva del torus. Non usare inputC per queste LUT: r e r+64 sarebbero antipodali ma richiederebbero lo stesso low, incompatibile con una LUT negaciclica anche con bias fisso.

Questa è una nuova rappresentazione. [L'estrattore mantenuto](../../runtime/core/src/split.rs) ha due Head t4/t5, tabelle32 e feedback8/16; non implementa il contratto sopra.

## Errori: condizione dell'indirizzo e del normalizzatore

Per la semantica basta che la Head scelga un k in `{h−1,h}` con r=x−64k in[0,127]; il caso h=0 può usare k=0. Questo è più permissivo della richiesta di conservare esattamente k del riferimento J0. Una condizione uniforme sufficiente è che l'indirizzo Head effettivo, nel lift locale, differisca da J0 di **al più7 gradi**. Per h=1..62, l'intervallo sufficiente è `[32h−40,32h+23]`; per h=0 è `[−40,23]`, per h=63 è `[1976,2071]`. J0±7 è contenuto in questi intervalli. Il limite simmetrico non si amplia a8: per h<=62,l=63, J0+8 seleziona h+1 e dà r=−1.

Gli indirizzi effettivi devono includere input, KS, centering, MS e ogni loro interazione. [a98.rs108–116](../../runtime/core/src/a98.rs) aggiunge una correzione alla body prima dello switch: qui non viene scambiata per un round ideale né viene dedotto un suo bound. Nessuna private phase è acquisita.

Scegliere lift coerenti rispetto allo **stesso** score/Head effettivi:

`score=xA+e0`, `Head=kB+eH`.

La moltiplicazione nativa porta il dirty a `rB+ed`, con **`ed=32*(e0−2eH)` modulo q**. Il passaggio a un errore reale richiede i lift, non una supposizione di assenza di wrap. Per ciascun normalizzatore a∈{low,carry}, definire il remainder completo di indirizzo μ_a, in gradi, in modo che il suo indirizzo effettivo sia

`Ja=16r + ed/D + μ_a (mod4096)`.

μ_a comprende KS/MS/centering/quantizzazione effettivi rispetto a questo input; non è una nuova distribuzione né un errore già limitato. Per ogni r, la cella scalare garantisce il valore desiderato per l'errore intero `Ja−16r` in[−7,7]. Pertanto una scelta conservativa di allowances, se certificata, è

`32*(E0+2*EH)/D + M_a <8`,

con |e0|<=E0, |eH|<=EH, |μ_a|<=M_a e differenza di indirizzo intera nel lift dichiarato. Il termine di quantizzazione deve restare in M_a: **non** interpretare <8 come margine della sola fase prima del round. I16 gradi tra centri danno una finestra intera±7; nella versione mantenuta i32 stati a58 hanno±31.

Se entrambe le celle sono ammesse, scrivere gli errori delle uscite scalari come eL/eC rispetto ai rispettivi valori ideali. Le due cifre finali hanno errori `e_low=eL` e `e_high=2eH+eC`. Non presumere indipendenza: entrambe dipendono da score, Head e chiave; un riferimento congiunto deve conservare questa dipendenza.

## Cosa manca prima di un prototipo

Due ternari sui chunk a57, con uscite a59 e combinazione `2*s_high+s_low−1/2`, rispettano primo minimo e tie-left; sentinel-left a T+1 mantiene la soglia inclusiva. Il refresh del controllo resta. La loro finestra ideale±15 è separata dalle admission Head/dirty e dagli errori eL,2eH+eC; non è un margine end-to-end.

La sequenza descritta avrebbe una Head e due BR scalari di normalizzazione, ma il numero di livelli dipende da parametri ancora da scegliere e validare. Servono bound completi per questi input effettivi, due uscite, confronto, refresh e selezione; metadati/encoding/callee/cache devono seguire le due cifre. Non è stata derivata una probabilità di fallimento, una fattibilità di parametri, un costo totale o un tempo. Il factor-pair condiviso base64 resta escluso da questa proposta: la sua possibile amplificazione l1=126/252 richiederebbe un contratto ulteriore. Nessun prototipo o prova cifrata è stato preparato.
