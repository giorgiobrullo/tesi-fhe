# Base64: obblighi d'errore del produttore

4 ottobre 2026. Sola lettura delle sorgenti correnti; nessun modello C3–C34, esecuzione, chiave, ciphertext, fase privata, copia runtime o helper. La proposta non è un percorso già disponibile. Radici: W=`/workspace/maintained/runtime/core/src`; T=`/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.8.1/src`.

## Convenzione effettiva da conservare

W/split.rs174–199 usa A112 KS corretto, A98 MS log12, BR, extraction e restore dell'offset pubblico. I normalizzatori112–126 riusano un singolo switched object; il ramo Scalar esegue due BR reali. La routine fissa oggi t4/t5 e tabelle32: non è già una Head128.

W/a112.rs190–221 ha KS3×5, native64, dimensioni2048→859: arrotonda/decompone i coefficienti e sottrae dal body la metà **signed wrapping** della correzione totale. W/a98.rs88–117 aggiunge alla correzione centered stock il half_case e il tie_bit. A log12, half_case=2^51. Non sostituire questo confine con stock raw o mean-only senza tie_bit.

T/core_crypto/algorithms/modulus_switch.rs64–101 include anche la correzione cumulata degli errori di divisione per2, prima del termine−half_case; W/A98 poi cancella quest'ultimo e aggiunge il tie. T/core_crypto/entities/modulus_switched_lwe_ciphertext.rs155–171 applica MS al body **dopo** quella correzione e a ogni mask separatamente. L'indirizzo è body_degree−Σs_i*mask_degree modulo4096, per lo stesso segreto binario. La correzione pubblica non dimostra un bound del residuo segreto o una legge di indipendenza.

## Bilancio simbolico, senza probabilità inventata

Pongo q=2^64, Q=q/4096=2^52 per grado. Un input dirty a Delta56 ha centro16r; una tabella128 centrata con negazione/rotazione8 richiede lo scarto discreto dall'indirizzo ammesso in[−7,7]. La baseline32/input58 ha centro64r e margine[−31,31] (W/split.rs39–49). I ±15 del futuro comparatore57 non sono il margine del produttore.

**Prima ammissione Head.** Serve un evento/bound dell'indirizzo della Head128 e della sua scelta del ramo: il suo output ideale deve dare un intero h per cui r=m−64h appartiene a0..127, incluso il wrap negativo previsto dal nuovo contratto. Il risultato pubblico del root segnala x63/address16: uno spostamento+8 sceglie h1 e produce dirty−1. Non basta quindi il contratto ai soli centri nominali. Non riutilizzo né rieseguo quel controllo pubblico; questa è una premessa di ingresso alla nota.

**Errore di uscita distinto.** Condizionatamente a un h ammesso, definire phase(I)=m*Delta51+e_I e phase(H)=h*Delta56+e_H, con lift coerenti. Il feedback proposto D=32*(I−2H) ha esattamente, moduloq:

`phase(D)=r*Delta56+32e_I−64e_H`.

e_H è il difetto dell'output completo Head rispetto al suo valore ideale ammesso: include errori crittografici/numerici effettivi; non solo un errore di LUT. La successiva A112 KS aggiunge e_K; definire rho_MS come residuo esatto in gradi del successivo A98 MS rispetto alla fase dopo KS, inclusi rounding del body, mask e tie. Non sostituirlo con una gaussiana o con zero. Anche il rounding finale di una sola componente non certifica rho_MS.

Con maggioranti validi B_I/B_H/B_K in unità native64 e B_MS in gradi, una condizione **sufficiente** per il solo indirizzo dirty è:

`32B_I + 64B_H + B_K + Q*B_MS <= 7Q`.

Da qui il budget disponibile per l'uscita Head è `(7Q−32B_I−B_K−Q*B_MS)/64`, che deve essere non negativo. Nel solo budget ottimistico con gli altri termini posti0 il tetto è7*2^46, ossia7/1024 di un simbolo Head56. È un tetto del maggiorante sufficiente, non un limite necessario sull'errore fisico o un floor osservato. Non assumo indipendenza: una correlazione potrebbe cancellare termini, ma manca il relativo teorema.

Servono inoltre i contratti rumorosi delle due PBS Scalar low/carry a57 e dell'high corretto: gli output devono avere il margine richiesto dal loro consumatore. Il rounding del chunk da solo non copre la successiva differenza/comparazione. Evitare il kernel condiviso non rende gratis o nulli gli errori Scalar.

## Il preset non chiude questi obblighi

T/shortint/parameters/v0_11/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs79–102 dichiara log2_p_fail−64.088 per MESSAGE1/CARRY3: message2*carry8=16, ordinaryPBS23×1, KS3×5, dimensioni859/GLWE1/N2048. T/shortint/engine/mod.rs102–140 costruisce l'accumulatore canonico da quel prodotto, padding e box_size=N/16. La scritta2^−64 non è una garanzia universale per Head15×2, LUT128/input56, KS/MS custom e input dirty adattivi. Neppure i32 stati custom della baseline acquistano tale certificato soltanto dal nome del preset.

Occorre un contratto di parametro per **queste geometrie e input**, con budget dell'indirizzo Head, uscita Head completa, KS/MS dirty e uscite Scalar, includendo FP/history e i lift. Una tabella nominale con plaintext space128 può essere una fonte candidata, ma cambiarne il nome non rebinderebbe la famiglia corrente né coprirebbe il feedback. Nessun parametro nuovo scelto qui.

**Conclusione:** ammettere i centri ideali non stabilisce ancora la viabilità rumorosa; nessuna prova nativa raccomandata ora. Se i budget precedenti sono giustificati, il minimo discriminatore è una sola famiglia nuova e un input normalizzato63 a51, percorso proposto completo, osservazione ordinaria dei due chunk57 attesi high0/low63 e stopfirst. Sarebbe un pilot del bordo, non p-fail, servizio o speedup. Nessun helper o rekey preparato.

Pin W: split `c145a703897dedd7be700d5e08c57d222bb8ddd45707612e9ac850f6963793d6`; a98 `a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4`; a112 `4f9ee8169c737597bbdb6120d59f4effb0a9d9702b73d35739f884bba9da1e9d`. Pin presetTFHE1.8.1 `ccc97d408b187b4ab3bc2ca41c614324323eaac693039ea5ebec65e0866d131a`.
