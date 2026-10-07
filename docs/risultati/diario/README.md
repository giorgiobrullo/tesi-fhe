# Diario completo degli esperimenti: F0–F83

Le 84 schede conservano il dettaglio del diario archiviato l’8 settembre
2026: impostazione degli esperimenti, tabelle, ragionamenti e risultati,
compresi i tentativi falliti. Sono raccolte in sei capitoli; ogni finding
ha un collegamento diretto nell’indice qui sotto.

Una sigla come F32 identifica una scheda del diario, non una versione del
software. Per seguire la tesi per la prima volta, leggere il
[percorso sperimentale](../../percorso-sperimentale.md); tornare qui
per i dettagli del singolo tentativo. I sei capitoli seguono lo sviluppo:
rappresentazione dei volti, scaling, protocollo, costo dei circuiti,
correzioni e infine selezione esatta dell'identità.

I titoli dell’indice riassumono il risultato con le correzioni note; i
capitoli conservano i titoli e i testi originali. Le note **Aggiornamento**
segnalano le correzioni successive. Le espressioni
«attuale» e «corrente» nel testo storico descrivono la versione di allora.
Per le conclusioni consolidate leggere la [sintesi con le correzioni](../prototipi-e-correzioni.md);
per la versione più recente, i [risultati del progetto](../../../findings.md).

Le [precisazioni del 22 settembre](../prototipi-e-correzioni.md#precisazioni-del-22-settembre-2026)
completano e, dove indicato, correggono anche le precedenti note: distinguono
le due serie di F32 e i loro timer, e chiariscono i limiti delle proposte
B8.1/B9 e B5.1 di F82.

Le [precisazioni del 2 ottobre](../prototipi-e-correzioni.md#precisazioni-del-2-ottobre-2026)
correggono l'interpretazione della separazione dei dati in F18, delimitano
il risultato sulla quantizzazione di F31 e distinguono persone, template
e foto effettive in F30. Chiariscono anche la suddivisione personalizzata
dei dieci fold della verifica 1:1. Sono correzioni posteriori esplicite:
i sei capitoli rimangono conservati. Il
[protocollo biometrico](../../validazione/PROTOCOLLO_BIOMETRICO.md) è distinto
dalle prove eseguite: [VGGFace2 e preparazione UI](../../validazione/README.md)
e [Georgia Tech](../selettore-e-generalizzazione.md#georgia-tech). I loro risultati
circoscritti non costituiscono una nuova calibrazione o una qualifica webcam.

Il ripristino conserva il contenuto scientifico delle schede. Sono stati
rimossi i promemoria di coordinamento e adattati i collegamenti. I percorsi
in monospace indicano file rispetto alla radice del repository; i riferimenti
all’archivio locale identificano materiali non inclusi nella pubblicazione.
Le [impronte dei testi](PROVENIENZA.json) distinguono il diario originale
dalle copie pubblicate e annotate.

## F0–F14: Prototipi, PCA, descrittori ed embedding CNN

| Finding | Risultato e rimando al diario |
|---|---|
| [F0](f00-f14.md#f0) | Concrete gira nativo su macOS arm64, senza Docker |
| [F1](f00-f14.md#f1) | Il modello di sicurezza |
| [F2](f00-f14.md#f2) | Tenere la galleria in chiaro da solo non basta: serve la formula giusta |
| [F3](f00-f14.md#f3) | Lezione pratica di Concrete: niente moltiplicazioni chiaro×chiaro nel circuito |
| [F4](f00-f14.md#f4) | Prototipo end-to-end funzionante (cartella experiments/05_pca/) |
| [F5](f00-f14.md#f5) | PCA: bassa accuratezza nelle prove LFW |
| [F6](f00-f14.md#f6) | L'argmin deve stare sul server (privacy): la decisione, e quanto costa |
| [F7](f00-f14.md#f7) | Descrittori locali: battono la PCA sui volti reali, ma con un bivio FHE |
| [F8](f00-f14.md#f8) | Verso il benchmark vero: dataset più duri, modello forte, integrazione |
| [F9](f00-f14.md#f9) | Descrittori locali: risultati vicini al caso nei benchmark esaminati |
| [F10](f00-f14.md#f10) | Descrittori nel protocollo open-set 1:N: risultati insufficienti |
| [F11](f00-f14.md#f11) | Argmin + soglia funziona; l'inputset di test non è un dominio di sicurezza |
| [F12](f00-f14.md#f12) | Come scala la PCA sui nostri dataset: accuratezza vs bit dei punteggi |
| [F13](f00-f14.md#f13) | Embedding CNN: miglioramento nelle prove biometriche |
| [F14](f00-f14.md#f14) | Embedding CNN: quantizzazione e costo del circuito esaminato |

## F15–F28: Scaling biometrico e limiti dei primi circuiti

| Finding | Risultato e rimando al diario |
|---|---|
| [F15](f15-f28.md#f15) | CNN profonda (ResNet50): un ritocco, e a costo FHE invariato |
| [F16](f15-f28.md#f16) | Il benchmark è saturo? Test scalando la galleria |
| [F17](f15-f28.md#f17) | Scaling su larga scala: a migliaia di iscritti il DIR scende davvero |
| [F18](f15-f28.md#f18) | Scaling VGGFace2: risultati e limiti della separazione dei dati |
| [F19](f15-f28.md#f19) | Modelli più grandi: guadagno limitato nel protocollo a frame singolo |
| [F20](f15-f28.md#f20) | Argmin cifrato sul server con embedding CNN: il limite, e cosa abbiamo provato |
| [F21](f15-f28.md#f21) | L'argmin server serve davvero? Dipende dal modello di minaccia |
| [F22](f15-f28.md#f22) | Comprimere l'embedding: a 128 dim quasi gratis in accuratezza (ma non è una leva FHE, corretto in F31) |
| [F23](f15-f28.md#f23) | Ottimizzare l'argmin server: niente hardware-lever, e la compressione aiuta al margine |
| [F24](f15-f28.md#f24) | Strategia a blocchi per l’argmin Concrete |
| [F25](f15-f28.md#f25) | Concrete su Tesla T4: esito del confronto GPU |
| [F26](f15-f28.md#f26) | Cosa fa la letteratura [lettura storica, superata dagli audit successivi] |
| [F27](f15-f28.md#f27) | Ottimizzare l'argmin su Concrete: il torneo aiuta, ma il real-time resta fuori |
| [F28](f15-f28.md#f28) | Il varco a soglia in Concrete: più economico dell'argmin, ma non real-time |

## F29–F42: Concrete, TFHE-rs e definizione del protocollo

| Finding | Risultato e rimando al diario |
|---|---|
| [F29](f29-f42.md#f29) | Scaling DigiFace completato fino a 48000: sul sintetico la profondità satura |
| [F30](f29-f42.md#f30) | AdaFace e il divario di dominio: il reale conta più del modello |
| [F31](f29-f42.md#f31) | Quantizzazione e costo Concrete: risultati e limiti |
| [F32](f29-f42.md#f32) | Primo confronto Concrete/TFHE-rs: input e timer differenti; [correzione consolidata](../prototipi-e-correzioni.md#f32-due-serie-e-perimetri-temporali-differenti) |
| [F33](f29-f42.md#f33) | Dove va il tempo: il breakdown end-to-end di una query privata |
| [F34](f29-f42.md#f34) | "Si può avere entrambi": prodotto scalare leveled e argmin radix verificato |
| [F35](f29-f42.md#f35) | Le decisioni dell'incontro di luglio: il design da chiudere |
| [F36](f29-f42.md#f36) | Riduzione a otto bit: verifica nel modello in chiaro |
| [F37](f29-f42.md#f37) | Core storico: soglia diretta a un PBS, veloce ma invalida vicino a T |
| [F38](f29-f42.md#f38) | La selezione radix in tfhe-rs: il torneo a 8 bit fa 4,7 s a N=128, ma vuole il ponte |
| [F39](f29-f42.md#f39) | Prima baseline CKKS: meccanismo utile, numeri non finali |
| [F40](f29-f42.md#f40) | L'output è un oracolo applicativo: ridurlo aiuta, non lo annulla |
| [F41](f29-f42.md#f41) | Prototipo a tre ruoli: un GLWE da 33 KB e output minimo |
| [F42](f29-f42.md#f42) | Il percorso da raccontare dopo l'audit (checkpoint F70, poi superato da F71) |

## F43–F56: Scaling, parametri, rumore e primi servizi

| Finding | Risultato e rimando al diario |
|---|---|
| [F43](f43-f56.md#f43) | Core storico fino a N=1024: scaling misurato, frontiera non validata |
| [F44](f43-f56.md#f44) | GhostFaceNet, misurato: "indifferente" vale per l'FHE, non per l'accuratezza |
| [F45](f43-f56.md#f45) | La strada del ponte: la matrice argmin costa 14 s ed è noisy vicino ai pareggi |
| [F46](f43-f56.md#f46) | Parametri del PBS di segno: tempi della versione pre-fold |
| [F47](f43-f56.md#f47) | I 3 bit come bonus di robustezza, e perché i set piccoli sbagliano |
| [F48](f43-f56.md#f48) | Fusione multi-frame: miglioramento della decisione in chiaro |
| [F49](f43-f56.md#f49) | Snapshot applicativo pre-fold preservato; 146 PBS non sono il servizio corrente |
| [F50](f43-f56.md#f50) | Bilancio del rumore: il modello centrale non garantisce il confronto |
| [F51](f43-f56.md#f51) | Galleria GGSW cifrata: primitiva riuscita, decisione non validata |
| [F52](f43-f56.md#f52) | Torneo con circuit bootstrapping: errori nella costruzione provata |
| [F53](f43-f56.md#f53) | Consuntivo dell'incontro: fatto, dimostrato e ancora aperto |
| [F54](f43-f56.md#f54) | Z-norm: soglie per template e risultati biometrici |
| [F55](f43-f56.md#f55) | Rumore del PBS e codifica dell'uscita sono due problemi distinti |
| [F56](f43-f56.md#f56) | Il bound del toro: chiusa la falla di overflow, non il client arbitrario |

## F57–F70: Ottimizzazioni, confronti e correzione della soglia

| Finding | Risultato e rimando al diario |
|---|---|
| [F57](f57-f70.md#f57) | Ambiguità rara, ma la cascata cifrata non è ancora validata |
| [F58](f57-f70.md#f58) | Limitare la norma della galleria stringe il bound; il vantaggio di velocità non è ancora misurato bene |
| [F59](f57-f70.md#f59) | Tutta l'uscita in una GLWE: 112× meno banda, ma non è l'uscita minimale |
| [F60](f57-f70.md#f60) | Il PBS multi-bit non aiuta in questi run: 3-13% più lento |
| [F61](f57-f70.md#f61) | Il probe non è un volto: separare output, configurazione e buona formazione |
| [F62](f57-f70.md#f62) | Sicurezza dei parametri e confronti: cosa si può normalizzare |
| [F63](f57-f70.md#f63) | Contributo: implementazione, integrazione e valutazione, non priorita' |
| [F64](f57-f70.md#f64) | Concrete sullo stesso Mac: confronto riproducibile, conclusione circoscritta |
| [F65](f57-f70.md#f65) | Bootstrapping ammortizzato: costo e interfacce esaminate |
| [F66](f57-f70.md#f66) | Scaling: lineare nel circuito attuale, non impossibile in assoluto |
| [F67](f57-f70.md#f67) | CKKS dopo l'audit: concorrente forte, ma la baseline deve includere i negativi open-set |
| [F68](f57-f70.md#f68) | L'audit che ha invalidato il comparatore diretto a un PBS |
| [F69](f57-f70.md#f69) | Il percorso residuale: 14 PBS ritirati, 9 PBS come fallback |
| [F70](f57-f70.md#f70) | Periodic-fold: 3 PBS/template integrati, frontiera riparata empiricamente |

## F71–F83: Identificazione esatta e ottimizzazioni del torneo

| Finding | Risultato e rimando al diario |
|---|---|
| [F71](f71-f83.md#f71) | Contratto finale: argmin esatto, soglia del vincitore, 0 oppure identita' |
| [F72](f71-f83.md#f72) | A28 split4: stesso exact-ID, 508 key switch in meno a N=127 |
| [F73](f71-f83.md#f73) | A29: exact-ID invariato e -8,876% nel confronto appaiato |
| [F74](f71-f83.md#f74) | A33 integrato: exact-ID completo sul fast path, promozione ancora aperta |
| [F75](f71-f83.md#f75) | A33 promosso: exact-ID invariato e -13,734% nel paired A29/A33 |
| [F76](f71-f83.md#f76) | A38 integrato e misurato: -13,828% nel paired, promozione ancora aperta |
| [F77](f71-f83.md#f77) | A41 elimina il decode largo con due LWE p16: 29/29 FHE, costo invariato |
| [F78](f71-f83.md#f78) | A44 max-15 passa 120/120 FHE, ma il bound raw resta condizionale |
| [F79](f71-f83.md#f79) | A62 materializza A50+A53: 3.390 BR e 142/142 FHE di componente |
| [F80](f71-f83.md#f80) | A64: progetto statico checked, circa 2,4 milioni di PBS stimati |
| [F81](f71-f83.md#f81) | Revisione del 4 settembre: risultati e filoni da verificare |
| [F82](f71-f83.md#f82) | Sessione del 4 settembre: A124 e proposte successive |
| [F83](f71-f83.md#f83) | A124: da seriale a 16 thread su N=64/127/128, con guardia sul carico |
