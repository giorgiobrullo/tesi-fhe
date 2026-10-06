# Metodo e copertura della ricerca bibliografica

[Indice della rassegna](../../letteratura.md) · [Bibliografia](fonti.md)

Il corpus comprende lavori applicativi, primitive, implementazioni ufficiali
e attacchi pertinenti al contratto. La ricerca è narrativa e documentata,
con controlli mirati su fonti primarie; non è una revisione sistematica PRISMA
né una prova di assenza di prior art. Le verifiche del 19 e 22 settembre e
del 2–5 ottobre 2026 sono descritte nel [registro delle versioni](versioni-e-verifiche.md)
e nelle schede di lettura. La data non garantisce che ogni lavoro pubblicato
sia indicizzato.

## Domande di inclusione

Un lavoro entra nel confronto se chiarisce almeno uno di questi aspetti:
funzione restituita, modello di fiducia, selezione cifrata, precisione degli
score, estrazione/packing/bootstrapping, validità biometrica o informazione
rilasciata. Le famiglie adiacenti sono incluse per spiegare un diverso
compromesso, senza attribuire loro il contratto locale.

| Famiglia | Copertura e uso |
|---|---|
| Precedenti di decisione biometrica | Erkin, Sadeghi, SCiFI; stabiliscono precedenti di minimo/soglia e modelli interattivi. |
| Sistemi moderni | HERS, GROTE, Cong, BCS, IDFace, Blind-Match, HyDia, CryptoFace, CipherFace e BSGS-Diagonal; confronto per output e parti. |
| Rappresentazione e ricerca | HEFT/fusione, indicizzazione protetta, k-NN, ANN/PIR; distinguere accuratezza, recall e argmin esaustivo. |
| Primitive TFHE | Multi-output, Head, correzione media, PFKS/packing, Tetris, FDFB, common-mask e RevoLUT; attribuzione e costo delle interfacce. |
| CKKS discreto e ibridi | Small-integer bootstrapping, functional bootstrapping, integer computer, RadixCKKS e CKKS/FHEW; dominio e latenza rispetto al throughput. |
| Sicurezza dell'uscita | Circuit privacy/sanitizzazione e ricostruzione da risposte; separare proprietà del ciphertext e inferenze dall'oracolo. |

La sola cifratura delle immagini o un dimostratore che restituisce distanze
non costituiscono selezione privata del nearest-ID. Marketing senza
protocollo verificabile e misure senza condizioni sufficienti non entrano
in una classifica di prestazioni.

Per ogni confronto annotiamo anche cosa e chi decifra, recall della preselezione,
interazione, preprocessing, stato conservato dal client e leakage consentito.
Teniamo separati probabilità d'errore del calcolo cifrato, alterazioni dovute
alla quantizzazione e tassi biometrici di errore. I tempi sono confrontabili
soltanto se coincidono contratto, fasi misurate e condizioni della macchina.

## Percorso di ricerca

Sono stati ricontrollati i riferimenti esistenti e seguiti related work,
link degli autori e bibliografie dei sistemi più vicini. Le ricerche pubbliche
hanno usato combinazioni di queste query, senza inviare dati del progetto:

- `homomorphic encrypted face identification 2026 argmax biometrics`
- `privacy preserving biometric identification fully homomorphic encryption 2025 2026 nearest neighbor`
- `CipherFace homomorphic Serengil`, `HEFT Homomorphically Encrypted`, `HEArgmax Nguyen Duong`
- `homomorphic biometric identification indexing Rathgeb Drozdowski`
- `face binary authentication Rahimi 2025 reconstruction`
- `circuit privacy TFHE secret key output noise`, `Sanitization of FHE Ciphertexts Ducas Stehle`
- Query per titolo/autore delle primitive Head Start, Tetris, Sharing the Mask, FDFB, RevoLUT, CKKS small integers e RadixCKKS.

Gli aggregatori sono usati soltanto per trovare le fonti. Le conclusioni
tecniche provengono da articoli, archivi degli autori, ePrint, arXiv,
proceedings e repository/documentazione ufficiali. Le metriche esterne non
sono state riprodotte localmente.

## Versioni e profondità della lettura

| Fonte / gruppo | Base effettivamente controllata in questa revisione | Limite |
|---|---|---|
| Erkin 2009, CipherFace v1, GPU BSGS-Diagonal v3 | Testo e algoritmi pertinenti | Non è una verifica formale di tutte le prove dei paper. La v3 GPU distingue conteggio membership e confronto per elemento. |
| IDFace | Testo primario arXiv v1 | Il sito CVF non è stato riaperto con successo; non mescolare numeri di versioni differenti. |
| BCS | PDF PoPETs 2025, sezioni di metodo ed esperimenti | Conservare riduzione della precisione e problemi di rumore delle label riportati dagli autori. |
| Primitive TFHE approfondite | PDF completi di Head, Tetris, compensazione media, Sharing the Mask, Chen, RevHomTrace, FDFB e RevoLUT; frontespizio, abstract e tabelle 5–6 dell'edizione finale TCHES della compensazione verificati il 22 settembre | Otto letture mirate di algoritmi, ipotesi e misure; nessuna certificazione di tutte le prove. La scheda distingue finale e preprint. |
| FDFB ricorsivo | Preproceedings SAC ed ePrint 2025/1255; il 3 ottobre il preprint di 22 pagine è stato letto integralmente, con controllo visivo delle formule e tabelle decisive | Il testo principale estratto coincide nelle due copie preliminari; manca il confronto con il capitolo finale di 21 pagine. |
| FAKES | Preprint Research Square v1 del 2023, cinque autori, 19 pagine PDF; letto integralmente con controllo visivo del protocollo | Metadati finali distinti: sei autori e 35 pagine. Il protocollo descritto resta riferito al preprint. |
| CKKS | Cinque PDF su CKKS discreto; PDF Lee; edizione USENIX Mazzone e appendice degli artefatti | Sette articoli approfonditi; separati batching, canonicalizzazione, modelli d'errore e tempo completo. |
| HEFT ed estensione journal | PDF autore HEFT 2022 e supplemento; PDF editoriale Akbari 2025 | Tabelle e pagine controllate; la discrepanza temporale del journal è confermata. |
| HEArgmax | PDF editoriale completo, 11 pagine con appendice | Protocolli e prove esaminati; controesempi statici al modello generale, nessun attacco software eseguito. |
| Privacy e indicizzazione | PDF CiC Kluczniak, ePrint Ducas corretto, arXiv Rahimi e Drozdowski | Quattro letture mirate; correzioni, ipotesi e compromessi esplicitati. |
| SCiFI | PDF integrale della versione pubblica autore | Riesaminate funzionalità, implementazione e limitazioni; altri riferimenti storici mantengono il perimetro precedente. |

L'approfondimento di settembre riguarda **23 articoli**, disponibili in PDF,
comprese le edizioni pubblicate HEArgmax e Akbari. È un gruppo di letture
identificato, non il conteggio dell'intero corpus. Appendici e versioni diverse dello
stesso lavoro non sono contate come articoli distinti. Le
[schede di lettura](testi-integrali/README.md) specificano pagine e versioni.
L'accesso al file completo non implica lettura riga per riga né verifica
formale di tutte le dimostrazioni.

I riferimenti e le revisioni specifiche sono nelle [fonti annotate](fonti.md)
e nella [scheda CKKS](ckks-discreto.md). La versione GPU letta è
[arXiv 2604.00546v3](https://arxiv.org/html/2604.00546v3); le diverse uscite
sono negli algoritmi 3–4. Il §6.2 esclude trial falliti dai tempi aggregati:
questa politica non permette di dedurre da sola una frequenza di fallimento.

<a id="riesame-del-2-ottobre-2026"></a>

La copertura comprende inoltre BioZKFHE, SMOOTHIE, Sorted Extended
Bootstrapping, sanitizzazione, correttezza reattiva, sicurezza dei protocolli
CKKS, rare-event simulation e ANN/PIR. Il [registro delle verifiche](versioni-e-verifiche.md)
distingue PDF locali, testi completi letti online e accesso parziale. Stable
Hash Generation e HEBI sono letti nelle copie accettate; per [HEBI](testi-integrali/hebi.md) sono
verificati protocollo, parti fidate, output, preselezione e misure nel
manoscritto di dieci pagine. HEFT arXiv v1 e FDFB ricorsivo SAC sono versioni
di lavori già inclusi; il secondo non è il finale Springer.

La lettura completa di [Liu, Informatica 2024](testi-integrali/liu-informatica.md)
lo colloca fra i riferimenti adiacenti: verifica 1:1 con UID dichiarato,
con specifiche insufficienti per una replica del circuito FHE e dei tempi.

<a id="letture-del-3-ottobre-2026"></a>

La [scheda FDFB ricorsivo](testi-integrali/fdfb-ricorsivo.md) separa il costo
della decomposizione di una LUT dal costo del nostro torneo. Distingue inoltre
il confronto con EBS su entrambi i metodi da quello in cui EBS è applicato
soltanto alla proposta. Il preprint ePrint e quello SAC sono due copie dello
stesso lavoro; il confronto del loro testo estratto non verifica l'edizione finale.

[FAKES](testi-integrali/fakes.md), individuato nelle referenze di SFRA,
entra fra i protocolli adiacenti: il volto serve per recuperare una chiave,
mentre la ricerca riguarda parole chiave e file cifrati. Il cloud calcola
l'insieme dei match e la variante multiutente assume un centro di
autenticazione fidato. Questi confini delimitano il confronto con la nostra
decisione cifrata `0/ID`. Non è stata eseguita la sua implementazione.

## Cosa resta da approfondire

I testi completi di Stable Hash Generation, PRECO, Tiptoe, Wally, Compass e
Pacmann sono stati consultati per confrontare funzione e leakage.
Per **SFRA** il testo integrale resta da acquisire: la scheda mantiene
la qualifica di accesso parziale e non attribuisce esattezza o velocità
non verificate. I tentativi del 3 ottobre tramite publisher e API hanno
restituito metadati o errori di accesso, senza ottenere il corpo dell'articolo.
Restano inoltre da acquisire e confrontare i testi finali di FDFB ricorsivo
e FAKES; i rispettivi preprint sono disponibili. L'[indice delle letture](testi-integrali/README.md)
distingue disponibilità dei testi e questioni scientifiche aperte. La ricerca
brevettuale resta parziale e separata dalla valutazione scientifica.

La rassegna copre le principali dimensioni necessarie a motivare questa
costruzione. Una futura modifica del contratto, dello schema o dell'avversario
richiede riaprire la ricerca su quella dimensione, non dichiarare definitiva
la bibliografia attuale. L'assenza di un risultato nel corpus non prova
che quel risultato non esista né conferisce priorità alla costruzione locale.
