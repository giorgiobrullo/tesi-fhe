# Metodo e copertura della ricerca bibliografica

[Indice della rassegna](../../letteratura.md) · [Bibliografia](fonti.md)

Ricognizione aggiornata il 19 settembre 2026, con controlli delle edizioni
pubblicate il 22 settembre. Il corpus comprende lavori
applicativi, primitive, implementazioni ufficiali e attacchi pertinenti al
contratto. È una ricerca narrativa documentata con controlli mirati su fonti
primarie; non è una revisione sistematica PRISMA né una prova di assenza di
prior art. La data non garantisce che ogni lavoro pubblicato sia indicizzato.

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
| FDFB ricorsivo | Preproceedings SAC 2025 già consultati; metadati e abstract dell'edizione LNCS 16207 del 2026 verificati il 22 settembre | Il capitolo finale integrale non è stato confrontato con il preproceedings. |
| CKKS | Cinque PDF su CKKS discreto; PDF Lee; edizione USENIX Mazzone e appendice degli artefatti | Sette articoli approfonditi; separati batching, canonicalizzazione, modelli d'errore e tempo completo. |
| HEFT ed estensione journal | PDF autore HEFT 2022 e supplemento; PDF editoriale Akbari 2025 | Tabelle e pagine controllate; la discrepanza temporale del journal è confermata. |
| HEArgmax | PDF editoriale completo, 11 pagine con appendice | Protocolli e prove esaminati; controesempi statici al modello generale, nessun attacco software eseguito. |
| Privacy e indicizzazione | PDF CiC Kluczniak, ePrint Ducas corretto, arXiv Rahimi e Drozdowski | Quattro letture mirate; correzioni, ipotesi e compromessi esplicitati. |
| SCiFI | PDF integrale della versione pubblica autore | Riesaminate funzionalità, implementazione e limitazioni; altri riferimenti storici mantengono il perimetro precedente. |

L'approfondimento successivo alla prima ricognizione riguarda **23 articoli**:
tutti ora disponibili in PDF, dopo la consegna delle edizioni pubblicate
HEArgmax e Akbari. Appendici e versioni diverse dello
stesso lavoro non sono contate come articoli distinti. Le
[schede di lettura](testi-integrali/README.md) specificano pagine e versioni.
L'accesso al file completo non implica lettura riga per riga né verifica
formale di tutte le dimostrazioni.

I riferimenti e le revisioni specifiche sono nelle [fonti annotate](fonti.md)
e nella [scheda CKKS](ckks-discreto.md). La versione GPU letta è
[arXiv 2604.00546v3](https://arxiv.org/html/2604.00546v3); le diverse uscite
sono negli algoritmi 3–4. Il §6.2 esclude trial falliti dai tempi aggregati:
questa politica non permette di dedurre da sola una frequenza di fallimento.

## Cosa resta da approfondire

SFRA, stable hashing e sistemi ANN/PIR quali PRECO, Tiptoe, Wally e Compass
sono piste adiacenti riconosciute; il testo completo serve prima di un
confronto dettagliato di leakage, esattezza o velocità. Il limite di accesso a Head/Tetris è superato. Anche i due limiti
di accesso a HEArgmax e Akbari sono superati; l'[indice delle letture](testi-integrali/README.md)
distingue disponibilità dei testi e questioni scientifiche ancora aperte. La ricerca brevettuale resta
parziale e separata dalla valutazione scientifica.

La rassegna ora copre le principali dimensioni necessarie a motivare questa
costruzione. Una futura modifica del contratto, dello schema o dell'avversario
richiede riaprire la ricerca su quella dimensione, non dichiarare definitiva
la bibliografia attuale.
