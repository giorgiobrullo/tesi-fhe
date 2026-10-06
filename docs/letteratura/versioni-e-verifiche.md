# Versioni e verifiche delle fonti

<a id="riesame-della-letteratura--2-ottobre-2026"></a>

[Rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Metodo](metodo-ricerca.md) · [BibTeX](bibliografia.bib)

Il registro distingue le versioni consultate, le parti effettivamente lette
e quelle ancora da verificare. Le osservazioni qui raccolte si riferiscono
alle letture del 2–5 ottobre 2026 e ai controlli di versione indicati nelle
schede. I tempi degli articoli non sono stati riprodotti.

Il confronto riguarda il primo minimo sui punteggi interi, la soglia del
vincitore e una risposta cifrata `0/ID`. Nessuna fonte esaminata giustifica
un primato di velocità o di priorità per la realizzazione locale.

<a id="cosa-cambia-nel-confronto"></a>

## Contratti e condizioni da confrontare

- **Sistemi biometrici:** BioZKFHE cifra anche la galleria, ma una commissione
  decifra i punteggi e decide. Stable Hash Generation preseleziona candidati;
  il lookup del codice non garantisce il minimo dell'intera galleria.
  HEBI protegge l'indice, conserva il compromesso del clustering e delega
  la decisione a una terza parte che decifra gli score.
- **Calcolo e bootstrap:** SMOOTHIE ottimizza prodotti scalari su ciphertext
  radix; il nostro accumulo LWE ha un costo diverso. Sorted Extended
  Bootstrapping e Companion Modulus Switch richiedono altre interfacce e
  budget: sono piste, senza un risparmio locale già dimostrato. La
  decomposizione di LUT di Belaïd–Bon–Rivain riusa intermedi fra più uscite;
  il confronto pubblicato non usa lo stesso target d'errore per tutti i metodi.
- **Garanzie:** correttezza sotto query adattive, circuit privacy verso chi
  decifra, integrità e informazioni rivelate dalla funzione sono proprietà
  distinte. Le costruzioni recenti non le conferiscono al runtime standard.
- **ANN/PIR:** PRECO, Tiptoe, Pacmann, Compass e Wally cambiano recall,
  interazione, fiducia o leakage. Una risposta ID/0, da sola, non rende
  PRECO equivalente alla ricerca esaustiva del progetto.
- **CKKS:** la revisione 2025/395 del 29 settembre cambia anche titolo e
  discussione della sicurezza. Si cita il testo accessibile, senza chiamarlo
  un finale di proceedings già controllato.

Le implicazioni sono integrate nelle schede di [sistemi](sistemi.md),
[primitive](primitive-e-codesign.md), [protocolli](protocolli-e-ricerca-privata.md)
e [CKKS](ckks-discreto.md). La [mappa del rumore](../validazione/RUMORE_COMPOSTO.md)
e il [protocollo biometrico](../validazione/PROTOCOLLO_BIOMETRICO.md) separano
gli obblighi del progetto dalle garanzie degli articoli.

## Versioni, pagine e accesso

Le pagine sono quelle dei PDF delle versioni indicate. «Testo completo»
significa accesso all'intero articolo e lettura delle sezioni pertinenti,
senza affermare una verifica riga per riga di tutte le prove. Alcuni archivi
consentono la lettura integrale online ma hanno rifiutato il download da
terminale. I PDF acquisiti sono copie private di consultazione, fuori dal
repository; i tentativi e gli hash sono conservati nel registro locale.

| Lavoro e versione | Base della lettura | Accesso |
|---|---|---|
| [BioZKFHE, arXiv v1](https://arxiv.org/abs/2607.22065v1), 24 luglio 2026; TDSC early access riportato nei metadati arXiv | Protocollo, layout, fiducia, valutazione; pp. 3–5, 9–15 | PDF locale |
| [SMOOTHIE, ePrint 2025/1267](https://eprint.iacr.org/2025/1267), revisione 8 giugno 2026, CRYPTO 2026 dichiarato | §§2–5; pp. 6–8, 21–28 | Testo completo online; download non ottenuto |
| [Sorted Bootstrapping, ePrint 2025/2214](https://eprint.iacr.org/2025/2214), ASIACRYPT 2025 | §§4–7 e parametri; pp. 19–33 | Testo completo online |
| [Belaïd–Bon–Rivain, LUT decomposition](https://www.nicolasbon.com/assets/pdf/26HLUT.pdf), copia autore; TCHES 2026(3) riportato sulla pagina autore | Algoritmi 1–5, §§3–6, pp. 5–27; figura 8 e tabelle 4–5 anche visivamente | PDF locale 32 pagine; [versione e limiti](testi-integrali/lut-decomposition.md); identità col finale non verificata |
| [Smart–Walter, CiC 3(1)](https://cic.iacr.org/p/3/1/8), 2026 | Modello e ipotesi, §§4,6; pp. 13–14, 24–26 | Testo completo online |
| [Bourse–Izabachène, CiC 3(1)](https://cic.iacr.org/p/3/1/3), 2026 | Sanitizzazione, campionamento e garanzie statistiche/computazionali | Testo completo online |
| [Hwang et al., ePrint 2025/216](https://eprint.iacr.org/2025/216), CCS 2025 | Costruzione, valutazione e ricevente malevolo, §5.4 pp. 27–28 | Testo completo online |
| [Rare Event Simulation, ePrint 2026/610](https://eprint.iacr.org/2026/610), marzo 2026, preprint | §§2.3,5.1–5.3,6; pp. 9–12,20–30; limite della composizione pp. 23–24 | Testo completo online |
| [Sicurezza CKKS, ePrint 2025/382](https://eprint.iacr.org/2025/382), ASIACRYPT 2025 | Funzionalità DPHE e compilatore; pp. 2–8,19–21 | Testo completo online |
| [CKKS 2025/395](https://eprint.iacr.org/2025/395), PDF 29 settembre 2026 | Nuovo titolo, modello e protocolli; pp. 2–3, §§3–6 | Testo completo online; metadata ASIACRYPT 2026, finale non verificato |
| [Stable Hash Generation](https://dasec.h-da.de/wp-content/uploads/2021/07/OsorioRoig-StableHashFaceIdentification-TBIOM-2021.pdf), copia accettata T-BIOM, early access 2021 / fascicolo 2022 | Preselezione, BFV e decifrazione sul client, §§3.3–3.5 pp. 4–6 | PDF locale |
| [HEBI, IJCB 2023](https://doi.org/10.1109/IJCB57857.2023.10448618), manoscritto accettato NVA | Articolo completo; indice, protocollo e tabelle, §§3–6 pp. 3–8 | PDF locale; [lettura e limiti](testi-integrali/hebi.md) |
| [SFRA, JISA 94](https://doi.org/10.1016/j.jisa.2025.104208), novembre 2025 | Introduzione e frammenti editoriali | **Parziale: fulltext da acquisire** |
| [PRECO, copia corretta](https://sachaservanschreiber.com/papers/preco.pdf), 24 maggio 2023, S&P 2022 | Risposta entro raggio, due server e leakage; pp. 3–4, §§7–8 | PDF locale |
| [Tiptoe, SOSP 2023](https://doi.org/10.1145/3600006.3613134), finale MIT | Client e cluster, §§2,4.1–4.2; pp. 2,4–5 | PDF locale |
| [Wally arXiv v7](https://arxiv.org/abs/2406.06761v7), 10 luglio 2026 | Batch, query finte e accessi DP; §§2.2,3,6, pp. 7–8,11,16–21 | PDF locale |
| [Compass, OSDI 2025](https://www.usenix.org/conference/osdi25/presentation/zhu-jinhao) | Collezione del client, HNSW e ORAM; §§3–4, pp. 4–5,7–10 | Testo completo online |
| [Pacmann, ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/391d50b3fe1c59b3e2b8b644e0c8fe81-Abstract-Conference.html) | Grafo, PIR e stato sul client; §§3–4, appendice B | PDF locale |
| [Liu, Informatica 48(18), 2024](https://doi.org/10.31449/inf.v48i18.6396) | Articolo completo; protocollo, formula, parametri e misure, pp. stampate 69–76 | PDF fornito; verifica 1:1, limiti di riproducibilità nella [scheda](testi-integrali/liu-informatica.md) |

Il riesame delle versioni comprende anche HEFT arXiv v1 (12 pagine) e
FDFB ricorsivo preproceedings SAC (22 pagine). Per HEFT sono controllati
i passaggi di protocollo e misura, senza assumere identità binaria con
i precedenti PDF autore e supplemento. La copia FDFB non è il finale
Springer. HEBI è un lavoro distinto da HEFT.

## Limiti e prossime letture

**SFRA resta da leggere integralmente.** L'accesso integrale a HEBI è
risolto con la versione accettata NVA. Rimane inoltre da
confrontare il finale Springer di FDFB ricorsivo col preproceedings già
consultato. La ricerca brevettuale resta parziale. Le versioni di Head,
Tetris, RevoLUT e della compensazione della media già citate sono state
ricontrollate; non si trasferiscono automaticamente le loro ipotesi alla
composizione locale. In particolare, le ipotesi d'indipendenza del modello
Head richiedono un raccordo al riuso effettivo di ciphertext e chiavi.

Rare-event simulation offre un metodo per controllare modelli di code rare,
ma il paper esamina KS e modulus switch separatamente e usa altre verifiche
per BR. Non chiude il `p_fail` composto del torneo. La biometria richiede
una propria valutazione indipendente dalla calibrazione.

Sono stati esaminati anche Shielding Latent Face Representations (FG 2025),
un framework multimodale ML-KEM/CKKS (Frontiers 2026), HEFDIVS e una rassegna
sull'iride. Non sono stati promossi a baseline: funzione, soggetto che
decifra o qualità delle garanzie dichiarate non consentono un confronto
diretto con questa decisione 1:N. La bibliografia è ampliata e verificabile,
senza una dichiarazione di completezza universale.

<a id="mosfhet-verifica-aggiuntiva-del-5-ottobre"></a>

## MOSFHET: versioni del codice e compatibilità

Per [MOSFHET](https://doi.org/10.1007/s13389-024-00359-z) abbiamo letto
le sezioni su rumore, UBR/MVFB e generazione dei dati di chiave nella
[copia istituzionale del 2024](https://zenodo.org/records/13769586).
La revisione ePrint del febbraio 2025 non è stata acquisita: queste letture
non attestano le sue modifiche.

Il confronto del codice distingue lo snapshot storico indicato dagli
autori, `0d58320559`, dal ramo attuale fissato al commit `a6e7fbb47c`.
Nel codice storico, l’angolo zero veniva saltato e il leaf monomiale
ritornava senza aggiungere l’input. Nel codice attuale,
[il caller UBR](https://github.com/antoniocgj/MOSFHET/blob/a6e7fbb47cd4451ebcc6693027e65a27d934a399/src/bootstrap.c#L124)
non salta quel contributo e arrotonda dopo la somma dei coefficienti;
[il leaf](https://github.com/antoniocgj/MOSFHET/blob/a6e7fbb47cd4451ebcc6693027e65a27d934a399/src/polynomial.c#L202)
aggiunge l’input invariato a zero. I wrapper intermedi sono stati
controllati allo stesso commit. Il rilievo storico non va quindi
presentato come un errore dimostrato nella versione attuale. Questo è
un controllo statico circoscritto, non una validazione FHE dell’intera libreria.

Per la nostra pipeline restano tre distinzioni:

- UBR con gruppi di più bit usa indicatori cifrati delle combinazioni
  di bit, assenti dalle chiavi correnti: richiede una configurazione diversa.
- MVFB riusa una preparazione su uno stesso ingresso. Le estrazioni
  successive di Head hanno ingressi dipendenti e diversi; nei
  normalizzatori il riuso delle due uscite è già presente. La presenza
  degli entrypoint multivalore negli autori non dimostra un risparmio locale.
- FTM-SE richiede di generare i coefficienti di chiave mentre li si usa.
  Le chiavi materializzate e la BSK Fourier della pipeline attuale non
  sono quel percorso. I tempi pubblicati non si trasferiscono alla demo.

Nessuna modifica al circuito o ai grafici deriva da questo confronto.
Il bound composto fino all’esito0/ID resta aperto, come indicato nella
[mappa del rumore](../validazione/RUMORE_COMPOSTO.md).
