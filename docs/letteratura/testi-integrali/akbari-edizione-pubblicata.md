# Akbari et al.: verifica dell'edizione pubblicata

Revisione del 19 settembre 2026 sul PDF editoriale completo. Il problema di accesso al PDF è chiuso. Sono state lette le sezioni pertinenti e controllate visivamente le pagine con tempi, tabelle e metriche; non sono stati riprodotti gli esperimenti né certificate integralmente le dimostrazioni.

**Riferimento definitivo:** Ramin Akbari, Luke Sperling, Nalini K. Ratha, Arun Ross e Vishnu Naresh Boddeti, *Homomorphically Encrypted Biometric Template Fusion and Matching*, IEEE Transactions on Biometrics, Behavior, and Identity Science, 7(4), ottobre 2025, pp. 573-587. DOI [10.1109/TBIOM.2025.3595438](https://doi.org/10.1109/TBIOM.2025.3595438). La prima pagina indica pubblicazione online il 4 agosto 2025 e versione corrente il 25 settembre 2025, con licenza CC BY 4.0. Il PDF consultato contiene 15 pagine: pagina editoriale = pagina PDF + 572. SHA-256: `804bfe2d89f8e2b2220c19143b5ca7afa3bd2cd07b944f76a04c10bc7d023ba5`.

## La discordanza nei tempi rimane nella versione finale

| Punto del PDF | Dato riportato | Unità e operazione |
|---|---|---|
| §I, PDF p. 2 / p. 574 | Circa 1130 + 5006 | Millisecondi per fusione di due vettori di 512 componenti a dimensione 32, più calcolo degli score su 1028 template |
| Tabella III, PDF p. 11 / p. 583, Authentication, Poly degree 2 | 1127,85 + 4,87 | Millisecondi di fusione per campione e millisecondi per match |
| §VI, PDF p. 13 / p. 585 | 1150 | Millisecondi dichiarati per fusione e matching sull'intera gallery di 1028 template |

La Tabella III è stata verificata visivamente. La riga di autenticazione contiene 22,72 ms di concatenazione, 979,54 ms di proiezione e 125,59 ms di normalizzazione, per 1127,85 ms di fusione. **4,87 ms è il costo per match, non per gallery.** I valori del corpo della tabella sono in millisecondi; i quattro valori di riferimento in chiaro nella didascalia, 0,62, 1,02, 11,75 e 4,51, sono invece in microsecondi.

**Ricostruzione aritmetica dell'audit:** 4,87 × 1028 = 5006,36 ms, coerente con i 5006 ms dell'introduzione. Sommando il valore di fusione si ottengono 6134,21 ms. Questa somma ricostruisce i costi pubblicati, non costituisce una nuova misura della latenza completa. Il PDF non riconcilia questi dati con i 1150 ms della conclusione. Non si seleziona quindi un tempo riassuntivo come riferimento per uno speedup della tesi.

Anche il risparmio di circa 11% attribuito alla variante senza normalizzazione (§V, PDF p. 12 / p. 584) richiede un denominatore esplicito: 125,59 / 1127,85 ≈ 11,14% della fusione nella riga di grado 2. §IV.C, PDF p. 11 / p. 583, descrive proprio la sottrazione della colonna Normalization da Fusion Total. Non documenta automaticamente un miglioramento dell'11% dell'intera query sulla gallery.

## Metriche, dati e variabilità

Il confronto principale usa **TMR a FMR dell'1%**, calcolato in chiaro dopo la decifrazione degli score (§IV.C e Tabella II, PDF p. 10 / p. 582). Per face/voice a 32 dimensioni, la variante cifrata Poly degree 2 riporta TMR 0,7643, contro 0,3142 del volto e 0,2356 della voce. I guadagni citati di circa 143,25% e 224,40% sono variazioni relative di questi valori: non punti percentuali né incrementi di AUROC. Le Figure 11-12, PDF p. 12 / p. 584, usano invece **AUROC** nelle analisi degli iperparametri. Sarebbe scorretto estendere l'etichetta TMR a ogni risultato dell'articolo.

§IV.A, PDF p. 9 / p. 581, distingue due costruzioni. Face/voice combina artificialmente campioni provenienti da CPLFW e Google Speech Commands: 10.760 coppie, 188 classi, suddivisione delle classi 60% training, 20% validazione e 20% test; il test contiene 1028 campioni. Face/fingerprint proviene da soggetti comuni, con 2472 coppie su 61 soggetti, ma introduce rumore uniforme U(0; 0,1) nei vettori facciali dell'85% degli esempi di training e test per rendere più difficile la modalità volto. È una perturbazione sperimentale delle feature, distinta dal rumore crittografico CKKS.

Figura 7, PDF p. 9 / p. 581, dichiara otto ripetizioni face/voice e dieci face/fingerprint con suddivisioni diverse. Le bande mostrate sono 0,3σ; anche Figura 8, PDF p. 10 / p. 582, usa questa convenzione. Non vanno presentate come intervalli al 95%.

## Assunzioni e collocazione nella tesi

§III.B, PDF p. 4 / p. 576, assume client onesti, chiavi comuni e server semi-honest; il server conosce la matrice di proiezione in chiaro e non possiede la chiave segreta. §III.C, PDF p. 5 / p. 577, distingue matching 1:N e verifica su identità dichiarata e restituisce gli score cifrati ai client perché li decifrino ed elaborino. §III.D5 e §III.E, PDF pp. 6-8 / pp. 578-580, motivano e descrivono l'apprendimento adattato alla normalizzazione polinomiale oppure alla sua eliminazione.

**Inferenza per la tesi:** il lavoro documenta fusione appresa, packing e compromessi tra approssimazione e riconoscimento. Il suo contratto espone gli score al client e non fornisce direttamente il nostro unico risultato `0/ID`. Una comparazione deve rendere espliciti destinatario dell'output, selezione finale, soglia e assunzioni sui client. I risultati biometrici restano legati ai dati e alle perturbazioni dichiarate.

Questa nota aggiorna la precedente lettura via testo web, conservata nella copia storica della rassegna. La [sintesi sui sistemi](sistemi.md) riflette ora l'edizione pubblicata: accesso e controllo visivo completati; Tabella III localizzata a PDF p. 11 anziché p. 10 e frase conclusiva sui tempi a PDF p. 13 anziché p. 12; uso di TMR limitato al confronto principale. La discordanza temporale resta un limite della fonte pubblicata, non un problema di estrazione del testo. Hash, pagine controllate e trascrizioni sono conservati nel registro locale della ricerca.
