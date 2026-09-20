# 24 - Common-mask Joint4 e BGV

Questi prototipi esplorano due costruzioni alternative al core Head/PFKS.
Il common-mask Joint4 cerca di condividere lavoro tra controlli correlati;
il prototipo BGV valuta un grafo completo di selezione su un anello più grande.

## Risultati

**Common-mask Joint4:** il circuito completo passa quattro scene N16,
compresi pareggi e rifiuto. Un pilot distinto usa una scena N16, una chiave
e quattro coppie misurate. La mediana delle riduzioni entro coppia è
**17,774834% rispetto al precedente common-mask**; Joint4 resta però
**24,567076% più lento di R3**. Non viene selezionato come percorso più veloce
né estrapolato a N127.

**BGV:** il grafo con phi(m)=65536 passa 210 stadi ammessi e tutti i 32.768
valori terminali, su una chiave e scene N8/8/8/4. La capacità finale è
**575,184 bit**; HElib riporta **135,336 bit di sicurezza**. La chiave pubblica
serializzata misura 3.150.947.064 byte, che non sono RSS.

La decifratura BGV osservata riguarda una copia diagnostica con `noiseBound`
impostato a zero. L'intervento non è necessario per l'ammissione: il ciphertext
originale era già `isCorrect=true` e tutti i suoi stadi avevano capacità
positiva. Il grafo precedente con anello più piccolo fallisce invece
l'ammissione, con capacità finale **−6,537 bit**, pur producendo valori
terminali diagnostici corretti. I risultati sotto contesti differenti non
costituiscono una sottrazione causale delle capacità.

Nessuno di questi test misura il vantaggio di BGV sulla latenza TFHE,
la correttezza a N127 o una probabilità globale di errore.
[Dati riepilogativi](RESULTS.json) e [rapporto BGV](evidence/BGV_FINAL_REVIEW.md).

## Codice e dipendenze

Sono disponibili il [worker common-mask](sources/common-mask-timing/Cargo.toml),
il [prefisso](sources/common-mask-prefix/Cargo.toml) e il
[grafo BGV](sources/bgv/src/main.cpp). Il common-mask contiene estratti che
non forniscono ancora tutte le dipendenze Cargo necessarie a una build autonoma.

BGV richiede HElib 2.2.0, l'header esterno `json.hpp` e CommonCrypto su macOS.
Il percorso dell'header nel CMake va configurato per il proprio ambiente.
Questi prototipi non offrono un'applicazione pronta all'avvio; per un servizio
integrato consultare la [demo 22](../22_demo_composita/README.md).
Il [primo PoC common-mask](../16_common_mask_poc/README.md) introduce il filone.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
