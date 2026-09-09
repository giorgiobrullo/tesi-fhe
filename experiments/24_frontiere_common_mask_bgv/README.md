# 24 — Common-mask Joint4 e BGV: risultati separati

Queste due strade esplorano costruzioni differenti dal core scelto per la demo.
I risultati qui raccolti sono punti di fattibilità e confronti limitati ai
casi realmente eseguiti.

**Common-mask Joint4:** il gate completo passa quattro scene N16, compresi
pareggi e rifiuto. Il pilot temporale è distinto: una scena N16, una chiave,
quattro coppie misurate. Usando la mediana delle riduzioni entro coppia, Joint4 è **17,774834% più veloce del precedente
common-mask**, ma **24,567076% più lento di R3**. Non viene promosso come
percorso più veloce né estrapolato a N127.

**BGV:** il grafo con phi(m)=65536 passa tutti i 210 stadi ammessi e i 32.768
valori terminali, su una chiave e scene N8/8/8/4. Capacità finale 575,184 bit;
HElib riporta 135,336 bit di sicurezza. La chiave pubblica serializzata in
streaming misura 3.150.947.064 byte: non è RSS. La decifratura osservata usa
una copia diagnostica; il ciphertext originale era già ammesso e rimane
invariato. Il precedente grafo con anello più piccolo conserva l'esito di
ammissione negativo, −6,537 bit. Nessuno di questi dati è un confronto della
latenza della query con TFHE.

[Risultati](RESULTS.json), [revisione BGV](evidence/BGV_FINAL_REVIEW.md),
[origini delle prove](EVIDENCE_ORIGINS.json).

## Sorgenti d'archivio e dipendenze

Sono inclusi gli estratti effettivi del
[worker common-mask](sources/common-mask-timing/Cargo.toml), del
[prefisso](sources/common-mask-prefix/Cargo.toml) e del
[grafo BGV](sources/bgv/src/main.cpp). Questi estratti **non costituiscono build
autonome portabili**. Sono copie per leggere il meccanismo sperimentato:

- Common-mask conserva path Cargo verso A126, R3 e il prefisso nella topologia
  originale; la chiusura completa resta negli archivi indicati dalla provenienza.
- BGV conserva la dipendenza HElib 2.2.0, `json.hpp` esterno e CommonCrypto
  su macOS; il CMake storico contiene il percorso locale dell'header.

Non vengono trasformati in implementazioni qualificate su un nuovo ambiente
soltanto cambiando i percorsi. La copia è verificata in
[COPY_ORIGINS.json](COPY_ORIGINS.json). Per un servizio già integrato e una
chiusura di sorgenti pronta da compilare consultare il [pacchetto 22](../22_demo_composita/README.md).
Il [primo PoC common-mask](../16_common_mask_poc/README.md) resta conservato.
