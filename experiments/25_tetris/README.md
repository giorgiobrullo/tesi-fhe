# 25 — Tetris: consumatore corretto, produttore più lento

Il prototipo supera i controlli con rumore del componente e del consumatore:
54 output completi e 2091 verifiche LWE nel percorso accelerato. Il confronto
del produttore comprende però sei circuit bootstrap freschi per creare il
controllo. In questo pilot **Tetris è 66,401451% più lento**, zero vittorie su
18 coppie, una famiglia di chiavi e tre scene. Medie geometriche circa
23,688078 contro 14,235500 ms.

Il costo comprende la conversione necessaria al consumatore; non è una
misura della query completa. Il negativo vale per questa costruzione,
non per ogni possibile variante Tetris. Il prototipo è escluso dalla demo.

Il [runtime misurato](runtime/Cargo.toml) include core locale, lockfile, piano
di timing incorporato e l'accelerazione split-FFT con
[licenza RevHomTrace](runtime/LICENSE-RevHomTrace). L'implementazione conserva
l'attribuzione nel sorgente. Il [primo tentativo fallito](failed-first/RESULT.json)
e il suo [sorgente](failed-first/tetris.rs) sono conservati separatamente.

[Risultati](RESULTS.json), [tempi del produttore](evidence/producer-timing.json),
[origini delle prove](EVIDENCE_ORIGINS.json) e
[verifica delle copie](COPY_ORIGINS.json) distinguono ogni revisione.
Il `SOURCE_DIGEST.txt` incorporato è un identificatore ereditato; non identifica
da solo tutta questa nuova cartella. I risultati sono quelli delle prove
originali, senza nuova compilazione o esecuzione durante il consolidamento.
Le dipendenze registry TFHE-rs 1.7.0 non sono vendorizzate.
