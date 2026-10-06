# Estrazione in due blocchi da 6 bit

Proposta respinta il 4 ottobre 2026: tre primi score diretti corretti, quarto
4095 restituisce 4094. Cinque casi omessi; nessun confronto o tempo misurato.
Questi file documentano la prova e non aggiornano il runtime mantenuto.

- `samples.csv`, `rows.jsonl`, `COMPLETE.json`: quattro casi effettivi.
- `SUMMARY.json`: risultato e impronte delle ricevute locali.
- `PROTOCOL.md`, `base64_probe.rs`: sequenza prefissata e helper eseguito.
  È un modulo di test figlio del servizio; non è un programma autonomo.
- `CONTRACT.md`, `ERROR_OBLIGATIONS.md`, `PUBLIC_LUTS.json`: controllo ideale
  e obblighi di rumore aperti, precedenti alla prova cifrata.
- `RESULT_REVIEW.md`: verifica indipendente dei risultati.

Le envelope indicate nei record restano nell’archivio locale
`/workspace/research/tmp/current-base64-producer-20261004/run01/`.
Qui sono incluse solo le loro dimensioni e impronte; nessun payload di chiavi
o cifrati. Non deserializzare né ripetere la famiglia. Le durate di lifecycle
delle ricevute non sono benchmark. Il protocollo parla della copia e del
launcher locali; nessuna qualifica di servizio o probabilità di errore.

[Metodo, risultato e limiti](../../docs/validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md).
