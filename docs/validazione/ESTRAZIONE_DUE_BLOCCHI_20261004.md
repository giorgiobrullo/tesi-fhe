# Estrarre il punteggio in due blocchi — 4 ottobre 2026

**La proposta fallisce nella prima prova cifrata.** Lo score normalizzato
4095 restituisce i blocchi [63,62] invece di [63,63], cioè 4094. I primi
tre casi sono corretti; la sequenza si ferma e i cinque successivi restano
non eseguiti. Il runtime mantenuto e i grafici non cambiano.

## Cosa volevamo ridurre

Prima del torneo, Head estrae lo score cifrato in tre cifre da 4 bit:
ciascuna vale 0…15. Questa proposta usa invece due blocchi da 6 bit,
ciascuno 0…63. Per esempio 4095 è 63×64+63. La precisione dello score
rimane la stessa; cambia il modo in cui lo rappresentiamo e lo estraiamo.

Il produttore proposto usa una Head e due normalizzatori scalari, per
3 rotazioni invece delle 4 del produttore corrente. Le due normalizzazioni
condividono soltanto l’input dopo KS e modulus switch; restano due rotazioni
distinte. Non abbiamo integrato il comparatore a due blocchi o il torneo.

Le LUT ideali funzionano su tutti i 4096 score normalizzati. Il loro margine
di indirizzo è però più piccolo: i nuovi normalizzatori ammettono ±7 gradi
interi, contro ±31 del riferimento a 32 stati. Questo controllo geometrico
non limita il rumore reale. Il preset canonico della libreria non certifica
automaticamente le LUT personalizzate a 128 stati.

## Cosa abbiamo eseguito

TFHE-rs 1.8.1, Rust 1.98.1 release, M4 Max e 16 thread, FFT Dif4/base1024.
Una famiglia Standard nuova: dimensioni 859→2048, GLWE2/N2048,
Head 15×2, normalizzatori 23×1 e KS 3×5. Nessun retry o chiave ricaricata.

L’ordine fissato prima delle chiavi è 63,64,0,4095,127,128,1023,1024.
Solo dopo otto PASS sarebbe stato eseguito un nono caso con due score
prodotti dal prefisso reale su template distinti. Non è stato raggiunto.

| Score normalizzato | Atteso [alto,basso] | Ottenuto | Esito |
|---:|---|---|---|
| 63 | [0,63] | [0,63] | Corretto |
| 64 | [1,0] | [1,0] | Corretto |
| 0 | [0,0] | [0,0] | Corretto |
| 4095 | [63,63] | [63,62] | Errato, stop |

Per ciascuno score eseguito: 3 BR, 2 KS, 3 estrazioni e 4 livelli di gadget,
verificati nei callsite effettivi. Sono decifrati solo i blocchi finali
arrotondati. Le envelope di chiavi, input e output falliti restano opache.
La revisione indipendente conferma il rifiuto e tutte le identità.

## Cosa conclude questa prova

La riduzione delle operazioni non basta: il produttore provato non conserva
sempre lo score. La variante è respinta nella forma e nei parametri eseguiti,
senza misurare un’accelerazione. Il solo output finale non identifica quale
passaggio abbia introdotto l’errore; non stima un tasso di fallimento e non
dimostra un errore della baseline o del servizio. Un dominio più ristretto
richiederebbe una qualifica propria; questa prova non la fornisce.

[Quattro casi](../../benchmark/base64-producer-20261004/samples.csv),
[riepilogo](../../benchmark/base64-producer-20261004/SUMMARY.json),
[protocollo e sorgente](../../benchmark/base64-producer-20261004/README.md),
[contratto ideale](../../benchmark/base64-producer-20261004/CONTRACT.md),
[obblighi di rumore](../../benchmark/base64-producer-20261004/ERROR_OBLIGATIONS.md),
[revisione del risultato](../../benchmark/base64-producer-20261004/RESULT_REVIEW.md).
