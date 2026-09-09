# CKKS8/12/16 — 8 settembre2026

Il primo confronto conserva16thread:12è quasi alla pari e8è più lento.
Tutti69output e151confronti completi dei ciphertext/input passano, oltre alle
quattro transizioni reali8→12→16→8 senza contesto o chiavi crittografiche.

| Budget | Mediana query | Variazione tempo rispetto a16 | Coppie più veloci |
|---|---:|---:|---:|
|8|3.220313s|+8.9820%|0/6|
|12|2.964014s|+0.2011%|1/6|
|16|2.957853s|riferimento|—|

La variazione deriva dalla media geometrica dei rapporti appaiati; non dal
rapporto delle mediane. Ogni tripla condivide chiave, ingresso cifrato e cache
pubblica. Sono escluse le due triple di riscaldamento; le sei misurate
coprono tutti gli ordini possibili. I team OpenMP predefiniti ed espliciti
osservati coincidono con i budget richiesti; ciò non identifica l'affinità
dei core o il numero di worker attivi in ogni kernel.

Prima della misura passano18output/45checkpoint del confronto originale e
combinato a16thread, quindi27output/90checkpoint fra8/12/16 suN128, soglie e
paritàN4 e intervallo4096N64. La misura aggiunge24output/16uguaglianze finali.
Tutte le unità di compilazione usano coerentementePARALLEL/OpenMP; non è
misurato separatamente l'effetto di cambiare quei flag rispetto ai vecchi
eseguibili.

Un solo processo con chiave nuova sostiene la misura: carico esterno medio
ponderato261.76%, copertura completa, stato high/unknown per ricambio processi.
Il risultato non trasferisce tempi al servizio e non è una prova del tasso
di fallimento. Tutti i processi dell'esperimento sono terminati.

Ricevuta: `THREAD_BUDGET_RESULT.json`,
SHA256 `f5a8c938ea1ad645d9d9fcddbdf2cd0d1f1364178ea99040a5850e536c0eddb6`.
Sorgenti, binario, log e analisi sono vincolati da `ONE_KEY_FREEZE.json`.
