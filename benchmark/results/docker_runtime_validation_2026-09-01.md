# Validazione runtime Docker del servizio periodic-fold - 1 settembre 2026

> **CHECKPOINT STORICO RITIRATO - F70 / Docker periodic-fold / `any_match`.** Questa prova
> verificava il packaging della vecchia baseline che restituiva soltanto un bit globale di
> apertura. Non verifica l'identita' piu' vicina, l'argmin cifrato o il contratto exact-ID finale;
> immagini, hash, 3 PBS e tempi non sono trasferibili al servizio attuale. "Sorgente finale"
> indicava soltanto l'ultimo sorgente di questo checkpoint. Per lo stato exact-ID attuale vedere
> il [README principale](../../README.md#implementazione-selezionata) e
> i [risultati sperimentali](../../findings.md); la cronologia tecnica dell'hardening exact-ID e' in
> [`exact_id_noise_hardening_2026-09-01.md`](exact_id_noise_hardening_2026-09-01.md).

Questa prova verificava il packaging e l'avvio dei due container sul sorgente conclusivo del
checkpoint periodic-fold. E' una regressione funzionale locale storica, non un benchmark matched,
un health check di produzione o una certificazione del comparatore.

## Ambiente e isolamento

Client e server sono stati eseguiti in due container su una rete Docker interna,
senza porte pubblicate sull'host. Il client accedeva al modello e al dataset
in sola lettura e conservava le chiavi in una directory separata. La prontezza
è stata verificata attraverso l'API applicativa, non tramite un HEALTHCHECK Docker.

Il binario Linux era identico nei due container, SHA-256
`7eeb03d571c5718b4c59f65edc470d7ad6b26854dedaf80e52a389cb3346d243`.
Il sorgente Rust della revisione aveva SHA-256
`c89d5666c31c60254b2ac388169a7cc6ea6df91801de2900dbd5bf4a5940f16c`.
Questo identifica la versione periodic-fold provata, non il servizio exact-ID attuale.

## Risultato applicativo

Entrambi i container sono rimasti attivi. Il client ha generato chiavi temporanee fresche,
consegnato soltanto la evaluation key e restituito da `/api/stato`:

- client `pronto=true`;
- server `chiave=true`, output `minimal` e comparatore
  `periodic_fold_3pbs_sperimentale`;
- configurazione `pbs_per_template=3` e `pbs_n127_incluso_or=400`.

Il modello era disponibile in sola lettura nel client. Con una sola identita' DigiFace:

- `POST /api/precarica?n=1`: HTTP 200, un iscritto in 3,9 s;
- `POST /api/verifica` con `sintetico=0`: HTTP 200, atteso `sintetico_0`, esito `aperto`;
- 3 PBS, probe 32.800 byte, esito 16.424 byte;
- server 101,4 ms, endpoint 845,6 ms nel singolo caso.

L'esito `aperto` verificava soltanto `any_match`: non conteneva ne' dimostrava l'identita' esatta.

Questi tempi a N=1 servono soltanto a dimostrare il percorso containerizzato. Le misure di quel
checkpoint a N=127 sono negli artefatti
`demo_e2e_periodic_fold_final_2026-09-01.{csv,json}`.

## Limiti della replica

Questo report documenta una configurazione storica. I suoi container e le chiavi
non fanno parte del clone; i comandi della demo attuale non ricreano quel run.
Per un'applicazione utilizzabile vedere la [guida client/server](../../demo/dual_view/README.md).
