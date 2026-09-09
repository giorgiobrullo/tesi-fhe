# Validazione runtime Docker del servizio periodic-fold — 1 settembre 2026

> **CHECKPOINT STORICO RITIRATO — F70 / Docker periodic-fold / `any_match`.** Questa prova
> verificava il packaging della vecchia baseline che restituiva soltanto un bit globale di
> apertura. Non verifica l'identita' piu' vicina, l'argmin cifrato o il contratto exact-ID finale;
> immagini, hash, 3 PBS e tempi non sono trasferibili al servizio attuale. "Sorgente finale"
> indicava soltanto l'ultimo sorgente di questo checkpoint. Per lo stato exact-ID attuale vedere
> il [README principale](../../README.md#stato-corrente-ed-evidenza-storica) e
> [`status.md`](../../status.md); la cronologia tecnica dell'hardening exact-ID e' in
> [`exact_id_noise_hardening_2026-09-01.md`](exact_id_noise_hardening_2026-09-01.md).

Questa prova verificava il packaging e l'avvio dei due container sul sorgente conclusivo del
checkpoint periodic-fold. E' una regressione funzionale locale storica, non un benchmark matched,
un health check di produzione o una certificazione del comparatore.

## Isolamento e provenienza

- `docker compose -p thesis-periodic-audit -f demo/docker-compose.yml config`: valido;
- SHA-256 del sorgente Rust del checkpoint prima e dopo build/run:
  `c89d5666c31c60254b2ac388169a7cc6ea6df91801de2900dbd5bf4a5940f16c`;
- immagine server: `sha256:92c8d4a3889b96aa53b734d42f9a19fd85fd91c0b9cd0cac24d35b1291c92519`;
- immagine client: `sha256:1a928f4eb68ef4c5164e99a4c65d519d2f0a58405b9350b34ea66ddd4f4828b2`;
- il binario Linux in entrambe le immagini aveva SHA-256
  `7eeb03d571c5718b4c59f65edc470d7ad6b26854dedaf80e52a389cb3346d243`.

Le porte host 8000 e 9000 erano gia' occupate da servizi preesistenti del workspace. Non sono
stati arrestati o modificati. Il run auditato ha quindi usato container con nomi unici, una rete
Docker `internal=true` e nessun port binding host (`PortBindings={}`). Le immagini non dichiarano
un `HEALTHCHECK`: lo stato e' stato verificato a livello applicativo dall'interno della rete.

Il run non ha eseguito un letterale `docker compose up`, che avrebbe pubblicato le porte definite
nel Compose versionato. Dopo `docker compose -p thesis-periodic-audit -f demo/docker-compose.yml
build`, la topologia isolata equivalente e' stata costruita esplicitamente in questo modo (i
percorsi `ABS_*` indicano copie o directory temporanee fuori dal repository):

```sh
docker network create --internal thesis-periodic-audit-net
docker run -d --name thesis-periodic-audit-server \
  --network thesis-periodic-audit-net --network-alias server \
  --env-file demo/config.env thesis-periodic-audit-server
docker run -d --name thesis-periodic-audit-client \
  --network thesis-periodic-audit-net --network-alias client \
  -e VARCO_SERVER=http://server:9000 \
  -v ABS_DATASET:/app/datasets/digiface/estratto:ro \
  -v ABS_MODEL_CACHE:/root/.insightface:ro \
  -v ABS_TEMP_KEYS:/app/chiavi \
  thesis-periodic-audit-client
```

Non sono stati passati argomenti `-p`. Stato e richieste applicative sono stati interrogati con
`docker exec` nel container client; i nomi, la rete e i bind temporanei sono poi stati eliminati.

## Risultato applicativo

Entrambi i container sono rimasti attivi. Il client ha generato chiavi temporanee fresche,
consegnato soltanto la evaluation key e restituito da `/api/stato`:

- client `pronto=true`;
- server `chiave=true`, output `minimal` e comparatore
  `periodic_fold_3pbs_sperimentale`;
- configurazione `pbs_per_template=3` e `pbs_n127_incluso_or=400`.

Per evitare download esterni durante la prova, una copia temporanea del modello locale esistente
e' stata montata in sola lettura ed estratta fuori dal repository. Con una sola identita'
DigiFace:

- `POST /api/precarica?n=1`: HTTP 200, un iscritto in 3,9 s;
- `POST /api/verifica` con `sintetico=0`: HTTP 200, atteso `sintetico_0`, esito `aperto`;
- 3 PBS, probe 32.800 byte, esito 16.424 byte;
- server 101,4 ms, endpoint 845,6 ms nel singolo caso.

L'esito `aperto` verificava soltanto `any_match`: non conteneva ne' dimostrava l'identita' esatta.

Questi tempi a N=1 servono soltanto a dimostrare il percorso containerizzato. Le misure di quel
checkpoint a N=127 sono negli artefatti
`demo_e2e_periodic_fold_final_2026-09-01.{csv,json}`.

## Cleanup

I container e la rete unici del run, le chiavi temporanee e la copia estratta del modello sono
stati rimossi. Non sono stati creati o eliminati volumi del progetto; le due immagini buildate
sono state conservate nella cache Docker. I listener preesistenti sulle porte 8000/9000 sono
rimasti invariati.
