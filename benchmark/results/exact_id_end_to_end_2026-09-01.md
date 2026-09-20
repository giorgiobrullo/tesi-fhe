# Identificazione esatta: verifica end-to-end del 2026-09-01

> **Storico: smoke end-to-end precedente ai tre hardening del rumore.** I risultati a 4.919/4.949
> PBS, le immagini Docker e gli screenshot appartengono al circuito iniziale poi superato. Restano
> utili per verificare il contratto HTTP/UI di quella revisione, ma non dimostrano la correttezza o
> la latenza del circuito corrente. Lo stato canonico e' in `../../README.md` e `../../status.md`;
> la cronologia tecnica e' in `exact_id_noise_hardening_2026-09-01.md`. La validazione post-fix
> resta un artefatto separato.

## Contratto verificato

- Il server calcola il primo argmin sul cifrato, seleziona la soglia del solo vincitore e
  restituisce un unico LWE.
- Il plaintext finale e' `0` per il rifiuto oppure `indice+1` per l'identita' accettata.
- Un rifiuto viene decifrato come `indice: null`; score e distanza non sono restituiti.

## Servizio e client locali, N=127

Comando di misura: `benchmark/demo_e2e.py`, con binario release e PID del server vincolati,
cache di calibrazione richiesta, tre genuini e tre impostori held-out.

- 3/3 genuini: apertura **e identita' esatta** corrette.
- 3/3 impostori: rifiuto corretto e nessuna identita' restituita.
- 4.919 PBS per query.
- server: 7.755,7-8.695,3 ms; mediana 8.468,05 ms.
- endpoint HTTP completo: 7.961,323-8.912,332 ms; mediana 8.671,392 ms.
- preload di 127 template: 18,7 s.
- probe cifrato: 32.840 byte; esito cifrato: 16.464 byte.

Artefatti:

- `benchmark/results/demo_e2e_exact_id_2026-09-01.csv`
  (`sha256 dee402f4173033135330343db674edf95d17a85e423515ac446f267d8d2855fd`)
- `benchmark/results/demo_e2e_exact_id_2026-09-01.json`
  (`sha256 1930cf7f5fbc7723f07f633903ed3d50c67d3074c1a14d0676e0b6ec6095139f`)

## Docker e browser reale

Le immagini sono state ricostruite dopo l'integrazione del core:

- server: `sha256:15ffb9ccaf9ab5bcf40915a830de9bcdc4821fb130a4ec502a294a303443d359`;
- client: `sha256:4cd950e5316649cf9d7530494034f7e0e9e76412b510d5cac8aa827b82c71b3d`.

Nel browser automatizzato, sulla pagina servita dal container client e con server container:

1. `popola galleria` ha concluso con `Galleria pronta / 127 iscritti`;
2. una query sintetica iscritta ha mostrato `Aperto / sintetico_1005`, 4.919 PBS e 9.544 ms
   lato server;
3. la query held-out sintetica 627 ha restituito via API
   `{"esito":"negato","identita":null,"atteso":"sintetico_1562"}` e la pagina ha mostrato
   `Negato / identita' non rilasciata`, 4.919 PBS e 13.066 ms lato server.

Screenshot:

- `demo/screenshots/exact-id-docker-2026-09-01.png`
  (`sha256 b99aa7916ac564e6f851102ff4820818200b20268cf677b1f80f25617d0f8712`)
- `demo/screenshots/exact-reject-docker-2026-09-01.png`
  (`sha256 0eaed852fc19d2123c4db97f2031826aecb33dfee5c3662fd7278f5022e0592c`)

I tempi Docker non vanno mescolati con quelli host: includono la virtualizzazione locale e qui
servono come verifica funzionale del pacchetto, non come benchmark prestazionale principale.

## Estremo del codice di uscita, N=128

Un test separato del servizio release ha iscritto 128 template binari distinti e costruito una
query il cui minimo unico era l'ultimo elemento. Il risultato decifrato e' stato:

```json
{"autorizzato":true,"indice":127,"codice":128,"iscritti":128}
```

Il server ha contato 4.949 PBS e 9.478,9 ms. Questo copre insieme la cardinalita' massima, il
massimo codice rappresentabile dal wire e un'identita' accettata nella coda della galleria; resta
uno smoke singolo, non un bound di latenza o di probabilita' di fallimento.

## Limiti dell'evidenza

- Sei query biometriche end-to-end non stimano da sole una probabilita' di fallimento TFHE.
- La validazione statistica DIR/FPIR resta quella clear sulla scena calibrata; questa prova lega
  invece il percorso operativo al contratto di identificazione.
- Il client fidato deve far rispettare `q_j in [-3,3]` e `||q||^2 <= 1024` prima della cifratura.
- La galleria e le soglie sono in chiaro sul server nel modello corrente.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
