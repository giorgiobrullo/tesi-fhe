# A74 — gate runtime locale del servizio A67/A62

Data: 2 settembre 2026.

## Verdetto

**PASS locale, non Docker, non promosso.** Il servizio A67 materializzato sul core A62 e il wire
v4 sono stati eseguiti su loopback con una chiave effimera nuova. Le due query FHE previste hanno
rispettato il contratto exact-ID:

| query | risultato atteso | risultato decifrato | tempo HTTP | BR/PBS |
|---|---:|---:|---:|---:|
| iscritto `ID16` | `16` (`1 + 15 * 1`) | `16` | 1,264560 s | 431 |
| impostore | `0` (`0 + 15 * 0`) | `0` | 1,241563 s | 431 |

La galleria funzionale contiene 16 vettori one-hot distinti in dimensione 512 con soglia
allineata `T=0`. Il picco RSS osservato per il server e' 288.480 KiB (281,719 MiB).

## Compatibilita' fail-closed

Tutti i 31 casi negativi previsti sono stati rifiutati:

- 7 chiavi client legacy, con versione o binding errato;
- 7 chiavi server legacy, con versione o binding errato;
- 8 probe legacy, troncati o con binding errato;
- 9 output legacy, base-16, troncati, con una sola LWE o binding errato.

I rifiuti lato server non riportano un conteggio PBS: avvengono prima della valutazione FHE. La
chiave segreta non e' stata installata nel server; il materiale effimero e' stato rimosso alla
fine del gate.

## Audit indipendente del report

Il report JSON e' stato riletto separatamente verificando:

1. coerenza tra i 31 casi e i quattro subtotali;
2. uguaglianza tra output atteso e osservato per entrambe le query;
3. ricostruzione base-15 dei codici `16` e `0`;
4. hash SHA-256 del binario A71 e dei cinque sorgenti dichiarati;
5. assenza di promozione e dichiarazione esplicita del limite del campione.

L'audit passa. Il binario verificato ha SHA-256
`35dd29890573790158d1174f391b83c607693183f663e79fbdfc69f658819021` e dichiara la variante
`a62-a50-a53-radix15-group4-two-p16-v1`.

## Limite della claim

Questo gate prova che il servizio locale completo sa restituire **l'identita' esatta oppure
zero**, e che il nuovo wire rifiuta i formati incompatibili. Non prova ancora:

- latenza o correttezza a `N=127`/DigiFace;
- stabilita' statistica della latenza;
- esecuzione nel packaging Docker;
- un bound end-to-end della probabilita' di errore dei 499 marginali a `N=16` o dei 3.930
  marginali a `N=127`.

Per questi motivi A67 resta un servizio candidato e A62 resta un componente FHE valido, non un
nuovo percorso promosso.

## Artefatti

- `exact_id_a74_a67_local_runtime_gate_2026-09-02.json`: report machine-readable;
- `exact_id_a74_a67_local_runtime_command_2026-09-02.log`: sequenza temporale del gate;
- `exact_id_a74_a67_local_runtime_server_2026-09-02.log`: log del servizio senza chiave segreta.
