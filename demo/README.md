# Demo end-to-end: il varco cifrato, con i ruoli separati davvero

La dimostrazione del sistema della tesi in funzione: una telecamera al varco, un terminale che
riconosce **senza mai mandare il volto**, e un server che decide **senza mai vedere nulla**. I due
ruoli sono due processi (due container), e sul filo passano solo byte cifrati.

```
   browser (telecamera)          CLIENT — terminale fidato              SERVER — macchina remota
   raffica di 3 frame  ──────►   ResNet100 in chiaro                    galleria IN CHIARO
                                 fusione multi-frame (F48)              chiave di VALUTAZIONE
                                 quantizzazione a 3 bit (F47)
                                 CHIAVE SEGRETA                 20 KB   prodotto scalare leveled
                                 cifra ──────────────────────────────►  + 1 bootstrap di segno
                                                                          per iscritto (F37/F46)
                                 decifra  ◄──────────────────────── 230 KB   esito cifrato
                                 "aperto / negato"                      (non può decifrare niente)
```

## Cosa mostra (ed è il punto in tesi)

- **Il server non ha la chiave segreta.** Riceve un GLWE da 20 KB, calcola, restituisce 230 KB
  cifrati. La pagina mostra i byte che attraversano il filo: è tutto quello che il server vede.
- **La galleria è in chiaro sul server** (Mondo 1: sono i suoi dati, raccolti alla registrazione).
  Cifrata è solo la *query*. Non è un obbligo: F51 misura che cifrare anche la galleria costa
  **lo stesso** (prodotto esterno GGSW⊡GLWE, 0,094 s a N=128), e F52 che si può avere anche
  l'argmin esatto invece della soglia per 1,3 s. La demo usa la versione più semplice.
- **L'esito è un bit, mai una distanza** (F40): il client apprende "aperto/negato" e l'identità,
  non quanto era vicino — la contromisura all'attacco per gradiente.
- **La raffica di frame non è scenografia**: è la fusione multi-frame che porta l'accuratezza da
  ~90% a ~98-99% (F48), e costa zero lato cifrato.

## Numeri misurati (M4 Max, 16 thread, galleria da 127 iscritti)

| tappa | dove | tempo |
|---|---|---|
| embedding di 3 frame (ResNet100) | client, in chiaro | ~170 ms |
| quantizzazione + cifratura (un GLWE) | client | ~10 ms |
| **varco cifrato (127 soglie in parallelo)** | **server** | **~150 ms** (set 2_2, Δ sicuro: vedi sotto) |
| decifratura dell'esito | client | ~8 ms |
| **totale per query** | | **~290 ms** |

Verificato con il server **in container** (immagine 138 MB, solo il binario Rust): identità iscritte
riconosciute con l'indice giusto, identità non iscritte rifiutate (`conteggio 0`).
Schema dei ruoli e dei byte: `benchmark/results/architettura.png`.

Byte sul filo: probe cifrato **20 KB**, esito cifrato **230 KB**, chiave di valutazione 119 MB
(una volta sola, alla messa in servizio).

## Come si lancia

```bash
# 0) calibrazione: scala di quantizzazione e soglia (una volta, dai dati della tesi)
uv run python demo/calibra.py 128 sintetico

# 1) tutto in container (consigliato per la dimostrazione: la separazione è fisica)
docker compose -f demo/docker-compose.yml up --build       # poi http://localhost:8000

# 2) oppure: server in container, client sul Mac (più veloce, usa il modello già scaricato)
docker compose -f demo/docker-compose.yml up --build server
uv run uvicorn demo.client.app:app --port 8000

# 3) oppure tutto locale, due processi
experiments/14_pipeline_tfhe_rs/target/release/varco_demo serve 9000 512 23 52 &
uv run uvicorn demo.client.app:app --port 8000
```

Nella pagina, in basso e in piccolo: **popola galleria** (127 identità sintetiche DigiFace: volti
generati, nessuna persona reale nelle schermate) → **registrami come …** (2 foto) → poi il solo
pulsante al centro, **Apri il varco** (3 frame). Senza telecamera c'è **senza telecamera**, che usa
un volto sintetico. Sotto l'esito, una riga sola:
`310 ms · il server ha visto 20 KB cifrati · 127 confronti sul cifrato in 125 ms`.

## Perché la demo usa i parametri "lenti" (F56)

Esiste una configurazione più veloce (0,064 s invece di 0,151 s a N=128), ma è sicura solo contro un
client *honest-but-curious*. Il punteggio viaggia come (s−T)·Δ su un toro a 64 bit: se Δ è tarato sul
range dei punteggi **osservati**, un client malicious può costruire un vettore — valori tutti dentro
il dominio legale — che porta s−T oltre il punto di avvolgimento, e il bootstrap di segno legge la
metà sbagliata del toro: **il varco apre senza che nessuno somigli a nessuno, in una query sola**.
Verificato: su tre probe costruiti così, il varco ne accettava due.

La demo usa quindi Δ derivato da un **bound indipendente dai dati** (`2·dim·q² + max‖g‖² + |T|`,
calcolato da `calibra.py`) e il set di parametri N=2048, l'unico la cui banda resta stretta a quel Δ.
Costa 2,4× in tempo e un punto di accuratezza; in cambio l'attacco è bloccato (0 su 3).

## La soglia è un parametro di installazione, non una costante

`calibra.py` calcola la soglia a FPIR=1% su **due** domini e lo scrive in `config.json`:

| dominio della galleria | soglia T | usando l'altra |
|---|---|---|
| volti reali (VGGFace2) | 269 | — |
| volti sintetici (DigiFace, la galleria della demo) | 23 | con 269 entrerebbe il **91%** degli impostori |

È il divario di dominio di F30 visto dal lato operativo: la stessa pipeline, tarata sul dominio
sbagliato, apre a tutti. In tesi vale come avvertenza pratica.

## I file

- `calibra.py` — scala, soglie (reale e sintetica), Δ; scrive `config.json`
- `client/app.py` — il terminale: telecamera → embedding → fusione → cifra → decifra
- `client/static/index.html` — la pagina: minimale, una cosa sola al centro (il vetro della
  telecamera, un pulsante, l'esito) e una riga sobria coi numeri della query
- `server/Dockerfile` — il server è **solo** il binario Rust `varco_demo serve`
- `docker-compose.yml` — i due container e la rete tra loro

Il varco vero e proprio è `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` (sottocomandi
`keygen`/`encrypt`/`decrypt`/`serve`): stesso circuito dei findings F37/F41/F43/F46/F47,
parametri `MESSAGE_1_CARRY_1` a 128 bit, uscita compatta a blocchi di 64.
