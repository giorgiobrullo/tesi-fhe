# Audit del confine cifrato del varco (2026-09-01)

> **CHECKPOINT STORICO RITIRATO - F70 / periodic-fold / `any_match`.** Questo report conserva
> misure e verifiche del servizio che restituiva soltanto
> `OR_i[score_i <= T_i]`: non descrive il contratto finale di identificazione exact-ID, non
> restituisce l'identita' piu' vicina e i suoi tempi/PBS non sono trasferibili all'argmin esatto.
> Le parole "corrente" e "finale" eventualmente presenti nei nomi degli artefatti si riferiscono
> esclusivamente a quel checkpoint del 1 settembre 2026. Per lo stato exact-ID attuale vedere il
> [README principale](../../README.md#implementazione-selezionata) e
> i [risultati sperimentali](../../findings.md); la cronologia tecnica dell'hardening exact-ID e' in
> [`exact_id_noise_hardening_2026-09-01.md`](exact_id_noise_hardening_2026-09-01.md).

## Esito del checkpoint periodic-fold allora corrente

Nel checkpoint qui documentato il servizio integrava un comparatore a fold periodico. Da
`x=(score-T-1/2)Delta` applica due correzioni sign-preserving con periodi `P=32` e `P=512`, poi il
PBS di segno finale. Sono **3 PBS/template**, eseguiti con le KSK/BSK standard gia' presenti:
non vengono aggiunte le chiavi WoP-PBS del vecchio candidato multi-cifra.

| galleria | soglie | OR a blocchi | totale `X-Pbs` |
|---:|---:|---:|---:|
| 127 | 381 | 19 | **400** |
| 128 | 384 | 19 | **403** |

Il modello chiaro del circuito verifica esaustivamente il predicato inclusivo per ogni
`score-T in [-4095,4095]` alla scala predefinita, oltre ai domini interi dei `log_delta` supportati.
Le regressioni cifrate con chiavi e cifrature fresche coprono ripetutamente i due punti adiacenti
alla soglia, un template denso vicino al bound, gli estremi del dominio e l'OR a galleria piena.
Questa evidenza funzionale non costituisce una prova del `p-fail` della composizione
dei tre PBS per template e dell'albero OR. L'header del servizio lo dichiara
`experimental-periodic-fold-3pbs`: il percorso e' integrato, non production-ready.

La variante a 9 PBS/template resta una fallback non integrata. Il precedente comparatore
WoP-PBS a 14 PBS/template e chiavi aggiuntive e' ritirato; il relativo report conserva soltanto
lo snapshot storico pre-fold identificato dai suoi hash.

Il vecchio benchmark applicativo da 20 positivi e 20 negativi e le latenze da circa 286 ms lato
server restano pre-fold: dichiaravano 146 PBS e non misuravano il checkpoint periodic-fold. Un
successivo artefatto evidence-grade misura invece il periodic-fold integrato su 20 positivi e 20
negativi:
**20/20 + 20/20 corretti**, sempre 400 PBS, mediana server 647,55 ms (p95 1.189,6 ms), mediana
endpoint HTTP locale 844,361 ms (p95 1.694,535 ms) e preload dei 127 template in 19,9 s. Il JSON
lega il processo al path assoluto del binario e registra hash di sorgente, binario, configurazione,
cache e manifest degli input. Era un campione applicativo del checkpoint periodic-fold, non una
stima di TAR/DIR/FPIR FHE di popolazione ne' un bound di latenza.

Un harness indipendente ha inoltre ripetuto 16 volte le cinque probe DigiFace di frontiera
preservate sotto una chiave fresca: **80/80 decisioni coerenti col chiaro**, 48 aperture e 32
rifiuti, zero discrepanze/errori, 80 ciphertext unici e sempre 400 PBS. La mediana server era
705,85 ms e il p95 968,9 ms; la mediana HTTP era 706,566 ms e il p95 970,086 ms. Replay ed E2E
vincolano entrambi il sorgente conclusivo di quel checkpoint `c89d5666...` e il binario
`2b6cef1f...`. Questo chiudeva il replay funzionale dei casi storici per `any_match`, non la
valutazione held-out completa e non una validazione exact-ID.

## Snapshot pre-fold riprodotto e ritirato

Il comparatore diretto allora in uso non implementava in modo affidabile `score <= T` vicino alla
soglia. Il bound di enrollment evitava il wrap del messaggio sul toro, ma non garantiva la
risoluzione del PBS. Con `N = 2048` e `Delta = 2^51`, un'unita' di score valeva solo
`2N * Delta / 2^64 = 0.5` unita' di rotazione del bootstrap; il margine di mezzo punto usato dal
comparatore ne valeva `0.25`. Il risultato vicino alla frontiera era quindi quasi casuale.

Questo invalidava l'uso diretto delle metriche NumPy chiare (TAR/FPIR a `T = 4`) come metriche del
servizio FHE pre-fold. I 20 positivi e 20 negativi del benchmark E2E non intercettavano il
problema: il positivo piu' vicino alla soglia aveva score minimo `-104`; il negativo held-out piu'
vicino `29`.

Gli hash qui sotto identificano esclusivamente il binario e il sorgente pre-fold usati per le
osservazioni di frontiera. Il successivo sorgente del checkpoint periodic-fold integrava il fold e
non coincideva con questo snapshot. Chiavi e cache erano artefatti locali ignorati da Git; la
frequenza degli esiti
vicino alla soglia dipendeva anche dalla casualita' di chiave e cifratura, mentre il fallimento
qualitativo fu riprodotto su molte cifrature fresche.

- SHA-256 sorgente `varco_demo.rs`: `d03aef39a2a328f0f47698bc9317f4623931f27379da10b7f51a00d0bd9df7d0`
- SHA-256 binario release: `7a8a88978aadbd3a51f0671a61d86665799516df9055340b436d91e97e850b92`
- parametri: `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`, `LOG_DO=60`
- servizio pre-fold: `serve <porta> 512 4 51`, galleria di 127 template, output minimale
- macchina: Apple M4 Max, macOS 27.0, Rust 1.97.1
- load average al momento dello snapshot: `32.86 59.29 49.77` (rende i tempi non comparabili,
  ma non cambia i bit decifrati)

Ogni osservazione sotto usa una nuova cifratura del probe. Il server viene avviato su una porta
locale libera, riceve `demo/chiavi/server.key`, e ogni risposta viene decifrata con
`demo/chiavi/client.key`.

## Galleria DigiFace esatta della calibrazione, snapshot pre-fold

Il test carica `G = datasets/digiface/_q_demo_calibrazione_resnet100.npz["G"]` (127 righe), con
soglia 4 per ogni riga. I probe vengono dallo stesso array `P` del cache. Gli score chiari sono
ricalcolati come `min_i(sum(g_i^2) - 2 * q dot g_i)`.

- SHA-256 cache NPZ: `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99`

| indice in `P` | score minimo chiaro | decisione chiara | autorizzato FHE |
|---:|---:|:---:|---:|
| 265 | 2 | si | 15/25 |
| 758 | 3 | si | 10/25 |
| 211 | 4 | si | 13/25 |
| 1943 | 5 | no | 13/25 |
| 407 | 7 | no | 9/25 |

Tutte le risposte pre-fold dichiaravano `X-Pbs: 146`. La sequenza di riproduzione era:

```text
1. np.load(...)["G"] e np.load(...)["P"]
2. POST /chiave con server.key
3. per i=0..126: POST /iscrivi con "g{i}\\t4\\n" + G[i]
4. per ogni indice [265, 758, 211, 1943, 407]:
   a. scrivere P[indice] in probe.txt
   b. varco_demo encrypt demo/chiavi probe.txt probe.ct 51
   c. POST /varco con probe.ct
   d. varco_demo decrypt demo/chiavi result.ct
   e. ripetere a-d 25 volte
```

Una sweep piu' larga, sempre sulla stessa galleria e con dieci cifrature fresche per probe, mostra
che non si tratta del solo punto di parita':

| score minimo | autorizzati FHE | score minimo | autorizzati FHE |
|---:|---:|---:|---:|
| -34 | 10/10 | 4 | 3/10 |
| -16 | 9/10 | 5 | 6/10 |
| -14 | 10/10 | 7 | 3/10 |
| -9 | 10/10 | 12 | 3/10 |
| -6 | 10/10 | 19 | 1/10 |
| 2 | 7/10 | 24 | 1/10 |
| 3 | 8/10 | 30 | 0/10 |
| 40 | 0/10 | 50 | 0/10 |

Questo suggerisce una banda di transizione larga decine di unita' di score. Una guard band puo'
essere una fallback veloce solo se il sistema cambia esplicitamente la propria semantica (zona
indeterminata o soglia piu' conservativa) e ricalibra TAR/FPIR sul percorso FHE; non rende esatto
il predicato diretto pre-fold.

## Template avversariale ma accettato, snapshot pre-fold

Con un solo iscritto:

```text
g = [3] * 150 + [1] + [0] * 361
T = 4
L1(g) = 451
sum(g^2) = 1351
bound = 2*3*451 + 1351 + 4 = 4061 <= 4095

q_score_5 = [3] * 74 + [2] + [0] * 75 + [1] + [0] * 361
q_score_3 = [3] * 74 + [2] + [0] * 75 + [2] + [0] * 361
```

Il server accetta l'enrollment. Su 100 cifrature fresche, lo score chiaro 5 (non-match) e' stato
autorizzato 48 volte; lo score chiaro 3 (match) e' stato autorizzato 54 volte.

## Controllo dell'albero OR, snapshot pre-fold

L'albero stesso instradava correttamente un hit nell'ultimo slot: 126 template `[1]*512`, poi il
target `[0]*512`, probe `[0]*512`, 20 cifrature fresche, 20/20 autorizzate. Ogni risposta aveva
`X-Pbs=146` e 16,424 byte. Il conteggio era coerente con il percorso pre-fold:
`127 + ceil(127/8) + ceil(16/8) + 1 = 146`.

Il test di servizio è stato poi corretto per mettere l'unico hit nell'ultimo slot. La verifica
manuale qui sopra conserva anche `X-Pbs` e dimensione dell'esito; nel checkpoint periodic-fold il
test automatico asseriva entrambe le proprietà e copriva anche la capienza di 128 template.

## Candidati provati in scratch prima del fold

Cambiare solamente la distribuzione da TUniform a
`V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64` (sempre `N=2048`) non risolve: sui cinque
probe DigiFace sopra ha autorizzato rispettivamente 14/25, 14/25, 10/25, 10/25 e 11/25.

Portare il polinomio a `N=8192` con
`V0_11_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64` migliora la risoluzione ma non basta. Sul
template avversariale ha autorizzato 9/30 non-match con score 5 e 19/30 match con score 3. Inoltre:

- keygen: 10.98 s;
- chiave server: 896,857,328 byte;
- probe: 131,104 byte;
- esito minimo: 65,576 byte;
- un iscritto: mediana server circa 110 ms sotto carico elevato.

Una strumentazione scratch che restituiva l'LWE leveled prima di keyswitch/PBS ha misurato, per
`N=8192`, errore standard di circa `1e-13` unita' di score: il prodotto scalare e l'offset sono
corretti. Il difetto e' localizzato alla risoluzione effettiva del passaggio keyswitch/PBS, non al
calcolo leveled.

Da questi tentativi pre-fold non emergeva un cambio di parametro drop-in che conservasse insieme
dominio di score, 146 PBS, dimensioni e latenza. Il fold periodico integrato ha poi cambiato il
circuito e il costo a 3 PBS/template; le alternative allora individuate restano storia della
decisione, non descrizioni del percorso exact-ID attuale.

Una sweep separata sul parameter set TUniform del percorso diretto pre-fold confermava il
compromesso fra risoluzione e dominio. Per ogni scala fu scelto un template di soli `1` con il
massimo numero dispari di coefficienti compatibile col radius, quindi furono provati 100 score
chiari 5 e 100 score 3:

| log2 Delta | radius ammesso | bound provato | score 5 autorizzati | score 3 autorizzati |
|---:|---:|---:|---:|---:|
| 54 | 511 | 501 | 34/100 | 74/100 |
| 55 | 255 | 249 | 21/100 | 95/100 |
| 56 | 127 | 123 | 15/100 | 100/100 |
| 57 | 63 | 53 | 1/100 | 100/100 |
| 58 | 31 | 25 | 0/100 | 100/100 |
| 59 | 15 | 11 | 0/100 | 100/100 |

La latenza pre-fold con un iscritto restava circa 14--15 ms: aumentare Delta non costava PBS
aggiuntivi. Ma la prima configurazione osservata senza errori (`2^58`) ammetteva soltanto
`abs(score-T) <= 31`, contro il bound 3,690 della galleria configurata. Non era quindi un rimedio
utilizzabile per quella demo.

## Copertura del checkpoint periodic-fold e verifiche allora necessarie

La correzione integrata copre nel modello chiaro ogni intero del dominio. La suite di servizio usa
keygen, cifratura e decifratura reali e ripete:

- `score-T=0` e `score-T=1`, per l'inclusivita' e il primo rifiuto;
- il template denso di bound 4.061 con score 3 e 5;
- casi costruiti ai due estremi del dominio, incluso rumore del prodotto GLWE;
- zero, uno nell'ultimo slot e tutti match a N=127, con `X-Pbs=400` e output da 16.424 byte;
- capienza N=128 con `X-Pbs=403`, soglie per template e sostituzione a galleria piena.

Nel checkpoint auditato la suite passa **10/10 test**; include anche gli hit agli indici interni
7, 8, 63, 64, 119 e 120. Il replay DigiFace da 80 query e l'E2E periodic-fold da 40 query sono
artefatti distinti dai test automatici e riguardano entrambi `any_match`.

Restano necessari prima di una conclusione production-grade:

1. una review dei parametri e un bound/prova della probabilita' di fallimento del circuito composto,
   non la semplice citazione del `log2_p_fail` nominale del singolo parameter set;
2. una valutazione FHE held-out statisticamente adeguata per DIR/FPIR, distinta dal campione E2E
   periodic-fold da 20 positivi e 20 negativi;
3. un binding crittografico fra evaluation key e secret key del client e una garanzia di
   provenienza/buona formazione del plaintext del probe, se si esce dal terminale fidato assunto.

## Altri difetti osservati e stato delle correzioni

- `/iscrivi` accettava token invalidi tramite `filter_map`: nel checkpoint il parser fu corretto
  per fallire al primo token non intero e fu aggiunto un test di regressione.
- `demo_e2e.py` sommava solo tempi interni e non verificava il numero realmente precaricato: nel
  checkpoint fu corretto per misurare anche il wall clock HTTP dell'endpoint, controllare `/stato`
  e salvare hash e configurazione.
  Gli artefatti pre-fold restano preservati e dichiarano 146 PBS; la coppia
  `demo_e2e_periodic_fold_final_2026-09-01.{csv,json}` misura invece il servizio periodic-fold a
  400 PBS sul sorgente conclusivo di quel checkpoint; la coppia senza suffisso `final` preserva il
  build precedente.
- `config.json` riportava metriche ottenute con la soglia specifica di ogni split mentre il
  deployment del checkpoint usava la mediana 273. Il calibratore fu corretto per salvare entrambe
  e, a T=273 fisso, FPIR aggregata 0,010571.
- Gli endpoint del server non hanno autenticazione o limiti sul `Content-Length`: chiunque possa
  raggiungere la porta puo' leggere nomi/soglie, azzerare o alterare la galleria, sostituire la
  chiave di valutazione e bloccare il loop sincrono con uno slow request. Sono limiti da demo, non
  proprieta' di un servizio production-ready.
