# A28 vs A29: benchmark appaiato exact-ID

Data run: 2026-09-02T07:55:17Z--08:12:48Z. Durata wall: 1.051,441 s.

## Esito

**PASS nel perimetro del confronto appaiato.** A29 conserva il contratto exact-ID e, nelle 60
coppie misurate, riduce la latenza server geometrica dell'**8,876%** rispetto ad A28
(`A29/A28 = 0,911245`, circa **1,097x**). L'intervallo bootstrap al 95% osservato in questo run e'
**[8,092%, 9,728%]**.

| misura primaria | A28 | A29 | confronto appaiato |
|---|---:|---:|---:|
| PBS/blind rotation per query | 5.600 | 4.965 | -635 (-11,34%) |
| latenza server media | 7.612,775 ms | 6.941,633 ms | delta medio -671,142 ms |
| latenza server mediana | 7.518,350 ms | 6.792,750 ms | delta appaiato mediano -692,850 ms |
| vittorie | 3/60 | 57/60 | nessun pareggio |

La mediana delle riduzioni appaiate e' 9,247%. La riduzione ottenuta confrontando separatamente le
due mediane, 9,651%, resta una misura secondaria: l'estimando preregistrato e' la media geometrica
dei rapporti appaiati `A29/A28`.

Non ci sono errori operativi ne' discrepanze semantiche nelle 72 coppie totali, incluse le 12 di
warm-up escluse dall'analisi primaria. I punteggi minimi clear `2, 3, 4, 5, 7` producono rispettivamente i
codici cifrati attesi `18, 46, 93, 0, 0`, dove `0` significa rifiuto e `i+1` identifica
esattamente il nearest template accettato. Il codice `46` del probe DigiFace `758` coincide con
l'oracolo intero/FHE, ma e' un falso positivo **biometrico** noto: non e' un errore crittografico.

## Disegno del confronto

Il run usa tre blocchi distinti, ciascuno con una coppia di chiavi fresca. Prima di avviare i
server di un blocco vengono preparati chiave di valutazione, galleria, dominio e tutti i probe
cifrati di quel blocco. Ogni coppia A28/A29 riceve quindi gli stessi byte del ciphertext, sotto la
stessa chiave e sulla stessa scena; la decifratura e' rimandata alla fine dell'intera fase
temporizzata.

Per ciascun blocco:

- 4 coppie di warm-up vengono eseguite e poi escluse;
- 20 coppie entrano nell'analisi;
- ognuno dei cinque probe compare quattro volte, due in ordine A28->A29 e due A29->A28;
- l'ordine di avvio dei server alterna A28/A29, A29/A28, A28/A29 fra i tre blocchi.

In totale sono quindi 60 coppie misurate e 12 warm-up. Tutti i 72 hash dei probe ciphertext sono
distinti fra coppie e identici fra A28 e A29 dentro ciascuna coppia; anche gli output sono 72
ciphertext distinti per implementazione. I tre blocchi hanno tre hash distinti della chiave di
valutazione. Nessun percorso, hash o materiale della chiave client e' registrato negli artifact.

L'intervallo e' ottenuto con 20.000 repliche di bootstrap non parametrico appaiato e stratificato:
prima si ricampionano i tre blocchi-chiave, poi le osservazioni entro gli strati fissi
`probe x ordine`, preservandone la numerosita'. La procedura stima la riduzione
`100 * (1 - media_geometrica(A29/A28))` e preserva l'accoppiamento A28/A29. Il ricampionamento
delle righe entro blocco le tratta pero' come scambiabili e non modella un'eventuale
autocorrelazione seriale del carico.

## Controlli di ordine e deriva

| partizione | riduzione geometrica A29 |
|---|---:|
| blocco 0 | 8,280% |
| blocco 1 | 9,378% |
| blocco 2 | 8,965% |
| ordine A28->A29 | 9,011% |
| ordine A29->A28 | 8,740% |
| prima meta' cronologica | 8,627% |
| seconda meta' cronologica | 9,124% |

La differenza fra gli ordini e' 0,270 punti percentuali e quella fra le due meta' cronologiche e'
0,497 punti. Le pendenze lineari delle latenze sono quasi parallele (-2,028 ms/coppia per A28 e
-1,998 ms/coppia per A29); la pendenza della riduzione e' +0,00250 punti/coppia.

La fase automatica aggiuntiva non e' stata eseguita, coerentemente con il piano: la larghezza
dell'intervallo (1,636 punti) e la differenza A/B vs B/A (0,270 punti) sono entrambe sotto le soglie
preregistrate di 2 punti.

## Dati e identificazione della revisione

- revisione a cui applicare le patch: `c5ab1b325c5c1a7c234d137bdedbbd7950222b16`;
- harness: `d4f553591f6fcb92f9cefdf7c9ffa65e394b1014c0045e0650b4377625fd1bed`;
- binario congelato A28: `09803d736d1fab5f9c26dc0799586d69ce9459408873d9d315b852280442073a`;
- binario congelato A29: `cb0d0c1736713ae7b7a36450456a6ea45cab5bd8ac63d0c08c78220b4aaba102`;
- patch sorgente A28: `58182d45efbfd8d6f87c5f5c842b83952e36a408f4639fb0e2ba019ed259115b`;
- patch sorgente A29: `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54`;
- core A29: `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4`;
- CSV: `7f18bbc584cb82ed60a5e7e7bd2adb6266ebd7c4c718265d2a7c46e2c6ae26df`;
- JSON: `80e1a9e835434f0c4e8dcc023db30713e7aafd309e253796e377deb578c2d356`.

Un controllo indipendente ha ricalcolato hash e metriche. Gli input identificati per
ciascuna revisione sono rimasti invariati durante il confronto.

Artifact grezzi:

- [CSV](fhe_digiface_exact_paired_a28_a29_2026-09-02.csv)
- [JSON](fhe_digiface_exact_paired_a28_a29_2026-09-02.json)
- [harness](../fhe_exact_id_paired_latency.py)

## Limiti

Il carico host era molto alto e non stazionario: load average 1/5/15 minuti
`20,38/37,834/28,414` prima e `59,04/67,90/58,971` dopo, su 16 CPU logiche. Il campione finale e'
in parte influenzato dal benchmark stesso e non esiste una traccia del carico per singola coppia.
Le latenze assolute e l'intervallo vanno quindi letti come condizionati a **questo** run appaiato,
non come prestazioni di una macchina idle o garanzia universale.

Il controllo appaiato, il bilanciamento dell'ordine, le pendenze quasi parallele e 57/60 vittorie
rendono persuasiva l'attribuzione relativa ad A29 nel campione. Restano pero' soltanto tre
blocchi-chiave e le query seriali entro blocco possono condividere perturbazioni di carico non
misurate; il bootstrap non trasforma il campione in una prova generale.

Questo artifact misura l'accordo exact-ID osservato e la latenza di implementazione su cinque probe di
frontiera con galleria DigiFace `N=127`. Non stima l'accuratezza biometrica della popolazione, non
dimostra la probabilita' di fallimento crittografico end-to-end e non sostiene alcun claim di
novita'.

I risultati si riferiscono alla revisione e agli input identificati in questo report.
Il clone non include il binario e tutti gli input del run storico; eseguire gli
script sul codice corrente non replica automaticamente queste misure.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
