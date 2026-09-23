# Percorso sperimentale

La domanda iniziale è se un server possa riconoscere un volto senza ricevere
in chiaro la richiesta. La galleria resta visibile al server: il client
calcola l'embedding, lo quantizza e lo cifra. La ricerca studia sia quanto
riconoscimento si perde con questa trasformazione, sia quanto costa cercare
un'identità sul dato cifrato.

I [primi programmi 00–04](../experiments/README-00-04.md) isolano operazioni,
formula dello score e scambio fra client e server, prima di usare foto reali.

## 1. Ottenere un vettore che riconosca davvero le persone

Il confronto non parte dalla foto così com'è. Il client la trasforma in un
vettore di numeri, detto *embedding*, e lo converte in interi prima di
cifrarlo. All'inizio abbiamo usato la [PCA](../experiments/05_pca/README.md):
il prototipo funzionava, ma sui volti reali riconosceva male. I
[descrittori locali](../experiments/07_descrittori_locali/README.md) andavano
meglio su LFW, senza reggere i benchmark più difficili. Con una
[rete per i volti già addestrata](../experiments/08_cnn/README.md) la qualità
è salita nettamente nel protocollo 1:N con persone sconosciute da rifiutare.

Questo decide *quanto è buona la descrizione del volto*. Il circuito può
calcolare esattamente sui numeri cifrati e comunque scegliere la persona
sbagliata se il vettore non distingue bene le foto. Le [schede storiche](risultati/storico.md)
documentano dataset e limiti di questi passaggi.

Era prevista anche una prova su gallerie MegaFace molto più grandi, ma
[lo schema 11](../experiments/11_megaface/README.md) è rimasto senza loader
dei dati: non esiste una curva MegaFace misurata in questo percorso.

## 2. Spostare la decisione sul dato cifrato

Nei primi prototipi il server calcolava **uno score cifrato per ogni voce**;
più basso era, migliore era il candidato. Il client li decifrava tutti e
sceglieva il minimo. Funzionava, ma rivelava al client i punteggi verso
l'intera galleria. Nell'[esperimento 06](../experiments/06_argmin_soglia/README.md)
abbiamo spostato sul server anche la scelta e il rifiuto. Quella versione
restituiva ancora **indice del più vicino + sì/no**: in un rifiuto il client
poteva conoscere l'indice. La successiva regola **0/ID** restituisce solo
zero oppure l'ID accettato.

Confrontare due score cifrati costa più che calcolarli, e il tempo cresceva
molto con i bit degli score. La
[prova GPU](../experiments/09_gpu/README.md) non ha risolto la latenza
del circuito e del carico testati. Il [torneo](../experiments/10_argmin_struttura/README.md)
confronta le coppie in parallelo: fra quattro candidati confronta (1,2) e
(3,4), poi i due vincitori. Nelle prove Concrete era più veloce della
catena sequenziale, ma il tempo restava nell'ordine delle decine di secondi.

## 3. Capire quale operazione rallenta tutto

Un [primo confronto Concrete/TFHE-rs](../experiments/13_tfhe_rs_headtohead/README.md)
mostrava un argmin TFHE-rs rapido, ma non misurava la stessa pipeline nelle
stesse condizioni: i rapporti intorno a 100× restano storici, non la velocità
guadagnata dall'applicazione completa. Nel medesimo prototipo TFHE-rs,
calcolare *tutti gli score* con l'API intera ad alto livello costava molto
più dell'argmin. Usando le primitive a basso livello, la parte lineare del
punteggio poteva evitare i bootstrapping che propagavano i riporti.
Questa scelta è stata sviluppata nei [circuiti successivi](../experiments/14_pipeline_tfhe_rs/README.md).

Il [primo esperimento CKKS](../experiments/15_ckks_confronto/README.md)
calcolava score e soglie per candidato, non ancora l'uscita 0/ID completa.
Abbiamo esaminato anche il [common-mask](../experiments/16_common_mask_poc/README.md),
che prova a condividere lavoro fra cifrati. Sono percorsi con uscite,
parametri o prove proprie; il microbenchmark common-mask non è una demo di
identificazione completa.

## 4. Restituire soltanto zero o l'identità

Le versioni A28–R3 hanno costruito il torneo e la selezione finale: scegliere
**prima** lo score minimo, mantenere il primo candidato nei pareggi e
controllare **poi** la soglia di quel vincitore. Se fallisce, si restituisce
zero; un altro candidato con soglia più permissiva non prende il suo posto.
L'[esempio con due candidati](come-funziona-il-confronto.md) segue i passaggi.

L'[esperimento 17](../experiments/17_head_pfks_tfhe17/README.md) ha aggiunto
Head per estrarre le cifre degli score e PFKS per portare avanti i dati
del vincitore nel torneo. All'inizio il servizio era provato su una galleria
di 127 voci con una soglia comune. L'[esperimento 18](../experiments/18_scaling_soglie_miste/README.md)
ha separato tre esigenze: accettare gallerie di altre dimensioni,
rappresentare ID più grandi e trasportare soglie diverse insieme ai
rispettivi candidati. Il formato a tre cifre *può rappresentare* 3374 ID;
le prove FHE rumorose hanno taglie più piccole e documentate.
[Core e scaling](risultati/core-e-scaling.md).

## 5. Ridurre il costo e integrare il servizio

Con la funzione fissata, gli esperimenti successivi hanno lavorato sui
passaggi costosi: [configurazione CPU](../experiments/19_runtime_cpu/README.md),
[estrazione delle cifre](../experiments/20_normalizzatori_carry/README.md),
[selezione dei dati noti e parallelismo](../experiments/21_costanti_pubbliche_parallelismo/README.md).
La [demo composita](../experiments/22_demo_composita/README.md) misura la loro
integrazione con client e servizio. Ogni percentuale confronta due versioni
particolari: non si ottiene il guadagno finale sommando i miglioramenti
intermedi. [Componenti e servizio](risultati/normalizzatore-e-demo.md).

Sono conservati anche i tentativi che non hanno vinto nei propri confronti:
PGO, alcune combinazioni G4, Tetris con le conversioni provate e le politiche
DAG. Le [alternative](risultati/alternative.md) spiegano cosa è stato
misurato e perché non è stato selezionato. Un esito negativo di quel
prototipo non è una confutazione della tecnica in generale.

## Correttezza del selettore e costo della correzione

Un errore osservato nella campagna del 9 settembre ha richiesto di riesaminare
il selettore. Head e confronto erano corretti, ma il controllo raggiungeva
l'indirizzo 341, oltre la finestra 300–340. Il selettore mescolava cifre di
posizioni diverse e il torneo restituiva ID75 invece di ID1.

La correzione rigenera il controllo prima della selezione. L'ottimizzazione
successiva, chiamata `pack4` nei sorgenti, trasferisce insieme fino a quattro
cifre che codificano punteggio, ID e soglia. Richiede meno operazioni e
mantiene la rigenerazione del controllo.
La lezione è verificare insieme rumore, finestre e cifre trasportate: un'uscita
corretta nella demo non garantisce il margine su altre chiavi.
[Diagnosi e correzione](selector-repair-20260920.md).

Nel confronto diretto con l'originale del 19 settembre, il circuito corretto
richiede **il 6,87% di tempo in più**, circa **0,121 s** di differenza mediana
appaiata. Entrambe le versioni passano i casi di questa prova; il rischio
della versione originale non equivale a un errore osservato su ogni input.
L'intervallo condizionato alle tre famiglie riusate è +6,21%–+7,52%.
[Misure e limiti del confronto](selector-direct-cost-20260920.md).

## Risultati confrontabili

La progressione è stata ricostruita e rimisurata il 20 settembre, applicando
la correzione ai quattro stadi interessati: Head M, Head generale, CPU e
composizione finale. Gli altri sei mantengono il proprio circuito.

![Progressione del costo cifrato](../output/figures/progressione-fhe/selettori-corretti-20260920/progressione.png)

A N127/D512/T4, le mediane passano da **7,79 s a 1,82 s**; le 450 esecuzioni
includono 150 warmup e 300 misure. Il grafico usa 30 misure per versione e
mostra l'intervallo interquartile. Il pannello dei prototipi N8/D64 riguarda
un altro compito e non entra in questo confronto.
[Dati della progressione](../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md).

Il confronto CKKS/TFHE usa invece CKKS balanced-v3 e il circuito TFHE CPU
corretto, senza le aggiunte della demo finale. A N128 con soglia generale,
le mediane dei blocchi sono **3,41 s per CKKS e 2,60 s per TFHE**. CKKS
restituisce uno scalare approssimato, arrotondato sul client; TFHE tre cifre
discrete. Il tempo va letto insieme a questa differenza di contratto.
[Dati e metodo CKKS/TFHE](../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md).

Le campagne usano Apple M4 Max e 16 thread. Durante le misure erano attivi
anche altri processi sul computer: i tempi descrivono queste condizioni,
senza quantificare il rallentamento dovuto all'attività in background.
Misurano il core, escludendo chiavi, cifratura, embedding e HTTP. La demo
corrente aggiunge anche la trasformazione anchor: il suo circuito è distinto
dal finale del grafico e dal TFHE del confronto CKKS. Le
[questioni aperte](limiti.md) riguardano rumore composto,
validazione biometrica e sicurezza del protocollo.
