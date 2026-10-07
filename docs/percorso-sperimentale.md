# Percorso sperimentale

La domanda è se un server possa riconoscere un volto senza ricevere in chiaro
la richiesta. La galleria resta visibile al server; il client calcola il
vettore del volto, lo quantizza e lo cifra. Per arrivare a una risposta utile
occorrono sia un buon riconoscimento sia una decisione cifrata corretta e
abbastanza rapida.

Il percorso segue otto passaggi: rappresentare il volto, definire la risposta,
costruire il circuito, ridurne il costo, misurarlo, integrarlo e valutarne
riconoscimento e garanzie. Ogni passaggio presenta la soluzione scelta e
le prove che la motivano. I collegamenti portano ai dettagli sperimentali.

Per approfondire una conclusione ci sono i [risultati](../findings.md);
per capire i rami scartati, il capitolo dei [tentativi e risultati negativi](risultati/alternative.md).
Quando serve il programma o il dato originale, la
[mappa degli esperimenti](../experiments/README.md) indica dove trovarlo.
Le versioni misurate restano associate ai rispettivi rapporti, anche quando
la demo adotta un programma successivo.

Nel testo, sigle come **A23** identificano un tentativo e **F14** una scheda
di risultati. I numeri delle cartelle, come `08_cnn`, identificano le campagne.
L’[esempio del confronto e glossario](come-funziona-il-confronto.md)
spiega i termini del circuito usati nei passaggi successivi.

<a id="1-ottenere-un-vettore-che-riconosca-davvero-le-persone"></a>

## 1. Trovare una rappresentazione del volto utile

I [programmi 00–04](../experiments/README-00-04.md) isolano operazioni cifrate,
formula dello score e scambio client/server. Il primo prototipo sulle foto
usa [PCA](../experiments/05_pca/README.md): funziona come pipeline, ma riconosce
male nei dati provati. I [descrittori locali](../experiments/07_descrittori_locali/README.md)
migliorano LFW senza reggere i benchmark più difficili. Gli
[embedding CNN](../experiments/08_cnn/README.md) danno risultati migliori e
diventano la rappresentazione usata nelle prove successive.

Resta da misurare l’effetto della quantizzazione e delle soglie su persone
iscritte e sconosciute. Le [schede biometriche](risultati/prototipi-e-correzioni.md)
raccolgono protocolli, dati e condizioni delle prove. Il progetto
[MegaFace](../experiments/11_megaface/README.md) non produce una campagna:
il loader rimane incompleto. Non gli viene attribuita una curva misurata.

<a id="2-spostare-la-decisione-sul-dato-cifrato"></a>
<a id="3-capire-quale-operazione-rallenta-tutto"></a>

## 2. Portare anche la decisione sul server

La risposta richiesta è **0/ID**: il server sceglie il primo minimo, verifica
la soglia del solo vincitore e restituisce zero se non è autorizzato.
Scelta e soglia vengono calcolate sul dato cifrato. Restituire tutti gli score
al client, oppure indice e sì/no separati, rivelerebbe informazioni ulteriori
anche in caso di rifiuto. L’[esperimento 06](../experiments/06_argmin_soglia/README.md)
documenta il confronto fra queste forme di risposta.

Il confronto cifrato è costoso in Concrete. La
[prova GPU](../experiments/09_gpu/README.md) non risolve la latenza del carico
esaminato; il [torneo](../experiments/10_argmin_struttura/README.md) migliora
la catena sequenziale, ma i tempi restano elevati. Il
[confronto con TFHE-rs](../experiments/13_tfhe_rs_headtohead/README.md)
mostra un argmin più rapido e uno scoring ancora costoso con le API intere.
Il passo successivo è usare primitive a basso livello per la parte lineare.

I confronti fra primitive dipendono dalla funzione e dal dominio misurati.
Anche [CKKS iniziale](../experiments/15_ckks_confronto/README.md) e la
[PoC common-mask](../experiments/16_common_mask_poc/README.md) hanno uscite e
condizioni proprie: il costo di una primitiva non è ancora quello del servizio.

<a id="4-restituire-soltanto-zero-o-lidentità"></a>

## 3. Costruire il contratto esatto 0/ID

La [pipeline 14](../experiments/14_pipeline_tfhe_rs/README.md) affronta
dominio, risoluzione e rumore. Il confronto deve distinguere anche i valori
vicini alla soglia: il comparatore diretto a una PBS non copre quel requisito.
Le costruzioni multibit e periodic-fold realizzano il predicato di appartenenza;
la decisione completa richiede anche la selezione dell’identità.

A23 completa primo argmin, soglia del vincitore e 0/ID. Split 4, ManyLUT,
accumulatore sparso, scan e parallelismo riducono poi il costo. Le
[prove fino ad A66](risultati/diario/f71-f83.md) conservano anche errori di
codifica e componenti corretti che richiedevano una nuova verifica dopo
la composizione. Un test isolato riuscito permette di tentare il raccordo;
non certifica automaticamente l’intero servizio.

Il ramo [comparatore/PFKS](evidence/repo-coverage-20261005/pfks-successors.md)
passa dai componenti alle composizioni complete N2, poi N127 e servizio.
Il [pacchetto 17](../experiments/17_head_pfks_tfhe17/README.md) raccoglie
la costruzione Head/PFKS e il servizio della campagna.
Il [pacchetto 18](../experiments/18_scaling_soglie_miste/README.md) estende
taglie, ID e soglie miste. Il formato a tre cifre rappresenta 3374 ID;
le taglie effettivamente provate restano quelle indicate nei rapporti.

Il selettore del circuito adottato rigenera il proprio controllo prima di
trasferire le cifre del candidato scelto. Questo passaggio, chiamato
**refresh**, mantiene il controllo nella finestra prevista dalla selezione,
sotto le condizioni sui residui descritte nel [rapporto del selettore](selector-repair-20260920.md).
La verifica di queste condizioni nel circuito completo resta distinta dalla
correttezza della singola operazione.

<a id="5-ridurre-il-costo-e-integrare-il-servizio"></a>

## 4. Ridurre il costo del circuito completo

Con la funzione fissata, si confrontano [FFT e configurazione CPU](../experiments/19_runtime_cpu/README.md),
[normalizzatori](../experiments/20_normalizzatori_carry/README.md),
[costanti pubbliche e parallelismo](../experiments/21_costanti_pubbliche_parallelismo/README.md).
Il [pacchetto del servizio composito](../experiments/22_demo_composita/README.md)
documenta l’integrazione delle primitive nell’applicazione. I guadagni si riferiscono a baseline diverse:
la composizione deve essere misurata direttamente.

Il trasferimento `pack4` riunisce fino a quattro cifre di punteggio, ID e
soglia, riducendo il numero di gruppi da elaborare e conservando il refresh
del controllo. Il [confronto del selettore](selector-direct-cost-20260920.md)
misura l’effetto delle sue scelte sul tempo del calcolo cifrato.

PGO e alcune combinazioni non confermano un vantaggio. Il produttore
[Tetris](../experiments/25_tetris/README.md)
supera il controllo cifrato ma costa di più incluse le conversioni.
Le politiche del [torneo DAG](../experiments/26_torneo_dag/README.md)
non superano i rispettivi screening di latenza. Sono negativi delle costruzioni
e condizioni provate, conservati insieme alle alternative selezionate.

Anche [CKKS](../experiments/23_ckks_ottimizzazioni/README.md),
[common-mask e BGV](../experiments/24_frontiere_common_mask_bgv/README.md)
proseguono con programmi propri. Joint 4 migliora il precedente common-mask
ma resta più lento di R3; BGV passa nel contesto più grande senza un vantaggio
di latenza qualificato. Questi rami non diventano percentuali aggiuntive
da attribuire alla demo TFHE.

<a id="correttezza-del-selettore-e-costo-della-correzione"></a>
<a id="6-correggere-il-selettore-e-misurare-il-costo-della-correzione"></a>
<a id="risultati-confrontabili"></a>
<a id="7-rimisurare-la-progressione-su-compiti-confrontabili"></a>
<a id="5-correggere-il-selettore-e-rimisurare-la-progressione"></a>

## 5. Misurare la progressione a parità di compito

La valutazione confronta dieci implementazioni complete della funzione
0/ID sulle stesse cinque scene, con 127 template di 512 coordinate e soglia
4. Le versioni con estrazione Head includono il refresh del selettore;
il finale usa il trasferimento `pack4`. I tempi includono queste operazioni.

![Progressione del costo cifrato](../output/figures/progressione-fhe/selettori-corretti-20260920/progressione.png)

Le mediane passano da **7,79 s a 1,82 s**, su TFHE-rs 1.7 e M4 Max con
16 thread. Sono tempi del calcolo cifrato: preparazione delle chiavi,
cifratura, decifratura e HTTP sono esclusi. I [dati e il metodo](../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md)
riportano campioni, controlli e condizioni della macchina.

Il pannello iniziale del grafico usa 8 template di 64 coordinate e misura
un compito diverso. I due pannelli vanno letti separatamente; il passaggio
da 7,79 s a 1,82 s riguarda soltanto il tratto completo 0/ID.

Il [confronto CKKS/TFHE](../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md)
è una campagna distinta. CKKS restituisce uno scalare approssimato e TFHE
cifre discrete; il TFHE di quel confronto, il finale della progressione
e la demo con trasformazione anchor sono circuiti differenti.

<a id="8-aggiornare-la-libreria-e-verificare-il-servizio"></a>
<a id="9-cercare-il-risparmio-nelle-fasi-che-costano-di-più"></a>
<a id="6-aggiornare-la-libreria-e-provare-altre-riduzioni"></a>

## 6. Integrare il circuito nell’applicazione

La demo usa TFHE-rs 1.8.1. La [verifica della migrazione](validazione/TFHE_181_MIGRATION.md)
copre compilazione, test e casi cifrati. Il [confronto appaiato con la 1.7](validazione/TEMPI_181_20261004.md)
misura +0,88–2,09% nei tre casi del servizio: l’aggiornamento non produce
un vantaggio di velocità in quel campione. Il risultato riguarda le condizioni
provate; il grafico della progressione resta riferito alla 1.7.

La [demo](validazione/DEMO_SSE_20261004.md) richiede 2,10–2,24 s dal POST al
risultato SSE nei tre casi misurati, con elaborazione della foto e FHE,
esclusi avvio, cattura e rendering. La [profilazione](validazione/PROFILO_RUNTIME_20261004.md)
colloca circa 56% del tempo nel torneo e 41% in Head e orienta i tentativi successivi.

La profilazione permette di valutare interventi mirati. Il
[torneo DAG](../benchmark/tournament-dag-20261004/README.md)
rallenta tutte le otto coppie del confronto valido e non viene adottato. La strada
[FCMA](../benchmark/fcma-codegen-20261004/README.md) passa prima dal codice
generato, poi da [aritmetica e tempi su operandi pubblici](../benchmark/fcma-public-gate-20261004/README.md).
Il risparmio osservato riguarda un singolo aggiornamento complesso sintetico;
non è una misura del circuito FHE.

Il [comparatore compresso](validazione/COMPARATORE_COMPRESSO_20261004.md)
fallisce il primo controllo; il [binario](validazione/COMPARATORE_BINARIO_20261004.md)
passa come primitivo ma [fallisce nella pipeline](validazione/PIPELINE_BINARIA_20261004.md).
Anche l’[estrazione in due blocchi](validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md)
non supera la verifica cifrata. I rapporti collegati conservano gli errori
osservati e distinguono le prove eseguite dai casi non raggiunti.

[Raw 9](risultati/selettore-e-generalizzazione.md#raw9) migliora lo stadio
terminale ma non dimostra un beneficio stabile sull’intera query.
Il [profilo delle cifre ID](risultati/selettore-e-generalizzazione.md#pfks-id) riduce
la priorità della cache. L’[analisi GLWE](risultati/selettore-e-generalizzazione.md#glwe)
esclude il semplice riuso proposto; [CBS](risultati/selettore-e-generalizzazione.md#cbs)
richiede ancora un’interfaccia coerente e non è un prototipo FHE fallito.
Nessuna di queste proposte sostituisce il runtime mantenuto.

<a id="6-verificare-di-nuovo-il-riconoscimento-dopo-lintegrazione"></a>
<a id="10-verificare-il-riconoscimento-dopo-lintegrazione"></a>

## 7. Verificare il riconoscimento dopo l’integrazione

Il circuito può restituire esattamente il risultato previsto e accettare
comunque uno sconosciuto. Le [prove VGGFace 2](validazione/BIOMETRIA_VGGFACE2_20261002.md)
valutano il riconoscimento con iscrizione a tre foto.
La [preparazione UI](validazione/BIOMETRIA_UI_20261002.md) cambia alcune
decisioni sugli stessi input: deve entrare anch’essa nel protocollo biometrico.
Non sono sessioni webcam né nuove esecuzioni FHE.

Il [test Georgia Tech](risultati/selettore-e-generalizzazione.md#georgia-tech)
aggiunge 20 iscritti e 30 sconosciuti, con foto di iscrizione e verifica separate
e 100 persone del catalogo a completare la galleria. Per ciascuna condizione,
una foto o fusione di tre, riconosce 20/20 iscritti e accetta 1/30 sconosciuti.
Il falso accesso riguarda la stessa persona: le due condizioni non sono
campioni indipendenti. Soglia e scala restano fissate e il campione non
dimostra un tasso di falsi accessi dell’1%.

<a id="11-distinguere-i-test-dalla-garanzia-matematica"></a>
<a id="domande-e-conclusioni-sostenute-dal-percorso"></a>

## 8. Separare l’evidenza sperimentale dalla garanzia matematica

I test verificano input, chiavi e programmi eseguiti. Una probabilità
complessiva di errore richiede un bilancio di tutti i passaggi, del riuso
delle chiavi e del calcolo numerico effettivo. Un bound ideale non si
trasferisce automaticamente al percorso FFT.

La [mappa del rumore](validazione/RUMORE_COMPOSTO.md) distingue le
identità algebriche, le ipotesi dei modelli e i limiti ancora da dimostrare
per il programma effettivo. La probabilità complessiva di errore della
baseline mantenuta resta aperta: i casi FHE corretti e i controlli di
singoli passaggi non sostituiscono questo bilancio.

Le [questioni aperte](limiti.md) raccolgono il lavoro ancora necessario:
garanzia del circuito effettivo, dati biometrici indipendenti, protocollo
contro avversari più forti e generalizzazione delle prestazioni.
