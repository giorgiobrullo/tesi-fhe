# Tentativi A: filoni e decisioni

<a id="tentativi-a-censimento-e-decisioni"></a>

[Percorso sperimentale](../percorso-sperimentale.md) · [Catalogo individuale](catalogo-tentativi-a.md) · [Sorgenti e risultati](../../experiments/attempts-a/README.md)

Le sigle A identificano tentativi tecnici, progetti, controlli e revisioni
di strumenti. Non sono tutte prove FHE eseguite e non coincidono con le
cartelle numerate 00–26 o con le schede F. Una stessa idea può avere più
sigle quando cambia il programma, il protocollo o l'osservatore.

Per seguire anche le piste esterne alla numerazione A, leggere
[tentativi, risultati negativi e correzioni](alternative.md): collega
i limiti delle singole prove alle decisioni nell'intero percorso.

## Che cosa è censito

Il [censimento delle fonti individuate](../evidence/repo-coverage-20261005/tentativi-a-inventory.json)
comprende **160 directory A, 150 sigle distinte nelle directory e 36 righe
del registro originario**. Con i file di risultati, le patch e una citazione
testuale e i programmi/test pubblici censiti il 6 ottobre, l'unione copre
**187 sigle**. A108 comprende anche la riesecuzione
del 5 ottobre; A70 compare come richiamo a un audit statico nel report A73,
senza attribuirgli una nuova esecuzione.

Il [catalogo individuale](catalogo-tentativi-a.md) collega ogni sigla alla
proposta, all'esito documentato e al seguito. Il JSON conserva il censimento
dei file e aggiunge gli estratti verificati delle fonti, con righe e impronte.
Ogni risultato conserva il programma e il perimetro che lo hanno prodotto;
le correzioni successive spiegano quale conclusione cambia e perché.

Le otto sigle non rilevate nelle fonti censite sono A42, A43, A47, A48,
A54, A100, A113 e A119. La numerazione discontinua non dimostra che
siano esistiti esperimenti poi cancellati. Il censimento conta gli
identificatori individuati, non tutte le esecuzioni della ricerca.

I percorsi `archive_relative` identificano le fonti originali; le mappe
dei [materiali A](../../experiments/attempts-a/README.md) li associano ai
file inclusi nella repository. Il catalogo collega sorgenti per 149 sigle
e risultati strutturati per 111. Le altre voci comprendono progetti, analisi
e prove documentate nei rapporti: non si deduce l’esistenza di un programma
autonomo dal solo identificatore. Le etichette «corrente» e «aperto» negli
estratti si riferiscono alla data della fonte; la colonna del seguito
esplicita gli sviluppi successivi.

La verifica dei programmi pubblici in `benchmark/` e `tests/` ha recuperato
[A35](catalogo-tentativi-a.md#a35), assente dal primo perimetro delle directory:
block-label a una BR e classificatore fuso hanno ostacoli statici circoscritti;
radix-5 ha esito clear favorevole ed entra selettivamente in A38. I tre
[log originali](../../experiments/attempts-a/a35/results/RESULTS.public.json)
attestano 9, 10 e 10 unit test passati nell’audit del 2 ottobre, senza nuove
esecuzioni o attribuzioni di correttezza FHE ai modelli.

## Come leggere gli esiti

| Esito | Che cosa stabilisce |
|---|---|
| Errore FHE osservato | Il programma eseguito non restituisce sempre il risultato atteso nei casi salvati. |
| Corretto ma non selezionato | I casi passano, ma costo o requisiti non giustificano l'adozione. |
| Beneficio inconclusivo | Le misure non sostengono un vantaggio affidabile nel perimetro richiesto. |
| Limite statico | Algebra, interfaccia o costo strutturale escludono la proposta nelle premesse dichiarate; non è una misura FHE. |
| Evidenza invalida | Il test o la registrazione non consentono la conclusione; non equivale a un errore dell'algoritmo. |
| Non eseguito nel perimetro descritto | La fonte attesta che quella prova non è stata eseguita; eventuali successori vanno verificati separatamente. |

Ogni scheda specifica il tipo di evidenza: progetto, modello, compilazione,
prova cifrata di componente, composizione o misura. Un successo nel proprio
perimetro non si trasferisce automaticamente a una variante o all'intera
pipeline. I paragrafi seguenti raccontano i passaggi principali; il catalogo
permette di seguirli sigla per sigla.

<a id="primo-contratto"></a>

## A01–A27: fissare il contratto e correggere le prime conclusioni

| Tentativi | Passaggio e decisione | Dove leggere |
|---|---|---|
| A01–A03, A10, A17 | Correzioni dei domini e ritiro del comparatore diretto vicino alla soglia. I log precedenti non provano esattezza su tutto il dominio. | [F56](diario/f43-f56.md#f56) e [F57–F70](diario/f57-f70.md), [sintesi corretta](prototipi-e-correzioni.md) |
| A04 | Torneo con circuit bootstrapping: errori osservati nella costruzione provata; non è una bocciatura di ogni argmin TFHE. | [F52](diario/f43-f56.md#f52) |
| A05–A07, A15–A16 | Cambia il contratto di risposta e si distingue la calibrazione biometrica dalla provenienza del probe. Membership e identità del primo minimo sono compiti diversi. | [F40](diario/f29-f42.md#f40), [F61](diario/f57-f70.md#f61), [F71](diario/f71-f83.md#f71) |
| A08–A09, A13–A14, A21–A22 | Baseline e alternative CKKS: scope incompleti, conversioni costose o provenienza parziale; i tempi di uno score non sono automaticamente quelli dell'identificazione completa. | [F39](diario/f29-f42.md#f39), [F67](diario/f57-f70.md#f67), [esperimento 15](../../experiments/15_ckks_confronto/README.md) |
| A11–A12 | Compressione e BatchBoot: limiti delle misure e necessità di un bridge compatibile; nessuna impossibilità generale dimostrata. | [F22–F28](diario/f15-f28.md), [F65](diario/f57-f70.md#f65) |
| A18–A20 | Comparatore multibit e periodic-fold restano baseline per un predicato diverso dal contratto finale 0/ID. «Ritirato» non significa che tutti i loro test fallissero. | [F69–F70](diario/f57-f70.md#f69) |
| A23–A26 | Primo argmin esatto, evoluzione dello stato e correzione dell'interpretazione negaciclica di −1. Le versioni superate restano associate ai propri test. | [F71](diario/f71-f83.md#f71) e [F72](diario/f71-f83.md#f72) |
| A27 | Il PoC common-mask non giustificava lo speedup precedentemente attribuito; servivano output consumati e confronto coerente. | [Esperimento 16](../../experiments/16_common_mask_poc/README.md) |

<a id="costruzione"></a>

## A28–A124: costruire e misurare la selezione esatta

La sequenza adottata passa da split4 e ManyLUT ad accumulatore sparso,
uscita a due LWE, riduzioni base 15 e parallelismo. Le
[schede F72–F83](diario/f71-f83.md#f72) conservano i passaggi A28, A29,
A33, A38, A41, A44, A62, A64, A66 e A124, con suite e perimetri propri.
A64, per esempio, è utile come riferimento controllato ma il costo stimato
è troppo grande per il percorso selezionato: non va scomparso dal racconto.

In parallelo esistono filoni di output/packing (A34–A61), servizio e
riproducibilità (A63–A76), buffer e parallelismo (A77/A80/A85), modelli del
rumore e legame col codice (A79/A84/A90/A93/A94), common-mask (A78/A107),
Head Start e Chen (A88–A104), altri algoritmi e rappresentazioni
(A81–A83/A105–A123). Questi gruppi orientano la lettura; l'appartenenza a
un gruppo non assegna a tutti i membri lo stesso esito.

Per seguire ogni passaggio, dal primo progetto al successore, si parte dalle
[schede A28–A77](catalogo-tentativi-a.md#a28) e
[A78–A124](catalogo-tentativi-a.md#a78). Il
[censimento](../evidence/repo-coverage-20261005/tentativi-a-inventory.json)
conserva anche i titoli e gli stati del registro originario.

<a id="pfks"></a>

## A108 e il seguito PFKS: conservare anche la correzione della diagnosi

A108 prova una selezione packed mediante convoluzione e fallisce il gate
su cinque configurazioni di parametri. Il risultato negativo è già
riportato in [F81](diario/f71-f83.md#f81). I rapporti originali non autorizzano
a presentare i tempi delle braccia errate come accelerazioni.

La diagnosi iniziale parlava di errori «dentro il supporto certificato».
La revisione successiva, richiamata nella
[riesecuzione con verifica dei log](../../experiments/14_pipeline_tfhe_rs/results/a108_rerun_2026-10-05/README.md#codice-e-verifica),
ritira quell'attribuzione: la fase decifrata arrotondata non stabilisce il
supporto della rotazione coefficiente per coefficiente. Gli output errati
rimangono evidenza negativa, ma la loro causa richiede osservazioni aggiuntive.
Il **5 ottobre A108 è stato rieseguito con tracce complete**: stesso
sorgente, lockfile e TFHE-rs 0.11.3, cinque configurazioni e otto fixture
ciascuna. Con nuove chiavi falliscono rispettivamente 4, 3, 4, 5 e 6 casi
su otto; il riferimento scalare decodifica correttamente tutte le uscite.
I [295 record e la verifica indipendente](../../experiments/14_pipeline_tfhe_rs/results/a108_rerun_2026-10-05/README.md)
sono inclusi insieme ai sorgenti. È una nuova campagna, con compilatore
e provenienza dichiarati, che conferma il negativo e conserva ogni esito.

A120–A122 cambiano il test del margine e il datapath; A127 e i successivi
osservatori separano l'errore del payload dall'indirizzo effettivo.
A134/A137/A147/A151/A167/A171/A174/A186/A191 appartengono a questa
prosecuzione. Gli esiti successivi esistono: A137 passa il componente D2
su 24 fixture in tre processi; A174 passa le 24 fixture D1 e i controlli.
Il primo risultato A191 aggiunge il comparatore effettivo. Le
[fonti dei passaggi](../evidence/repo-coverage-20261005/pfks-successors.md)
distinguono questi perimetri. Il [passo di integrazione del 5 settembre](../evidence/repo-coverage-20261005/integration-results.md)
arriva poi da score effettivi all'ID su N2, con quattro casi corretti.
La successiva composizione adottata è descritta nel
[core Head/PFKS](../../experiments/17_head_pfks_tfhe17/README.md).

<a id="estrazione"></a>

## A125–A185: il produttore può passare e il consumatore fallire

La linea A125/A130 prova il riuso di correzioni dei bit bassi; A165 e A169
cambiano quali correzioni vengono emesse alla scala richiesta. Un primo
successo di A169 non chiude il percorso. Il successivo test A185, eseguito
attraverso A182 sul contratto A175, registra un **negativo verificato**:
i valori decifrati dal produttore passano, ma un consumatore effettivo
fallisce a score 17/bit 2. La baseline dello stesso controllo passa.

È il motivo per cui il registro distingue primitiva, composizione e query
completa. Il negativo sulla nuova chiave non cancella il precedente
successo e non esclude tutte le costruzioni di estrazione.
[Estratto del risultato verificato](../evidence/repo-coverage-20261005/a185-result.md).

<a id="padding"></a>

## A149–A195: precisione ed errori degli strumenti

La [prova A149, lanciata con A179](../evidence/repo-coverage-20261005/a149-result.md),
dà un negativo funzionale; [A187](../evidence/repo-coverage-20261005/a187-result.md)
cambia la premessa di precisione e passa la propria prima prova. Sono programmi e
chiavi distinti, non un risultato precedente riscritto.

L'espansione A192 termina con codice 0 ma il verificatore ne rifiuta
l'evidenza: l'osservatore etichetta sempre la chiave con 0, anche nel ciclo
su più chiavi. A195 corregge quella registrazione in un successore separato.
Il [record conservato](../evidence/repo-coverage-20261005/a192-result.md)
non dimostra un errore dell'algoritmo crittografico e non permette di usare
A192 come qualifica multichiave. A195 ha invece già passato smoke e
programma completo N4: **16 fixture su tre chiavi nuove, 48 componenti**,
con verifica indipendente del risultato salvato.
[Esiti A190/A195](../evidence/repo-coverage-20261005/a190-a195-results.md).

Il successore R3 integra poi cifre degli score effettivi, selezione e A53:
63 casi su sei chiavi e integrazione nel servizio N127 risultano corretti
nel [resoconto del 5 settembre](../evidence/repo-coverage-20261005/integration-results.md).
Il successivo passaggio R3 → Head/PFKS è nell'
[esperimento 17](../../experiments/17_head_pfks_tfhe17/README.md).

<a id="common-mask"></a>

## Common-mask e controlli: un gate fallito non è sempre un output errato

Nel witness A150 le due braccia positive common-mask passano, ma uno dei
controlli negativi non viene rilevato. Il gate completo resta fallito: è
una limitazione del witness, non un errore common-mask osservato.
[Estratto del risultato](../evidence/repo-coverage-20261005/a150-result.md).

A132/A146/A155/A176/A188/A190 proseguono il filone con ambiti distinti.
Anche qui esistono esiti: A190 passa la ricorrenza cifrata persistente
N4 a otto round, con 1.820 verifiche semantiche e 336 verifiche del supporto,
senza errori nel test. La [successiva integrazione](../evidence/repo-coverage-20261005/integration-results.md)
collega estrazione, A34, otto round common-mask e A53: passano le tre scene
N4 nelle due politiche. Il risultato successivo è
[Joint4 nell'esperimento 24](../../experiments/24_frontiere_common_mask_bgv/README.md):
corretto nei casi N16, ma più lento del riferimento R3 nel pilot. Questi
risultati non qualificano automaticamente ogni precedente variante.

<a id="che-cosa-rimane-da-consolidare"></a>

<a id="copertura-e-aggiornamento"></a>

## Risalire dalla conclusione alla prova

Le **187 schede individuali** comprendono studi del rumore, prove fallite,
controlli degli strumenti e progetti non eseguiti. Ogni voce lega l’esito
al tipo di evidenza e al seguito. Per ricostruire una revisione si usano
le [mappe di sorgenti e risultati](../../experiments/attempts-a/README.md);
per valutare la correttezza della pipeline si usano le prove riferite
al programma effettivamente adottato.
