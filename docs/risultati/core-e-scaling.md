# Core, servizio iniziale e scaling

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati al 9 settembre 2026. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F84 - Contratto exact 0/ID e implementazione selezionata

Per i punteggi interi ammessi, il server sceglie il primo minimo in ordine
di identità e verifica la soglia inclusiva del vincitore: per il vincitore
`j` (identità numerate da 1 a N) restituisce `j` se `s_j ≤ T_j`, altrimenti `0`. Non cerca un altro candidato
con una soglia più favorevole. La decisione e la selezione
avvengono sui cifrati; galleria e soglie sono pubbliche nel modello attuale.

L'implementazione selezionata usa TFHE-rs 1.7, Head con correzione media, PFKS
`direct-window`, tre cifre cifrate in base 15 e gruppi di payload adattati al
modo uniforme/misto e ai tagli pubblici. La demo composita
sceglie `public_parallel`, senza G4: normalizzatore condiviso, confronti
classici e selettore paralleli, trasporto delle sole cifre ID necessarie,
selezione finale del solo ID e specializzazione delle costanti pubbliche.
Eredita FFT Dif4 fissa, 16 thread e build opt3/CGU1 senza native, LTO o PGO.
Il client immagini usa il solo rilevatore necessario all'allineamento,
conservando embedding, fusione e quantizzazione nei casi verificati.

La rappresentazione ammette fino a 3374 identità, subordinatamente anche
ai controlli sul dominio dei punteggi. Questo limite non è una qualifica FHE
a ogni taglia: l'estensione generale precedente ha casi noisy fino a 1024 e
casi di servizio fino a 225; le prove delle revisioni successive hanno le
proprie taglie. Le suite di versioni precedenti non qualificano automaticamente
la sorgente composita.

Riferimenti: [esperimento 22](../../experiments/22_demo_composita/README.md),
[riepilogo dell'integrazione](../../experiments/22_demo_composita/RESULTS.json),
[risultati dell'estensione generale](../../experiments/18_scaling_soglie_miste/RESULTS.json).

## F85 - Head/PFKS: core completo e primo servizio

Il confronto finale M/H/R3 del 6 settembre usa una nuova famiglia di chiavi,
otto input, due terne di riscaldamento escluse e sei terne misurate con tutti
gli ordini. Le mediane sono 3,048836 / 3,071472 / 4,615544 secondi.
La mediana delle riduzioni entro coppia per M è 0,7963% rispetto a H e
34,0848% rispetto a R3; tutte le sei coppie favoriscono M. Passano 31
uscite complete e i controlli di uguaglianza e delle fasi. Split, base e
correzione media cambiano insieme: il contributo dei 127 KS eliminati non è
isolato. Questo estimatore è diverso dalle riduzioni geometriche usate
nelle campagne successive.

Il primo servizio riutilizzabile N127 passa separatamente 15 uscite e 39
rifiuti attesi, con sei nuove cifrature della query sotto una nuova famiglia.
M usa il profilo nativo full51/low60; i controlli full52 richiedono l'adattamento
esplicito documentato. Il confronto M/H/R3 usa per R3 parole full51 moltiplicate
per due: non è un confronto con input nativi full52 del servizio. Questa prima
versione restituisce due cifre base 15 e conserva il percorso precedente alle
altre taglie; l'estensione a tre cifre è successiva.

Riferimenti: [esperimento 17](../../experiments/17_head_pfks_tfhe17/README.md) e
[riepilogo dei risultati originali](../../experiments/17_head_pfks_tfhe17/RESULTS.json).

## F86 - Taglie variabili e soglie generali o miste

La campagna a due cifre misura M a 17 taglie da 1 a 224. A 15 taglie condivise
fino a 128, il confronto con A126 invariato su tre nuove chiavi dà riduzioni
geometriche appaiate del 25,60–50,97%. A N127 le mediane M/A126 sono
3,031/6,115 secondi. La campagna e lo smoke preliminare passano 1272 uscite
complete e 12 uguaglianze seriale/parallelo; R3 è un controllo separato.

Il pilot distinto M3/A126_3 adatta esplicitamente anche il controllo a tre
cifre: una nuova chiave, cinque taglie 224/225/256/512/1024, due warmup esclusi
e quattro coppie misurate per taglia. Passano 60 uscite; 20/20 coppie
favoriscono M3, con riduzioni del 50,45–52,44%. A N1024 le mediane sono
23,451/49,062 secondi. Non è disponibile un intervallo fra più chiavi.

La correttezza con soglia uniforme generale, soglia del vincitore diversa
per identità e ID più larghi ha controlli separati su tre chiavi. Alcuni casi
con soglie estreme usano scorciatoie pubbliche e non sono valutazioni noisy
non banali. Il servizio generale passa 18 uscite e 44 rifiuti specifici;
le successive prove fotografiche sono sintetiche. Lo scaling dei tempi non
misura il vantaggio su ogni configurazione di soglie né la latenza web.

Riferimenti: [esperimento 18](../../experiments/18_scaling_soglie_miste/README.md)
e [riepilogo delle campagne e dei limiti](../../experiments/18_scaling_soglie_miste/RESULTS.json).

## F87 - FFT fissa e configurazione CPU

Su due nuove famiglie di conferma, CGU1/16 thread/FFT fissa riduce il tempo
del 18,37% rispetto al riferimento FFT fissa/8 thread. Passano 450 uscite
complete. L'intervallo al 95% del rapporto dei tempi, costruito sulle due medie
per chiave, è 0,6768–0,9846: le 48 coppie misurate non sono 48 chiavi
indipendenti. Il confronto diretto con il riferimento originario a FFT
adattiva dà 16,63% e comprende anche la diversa politica numerica.

CGU1 preso da solo e native non confermano un beneficio. ThinLTO, FatLTO,
le combinazioni native/LTO, la rimozione di copie PFKS e la cache LUT sono
state provate senza un vantaggio selezionato. PGO, addestrato e verificato
separatamente, è 1,53% più lento su una chiave nuova e 24 coppie, con
10 vittorie. La configurazione scelta resta senza queste opzioni.

La FFT fissa è installata prima di creare o caricare le chiavi Fourier e
permette i controlli di identità dei cifrati. Le vecchie differenze fra
processi sono compatibili con la scelta adattiva del piano; senza i piani
storici registrati non è una causa dimostrata per ogni differenza. Tutte le
coppie finali riportano segnalazioni di carico esterno e attribuzione del
carico parzialmente incerta.
Sedici thread software non dimostrano affinità a specifici core fisici.

Riferimenti: [esperimento 19](../../experiments/19_runtime_cpu/README.md) e
[riepilogo dei confronti CPU](../../experiments/19_runtime_cpu/RESULTS.json).
