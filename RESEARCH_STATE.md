# Stato pubblico della ricerca

Aggiornamento: 9 settembre 2026. Questo file è il riepilogo destinato al
repository pubblico. Il registro operativo integrale, gli audit datati e
gli archivi originali rimangono conservati localmente.

Il progetto studia identificazione **exact 0/ID**: primo minimo dei punteggi
interi, soglia inclusiva del solo vincitore e rifiuto espresso come zero.
Il terminale è fidato; galleria e soglie sono pubbliche al server.
Il [README](README.md) descrive il contratto e le condizioni di ammissione.

La versione selezionata è la [demo composita 22](experiments/22_demo_composita/README.md):
TFHE-rs 1.7, Head con correzione media, PFKS, normalizzatori condivisi,
specializzazione delle costanti pubbliche e parallelismo classico.
Restituisce tre cifre LWE in base 15. L'[interfaccia client/server](demo/dual_view/README.md)
separa l'accesso dalla gestione della galleria.

I [pacchetti 17–26](experiments/README.md) conservano sorgenti, risultati
e tentativi negativi del 4–8 settembre. La successiva
[campagna comune del 9 settembre](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
misura i core in due sezioni con contratto e dimensioni diversi. Non si
confrontano le velocità attraverso lo stacco né si sommano i guadagni di
campagne diverse.

**Head generale conserva un errore irrisolto:** nel primo tentativo aveva
restituito ID75 invece di ID1 e il replay ha riprodotto gli stessi cifrati.
I 450/450 risultati corretti della nuova campagna, inclusi i 45/45 di quella
versione, non cancellano il precedente fallimento. La figura lo segnala e
mantiene descrittivi i confronti che coinvolgono quel punto.

Restano aperti la probabilità di fallimento dell'intero circuito, le premesse
effettive del sampler e del runtime, la ripetibilità dei tempi, l'accuratezza
biometrica indipendente e le difese del protocollo. La ricerca resta aperta;
nessun conteggio di prove corrette o tempo misurato chiude questi obblighi.

- [Risultati consolidati e correzioni](findings.md).
- [Questioni aperte](OPEN_QUESTIONS.md).
- [Provenienza, contenuti distribuiti e limiti di riproducibilità](docs/riproducibilita.md).

La presenza di questo file permette anche al client immagini storico di
riconoscere la radice del repository; il suo contenuto non è una
configurazione crittografica né un manifest della sorgente qualificata.
