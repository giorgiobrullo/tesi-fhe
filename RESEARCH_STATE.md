# Stato della consegna: pack4, 20 settembre 2026

La baseline locale selezionata è pack4, descritta in
[PACK4_VALIDATION.md](PACK4_VALIDATION.md). I 134 file del runtime consegnato
restano congelati; [BUILD_AND_RUN.md](BUILD_AND_RUN.md) documenta compilazione
ed esecuzione. Questa pagina aggiorna la documentazione del pacchetto senza
modificare il circuito o anticipare nuove prove.

Pack4 mantiene il refresh 4/12 e la finestra PFKS della correzione B e
raggruppa fino a quattro cifre. La sua campagna verifica 432 chiamate su
tre famiglie nuove, con audit indipendente delle 1.296 LWE finali; le prove
del servizio comprendono tre roundtrip CLI/HTTP con esito 1/0/0 e rifiuto
del vecchio envelope W287. Il limite formale del circuito composto resta
aperto, come gli altri obblighi in [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

Il rapporto primario pack4/B è 0,952561993, riduzione del 4,7438%, con
intervallo bootstrap95% [0,948049442; 0,957387164] condizionato alle tre
famiglie osservate. Tutte le durate sono conservate, insieme al carico
esterno e alle finestre di attribuzione incerta. Il +13,17% della
[prima correzione B](SELECTOR_REPAIR_VALIDATION.md) appartiene a una campagna
precedente; i due rapporti non vengono combinati.

Il successivo [confronto diretto pack4/originale](docs/selector-direct-cost-20260920.md)
misura **+6,8737456%**, con intervallo bootstrap al 95% **[+6,21%; +7,52%]**
condizionato alle tre famiglie B riusate e ai casi osservati. La differenza
mediana appaiata è **0,1207 s per query**. Entrambe le versioni passano:
**216 chiamate complessive e 648 LWE finali** verificate indipendentemente.
Sono 18 coppie gate, 18 warmup e 72 misurate, di cui 60 primarie. Tutte le
144 chiamate misurate hanno un indicatore di carico esterno; 67 hanno
contabilità CPU parzialmente incerta. Nessun campione è escluso. Il dato
diretto sostituisce la stima indiretta di circa +7,8%, senza modificare le
precedenti campagne o i punti dei grafici.

I quattro approfondimenti sul costo sono **conclusi**. L'analisi non individua
refresh duplicati; la guardia pubblica esaminata non qualifica casi in cui
saltare il refresh; lo screening della sovrapposizione refresh/PFKS conserva
gli output ma non raggiunge il risparmio richiesto ed è **non adottato**;
il confronto diretto è completato. La baseline pack4 è invariata. Queste
conclusioni finite non sono una prova formale di correttezza né dimostrano
l'impossibilità di altre guardie. Non restano esecuzioni previste da questo
piano; le altre piste di ricerca non sono riattivate implicitamente.

La diagnosi storica ID75 riguarda il selettore della capsula del 9 settembre.
La baseline pre-fix del 19 settembre restituisce ID1 nel replay specifico;
anche B e pack4 restituiscono ID1. Questi casi restano distinti dalla
qualificazione su nuove famiglie e non dimostrano correttezza universale.
I [risultati](findings.md) indicano il relativo perimetro.

Per la lettura cronologica usare il
[percorso sperimentale](docs/percorso-sperimentale-20260920.md); i findings
sono il catalogo delle evidenze e la
[nota sul selettore](docs/selector-repair-20260920.md) ne conserva la diagnosi.

Le due rimisurazioni del 20 settembre sono concluse: progressione con
mediane A28/finale 7,787/1,821 s (N127/D512/T4), gate 50/50 e campagna 450/450;
CKKS/TFHE 216/216, con mediane di blocco 3,411/2,604 s a N128/general.
Il finale ricostruito e la baseline anchor/pack4 sono circuiti distinti.
[Percorso, nuove figure e metodo](docs/percorso-sperimentale-20260920.md).
Le figure storiche restano associate ai programmi e alle date originali.

## Riepilogo precedente, conservato integralmente

Il testo seguente è uno snapshot storico: le espressioni «runtime mantenuto»,
«nuovo circuito» e «causa irrisolta» si riferiscono al suo checkpoint e sono
superate, dove necessario, dallo stato corrente sopra e dai rapporti datati.

> **Stato della consegna corretta:** consultare [SELECTOR_REPAIR_VALIDATION.md](SELECTOR_REPAIR_VALIDATION.md). Il riepilogo seguente conserva il contesto storico precedente. La diagnosi del 19 settembre localizza il caso ID75 nel selettore PFKS; l'ultima baseline passa il replay specifico. La qualifica del nuovo circuito è separata.

# Stato della ricerca

Risultati: 9 settembre 2026. Organizzazione del codice: 18 settembre 2026.

Il progetto studia identificazione exact 0/ID: primo minimo dei punteggi
interi, soglia inclusiva del solo vincitore e rifiuto espresso come zero.
Il terminale è fidato; galleria e soglie sono pubbliche al server.
Il [README](README.md) descrive il contratto e le condizioni di ammissione.

Il [runtime mantenuto](runtime/README.md) deriva dalla
[demo composita 22](experiments/22_demo_composita/README.md):
TFHE-rs 1.7, Head con correzione media, PFKS, normalizzatori condivisi,
specializzazione delle costanti pubbliche e parallelismo classico.
Restituisce tre cifre LWE in base 15. L'[interfaccia client/server](demo/dual_view/README.md)
separa l'accesso dalla gestione della galleria. La revisione modulare ha
nuove identità di sorgente e circuito; gli snapshot e i tempi storici restano
associati alle versioni indicate nei report.

I [pacchetti 17–26](experiments/README.md) conservano sorgenti, risultati
e tentativi negativi del 4–8 settembre. La successiva
[campagna comune del 9 settembre](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
misura i core in due sezioni con contratto e dimensioni diversi. Non si
confrontano le velocità attraverso lo stacco né si sommano i guadagni di
campagne diverse.

Alla data del riepilogo storico, Head generale aveva un errore irrisolto: nel primo tentativo ha restituito
ID75 invece di ID1 e il replay ha riprodotto gli stessi cifrati. La nuova
campagna ha prodotto 450/450 risultati corretti, inclusi i 45/45 di quella
versione, senza spiegare la causa del fallimento. La figura lo segnala;
i confronti che coinvolgono quel punto restano descrittivi.

Restano aperti la probabilità di fallimento dell'intero circuito, le premesse
effettive del sampler e del runtime, la ripetibilità dei tempi, l'accuratezza
biometrica su dati indipendenti e le difese del protocollo. I test e i tempi
riportati documentano il prototipo entro le condizioni di ciascuna prova.

- [Risultati consolidati e correzioni](findings.md).
- [Questioni aperte](OPEN_QUESTIONS.md).
- [Eseguire il progetto e leggere i risultati](docs/riproducibilita.md).
