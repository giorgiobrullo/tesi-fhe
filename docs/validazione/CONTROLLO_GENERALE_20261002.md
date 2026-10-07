# Controllo generale — 2 ottobre 2026

[Risultati](../../findings.md) · [Validazione](README.md) · [Letteratura](../../letteratura.md)

I ricalcoli confermano i numeri dei grafici correnti. Non è emerso un nuovo
errore aritmetico nel percorso mantenuto, nelle condizioni del contratto.
Sono stati corretti un problema nel decoder delle immagini e alcune
formulazioni troppo forti sui risultati biometrici storici. La letteratura
è stata ampliata con fonti primarie recenti e letture integrali.

Il controllo non rende il sistema una soluzione biometricamente validata
su nuovi utenti, né chiude la probabilità di errore del circuito. Queste
due verifiche restano il lavoro principale da completare.

Il seguito aggiunge un [confronto appaiato della preparazione UI](BIOMETRIA_UI_20261002.md)
sugli stessi dati, il ricalcolo di un record Head storico e un riferimento
su decomposizione di LUT grandi. Sono controlli distinti, senza nuove
misure FHE o di latenza. La [tabella delle campagne](../riproducibilita.md#quale-risultato-descrive-quale-versione)
esplicita quale versione sostiene ciascun risultato.

## Quale versione è stata controllata

Il runtime locale è TFHE-rs **1.8.1**, con selettore corretto, packing fino
a quattro cifre, risposta a tre LWE in base 15 e soglia del primo minimo.
L'identità del circuito è
`96269130d3ed5fca499bf5ea04d901760400e2007992dc6feffbd832f739e367`.
I 134 file della selezione runtime sono invariati durante questa passata.
Le nuove build e i gate usano **Rust 1.98.1**; non sono benchmark temporali.

La progressione, il confronto CKKS/TFHE e le misure dell'interfaccia di
settembre restano risultati delle rispettive versioni **1.7**. Il
[pilot 1.8.1](TFHE_181_MIGRATION.md) è distinto: né una nuova compilazione
né un test corretto trasformano i vecchi tempi in misure di questa build.
Tutte le modifiche di questo controllo sono locali. Il sito ospitato non
è stato verificato, aggiornato o sottoposto alle regressioni di sicurezza.

## Correttezza: cosa passa

| Controllo | Esito e significato |
|---|---|
| Python: client, demo, formati e modelli storici | 409 test raccolti, 384 eseguiti correttamente, 25 saltati con prerequisiti espliciti |
| Interfaccia JavaScript | 46 test passati |
| Rust mantenuto, build release con lock e dipendenze offline | 36 test del servizio e 83 del core passati; 4 FHE ignorati dalla suite ordinaria |
| Gate FHE core esplicito | Una nuova famiglia di chiavi, tre query N2: soglia inclusiva, rifiuto comune, rifiuto del primo minimo con soglie diverse |
| Servizio HTTP reale, nuova build | Un'altra nuova famiglia di chiavi, sette query corrette: tre scene N120 e casi N127,128,225,226 |
| Modello intero indipendente | Tutti i 4096 score; 53.218 coppie, 103.590 casi di soglia e tornei fino a N3374; geometria delle finestre e decoder |

Nel gate HTTP, l'ID225 esercita la terza cifra. Il caso N226 contiene un
pareggio e rifiuta il primo minimo per la sua soglia; non passa al candidato
successivo. Le tre scene N120 riusano le fotografie d'iscrizione e verificano
il servizio, non l'accuratezza su nuove acquisizioni. Sono state decifrate e
confrontate dieci query FHE su due famiglie nuove complessive. Una suite
finita non misura una probabilità di fallimento estremamente piccola.

I test storici che richiedono cache, transcript, binari e snapshot privati
sono ora indicati come saltati quando mancano questi input. Quando gli
originali sono presenti, le verifiche esistenti restano obbligatorie.
La suite FHE del vecchio servizio a una LWE è opt-in: non viene compilata
implicitamente dalla scoperta Python. Vedere [tests/README.md](../../tests/README.md).
Un test saltato non certifica l'esperimento storico.

Il controllo dei binding passa su una copia pulita degli esatti file
fissati. Nel checkout, un `__pycache__` preesistente fa rifiutare la
configurazione: è stato conservato. Non si è aggirato un hash differente
né cambiata l'identità del circuito per far passare il controllo.

## Risultati: cosa rimane valido

Il ricalcolo indipendente dei dati conferma:

- progressione corretta: mediane A28/finale **7,787/1,821 s** nelle condizioni
  del [grafico](../../output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md);
- [costo diretto del fix](../selector-direct-cost-20260920.md): **+6,87%** nel
  confronto appaiato primario, con differenza mediana delle coppie **0,121 s**;
- tutte le 18 celle del confronto CKKS/TFHE e il pilot 1.7/1.8.1;
- curva thread: quasi dimezzamento da 1 a 2 e da 2 a 4; da 4 a 16 il tempo
  diventa il **43%**, invece del 25% ideale. È scaling sulla singola macchina;
- osservazioni della demo dopo SSE: mediana click→risultato **2,130 s**,
  con foto già caricata, nelle tre osservazioni archiviate.

Non è emersa la necessità di rimisurare tutta la storia. Questi risultati
mantengono hardware, circuiti, scene, timer e limiti dichiarati; non sono
una previsione del tempo di qualunque CPU o della demo online.

Le [precisazioni storiche](../risultati/prototipi-e-correzioni.md#precisazioni-del-2-ottobre-2026)
correggono invece quattro punti della valutazione biometrica:

1. Separare foto o identità non basta quando soglia, PCA o scala vengono
   scelte usando il pool poi valutato. I primi risultati restano esplorativi.
2. La perdita di accuratezza della vecchia quantizzazione è relativa al
   dataset sintetico e alla distanza completa. La soglia attuale è sullo
   score senza norma della query: non è la stessa decisione a soglia fissa.
3. N persone e N template sono quantità diverse. Alcune curve storiche
   usano più template per persona; M10/M20 consumano entrambi le sole sei
   fotografie disponibili, senza misurare davvero 10 contro 20.
4. I dieci fold personalizzati e la PCA sul pool completo non costituiscono
   una replica del protocollo ufficiale dei benchmark 1:1.

Diario congelato, CSV, cache e risultati originari sono stati preservati.
La correzione del testo spiega i limiti del dato, senza cancellare il
percorso sperimentale o rendere inesistenti i fallimenti precedenti.

## Correzione nel caricamento delle immagini

Il decoder chiamava `Image.open` prima di limitare i formati supportati.
Con Pillow12.2.0, un EPS malformato presentato come JPEG bloccava questa
lettura: il comportamento è stato riprodotto in un processo locale isolato
con timeout, senza interrogare il sito live. Il caso coincide con
[CVE-2026-59203 nell'advisory ufficiale Pillow](https://github.com/python-pillow/Pillow/security/advisories/GHSA-pg7v-jwj7-p798).

Ora [enrollment.py](../../demo/dual_view/enrollment.py) passa l'elenco dei
decoder consentiti prima della lettura. La regressione verifica che il
parser EPS non venga chiamato. Le dipendenze e il lock fissano almeno
Pillow12.3.0, e la suite è stata eseguita con quella versione. L'ambiente
Python precedente è stato conservato; per adottare il fix occorre aggiornare
l'ambiente usato per l'avvio. Il circuito FHE è invariato.

Le guide delle nuove build indicano inoltre Rust1.98.1, che corregge un
[errore di compilazione delle vtable](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/).
Non è stato dimostrato che quel difetto abbia coinvolto gli eseguibili o i
tempi storici del progetto. La nuova compilazione e i gate passano.

## Letteratura e lavoro ancora necessario

Il [riesame bibliografico](../letteratura/versioni-e-verifiche.md) aggiunge
BioZKFHE, SMOOTHIE, Sorted Extended Bootstrapping, correttezza reattiva,
sanitizzazione recente, rare-event simulation, sicurezza CKKS e ANN/PIR.
Per ciascuna fonte distingue versione, testo effettivamente letto e
differenza dal contratto. Nella prima passata HEBI e SFRA erano accessi
parziali; il finale
di FDFB ricorsivo resta da confrontare integralmente col preproceedings.
Questo rafforza il posizionamento della tesi, senza provare una SOTA completa.

La continuazione dello stesso giorno ha recuperato e letto integralmente
[HEBI, manoscritto accettato NVA](../letteratura/testi-integrali/hebi.md):
preselezione protetta, decisione con decifrazione sulla terza parte,
0,12 ms per cluster PEKS e circa 10 s nel totale tabellare. È stato letto
anche [Liu, Informatica 2024](../letteratura/testi-integrali/liu-informatica.md),
verifica 1:1 con specifiche insufficienti per una replica del circuito.
SFRA e il finale FDFB rimangono da acquisire. Nessuna modifica ai risultati
o alle garanzie del runtime deriva da queste letture.

Le prossime verifiche sono definite. La continuazione biometrica dello
stesso giorno è riportata sotto:

- **Biometria:** completare il [protocollo](PROTOCOLLO_BIOMETRICO.md)
  includendo preparazione dell’interfaccia, provenienza e nuove sessioni.
  La prima verifica della regola in chiaro ha condizioni più circoscritte.
- **Rumore:** chiudere il [bilancio composto](RUMORE_COMPOSTO.md), dall'ingresso
  al decoder, comprese dipendenze e trasformazioni dei normalizzatori.
  Il bound condizionato del selettore non copre da solo questi passaggi.
- **Protocollo:** mantenere espliciti terminale fidato, galleria visibile al
  server e assenza di una sanitizzazione validata. La demo ospitata mette
  client e server sullo stesso host; non protegge i dati dall'operatore.
- **Riproducibilità:** mantenere ambiente, build e binding coerenti quando
  si adotta l'aggiornamento, conservando separati runtime e dati storici.

Questi limiti non invalidano i risultati misurati nelle condizioni dichiarate.
Definiscono ciò che serve per passare da una demo e una valutazione
sperimentale a garanzie più generali.


## Continuazione: prima verifica biometrica in chiaro

La [nuova galleria VGGFace2](BIOMETRIA_VGGFACE2_20261002.md) usa parametri
congelati e candidati condizionatamente separati dallo sviluppo. Il piano
con una foto d'iscrizione si ferma a 119/120 template senza sostituzioni.
Una variante uniforme con tre foto forma N120 e conserva gli stessi query:
110/120 iscritti corretti con una foto, 119/120 con tre; rispettivamente
1/128 e 2/130 sconosciuti ammissibili accettati. 497 query ammissibili
concordano con l'oracolo intero in un ricalcolo indipendente.

È una valutazione in chiaro su foto originali, non una nuova query FHE
o un test del resize/JPEG dell'interfaccia o della webcam. I falsi accessi
interi osservati esistono anche nel riferimento float. La soglia storica
mirava a FPIR 1%, non zero; questo piccolo test non certifica quel limite.
Manifest, fallimenti e denominatori restano espliciti; nessun tuning sul
test, modifica al circuito o alle figure dei tempi.
