# CKKS/TFHE rimisurato con selettore corretto

Campagna del 20 settembre 2026, Apple M4 Max, 16 thread. [PNG per email](confronto-ckks-tfhe-selettore-corretto-20260920-email.png), [PNG completo](confronto-ckks-tfhe-selettore-corretto-20260920.png), [SVG](confronto-ckks-tfhe-selettore-corretto-20260920.svg), [PDF](confronto-ckks-tfhe-selettore-corretto-20260920.pdf).

Sei scene N64/N128: soglia uniforme allineata, uniforme generale e soglie
miste. La versione TFHE è il circuito CPU del confronto storico, ricostruito
con il selettore corretto. Non è la baseline anchor/pack4 più recente.
CKKS conserva binario OpenFHE 1.5.1 e configurazione balanced-v3 qualificati.
Le fixture pubbliche sono le stesse del confronto precedente; tempi e chiavi
provengono dalla nuova campagna. Non è applicato alcun fattore ai vecchi tempi.

## Risultati e metodo

216/216 query corrette: 162 misurate e 54 warmup. TFHE supera anche 30 query di gate
su due nuove famiglie; un lettore indipendente decifra tutti i 90 input GLWE,
le 144 uscite TFHE del confronto e ricontrolla il gate. Impone cifre canoniche,
ID attesi e margini stretti. CKKS usa sei nuovi contesti; le famiglie TFHE
sono due, riusate nei tre blocchi in ordine 1/2/1.

Per ogni blocco/scena, CKKS è la mediana di tre query. TFHE è la media
aritmetica delle mediane di tre query prima e dopo CKKS. Le barre mostrano
la mediana dei tre blocchi e i baffi il loro minimo/massimo, non intervalli
di confidenza. A N128/general: CKKS 3,410900 s, TFHE 2,603882 s. Non si confondono
questi estimatori con mediane aggregate di altre campagne.

Il timer comprende il calcolo cifrato completo ed esclude chiavi, cifratura,
decifratura, modello e HTTP. Tutti i processi sono seriali. Il carico esterno
campionato resta nel manifest; i campioni non dimostrano isolamento continuo.
Nessun campione è escluso in base al tempo o alla correttezza.

CKKS restituisce uno scalare approssimato che il client arrotonda. TFHE
restituisce tre cifre discrete base 15. Le decisioni osservate non equiparano
formato, leakage, precisione arbitraria, circuit privacy o garanzie globali.
Questa campagna non è una misura biometrica o un primato SOTA.

## Correzione trasparente del verificatore

L'auditor congelato prima delle chiavi si è fermato dopo 12 uscite perché
imponeva che la durata monotona Rust Instant fosse contenuta nella differenza
fra due timestamp SystemTime. È un confronto non garantito fra clock diversi.
Una copia revisionata dopo le misure rimuove soltanto quel vincolo, conserva
ordine UTC, durate positive, hash e decifrazioni, e registra entrambe le durate.
Il replay V2 sugli stessi dati passa 144/144 più il ricontrollo del gate di 30.
Il report fallito, sorgente originale, patch, due sintetici e freeze separato
restano conservati. Nessuna nuova chiave/query, tolleranza numerica selezionata
a posteriori o modifica alle misure. Il massimo scarto positivo era 43.375 ns.

## Provenienza

[samples.csv](samples.csv) contiene tutte le 216 query, warmup inclusi;
[blocks.csv](blocks.csv) contiene le 18 celle. [SOURCE_PINS.json](SOURCE_PINS.json)
lega audit, freeze, analisi, log, CSV e figure. L'esito del controllo visivo
successivo è in [PUBLICATION.json](PUBLICATION.json). Il generatore ricontrolla
ogni riga dei CSV contro i log e ricalcola mediane/range prima del rendering.

La campagna completa, inclusi cifrati e chiavi locali esclusi da questo export,
è `tmp/ckks-tfhe-selector-repaired-20260920/` nello spazio di ricerca.
Il report finale effettivo è `TFHE_FINAL_AUDIT_V2.json`; quello senza V2
conserva il fallimento del primo verificatore. I dati originali del 7 settembre
restano immutati nella loro cartella. La nuova figura è stata controllata
anche renderizzando il PDF in PNG: nessun testo tagliato o sovrapposto.

La copia pubblica di SOURCE_PINS sostituisce i percorsi personali con identificatori
di archivio. PUBLICATION conserva l'hash dell'originale congelato; il
[registro delle copie pubbliche](../../../../docs/publication-provenance-20260920.json)
distingue le due impronte. Le osservazioni e le figure sono invariate.
