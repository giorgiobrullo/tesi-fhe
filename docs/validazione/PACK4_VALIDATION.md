# Baseline con selettore corretto e packing a quattro cifre

Il packing raggruppa fino a quattro cifre per trasferirle insieme quando
si seleziona il vincitore di un confronto. L'[esempio con due candidati](../come-funziona-il-confronto.md)
segue queste cifre dal punteggio al risultato finale.

20 settembre 2026. Baseline locale adottata dopo correttezza, confronto appaiato,
regressione storica e collaudo del servizio. Il runtime selezionato è `runtime/`.
I risultati precedenti restano conservati nei rispettivi report datati.

Il refresh rigenera il controllo cifrato del selettore per aumentare il
margine disponibile. La configurazione 4/12 e le finestre ±63/±127 della
[correzione B](../../runtime/REPAIR.md) sono invariati.
Le cifre dello score e quelle non costanti di ID/soglia condividono gruppi
fino a quattro. Il limite impedisce la sovrapposizione del quinto payload.
La PFKS (*private functional key switching*) prepara ciascuna cifra in
un formato cifrato raggruppabile. La funzione e i byte della sua chiave
sono identici nelle due versioni confrontate.
Quattro termini modificano il rumore dell'accumulatore: per questo la geometria
è stata seguita da una nuova verifica FHE, senza sostituire chiavi o casi.

## Passaggio modificato

Score cifrati → estrazione delle cifre → torneo (confronto →
**selezione dei dati del vincitore**) → soglia → esito cifrato 0/ID.

Il confronto ha già prodotto la decisione cifrata. Il selettore deve
trasferire insieme score, ID e soglia del candidato scelto. Qui cambia
il raggruppamento delle cifre da trasferire, dopo che le costanti pubbliche
sono state riconosciute e tolte dal lavoro variabile.

## Prima e dopo

Il riferimento è **B, con il controllo del selettore già corretto**.
B aveva già le cifre pubbliche e il parallelismo; il nuovo intervento
riguarda solo il packing. Le tre cifre score, prima separate dai gruppi
ID/soglia, possono ora condividere gruppi fino a quattro con le altre
cifre variabili.

Esempio: un ramo richiede tre cifre score e una sola cifra ID variabile;
le altre cifre ID e la soglia sono già note. Il [pianificatore](../../runtime/core/src/public_digits.rs)
contiene questo caso.

| Operazione di quel selettore | Prima: B | Dopo: packing a quattro cifre |
|---|---|---|
| Preparazione PFKS | Quattro preparazioni, una per cifra. | Le stesse quattro preparazioni. |
| Gruppi | `[score₀, score₁, score₂]` e `[ID₀]`. | `[score₀, score₁, score₂, ID₀]`. |
| Rotazioni dei gruppi | Due. | Una. |
| Rigenerazione del controllo | Una rotazione di refresh. | La stessa rotazione di refresh. |

Per quel nodo, le rotazioni del selettore passano quindi da tre a due.
Il conteggio esclude il confronto che precede la selezione e il resto
della query. Con più cifre variabili cambiano il numero e la composizione
dei gruppi; quattro è il massimo per gruppo, non un risparmio fisso per
ogni nodo.

Si raggruppano componenti dei dati, non quattro persone. La preparazione
PFKS resta per cifra: il lavoro risparmiato è una rotazione ogni volta
che il nuovo packing elimina un gruppo. Il refresh che corregge il
controllo, la precisione dei punteggi e la regola del vincitore restano
invariati. Le verifiche e i tempi sotto sono quelli della campagna TFHE-rs
1.7; la configurazione mantenuta è nel [README del runtime](../../runtime/README.md).

## Verifica

Tre famiglie nuove: 90 coppie di correttezza, 18 coppie di riscaldamento e
108 coppie misurate. Tutte le 432 chiamate danno il risultato atteso, incluse
le scorciatoie pubbliche. Il lettore indipendente decifra 1.296 LWE finali e
verifica ID canonici e distanza stretta dalla mezza cella, sorgenti, chiavi,
conteggi, calendario e hash. I casi comprendono ID449/450/3374, parità,
soglia propria del vincitore, soglie miste e scorciatoie. Il pieno plaintext
degli input GLWE della campagna è vincolato dal codice e dagli hash, non
ridecifrato dal lettore: questo limite del verificatore resta esplicito.

L'ingresso storico salvato produce ID1 sia con B sia con pack4, usando la
stessa chiave storica corretta. La funzione di refresh che risolve il controllo
storico 341 è identica a quella già verificata in B; la geometria completa dei
quattro payload è verificata separatamente. Questo replay non è una nuova
famiglia indipendente né una misura di latenza.

83 test core e 36 test servizio passano; quattro test FHE storici restano ignorati.
Passano anche un test fixture e 32 controlli Python del client/configurazione.
Tre roundtrip reali CLI/HTTP restituiscono 1/0/0. L'envelope storico W287 viene
rifiutato con HTTP400 senza cambiare stato. Il servizio viene chiuso dal suo
controller. La PFKS interna B resta compatibile, mentre l'envelope pubblico
richiede la nuova identità di sorgente/circuito. Il ledger client è aggiornato.

## Tempi

Sui cinque scenari primari, 90 confronti appaiati: rapporto pack4/B
**0,952561993**, cioè **−4,7438% di tempo**. Intervallo bootstrap95% condizionato
alle tre famiglie osservate: **[0,948049442; 0,957387164]**. Mediane aggregate
**2,123361813 s per B e 2,010978417 s per pack4**; il rapporto appaiato non è
il rapporto di queste mediane. 83 coppie primarie su90 favoriscono pack4.
I cinque scenari migliorano fra1,95% e5,83%; il controllo secondario migliora4,92%.

Il timer comprende lo stesso calcolo cifrato completo; esclude chiavi,
cifratura, decifratura, serializzazione e HTTP. Nessun altro build/FHE è stato
lanciato in parallelo. È presente carico esterno: tutte216chiamate misurate
superano la soglia diagnostica20%di un core,76hanno finestre con copertura o
turnover di processi incerti. Tutte le durate sono mantenute. Il confronto è
condizionato a questa macchina, questo carico e queste famiglie; non dimostra
isolamento continuo. Il precedente +13,17% confrontava B con la versione
pre-fix: non viene combinato con questa nuova percentuale come misura diretta.

## Perimetro e continuità

Contratto invariato: primo minimo, parità al primo ID, soglia inclusiva del
vincitore e risposta cifrata0/ID. Parametri, Head, anchor, ammissione, wire a
tre cifre e G4 rifiutato restano invariati. Nessuna probabilità di fallimento,
correttezza universale, sicurezza complessiva o accuratezza biometrica segue
sulle basi di questa campagna finita. La prova formale composta rimane aperta.

La progressione storica corretta e il confronto CKKS/TFHE sono stati
rimisurati in campagne separate. Il [percorso corrente](../percorso-sperimentale-20260920.md)
include dati, grafici e finding tecnico; la documentazione della distribuzione
è allineata. Il finale ricostruito, la versione TFHE del confronto CKKS e
il runtime anchor/pack4 selezionato sono distinti: ogni numero mantiene il
proprio circuito e campione. Il runtime congelato resta invariato.
Le ricevute complete sono in `tmp/selector-overhead-optimization-20260920/`
nello spazio di ricerca locale. Nessun commit, caricamento o invio effettuato.
