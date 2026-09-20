# Baseline con selettore corretto e packing a quattro cifre

20 settembre 2026. Baseline locale adottata dopo correttezza, confronto appaiato,
regressione storica e collaudo del servizio. Il runtime selezionato è `runtime/`.
I risultati precedenti restano conservati nei rispettivi report datati.

Il refresh 4/12 e le finestre ±63/±127 della correzione B sono invariati.
Le cifre dello score e quelle non costanti di ID/soglia condividono gruppi
fino a quattro. Il limite impedisce la sovrapposizione del quinto payload.
La funzione e i byte della chiave PFKS sono identici nei due bracci confrontati.
Quattro termini modificano il rumore dell'accumulatore: per questo la geometria
è stata seguita da una nuova verifica FHE, senza sostituire chiavi o casi.

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
