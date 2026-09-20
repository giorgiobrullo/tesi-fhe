# Delivery del servizio con selettore pack4

Questa copia deriva dai sorgenti congelati della campagna pack4 del 20 settembre
2026. Il crate `selector_four_core_20260920` conserva il refresh 4/12 di B,
i due KS con correzione della media e la PFKS con finestra 1536±127.
Raggruppa le tre cifre dello score e le cifre ID/soglia non costanti in gruppi
di massimo quattro, agli offset 0/256/512/768. Le costanti pubbliche conservano
il ripristino originario. Il contratto resta primo minimo, precedenza al primo
ID nei pareggi, soglia inclusiva del vincitore e risposta cifrata 0/ID.

La preparazione aggiorna identità del servizio, configurazione, ledger del
client, ancore dei test e documentazione. Non cambia funzioni matematiche,
raggruppamenti o percorsi FHE del core della campagna. La ricevuta esterna
`DELIVERY_PREPARATION.json` e `SOURCE_DELTA.patch`, nella cartella superiore,
elencano ogni differenza e i digest dei sorgenti.

La PFKS interna di B è compatibile con questo stesso polinomio; il nuovo
envelope del servizio dipende invece da variante e digest del circuito.
Una vecchia chiave wire non è automaticamente riutilizzabile. Il controllo
del servizio usa una nuova famiglia e non esegue conversioni implicite.
La vecchia PFKS W287 ha una funzione diversa e resta incompatibile.

Modalità supportata: `public_parallel`, 16 thread, FFT Dif4/base1024; G4 viene
rifiutato. Input full51/low60, output tre LWE base15 a scala Delta59, galleria
da 1 a 3374 voci. Parametri, ammissione, riuso degli score, soglie e pareggi
mantengono il contratto della campagna. Il client rifiuta cifre e ID non canonici.

`configure.py --check` verifica le identità generate. Dopo qualsiasi modifica,
il root deve rigenerare i binding in questa delivery, compilare, verificare e
congelare il binario effettivo prima del gate di servizio. Target, chiavi e run
devono restare fuori da `runtime/`. `SOURCE_PINS.json` conserva i marcatori di
preparazione `compiled:false` e `executed:false`; gli esiti successivi sono
ricevute esterne, senza riscrivere i sorgenti congelati.

Il [contratto geometrico](REPAIR.md) è condizionale. La campagna, i test del
servizio e le prove formali hanno ambiti distinti. La preparazione non anticipa
esiti, tempi, adozione, sicurezza complessiva, circuit privacy o validità biometrica.
