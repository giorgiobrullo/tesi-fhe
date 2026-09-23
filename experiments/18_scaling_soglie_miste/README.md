# 18 - Gallerie più grandi e soglie diverse

L'[esperimento 17](../17_head_pfks_tfhe17/README.md) aveva un servizio che
sceglieva fra **127 candidati** e usava **la stessa soglia per tutti**.
Ogni candidato aveva uno score cifrato: più basso significa più vicino.
Il server restituiva l'ID del migliore se il suo score non superava la soglia;
altrimenti restituiva zero. Qui non cambiamo questa regola. Verifichiamo
quali modifiche servono per usarla con altre gallerie e altre soglie.

| Domanda | Cosa cambia |
|---|---|
| E se la galleria ha 200 voci? | Il servizio accetta un numero variabile di candidati. Due cifre in base 15 bastano ancora per l'ID: codificano fino a 224, oltre allo zero di rifiuto. |
| E se le voci diventano 225 o più? | Serve una **terza cifra dell'ID**. Per esempio, 225 si scrive `[0, 0, 1]` in base 15. Questo allarga gli ID rappresentabili fino a 3374; non aggiunge precisione agli score. |
| E se la soglia comune è diversa da quelle gestite dalla prima versione? | Il servizio ricava dalla galleria l'intervallo ammesso per gli score e sceglie come applicare quella soglia. Le condizioni numeriche sugli ingressi restano controllate. |
| E se ogni iscritto ha una soglia propria? | Il torneo deve portare avanti **score, ID e soglia dello stesso candidato**. Solo dopo aver scelto lo score minimo controlla la soglia che lo accompagna. |

L'ultima riga è la più facile da sbagliare. In questo esempio illustrativo,
ID 1 ha score **21** e soglia **20**; ID 2 ha score **26** e soglia **30**.
Vince ID 1 perché `21 < 26`, ma `21 > 20`, quindi la risposta è **0**.
ID 2 passerebbe la propria soglia, ma non diventa il vincitore. A parità
di score resta il primo candidato nell'ordine della galleria. La soglia
è inclusiva: uno score uguale alla propria soglia passa.

L'«intervallo degli score» della tabella non è una misura delle foto:
è il limite numerico che il servizio deduce dai template pubblici della
galleria e dai vincoli sugli ingressi. La prima versione collocava gli
score in una finestra legata alla soglia comune per sfruttare un controllo
finale più semplice. La nuova variante gestisce anche una soglia comune
fuori da quella disposizione. È un'estensione degli input ammessi,
non una modifica della regola di riconoscimento.

Il motore riceve il vettore della foto cifrato e i vettori iscritti
pubblici; restituisce soltanto `0/ID` cifrato. **Head** estrae le cifre
degli score; **PFKS** prepara le cifre che il selettore trasferisce nel
torneo. La [guida con due candidati](../../docs/come-funziona-il-confronto.md)
mostra il calcolo completo. Le cifre dello score sono in base 16; le cifre
dell'ID sono in base 15: sono due rappresentazioni distinte.

## Varianti

| Variante | Quale limite rimuove |
|---|---|
| [Galleria variabile](source/fast-core-scaling-20260906/core/README.md) | Da 1 a 224 voci, due cifre ID; mantiene la disposizione originaria degli score e una soglia per tutti. |
| [Soglia comune generale](source/fast-core-uniform-20260906/core/README.md) | Da 1 a 224 voci; ammette anche altre posizioni della soglia rispetto all'intervallo degli score. |
| [Terza cifra ID](source/fast-core-wide-id-20260906/core/README.md) | Fino a 3374 ID rappresentabili, sempre con una soglia comune. |
| [Soglie individuali](source/fast-core-mixed-20260906/core/README.md) | Tre cifre ID e soglia conservata insieme allo score del vincitore. |

Il [controllo A126 a tre cifre](source/fast-core-wide-id-20260906/older-control/README.md)
è un adattamento esplicito, distinto dall'A126 invariato fino a N128.
Le varianti M usano input nativi full51/low60; A126 e R3 usano full52/low60.
Le risposte a tre cifre si ricostruiscono come `low + 15*middle + 225*high`.

Per leggere le estensioni nell'ordine, seguire le quattro righe della
tabella. I README annidati descrivono API, formati e conteggi delle copie
storiche TFHE-rs 1.7.0 e sono conservati con i relativi sorgenti. Non sono
istruzioni per il servizio attuale, descritto nel
[README del runtime](../../runtime/README.md). Nei risultati, **M** indica
la linea Head/PFKS, **M3** la variante con tre cifre ID; **A126** è il
riferimento precedente e **A126_3** il suo adattamento esplicito a tre cifre.

## Risultati e limiti

La campagna di scaling usa tre chiavi e 17 taglie fino a N224. Alle 15 taglie
condivise fino a N128, M riduce il tempo del **25,60–50,97%** rispetto ad A126
invariato. A N127 le mediane M/A126 sono **3,031/6,115 secondi**.
Campagna e controllo preliminare producono 1272 uscite corrette e 12
uguaglianze seriale/parallelo; R3 è un controllo separato.

Il pilot più largo confronta M3 con A126_3 a N224/225/256/512/1024 su una
nuova chiave: due coppie di riscaldamento escluse e quattro misurate per
taglia. Tutte le **20/20 coppie** favoriscono M3, con riduzioni geometriche
appaiate del **50,45–52,44%**. A N1024 le mediane sono **23,451/49,062 secondi**;
passano 60 uscite complete. Non c'è un intervallo tra chiavi per questo pilot.

I controlli di correttezza per soglie generali, ID larghi e soglie miste
sono separati e usano tre chiavi. Le soglie estreme includono scorciatoie
pubbliche. Capacità 3374, casi FHE del core fino a 1024 e controlli HTTP
fino a 225 sono evidenze diverse. I tempi conservano carico esterno e non
misurano ogni configurazione di soglie, la latenza web o una probabilità
formale di errore. [Dati e risultati](RESULTS.json).

## Compilazione

Ogni variante ha un runner in `candidate/Cargo.toml` e una libreria in `core/`.
Servono Rust e le dipendenze del lockfile, fra cui TFHE-rs 1.7.0. Per la
variante a soglie miste, da questa cartella:

```sh
cargo build --release --locked \
  --manifest-path source/fast-core-mixed-20260906/candidate/Cargo.toml \
  --target-dir .local/target-mixed
```

Le API e i test mirati sono descritti nei documenti delle varianti.
Per il servizio integrato partire dalla [demo 22](../22_demo_composita/README.md).

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
