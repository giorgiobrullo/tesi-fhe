# Verifica storica del runtime e della demo, 18 settembre 2026

Questa pagina conserva i controlli della revisione del 18 settembre, precedente
alla riparazione del selettore. Il [runtime mantenuto](../runtime/README.md)
ha ora sorgenti e binding diversi: la sua qualifica è documentata separatamente
in [PACK4_VALIDATION.md](validazione/PACK4_VALIDATION.md).
I test, gli accessi e gli hash sotto non vengono trasferiti alla nuova revisione.
Gli snapshot e i risultati in `experiments/` conservano il proprio ambito.

## Correzioni verificate

La galleria ignora le letture precedenti a una modifica e attende uno stato
aggiornato. Il ritorno alla pagina dalla cache del browser mantiene un solo
ciclo di aggiornamento. Chiudere la fotocamera durante l'avvio non la riattiva.
Il backend Rust rifiuta le richieste dirette del browser e gli Host estranei
al servizio locale: le pagine passano attraverso i rispettivi servizi Python.
Questi cambiamenti correggevano difetti riprodotti senza cambiare gli algoritmi
FHE della revisione del 18 settembre.

## Controlli eseguiti il 18 settembre

| Controllo | Risultato |
|---|---:|
| Test Python di interfaccia, protocollo, pipeline e binding | 66 passati |
| Test Rust del servizio, inclusi CLI e parser HTTP | 36 passati |
| Test ordinari del core Rust | 78 passati |
| Regressioni JavaScript su galleria, polling e fotocamera | 7 passate |
| Verifiche CLI sul binario compilato | 6 passate |
| Regressione FHE mirata con chiavi nuove in memoria | 3 query corrette |
| Accessi dal browser con immagini e cifrati reali | 3 esiti corretti |

Cinque delle sette regressioni JavaScript falliscono sui sorgenti precedenti.
Sono test deterministici delle risposte asincrone, senza dipendenze aggiuntive;
la versione Node.js usata è 26.8.1. Comandi nella [guida ai test](riproducibilita.md#eseguire-i-test-della-demo).

Le suite Rust sono eseguite in release con Rust 1.93.1 su macOS ARM64:
ottimizzazione 3, una unità di generazione del codice, nessun LTO né PGO e
CPU generica. La compilazione conserva warning nei componenti sperimentali.
Gli 80 test con `opt-lut-cache` e `opt-owned-pfks` erano già passati sulla
precedente revisione del servizio. Allora il core era byte-identico e quei
test non furono ripetuti; questa identità non riguarda il selettore nuovo.

## Percorso completo

Il browser ha usato immagini sintetiche locali DigiFace, i modelli biometrici
locali e una nuova famiglia di chiavi per questo binario. Sono verificati
iscrizione, modifica del nome e della soglia, rimozione, immagine non valida
e blocco dell'accesso con galleria vuota.

Due iscrizioni dello stesso template con soglie `[273,273]` consentono l'accesso.
Con soglie `[-4096,273]` l'accesso è negato: il primo vincitore non supera la
propria soglia e la seconda iscrizione non lo sostituisce. Dopo la rimozione
del primo iscritto e il riavvio dei tre servizi, l'accesso al restante è
consentito. Galleria e registro restano identici al riavvio; il client
ricarica la chiave di valutazione. Tre richieste dirette al backend con
origine browser o Host estraneo ricevono 403 senza modificare la galleria.

Il permesso fotocamera negato è simulato nel browser; le chiusure durante
l'avvio sono verificate dai test JavaScript. Nessuna fotocamera fisica è stata
aperta. Le prove su immagini non misurano l'accuratezza biometrica.

## Limiti della prova FHE

La regressione nativa usa chiavi nuove in memoria, 16 thread, FFT Dif4/base1024
e modalità `public_parallel`. Due template identici hanno punteggio -1:
soglie `[-1,-1]` restituiscono ID1, `[-2,-2]` restituiscono zero e `[-2,100]`
restituiscono zero. Verifica primo minimo, soglia inclusiva e rifiuto del
vincitore senza scegliere un'alternativa più permissiva.

Quattro test FHE sono ignorati dalla suite ordinaria; questa regressione è
eseguita separatamente, le tre diagnostiche storiche restano distinte.
I test e gli accessi dal browser non sono un benchmark né una dimostrazione
generale di correttezza o probabilità di fallimento.

La diagnosi del 19 settembre spiega il caso storico chiamato «Head generale»:
l'indirizzo 341 supera la finestra 300…340 del selettore e altera i payload,
producendo ID75 anziché ID1. Le 127 estrazioni Head di quella istanza sono
corrette. Il replay separato della baseline del 19 settembre restituisce ID1;
nel medesimo nodo osserva indirizzo 318. Questo pass non dimostra una robustezza
generale né identifica una singola modifica responsabile del cambio di
ciphertext. Diagnosi, replay e riparazione restano prove distinte nel
[registro della riparazione](validazione/SELECTOR_REPAIR_VALIDATION.md).

## Identità della revisione verificata

- `service_source_sha256`: `d09c3e89247c8bb960ec183bc229c6f5fe0e2887b8747c585a9efaf140420c3c`.
- `core_source_sha256`: `9f6722cad478d125a9943a602c95c83ec934046a33b5f266bbb28b8c7fb2eb04`.
- `circuit_sha256`: `a081bc8b262c2f61d650a58ec7f45e842ab0adbc335a3375b0f4b7af1694842e`.
- `compiled_binary_sha256`: `04527805626a80489f50c239491baebb493e48b1a6804d2b93a0536fcd0777ae`.

Le quattro impronte sopra identificano la revisione storica verificata.
Il [manifest dei sorgenti attuale](../runtime/SOURCE_PINS.json) identifica
invece la revisione distribuita oggi. I flag di preparazione di un manifest
non sostituiscono le ricevute dei test e delle esecuzioni della stessa versione.
