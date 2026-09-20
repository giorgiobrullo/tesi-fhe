# Tesi-FHE: identificazione facciale con query cifrata

Tesi sperimentale sul riconoscimento facciale 1:N con crittografia omomorfica.
Il client estrae l'embedding di un volto e lo cifra; il server lo confronta
con una galleria e restituisce un risultato cifrato. Il client scopre
l'identità corrispondente, oppure che nessun accesso è consentito.

Il lavoro segue due filoni: la qualità del riconoscimento dopo la quantizzazione
e il costo della ricerca sul dato cifrato. Gli esperimenti partono da PCA,
descrittori locali e reti preaddestrate, poi confrontano i circuiti Concrete,
TFHE-rs e CKKS. L'implementazione attuale usa TFHE-rs.

## Come funziona

Per ogni template della galleria il server calcola il punteggio
`score_i(q) = ||g_i||² − 2〈g_i,q〉`. Sceglie il primo minimo e controlla
la soglia associata a quel template:

```text
k = primo argmin_i score_i(q)
risultato = k + 1, se score_k(q) <= T_k
            0, altrimenti
```

La risposta contiene soltanto l'ID o zero, codificato in tre cifre LWE in
base 15. I pareggi favoriscono il primo indice; la soglia di un altro
iscritto non può autorizzare la richiesta.

### Modello di fiducia

Il client è fidato e gestisce acquisizione, embedding, quantizzazione e chiavi.
Il server segue il protocollo ma può cercare di ricavare informazioni dai
messaggi: conosce galleria e soglie, mentre query e risposta sono cifrate.
Il client deve rispettare i vincoli numerici degli input. Il prototipo non
fornisce una prova generale del rumore composto o sicurezza contro client
malevoli; questi problemi sono descritti nelle [questioni aperte](docs/limiti.md).

## Demo

La demo offre una pagina server per iscrivere e gestire i volti e una pagina
client per richiedere l'accesso da foto o fotocamera. La galleria parte vuota.

Per preparare l'ambiente Python:

```sh
uv sync --locked --python 3.12
```

Seguire la [guida della demo](demo/dual_view/README.md) per i requisiti,
la compilazione del motore Rust, i modelli, le chiavi e l'avvio.

## Implementazione selezionata

Il motore è in [runtime/](runtime/README.md). Usa TFHE-rs 1.7, estrazione
Head/PFKS, un torneo per il minimo e selezione finale a soglia. La versione
attuale rigenera il controllo del selettore e raggruppa fino a quattro cifre
per ridurre il numero di operazioni. Il servizio usa 16 thread e una FFT fissa.

## Risultati

![Evoluzione del tempo di calcolo cifrato](output/figures/progressione-fhe/selettori-corretti-20260920/progressione.png)

Nel confronto comune a 127 iscritti e 512 coordinate, il tempo mediano del
calcolo cifrato passa da **7,79 s a 1,82 s**. La misura è su Apple M4 Max,
con 16 thread, ed esclude embedding, cifratura e comunicazione HTTP.
Il pannello dei primi prototipi usa un compito e dimensioni diversi.
[Dati e metodo del grafico](output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md).

## Struttura e lettura

- [Percorso sperimentale](docs/percorso-sperimentale-20260920.md): domande, scelte e risultati dello sviluppo.
- [Findings](findings.md): risultati e riferimenti alle singole prove.
- [Letteratura](letteratura.md): sistemi precedenti e confronto delle loro ipotesi.
- [Esperimenti](experiments/README.md): sorgenti delle diverse versioni, inclusi i tentativi senza miglioramenti.
- [Benchmark](benchmark/): valutazioni dei modelli e dei circuiti; [core/](core/README.md) contiene le utility Python dei prototipi.
- [Riproducibilità](docs/riproducibilita.md): ambiente, test, dati e provenienza delle misure.
