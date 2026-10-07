# Limiti e sviluppi futuri

Aggiornato il 5 ottobre 2026. Elenco unico delle domande aperte e delle prove
necessarie, collegato al [percorso](percorso-sperimentale.md) e al
[mappa degli esperimenti](../experiments/README.md).

## 1. Probabilità di fallimento del circuito composto

Qual è la probabilità di un'uscita errata su nuove chiavi e input ammessi?
Serve un limite per la composizione Head/BR/KS/PFKS, accumulatore a quattro
payload, torneo e decoder, tenendo conto delle dipendenze fra errori.
I margini geometrici ±63/±127 sono condizionati ai residui; né i test finiti
né il `p_fail` di una singola primitiva forniscono quel limite.

La prova deve usare parametri, scale e indirizzi effettivi e giustificare le
premesse su sampler, generatore casuale e calcolo floating point. Le
[mappe del normalizzatore](../experiments/20_normalizzatori_carry/evidence/NORMALIZER_ERROR_MAPS.md)
vincolano vettori salvati, non la distribuzione su chiavi future.
[Diagnosi e correzione del selettore](selector-repair-20260920.md).

La [mappa del rumore](validazione/RUMORE_COMPOSTO.md) raccoglie i passaggi,
le premesse e i budget da giustificare. Le identità e i limiti condizionati
dei singoli modelli vanno distinti dalla garanzia numerica della baseline
mantenuta, ancora aperta. Un budget sufficiente non chiuso non dimostra,
da solo, un ID finale errato.

## 2. Accuratezza biometrica e validità degli input

Quanto incidono embedding, quantizzazione, soglie e fusione sugli errori
open-set? Servono dati indipendenti, impostori e condizioni di acquisizione
definite; TFHE e CKKS vanno confrontati sulla stessa regola e sugli stessi dati.
La correttezza aritmetica su scene sintetiche non misura questi errori.

La [prova del 2 ottobre](validazione/BIOMETRIA_VGGFACE2_20261002.md) e il
[confronto della preparazione UI](validazione/BIOMETRIA_UI_20261002.md)
forniscono un primo controllo circoscritto, con iscrizione a tre foto,
falsi accessi e denominatori espliciti. Il confronto UI usa una coorte
già consultata: non chiude la generalizzazione a nuove gallerie o webcam
e non serve a scegliere una soglia su quegli stessi errori.

La [prova Georgia Tech del 5 ottobre](risultati/selettore-e-generalizzazione.md#georgia-tech)
aggiunge 50 persone, con 20 iscritti e 30 sconosciuti. In ciascuna delle due
condizioni riconosce 20/20 iscritti e accetta 1/30 sconosciuti. Le condizioni
usano le stesse persone: non sono due campioni indipendenti. È una verifica
biometrica in chiaro; non qualifica webcam, latenza FHE o un tasso di falsi
accessi dell'1%. Rimangono necessarie sessioni e popolazioni indipendenti.

Come attestare che un probe ammesso provenga dall'acquisizione autorizzata?
Prove di intervallo e norma verificano predicati aritmetici, non origine,
presenza fisica o consenso. Occorrono un modello degli attacchi, inclusi
quelli adattivi sull'output 0/ID, e difese verificabili per quel modello.

## 3. Integrità, freschezza e autorizzazione del servizio

Come legare richiesta, chiave, galleria, soglie e risposta, impedendo replay
e accessi non autorizzati? Serve un protocollo con avversari espliciti,
autenticazione, revoca e freschezza verificabili. La cifratura della query
non autentica il risultato; resta da stabilire anche la circuit privacy.
Un servizio funzionalmente corretto non prova sicurezza contro parti malevole.

## 4. Ripetibilità dei tempi e generalizzazione

Come variano i tempi fra chiavi, sessioni, macchine, taglie e carichi?
Servono repliche su queste unità, con intervalli coerenti con l'indipendenza
effettiva. Gli intervalli attuali sono condizionati alle famiglie osservate;
il carico esterno limita l'interpretazione. La capacità di rappresentare un
ID non dimostra prestazioni a quella taglia. Cattura e utenti concorrenti
richiedono misure distinte dal core.
[Metodo e limiti del confronto diretto](selector-direct-cost-20260920.md).

## 5. Possibili sviluppi e prove necessarie

| Domanda | Evidenza discriminante |
|---|---|
| Una politica basata sul lavoro pubblico per nodo migliora lo scheduling? | Conteggi reali dopo i tagli ID/soglia, poi confronto completo; le politiche DAG già provate non bastano. |
| Un worker client persistente evita costi rilevanti? | Profilo separato di avvio, deserializzazione, cifratura e decifratura, seguito da confronto end-to-end. |
| Il predicato terminale con sentinel pubblico si può specializzare? | Verifica di dominio, riporti, soglia inclusiva e rumore, poi tempo della query; riguarda un solo predicato. |
| Un produttore Tetris con meno conversioni è vantaggioso? | Correttezza delle interfacce e costo di tutte le conversioni, prima sul componente e poi sulla query. |
| Il circuito custom è utile su GPU? | Prototipo CUDA compilato, correttezza FHE e tempi comprensivi di conversioni e trasferimenti. |

La specializzazione terminale [raw9](risultati/selettore-e-generalizzazione.md#raw9)
è stata provata: lo stadio finale migliora, ma il beneficio sulla query
completa resta inconclusivo. Il [profilo PFKS degli ID](risultati/selettore-e-generalizzazione.md#pfks-id)
ha invece ridotto la priorità di una cache: quel lavoro è già poco costoso,
e non è stata implementata una cache da cui dedurre un guadagno.

Precedenti: [DAG](../experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md),
[Tetris](../experiments/25_tetris/README.md), [CPU](../experiments/19_runtime_cpu/README.md)
e [servizio](../experiments/22_demo_composita/README.md).

## 6. Filoni alternativi

Common-mask/Joint4, BGV e LFBS richiedono di risolvere ostacoli di formato,
rumore, conversione o scaling. Il caso BGV N8 corretto non dimostra un vantaggio di latenza;
Joint4 N16 non dimostra scaling a N127. Una nuova prova deve cambiare una
premessa concreta delle costruzioni già studiate. Il CKKS ottimizzato resta
un valutatore con contratto distinto. Gli esiti negativi non dimostrano
l'impossibilità di un'intera famiglia di metodi.

Precedenti: [CKKS](../experiments/23_ckks_ottimizzazioni/README.md),
[common-mask e BGV](../experiments/24_frontiere_common_mask_bgv/README.md).

Le analisi di [riuso del GLWE](risultati/selettore-e-generalizzazione.md#glwe) e
[CBS](risultati/selettore-e-generalizzazione.md#cbs) richiedono una rappresentazione
compatibile del vincitore e dei suoi dati. Il mancato innesto diretto è un
limite delle proposte esaminate; non sono nuovi prototipi FHE falliti.
