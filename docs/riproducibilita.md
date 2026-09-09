# Riproducibilità e provenienza

Questa versione del repository distribuisce il codice della demo,
documentazione consolidata, esperimenti recenti e risultati scientifici
selezionati. Conserva separatamente gli archivi originali locali: non è una
copia integrale di tutte le prove e dei relativi ambienti di esecuzione.

## Materiale pubblicato

- Il [README](../README.md), i [risultati consolidati](../findings.md) e le
  [questioni aperte](../OPEN_QUESTIONS.md) descrivono contratto, conclusioni e limiti.
- I [pacchetti 17–26](../experiments/README.md) raccolgono sorgenti storici,
  lockfile, include pubblici, riepiloghi `RESULTS.json` e prove selezionate
  nelle rispettive cartelle `evidence/`.
- La [demo client/server](../demo/dual_view/README.md) usa il core del
  [pacchetto 22](../experiments/22_demo_composita/README.md). I suoi requisiti
  e le istruzioni di avvio sono nei README; modelli e dipendenze esterne
  richiedono il proprio ambiente.
- La [campagna comune del 9 settembre](../output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md)
  include figura e dati leggibili. Le osservazioni e i riepiloghi consentono
  di controllare le statistiche pubblicate; non contengono l'intera prova FHE.

I sorgenti ripetuti fra esperimenti sono snapshot dei programmi confrontati.
Sostituirli con l'ultima libreria cambierebbe la sorgente del risultato
storico. Le copie conservano i file incorporati e i propri identificatori;
i nomi storici non attestano una nuova misura nella posizione pubblicata.

## Cosa attestano manifest e controlli

`PROVENANCE.json`, `COPY_ORIGINS.json`, `EVIDENCE_ORIGINS.json` e
`PACKAGE_PINS.json`, dove presenti, identificano origini e impronte dei file.
I `RESULTS.json` distinguono risultati originali, controlli sulle copie,
stimatori e limiti. Un'impronta permette di confrontare i byte disponibili;
non dimostra da sola correttezza matematica, compilabilità su ogni ambiente
o correttezza dell'esecuzione originaria.

Verificare una copia per hash, eseguire test senza crittografia, ricompilare,
controllare risultati FHE con rumore e ripetere un benchmark sono attività
diverse. I pacchetti dichiarano quali siano state effettivamente eseguite.
In particolare, i controlli del client con rete e crittografia simulate non
sono una nuova qualificazione FHE. La preparazione del repository non ha
rieseguito i benchmark storici.

I grandi archivi di input/output cifrati, chiavi, replay e ricevute native
restano locali. Le tabelle pubblicate non consentono di ripetere da sole
le decifrature originali. Una nuova esecuzione richiede dipendenze compatibili,
nuove chiavi e un piano esplicito: i suoi risultati sono nuove osservazioni,
senza ereditare automaticamente la qualifica delle vecchie chiavi o revisioni.

## Dipendenze e copie parziali

I README indicano le chiusure dei sorgenti e le dipendenze esterne necessarie.
I crate registry, i modelli biometrici, le librerie compilate e i target
di build non sono vendorizzati nei nuovi pacchetti. Le piccole LUT binarie
incluse sono corpi pubblici deterministici, non chiavi o probe cifrati.

Il [pacchetto 24](../experiments/24_frontiere_common_mask_bgv/README.md)
contiene **estratti storici** common-mask e BGV, con dipendenze locali non
completamente chiuse. Serve a leggere le costruzioni e i risultati provati;
non è presentato come build autonoma portabile. Per il servizio integrato
il punto d'ingresso è il [pacchetto 22](../experiments/22_demo_composita/README.md).

Il [riepilogo pubblico della ricerca](../RESEARCH_STATE.md) conserva anche
il nome usato dal client immagini per trovare la radice del repository.
Non contiene il registro operativo locale né ne sostituisce le evidenze.

## Riferimenti agli archivi locali

Le cartelle originali `docs/archive/`, `docs/research-state/`, `docs/personal/`
e `tmp/` non fanno parte di questa selezione pubblica. Vi rimangono diari,
audit completi, rapporti personali e ricevute dei run. I percorsi citati
come *locali* nella documentazione e nei manifest sono identificatori di
provenienza, non collegamenti a file scaricabili dal repository pubblico.
Gli originali e i tentativi falliti sono conservati senza eliminarli.

Alcuni rapporti originali copiati mantengono intenzionalmente il testo e
i collegamenti relativi della posizione d'origine. In particolare:

- [Rapporto originale della composizione](../experiments/22_demo_composita/evidence/ORIGINAL_RISULTATI.md)
  rinvia a sottoarchivi quali `service-audit/`, `composite/`, `tetris/` e
  ricevute di lancio/verifica del browser, disponibili nell'archivio locale.
- [Rapporto originale CKKS](../experiments/23_ckks_ottimizzazioni/evidence/ORIGINAL_COMBINED_RESULTS.md)
  rinvia a `COMBINED_THREE_KEY_RESULT.json`, `THREE_KEY_FREEZE.json` e
  `RUN_PLAN.json` della posizione originale.

Anche tre rapporti storici in `benchmark/results/` rinviano al vecchio
`status.md`, che resta un registro operativo locale.

Quei collegamenti storici non si risolvono dalla cartella pubblicata.
Il testo rimane identico per preservare le impronte dichiarate: per la
navigazione pubblica usare README, `RESULTS.json` e le prove selezionate
del pacchetto. Un riepilogo pubblico non viene presentato come equivalente
al rapporto integrale o al replay degli originali mancanti.

## Limiti da preservare nella lettura

Le riduzioni di tempo appartengono ai rispettivi confronti appaiati e non
si sommano. Campioni correlati, chiavi limitate e carico esterno conservano
il proprio ruolo nelle conclusioni; capacità rappresentativa, correttezza
FHE osservata, accuratezza biometrica e probabilità formale di errore
rimangono affermazioni distinte.

La figura del 9 settembre mantiene due sezioni con uno stacco di contratto
e dimensioni, barre interquartili e tempo logaritmico. Il precedente errore
di Head generale rimane irrisolto anche dopo i nuovi risultati corretti:
conservarne l'indicazione è parte del metodo, non una scelta grafica opzionale.
