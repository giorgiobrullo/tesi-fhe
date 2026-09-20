# Questioni aperte - exact 0/ID

Aggiornamento della baseline pack4 e dei suoi limiti: 20 settembre 2026.
I [risultati consolidati](findings.md) e gli
[esperimenti numerati](experiments/README.md) descrivono ciò che è stato
provato. Questa pagina descrive i problemi ancora aperti e le prove utili a
valutare possibili miglioramenti.

- [Rumore composto e robustezza del selettore](#1-probabilità-di-fallimento-del-circuito-composto)
- [Accuratezza biometrica e input](#2-accuratezza-biometrica-e-validità-degli-input)
- [Sicurezza del servizio](#3-integrità-freschezza-e-autorizzazione-del-servizio)
- [Ripetibilità dei tempi](#4-ripetibilità-dei-tempi-e-generalizzazione)
- [Possibili sviluppi](#5-possibili-sviluppi-e-prove-necessarie)
- [Filoni alternativi](#6-filoni-alternativi)

## 1. Probabilità di fallimento del circuito composto

La [baseline pack4](PACK4_VALIDATION.md) mantiene la correzione B e raggruppa
fino a quattro payload. Le prove di correttezza, il confronto appaiato e il
collaudo del servizio sono conclusi; i margini geometrici ±63/±127 restano
condizionati agli indirizzi effettivi. Non dimostrano la coda del rumore
della somma di quattro payload o del torneo completo.

Manca una giustificazione completa della distribuzione e della coda del
rumore realmente prodotto da Head/BR/KS/PFKS, delle dipendenze fra campioni e
della loro composizione nel torneo e nel decoder terminale. Le mappe carry-v2
hanno verifiche dell'intero dominio su tre chiavi e limiti deterministici
condizionati ai vettori salvati; non danno una probabilità sulle chiavi future.
Anche il `p_fail` di una primitiva di catalogo e un maggior margine nominale
non coprono automaticamente il circuito raw composto.

La prova dovrà riferirsi al sorgente e ai parametri effettivi, agli indirizzi
raggiungibili, alle scale, ai consumatori e alle dipendenze introdotte dalle
operazioni lineari. Restano da vincolare le premesse effettive del sampler e
del runtime: percorso eseguito, stato floating point, generatore casuale e
catena dalla generazione delle chiavi al circuito. Le analisi condizionali
del sampler coprono solo una parte di questo percorso. Un eventuale cambio
di parametri richiederà una nuova verifica delle premesse e della prova.

Il fallimento storico chiamato «Head generale», ID75 invece di ID1 nel
primo tentativo del 9 settembre, ha ora una causa localizzata. Nel nodo
`merge/0/37` l'indirizzo 341 esce dalla finestra 300…340 del selettore e
mescola le cifre; le 127 estrazioni Head e i confronti ternari dell'istanza
sono corretti. Il controfattuale fissato 341→340 restituisce ID1, senza
costituire una riparazione generale. Il successivo 45/45 storico rimane
un'osservazione distinta, non la spiegazione del fallimento.

Il replay della baseline del 19 settembre sulla stessa famiglia e sugli
stessi input restituisce ID1 e osserva indirizzo 318 nel nodo interessato.
Il diverso ciphertext intermedio non permette di attribuire il cambio a una
sola ottimizzazione. Restano aperti la robustezza su altre chiavi e il limite
di fallimento del circuito composto. Il selettore con refresh e nuova
finestra ha il [rapporto storico B](SELECTOR_REPAIR_VALIDATION.md);
pack4 ha successivamente superato una propria campagna. Nessuna delle due
qualifiche empiriche eredita una garanzia generale dal replay o dalle suite
delle revisioni precedenti.

Riferimenti: [normalizzatore e limiti](experiments/20_normalizzatori_carry/README.md),
[mappe di errore osservate](experiments/20_normalizzatori_carry/evidence/NORMALIZER_ERROR_MAPS.md),
[campagna comune e fallimento conservato](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).

## 2. Accuratezza biometrica e validità degli input

Le identificazioni esatte su scene sintetiche non misurano riconoscimento di
persone, errori open-set o qualità della cattura. Serve una valutazione su
dati indipendenti, con identità, soglie, quantizzazione, fusione e condizioni
di acquisizione definite; le prime prove a un solo seed restano distinte
dalle verifiche successive. Il confronto biometrico TFHE/CKKS richiede stessa
regola e stessi dati, inclusi impostori e rifiuti, oltre ai rispettivi errori
numerici e crittografici.

Un client può cifrare un vettore ammesso che non proviene da un volto.
Una prova di intervallo o di norma dimostra il predicato aritmetico scelto;
non dimostra origine del probe, presenza fisica, consenso o autorizzazione.
Restano da specificare attacchi adattivi attraverso l'output 0/ID, legame fra
chiave e soggetto, attestazione dell'acquisizione e difese coerenti con il
modello di minaccia. I bound di overflow e i rifiuti del servizio non chiudono
questi problemi.

La [sintesi storica corretta](findings.md#f0f83---risultati-storici-e-correzioni-consolidate)
riassume questi limiti.

## 3. Integrità, freschezza e autorizzazione del servizio

La confidenzialità della query non autentica da sola input, configurazione
della galleria e risultato. Occorre fissare gli avversari ammessi e verificare
come il protocollo lega richiesta, chiave, versione della galleria, soglie e
risposta, impedisce riuso indesiderato e gestisce autorizzazioni e revoche.
La verifica di un servizio locale corretto non è una prova di sicurezza del
protocollo contro client o server malevoli.

## 4. Ripetibilità dei tempi e generalizzazione

I confronti appaiati positivi hanno chiavi, scene, macchina e condizioni
specifiche. Molte finestre conservano carico esterno alto o attribuzione
incerta; nessuna pulizia retrospettiva dei campioni risolve questo limite.
Resta da quantificare la variabilità su più chiavi, sessioni e condizioni,
con incertezza coerente con l'unità indipendente effettiva. La capacità di
rappresentare 3374 ID non è una misura FHE né una latenza a tutte quelle taglie.

Il rapporto pack4/B 0,952561993 ha intervallo bootstrap95% condizionato alle
tre famiglie [0,948049442; 0,957387164]. Il carico esterno supera la soglia
diagnostica del 20% di un core in tutte le 216 chiamate misurate; 76 hanno
finestre con attribuzione incerta. Nessuna durata è scartata. Il +13,17%
storico di B/pre-fix appartiene a un altro confronto: non viene combinato con
pack4/B. I due nuovi grafici sono inclusi, con campagne, estimatori e
limiti distinti nel [percorso corrente](docs/percorso-sperimentale-20260920.md).
Non trasferiscono i vecchi tempi né dimostrano la variabilità su chiavi future.

La demo composita storica del pacchetto 22 ha un vantaggio HTTP diretto misurato su scene sintetiche, mentre
cattura, galleria personale e carico concorrente di utenti restano fuori da
quel confronto. Non è corretto sommare i guadagni dei componenti o trasferire
al core corrente le suite delle revisioni precedenti. Una nuova valutazione
del runtime, inclusa la riparazione del selettore, deve partire dal profilo
della composizione attuale; native,
LTO, PGO, cache e copie sono già stati provati nelle rispettive versioni.

Riferimenti: [configurazione CPU](experiments/19_runtime_cpu/README.md),
[composizione e servizio](experiments/22_demo_composita/README.md),
[campagna comune successiva](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).
Quest'ultima conserva 16 thread per tutti i core exact e distingue il
calcolo cifrato dai tempi HTTP; non sostituisce le precedenti conferme.

## 5. Possibili sviluppi e prove necessarie

| Premessa da verificare | Primo controllo utile | Evidenza che ancora manca |
|---|---|---|
| Il costo dei nodi pubblici varia dopo i tagli ID/soglia | Ricostruire dal sorgente il lavoro effettivo per nodo: payload, gruppi e primitive rimasti. Confrontarlo con la politica attuale prima di una nuova implementazione. | Un vantaggio di una politica interna basata sul lavoro pubblico, distinto dal solo numero di merge pronti. Le politiche DAG D/I/W già provate sono più lente. |
| Avvio dei processi e ricarica delle chiavi incidono sul client | Profilare cifratura/decifratura, deserializzazione e file temporanei nel client selezionato, senza attribuire a priori tutto il costo al processo. | Il costo evitabile e un confronto completo con un eventuale worker locale persistente. |
| Il predicato finale con sentinel pubblico ammette una specializzazione | Verificare dominio intero, riporti e rappresentazioni ridondanti, soglia inclusiva e controllo consumato dal selettore. | Correttezza noisy e tempo della query completa; il risparmio massimo strutturale riguarda un solo predicato per query. |
| Un produttore Tetris diverso riduce le conversioni | Materializzare una variante con conversioni ridotte o condivise e misurarle tutte nel componente. | Compatibilità completa e vantaggio del produttore, poi dell'intera query; la variante a sei circuit bootstrap è già negativa. |
| Il circuito custom è utile su GPU | Compilare ed eseguire un prototipo CUDA verificandone parametri e output, poi confrontare il costo completo con la versione CPU. | Compilazione CUDA, correttezza FHE e tempi comprensivi di conversioni e trasferimenti. I controlli CPU e i vecchi benchmark Concrete/T4 non li sostituiscono. |

Le prime due voci separano una nuova premessa dai tentativi appena conclusi.
Il DAG originale e D/I/W sono già stati provati; i loro profili non
dimostrano capacità CPU inutilizzata. La specializzazione finale è un'ipotesi
algebrica senza guadagno misurato. Il percorso GPU richiede misure CUDA complete.

Riferimenti: [interpretazione della diagnosi DAG](experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md)
e [esperimento Tetris](experiments/25_tetris/README.md).

## 6. Filoni alternativi

Common-mask/Joint4, BGV e LFBS conservano risultati, modelli e ostacoli propri.
Una nuova prova utile deve cambiare una premessa concreta: formato e rumore
alle interfacce, costo delle conversioni, anello, fan-in o rappresentazione.
Il full N8 BGV corretto non fornisce una latenza competitiva; Joint4 N16 non
stabilisce scaling N127. Il CKKS ottimizzato è un valutatore distinto dalla
demo TFHE. Le negative conservate circoscrivono costruzioni, senza dichiarare
impossibile un'intera famiglia architetturale.

Le vecchie proposte di normalizzatore, confronti classici, parallelismo del
selettore, cifre pubbliche, attraversamento PFKS e composizione G4 sono già
state provate. La demo composita include le varianti selezionate; G4 è stato escluso
in base al confronto finale.

Riferimenti: [CKKS](experiments/23_ckks_ottimizzazioni/README.md),
[common-mask e BGV](experiments/24_frontiere_common_mask_bgv/README.md).
