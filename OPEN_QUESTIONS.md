# Questioni aperte — exact 0/ID

Aggiornamento: 9 settembre 2026. I [risultati consolidati](findings.md) e gli
[esperimenti numerati](experiments/README.md) descrivono ciò che è stato
provato. Qui restano obblighi scientifici e proposte ancora discriminatorie.
Una proposta non è un risultato né un esperimento già programmato.
L'obiettivo di ricerca locale è indefinito; questo elenco non introduce una
regola di arresto o una latenza da raggiungere.

## 1. Probabilità di fallimento del circuito composto

Manca una giustificazione completa della distribuzione e della coda del
rumore realmente prodotto da Head/BR/KS/PFKS, delle dipendenze fra campioni e
della loro composizione nel torneo e nel decoder terminale. Le mappe carry-v2
hanno verifiche dell'intero dominio su tre chiavi e limiti deterministici
condizionati ai vettori salvati; non danno una probabilità sulle chiavi future.
Anche il `p_fail` di una primitiva di catalogo e un maggior margine nominale
non coprono automaticamente il circuito raw composto.

Serve legare l'argomento al sorgente e ai parametri effettivi, agli indirizzi
raggiungibili, alle scale, ai consumatori e alle dipendenze introdotte dalle
operazioni lineari. Restano da vincolare le premesse effettive del sampler e
del runtime: percorso eseguito, stato floating point, generatore casuale e
catena completa dalla generazione delle chiavi al circuito. I precedenti
audit condizionali del sampler non costituiscono questa catena completa.
Un eventuale nuovo set di parametri richiede premesse e prove proprie;
la migrazione, da sola, non chiude questo argomento.

Resta inoltre da spiegare il fallimento osservato di **Head generale** nel
primo tentativo della campagna comune del 9 settembre: ID75 invece di ID1,
riprodotto con gli stessi input, chiave e binario. Il successivo 45/45
corretto di quella versione non risolve l'errore. Una diagnosi deve partire
dal caso conservato, senza confondere nuovi successi con una correzione.

Riferimenti pubblicati: [normalizzatore e limiti](experiments/20_normalizzatori_carry/README.md),
[mappe di errore osservate](experiments/20_normalizzatori_carry/evidence/NORMALIZER_ERROR_MAPS.md),
[campagna comune e fallimento conservato](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).
Le analisi integrali restano locali in
`tmp/speed-campaign-20260907-night/structural-routes/shared-normalizers/carry-based-v2/NOISE_EVIDENCE_STATUS.md`
e `docs/personal/wrap-up-2026-09-06.md`.

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

La [sintesi storica corretta](findings.md#f0f83--risultati-storici-e-correzioni-consolidate)
riassume questi limiti. Fonti integrali locali non distribuite: F40, F56,
F61 e appendice B in `docs/archive/2026-09-08-before-consolidation/findings.md`;
correzioni in `docs/research-state/2026-09-04/audit.md`.

## 3. Integrità, freschezza e autorizzazione del servizio

La confidenzialità della query non autentica da sola input, configurazione
della galleria e risultato. Occorre fissare gli avversari ammessi e verificare
come il protocollo lega richiesta, chiave, versione della galleria, soglie e
risposta, impedisce riuso indesiderato e gestisce autorizzazioni e revoche.
La verifica di un servizio locale corretto non è una prova di sicurezza del
protocollo contro client o server malevoli.

Gli obblighi applicativi storici restano nell'archivio locale
`docs/archive/2026-09-08-before-consolidation/findings.md`.

## 4. Ripetibilità dei tempi e generalizzazione

I confronti appaiati positivi hanno chiavi, scene, macchina e condizioni
specifiche. Molte finestre conservano carico esterno alto o attribuzione
incerta; nessuna pulizia retrospettiva dei campioni risolve questo limite.
Resta da quantificare la variabilità su più chiavi, sessioni e condizioni,
con incertezza coerente con l'unità indipendente effettiva. La capacità di
rappresentare 3374 ID non è una misura FHE né una latenza a tutte quelle taglie.

La demo composita ha un vantaggio HTTP diretto su scene sintetiche, mentre
cattura, galleria personale e carico concorrente di utenti restano fuori da
quel confronto. Non è corretto sommare i guadagni dei componenti o trasferire
al core corrente le suite delle revisioni precedenti. Una nuova valutazione
del runtime deve partire dal profilo della composizione attuale; native,
LTO, PGO, cache e copie sono già stati provati nelle rispettive versioni.

Riferimenti: [configurazione CPU](experiments/19_runtime_cpu/README.md),
[composizione e servizio](experiments/22_demo_composita/README.md),
[campagna comune successiva](output/figures/progressione-fhe/benchmark-comune-matplotlib-20260909/LEGGIMI.md).
Quest'ultima conserva 16 thread per tutti i core exact e distingue il
calcolo cifrato dai tempi HTTP; non sostituisce le precedenti conferme.

## 5. Proposte concrete ancora da discriminare

| Premessa da verificare | Primo controllo utile | Evidenza che ancora manca |
|---|---|---|
| Il costo dei nodi pubblici varia dopo i tagli ID/soglia | Ricostruire dal sorgente il lavoro effettivo per nodo: payload, gruppi e primitive rimasti. Confrontarlo con la politica attuale prima di una nuova implementazione. | Un vantaggio di una politica interna basata sul lavoro pubblico, distinto dal solo numero di merge pronti. Le politiche DAG D/I/W già provate sono più lente. |
| Avvio dei processi e ricarica delle chiavi incidono sul client | Profilare cifratura/decifratura, deserializzazione e file temporanei nel client selezionato, senza attribuire a priori tutto il costo al processo. | Il costo evitabile e un confronto completo con un eventuale worker locale persistente. |
| Il predicato finale con sentinel pubblico ammette una specializzazione | Verificare dominio intero, riporti e rappresentazioni ridondanti, soglia inclusiva e controllo consumato dal selettore. | Correttezza noisy e tempo della query completa; il risparmio massimo strutturale riguarda un solo predicato per query. |
| Un produttore Tetris diverso riduce le conversioni | Materializzare una variante con conversioni ridotte o condivise e misurarle tutte nel componente. | Compatibilità completa e vantaggio del produttore, poi dell'intera query; la variante a sei circuit bootstrap è già negativa. |
| Il circuito custom è utile su GPU | Ottenere prima gli esiti effettivi del notebook già consegnato e verificarne sorgente, parametri e output. | Compilazione CUDA, correttezza FHE e tempi comprensivi di conversioni e trasferimenti. I controlli CPU e i vecchi benchmark Concrete/T4 non li sostituiscono. |

Le prime due voci separano una nuova premessa dai tentativi appena conclusi.
Il DAG originale e D/I/W non sono idee ancora inesplorate; i loro profili non
dimostrano capacità CPU inutilizzata. La specializzazione finale è un'ipotesi
algebrica, senza guadagno misurato. Il notebook GPU è stato preparato per
l'utente; questo documento non autorizza upload o esecuzione remota.

Riferimenti pubblicati: [interpretazione della diagnosi DAG](experiments/26_torneo_dag/evidence/POST_SCREEN_INTERPRETATION.md)
e [esperimento Tetris](experiments/25_tetris/README.md).
L'inventario esteso delle integrazioni e proposte resta locale in
`docs/research-state/2026-09-08/INTEGRATION_AND_NEXT_ROUTES.md`.

## 6. Filoni alternativi e memoria dei tentativi

Common-mask/Joint4, BGV e LFBS conservano risultati, modelli e ostacoli propri.
Una nuova prova utile deve cambiare una premessa concreta: formato e rumore
alle interfacce, costo delle conversioni, anello, fan-in o rappresentazione.
Il full N8 BGV corretto non fornisce una latenza competitiva; Joint4 N16 non
stabilisce scaling N127. Il CKKS ottimizzato è un valutatore distinto dalla
demo TFHE. Le negative conservate circoscrivono costruzioni, senza dichiarare
impossibile un'intera famiglia architetturale.

Le vecchie proposte di normalizzatore, confronti classici, parallelismo del
selettore, cifre pubbliche, attraversamento PFKS e composizione G4 sono già
state provate. La demo composita è stata qualificata e G4 escluso dal confronto
finale; nessuna di queste azioni resta semplicemente «da integrare».

Riferimenti: [CKKS](experiments/23_ckks_ottimizzazioni/README.md),
[common-mask e BGV](experiments/24_frontiere_common_mask_bgv/README.md).
Il diario completo e le idee storiche restano locali in
`docs/archive/2026-09-08-before-consolidation/findings.md`; la
[guida alla provenienza](docs/riproducibilita.md) distingue questo archivio
dalle copie distribuite.
