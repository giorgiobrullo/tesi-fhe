> **Rapporto storico della baseline anchor del 19 settembre, precedente alla correzione del selettore.** I conteggi, i tempi, i binding e le frasi «questa versione» nel testo seguente appartengono a quella consegna. Il runtime incluso qui è diverso: la sua qualifica è documentata in [SELECTOR_REPAIR_VALIDATION.md](SELECTOR_REPAIR_VALIDATION.md). Il compilatore effettivo delle ricevute storiche è Rust 1.98.0; l'indicazione 1.93.1 nel testo conservato è un errore documentale. La causa del caso storico ID75 è stata successivamente localizzata nella finestra del selettore, come spiegato nel nuovo rapporto.

# Baseline locale del 19 settembre 2026

Questa versione integra soltanto il riuso degli score tramite anchor. Ha superato
le verifiche locali di correttezza, confronto appaiato e servizio previste dal
[protocollo finale](FINAL_DEFAULT_PROTOCOL.md). Il vantaggio prestazionale della
versione pulita resta inconclusivo. La versione del 18 settembre è conservata
separatamente; questa consegna non comporta pubblicazione, commit o push.

Il core calcola il prodotto del primo template e lo aggiorna quando un'altra
voce differisce in al massimo 16 coordinate pubbliche. Negli altri casi usa la
convoluzione originale. La modifica conserva tutte le parole dell'LWE estratto,
il primo minimo nei pareggi, la soglia inclusiva del vincitore e l'uscita `0/ID`.
Non aggiunge flag, contatori sperimentali o percorsi alternativi al runtime.

## Decisione sui candidati

Il rapporto è il tempo della variante diviso quello del riferimento: valori
inferiori a 1 indicano meno tempo. Gli intervalli sono bootstrap al 95% sulle
scene e sulle famiglie di chiavi esaminate, senza correzione per confronti multipli.

| Candidato | Rapporto | Intervallo | Esito |
|---|---:|---:|---|
| Anchor, conferma su due famiglie nuove | 0,983928 | 0,973538–0,993863 | Unico candidato qualificato |
| Normalizzatore sul corpo | 0,997565 | 0,982999–1,012196 | Escluso |
| Combinazione | 0,999678 | 0,982128–1,018342 | Esclusa |
| Anchor pulito, confronto finale su un'altra famiglia | 0,998006 | 0,989160–1,005990 | Regola finale superata; beneficio incerto |

Il candidato anchor riduce il tempo dell'1,61% nella conferma iniziale. Il
confronto finale della versione senza strumenti sperimentali stima invece
lo 0,20%, con un intervallo che comprende anche un rallentamento. Vince 12
delle 30 coppie primarie; il risparmio mediano appaiato è negativo, −8,013 ms.
Non si trasferisce quindi l'1,61% al binario definitivo, né si aggregano le due
campagne. La differenza tra le stime non identifica da sola una causa.

Il protocollo finale richiede rapporto primario sotto 1 e rapporto di ogni
scena al massimo 1,02. Sono controlli sulle stime puntuali, senza dimostrazione
statistica di non regressione. Il controllo di fallback ha rapporto 1,005289
e intervallo 0,987740–1,022410. Non è stabilita l'equivalenza prestazionale.

## Verifiche e identità della consegna

- Conferma iniziale: 384 coppie, 768 chiamate sulle due famiglie nuove e sulle
  tre varianti. Tutti i risultati sono corretti e i ciphertext appaiati identici.
  Sono incluse 756 valutazioni FHE e 12 rifiuti pubblici senza FHE.
- Versione pulita: 22 coppie di controllo, 6 di riscaldamento e 36 misurate,
  per 128 chiamate totali, di cui 126 FHE. Uguaglianza completa delle parole
  cifrate e correttezza rispetto agli oracoli in tutte le coppie.
- Build della consegna: 79 test core e 36 test servizio passati; 4 test FHE
  storicamente ignorati restano tali. Un test delle fixture del confronto
  finale è passato nella preparazione del relativo harness.
- Servizio della consegna: tre richieste reali, ciascuna con cifratura CLI,
  invio HTTP e decifratura CLI, su una famiglia di chiavi nuova e compatibile.
  Esiti `1`, `0`, `0`: accettazione, rifiuto e soglia del primo vincitore nel
  pareggio. Verificati identità, contatori FHE e versione della galleria.

La copia consegnata corregge quattro link nei due README del runtime. Tutti
i sorgenti computazionali e i file Cargo restano identici alla versione pulita
misurata; cambiano i documenti e nove binding generati. Il nuovo binario ha
superato i test e una propria prova del servizio con chiavi nuove. Non è stato
misurato nuovamente: i tempi sopra appartengono al precedente binario congelato,
identificato separatamente nei [risultati e nelle impronte](BASELINE_BENCHMARKS.json).

Un primo tentativo di packaging aveva riutilizzato dalla cache il vecchio
eseguibile. La verifica ha rifiutato il suo binding prima di avviare il servizio;
tentativo e chiavi sono conservati nel workspace, esclusi dalla consegna.
Il binario consegnato è quello ricompilato e verificato successivamente.

Rust 1.93.1, TFHE-rs 1.7.0, 16 thread, ottimizzazione 3, una codegen unit e
LTO disattivato. I tempi del core includono pianificazione e preparazione degli
anchor, ma escludono generazione/caricamento chiavi, cifratura, decifratura e I/O
dei report. Per compilazione e avvio vedere il [runtime](../../runtime/README.md).
L'archivio contiene sorgenti e documenti, senza le chiavi delle prove.

## Ricerca ancora aperta

Il confronto affine ha superato 60 casi FHE del componente, 54 attivi e 6
fallback, con audit indipendente di 1440 payload e 492 indirizzi small-LWE.
Non è incluso in questa baseline: manca l'integrazione nel torneo completo,
il predicato finale `0/ID` e il confronto temporale appaiato. Il prossimo test
utile è il primo livello del torneo con guardia e fallback, seguito da queste
verifiche. Nessuna di tali prove è già avviata o accodata.

I controlli osservati non danno un limite generale alla probabilità di errore
FHE e non risolvono il problema storico di Head. Le tre richieste del servizio
sono una verifica d'integrazione su fixture piccole, senza prova della webcam
fisica, della latenza end-to-end o dell'intero spazio di input.
