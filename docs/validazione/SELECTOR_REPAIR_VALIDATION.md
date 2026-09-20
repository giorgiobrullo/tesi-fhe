# Correzione del selettore e nuova baseline locale

Consegna del 20 settembre 2026. La revisione con refresh del controllo è adottata come nuova baseline locale per le condizioni verificate qui. La baseline del 19 settembre rimane conservata integralmente in `output/baseline-20260919/` nel workspace. Questa adozione non equivale a una prova universale di correttezza.

## Origine e diagnosi

La geometria stretta entra nella linea M il 6 settembre, togliendo il refresh e usando gruppi con offset0/41/82 e margine±20. La correzione della media introdotta quel giorno riduce una componente dello scarto, ma mantiene la finestra. Il primo output errato rintracciato nella linea con mean-centering è del9settembre: ID75 invece diID1.

La diagnosi riproduce il caso storico. Nel confronto ID75/ID76 il controllo raggiunge341, fuori dal supporto300…340, e la selezione mescola tutte le sei cifre. Le127 estrazioni Head sono corrette. Lo spostamento diagnostico di un solo grado restituisceID1. La baseline più recente, prima della riparazione, passa invece lo stesso replay con indirizzo318: conserva il rischio geometrico, ma non è dimostrato un suo errore in questa capsula. Nessuna singola ottimizzazione è identificata come causa del cambiamento fra i ciphertext intermedi.

La [ricostruzione documentata](../selector-repair/INTRODUCTION_HISTORY.md) conserva cronologia, fonti e distinzione fra osservazioni e conclusioni.

## Modifica e correttezza osservata

Il nuovo selettore rigenera il controllo verso4/12, applica una seconda KS con correzione della media e usa una finestra PFKS centrata in1536, raggio127, con offset0/256/512. Mantiene massimo tre cifre per gruppo, anchor, specializzazioni pubbliche, primo minimo, pareggi stabili, soglia inclusiva del vincitore e risposta0/ID. Richiede una nuova funzione e chiave PFKS. G4 è rifiutato.

- Modello finito: geometria del refresh corretta entro±63 e selezione entro±127, condizionatamente alla correttezza dei ternari e dei residui nelle celle di decodifica.
- Componente storico: conserva esattamente il controllo a341; il refresh produce12, il controllo successivo raggiunge1534 e tutte le sei cifre selezionano correttamenteID76. Audit indipendente dei65eventi e delle sei identità algebriche passato.
- Torneo completo sulla capsula storica: sia baseline precedente sia riparazione restituisconoID1.
- Tre famiglie nuove:90/90coppie di correttezza,18/18coppie di riscaldamento e108/108coppie misurate con risposte corrette in entrambi i bracci. Incluse parità, soglie del vincitore, rifiuti pubblici, soglie estreme eID449/450/3374. Sono432invocazioni totali, comprese le scorciatoie pubbliche; non tutte eseguono FHE.
- Audit indipendente: 432 risposte e 1296 LWE decifrati, hash, oracoli, contatori e ordine delle prove verificati; nessun errore di evidenza.
- Test:80core,36servizio,27client/configurazione,1fixture appaiata e3geometrie del componente passati. Quattro test FHE storici ignorati restano tali.
- Servizio: tre richieste reali su fixtureN2, con cifratura CLI, HTTP e decifratura CLI, restituiscono1/0/0. Una chiave valida della vecchia versione viene rifiutata conHTTP400, senza cambiare lo stato del servizio. Non è una prova della webcam o della latenza end-to-end.

## Costo misurato

Rispetto alla baseline precedente, il costo primario geometrico appaiato è **+13.17%**, rapporto **1.13166**, intervallo bootstrap95% **[1.12264, 1.14101]**. Le mediane aggregate sono1.8546s e2.1076s. Il rapporto non è calcolato dividendo queste mediane.

| Scena | Coppie misurate | Mediana precedente,s | Mediana corretta,s | Rapporto appaiato |
|---|---:|---:|---:|---:|
| `n127_uniform_general` | 18 | 1.7722 | 2.0398 | 1.14409 |
| `n128_anchor_fallback_control` | 18 | 1.7838 | 2.0186 | 1.12222 |
| `n128_block_thresholds` | 18 | 1.8042 | 2.0568 | 1.11958 |
| `n128_uniform_aligned` | 18 | 1.7926 | 2.0267 | 1.14345 |
| `n129_alternating_thresholds` | 18 | 1.8723 | 2.1625 | 1.13572 |
| `n225_uniform_general` | 18 | 3.0445 | 3.3887 | 1.11577 |

Le prime cinque scene del protocollo formano90coppie primarie; `n128_anchor_fallback_control` è il controllo secondario con18coppie. Tutti i campioni restano inclusi. Ogni coppia usa lo stesso input cifrato e gli stessi componenti ordinary/Head; la PFKS cambia con la funzione. L'ordine è alternato AB/BA. Le famiglie sono le stesse fra gate e misure; tutti i gate precedono i tempi. Le misure avvengono il20settembre, dopo la pausa fra le due fasi, e non vengono aggregate con i tempi storici o diagnostici.

L'intervallo usa10000 ricampionamenti delle coppie entro ciascuna cella famiglia×scena, seed20260919; è condizionato alle tre famiglie osservate. Le ripetizioni non sono nuove famiglie. Non è stabilita una latenza universale o l'isolamento da ogni processo del sistema operativo. I due task di ricerca non eseguono benchmark concorrenti nella finestra registrata.

Il costo strutturale è unaBR, unaKS e un campione estratto in più per selezione effettiva; PFKS e gruppi payload restano invariati. Per il replay storicoN127, i contatori passano da1142/1016/1681 a1269/1143/1808 per BR/KS/campioni, con538PFKS in entrambi. I tempi sopra misurano il percorso del core completo, escludendo chiavi, cifratura, decifratura, serializzazione e HTTP.

Ambiente: Mac16,9,16core,64GiB, macOS27.2, Rust/Cargo1.98.0, TFHE-rs1.7.0,16thread, FFT Dif4/base1024, releaseopt3/CGU1/no-LTO. Il compilatore1.93.1 indicato in alcuni documenti conservati era un errore documentale; le ricevute identificano1.98.0.

## Identità, evidenza e limiti

Il runtime incluso è byte-identico ai133file congelati prima delle nuove chiavi. Il servizio incluso è il binario verificato dalle tre richieste; le misure del core appartengono al binario appaiato congelato, che compila gli stessi sorgenti del core. Le modifiche finali di documentazione sono esterne al runtime.

Impronte, tempi individuali e aggregati sono in [SELECTOR_REPAIR_BENCHMARKS.json](SELECTOR_REPAIR_BENCHMARKS.json); il [protocollo](../selector-repair/PROTOCOL.md) era fissato prima delle chiavi. Evidenza completa locale: `tmp/selector-repair-20260919/` nel workspace, inclusi tentativi falliti e correzioni dei soli strumenti di audit. Un primo audit del componente rifiutava tre log di build vuoti: una correzione strettamente limitata a quei file conserva invariati tutti i controlli crittografici.

Il pacchetto non include chiavi o tracce private della nuova campagna. Conserva le LUT pubbliche e due ciphertext dimostrativi storici già presenti nella baseline originale. I risultati precedenti non vengono cancellati o riqualificati retroattivamente.

Restano aperti il limite formale di fallimento dell'intero circuito, le garanzie dei parametri e del sampler, circuit privacy, input arbitrari e validazione biometrica. Zero errori nei campioni non dimostra probabilità zero. Questa campagna corregge il selettore e ne misura il costo; non dimostra completezza della letteratura o superiorità SOTA.
