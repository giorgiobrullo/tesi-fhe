# Pipeline con comparatore binario — 4 ottobre 2026

**Il prototipo completo fallisce il quinto caso.** I primi quattro restituiscono
l'ID atteso; il quinto restituisce ID2 dove il contratto richiede rifiuto (0).
La prova si interrompe e il sesto caso non viene eseguito.

La [prova precedente](COMPARATORE_BINARIO_20261004.md) aveva verificato il solo
primitivo sulle due cifre basse, con cifre cifrate fresche. Qui lo abbiamo
integrato in una copia separata della pipeline: Head emette middle/low a
Δ=2^55 e top a Δ=2^59; due copie del riporto moltiplicate per 16 conservano
il feedback alle scale precedenti. Le soglie usano le stesse scale per
posizione, gli ID restano a Δ=2^59. Il confronto usa due PBS distinte,
seguito dal refresh e dalla selezione PFKS già previsti.

Una sola famiglia fresca, sei query N2 fissate prima delle chiavi, con
soglie comuni e soglie diverse per candidato. TFHE-rs 1.8.1, Classic/Standard
859/GLWE size 2/N2048, FFT Dif4/base1024, Rust 1.98.1. Nessuna chiave scelta
fra più tentativi e nessun riavvio dopo la divergenza.

| Caso eseguito | ID atteso | ID ottenuto |
|---|---:|---:|
| Soglia comune inclusiva, carry 1023/1024 | 1 | 1 |
| Soglia comune: rifiuto al pareggio con la sentinella | 0 | 0 |
| Soglia comune: pareggio tra template distinti | 1 | 1 |
| Soglie diverse: minimo rifiutato, altro candidato accettabile | 0 | 0 |
| Soglie diverse: primo pari rifiutato, secondo accettabile | 0 | **2** |

Nel quinto caso la query è `(1,1)` e i due template sono `(1,0)` e `(0,1)`;
le altre coordinate sono zero. Entrambi hanno score −1. Le loro soglie sono
−2 e −1: il **primo minimo** deve restare il primo candidato, che non passa
la propria soglia, quindi l'esito è 0. La soglia più permissiva del secondo
non deve sostituirlo. L'ID finale decifrato è invece 2.

Tutti i conteggi previsti e i controlli dello scheduler sono passati:
due confronti binari per query, nessun percorso legacy a tre PBS. Questo
conferma quale circuito è stato eseguito, ma l'ID finale non localizza
la causa fra Head, confronto, refresh, trasporto dei payload e verifica
finale. Non sono state ispezionate fasi private intermedie.

Il risultato riguarda questo prototipo e questa famiglia. Non stabilisce
un tasso d'errore, un problema nella baseline mantenuta o un guadagno di
tempo. Il sesto caso, accettazione inclusiva Mixed di ID2, resta non provato.
La famiglia della prova precedente è diversa: non è un confronto appaiato.
Il runtime mantenuto non è stato modificato.

[Cinque casi CSV](../../benchmark/binary-pipeline-20261004/samples.csv),
[record originali](../../benchmark/binary-pipeline-20261004/rows.jsonl),
[protocollo](../../benchmark/binary-pipeline-20261004/PROBE_PROTOCOL.md),
[revisione indipendente](../../benchmark/binary-pipeline-20261004/RESULT_REVIEW.md),
[riepilogo e provenienza](../../benchmark/binary-pipeline-20261004/SUMMARY.json).
Il test Rust termina con exit 101 dopo il rifiuto scientifico registrato;
il launcher termina con exit 0 dopo averne verificato i dati, non perché la
candidata sia passata. I receipt conservano durate di processo, non misure
di latenza.

Il [manifest compilato](../../benchmark/binary-pipeline-20261004/SOURCE_BUILD.json)
lega 144 input conservati nell'archivio locale
`/workspace/research/tmp/current-binary-pipeline-20261004`,
con sorgenti in `runtime/`. Questi dati documentano quella singola prova;
non costituiscono un pacchetto eseguibile di riproduzione. Chiavi, envelope
cifrati e binario restano nell'archivio locale e non sono inclusi qui.

## Diagnosi del produttore delle cifre

Una prova successiva, con una famiglia nuova, ha separato il produttore
scoring+Head dal confronto. Per lo stesso input pubblico del pareggio,
i due score normalizzati sono62 e dovrebbero dare le cifre
`[top,middle,low]=[0,3,14]`. I risultati arrotondati sono invece
`[0,3,13]` e `[0,3,15]`: cifre valide, ma punteggi diversi da quelli attesi.

La diagnosi si ferma qui; i due confronti previsti non vengono eseguiti.
Il difetto compare quindi nel tratto che produce le cifre, prima del
comparatore e del selettore. Non abbiamo osservato separatamente il
prefisso scoring e i passaggi interni di Head, né ricostruito la causa
della famiglia fallita nella prova completa. La variante resta respinta;
nessuna nuova latenza è misurata e il runtime mantenuto resta invariato.

[Stadio osservato](../../benchmark/binary-pipeline-20261004/stages/stages.csv),
[record originali](../../benchmark/binary-pipeline-20261004/stages/rows.jsonl),
[protocollo](../../benchmark/binary-pipeline-20261004/stages/PROBE_PROTOCOL.md),
[revisione](../../benchmark/binary-pipeline-20261004/stages/RESULT_REVIEW.md),
[provenienza](../../benchmark/binary-pipeline-20261004/stages/SUMMARY.json).

## Controllo della codifica

Le cifre basse del prototipo hanno distanza Δ=2^55, sedici volte più piccola
di Δ=2^59 della baseline. L'errore assoluto tollerabile nella decifratura
si riduce quindi di sedici volte. Ridurre i valori della LUT conserva il calcolo ideale,
ma non dimostra che tutti gli errori introdotti dalla rotazione cifrata si
riducano della stessa quantità. Inoltre le copie del riporto moltiplicate
per 16 moltiplicano anche il loro errore. Questo spiega quale garanzia manca;
non misura il rumore e non identifica l'operazione responsabile del caso fallito.

Conservare Δ=2^59 e cambiare soltanto i pesi del packing non risolve il
problema generale. A questa scala la fase si ripete ogni 32 unità: per esempio,
`16 × differenza_middle + differenza_low` vale 32 quando le differenze sono
`(2,0)`, quindi ha la stessa fase del pareggio `(0,0)`, pur richiedendo una
scelta diversa. Una verifica pubblica di tutte le **1.024 coppie di pesi
interi modulo 32** trova una collisione di questo tipo per ogni coppia.
Nessuna LUT o aggiunta costante può distinguere due fasi ideali uguali.
Il risultato riguarda una sola PBS applicata a quella combinazione delle
due cifre, sul loro dominio completo; non esclude altri algoritmi a due PBS.

Abbiamo controllato anche se alcune cifre dello score potessero essere
note in anticipo, usando soltanto i template pubblici e il limite
`||query||² ≤ 1024`. Nella galleria del benchmark da 120 persone le norme
dei template vanno da 589 a 666, il dominio dei punteggi è `[-987,2318]`
e l'intervallo certificato per la cifra alta di ogni foglia è `[0,12]`.
Questi limiti non certificano alcuna cifra costante da omettere.
Non dimostrano che tutti i valori dell'intervallo si presentino realmente
o che limiti pubblici più precisi siano inutili.

Non sono state eseguite altre prove cifrate. La variante resta respinta e
la baseline resta invariata; non attribuiamo a questa analisi un guadagno
di tempo, un tasso d'errore o una garanzia formale sull'intera pipeline.

[Intervalli della galleria](../../benchmark/binary-pipeline-20261004/encoding/public-bounds.json),
[collisioni per tutti i pesi modulo 32](../../benchmark/binary-pipeline-20261004/encoding/affine-aliases.json).
