# Due cifre in un confronto — 4 ottobre 2026

**La proposta non supera la prima prova cifrata.** Confrontare insieme le
due cifre basse avrebbe tolto una rotazione da ciascun confronto, ma richiede
una diversa codifica. Con i parametri provati, anche la correzione pubblica
dell'arrotondamento restituisce un pareggio per **255 contro 0**. Le singole
cifre, confrontate con la codifica attuale, restituiscono tutti gli esiti attesi.
La proposta resta separata dal runtime mantenuto.

## Passaggio modificato

Oggi il torneo confronta top, middle e low dello score con tre PBS ternari:
ciascuno restituisce minore, uguale o maggiore. Poi combina i tre risultati
e rigenera il controllo del selettore. La nuova proposta confronta top
separatamente e middle/low insieme: due PBS ternari, mantenendo il refresh.
Non cambia la regola del primo minimo o la soglia inclusiva.

Per due cifre in base16, `z = 16*d_middle + d_low` rappresenta la differenza
fra i due valori a otto bit; z va da −255 a 255. Con la codifica attuale
Delta=2^59, z=−1 e z=31 diventano lo stesso messaggio: una LUT non può
distinguerli. La nuova proposta usa Delta'=2^55, il cui periodo è512.
I messaggi non collidono più, ma i centri sono distanti soltanto otto
gradi invece di128. La LUT ternaria ha un margine uniforme massimo di
**±3 gradi**, contro i ±63 della LUT attuale. Questo è un limite geometrico,
non una probabilità di errore.

## Prova e risultato

Helper autonomo TFHE-rs1.8.1, M4 Max, una sola famiglia di chiavi generata
normalmente. Stessi parametri Classic/Standard 859/GLWE2/N2048 e FFT
Dif4/base1024 del runtime, Rust1.98.1 release opt3/CGU1/LTOoff.
Il nuovo encoding non eredita il p-fail dichiarato per il parametro standard.

Per ogni coppia, il riferimento cifra nuovamente le tre cifre a Delta59
e verifica tutti i ternari. La proposta cifra middle/low a Delta55 e
calcola il combinato. Dopo un solo key switching, lo stesso cifrato
alimenta due rotazioni: senza correzione e con la correzione mean-only
già usata dal selettore. Il decoder espone soltanto minore/uguale/maggiore.

| Coppia di valori a otto bit | Atteso | Riferimento | Proposta senza correzione | Con correzione |
|---|---|---|---|---|
| 0 / 0 | Uguale | Corretto | Minore | Uguale |
| 0 / 1 | Minore | Corretto | Uguale | Minore |
| 1 / 0 | Maggiore | Corretto | Maggiore | Maggiore |
| 16 / 15 | Maggiore | Corretto | Maggiore | Maggiore |
| 15 / 16 | Minore | Corretto | Minore | Minore |
| **255 / 0** | **Maggiore** | **Corretto** | **Uguale** | **Uguale** |

Il protocollo prevedeva otto coppie ripetute con quattro cifrature fresche,
massimo32 casi. Il primo errore senza correzione è conservato; il programma
si ferma al primo errore del ramo corretto, dopo sei casi. **Gli altri26
non sono stati eseguiti.** Tutti i18 ternari del riferimento sono corretti.
Tre errori senza correzione e uno con correzione sono osservazioni di questa
sequenza interrotta, non tassi d'errore né una misura dell'efficacia generale
della correzione. Exit2 indica il rifiuto previsto del candidato; build e
riferimento sono passati. La revisione indipendente conferma record e hash.

## Conseguenza per la pipeline

Non si integra questa versione. Il test dimostra un errore nel primitivo
provato, prima di aggiungere il rumore di Head, selezione PFKS e torneo.
Non identifica da solo quale componente dell'errore abbia causato la
risposta e non esclude ogni comparatore compresso.

L'ingresso attuale emette solo cifre a Delta59: dividerne i coefficienti
non fornisce una conversione valida. Cambiare le LUT di emissione e
moltiplicare copie per16 cambierebbe anche l'errore del feedback. Conservare
due rappresentazioni nel torneo richiederebbe ulteriori lane o conversioni.
Questi cambiamenti non sono stati implementati né valutati da questa prova.
Nessun refresh, esito0/ID, nuova latenza o garanzia composta viene qualificato.
I [tempi del runtime attuale](TEMPI_181_20261004.md) rimangono un'altra campagna.

TFHE-rs offre anche il drift, che prova somme con cifrature di zero per
ridurre l'errore del modulus switch. È diverso dal centraggio provato qui,
ma richiede chiavi ausiliarie e parametri giustificati per questo margine.
In release la routine può usare il miglior candidato anche quando non
raggiunge il bound richiesto: attivarla non fornirebbe da sola una garanzia.
Il [controllo della sorgente](../../benchmark/comparator-encoding-20261004/MS_REDUCTION.md)
documenta questo limite; il drift non è stato eseguito.

[Sei casi](../../benchmark/comparator-encoding-20261004/samples.csv),
[record originali](../../benchmark/comparator-encoding-20261004/rows.jsonl),
[riepilogo](../../benchmark/comparator-encoding-20261004/SUMMARY.json),
[protocollo e sorgente](../../benchmark/comparator-encoding-20261004/README.md),
[revisione indipendente](../../benchmark/comparator-encoding-20261004/RESULT_REVIEW.md).
Chiavi e cifrati del primo fallimento sono conservati come file opachi
soltanto nell'archivio locale `tmp/current-comparator-encoding-20261004/run01`.
