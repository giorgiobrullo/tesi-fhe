# Due cifre in un confronto: variante binaria — 4 ottobre 2026

**Il nuovo primitivo passa gli otto casi fissati**, inclusi 255 contro 0 e
i due pareggi. Il riferimento sulle singole cifre restituisce correttamente
tutti i 24 ternari. È la prima prova cifrata di questa variante; non è
ancora il confronto completo usato dalla demo e non misura un guadagno.

## Cosa cambia rispetto alla proposta precedente

Il [primo tentativo](COMPARATORE_COMPRESSO_20261004.md) confrontava le due
cifre basse restituendo minore, uguale o maggiore. La variante binaria
restituisce soltanto quale lato conservare: **Left quando il suo valore è
minore o uguale, Right quando è maggiore**. Il pareggio non richiede più
un messaggio separato. Per esempio, (15,15) in base 16 vale 255.

Nella futura composizione, la cifra alta resta ternaria. Il controllo
`2*s_top + b(z)`, con `b(z)=-1` per z≤0 e +1 per z>0, lascia dominare
la cifra alta quando differisce e conserva Left sul pareggio completo.
Con la sentinella Left di valore soglia+1 e ID0, questa convenzione mantiene
anche la soglia inclusiva. Il refresh rimane necessario; il vecchio offset
di mezzo Delta va rimosso dall'assemblaggio del confronto.

La codifica delle due cifre resta Delta55, con `z=16*d_middle+d_low` e
centri distanti otto gradi. Cambia il body della LUT: −Delta59 agli indici
0…3, zero a4, +Delta59 a5…2047. Il margine uniforme resta **±3 gradi**;
solo alcuni bordi migliorano, fra cui z=255 e z=−1, con raggio11.
Questa è geometria ideale, non una garanzia sul rumore.

## Prova eseguita

Helper autonomo TFHE-rs1.8.1, parametri Classic/Standard 859/GLWE2/N2048,
FFT Dif4/base1024, Rust1.98.1 release opt3/CGU1/LTOoff. Una sola famiglia
ordinaria fresca, otto coppie, nessun retry o selezione di una chiave.

Per ogni coppia si cifrano nuovamente le tre cifre del riferimento a
Delta59, con cifra alta zero. La candidata cifra middle/low a Delta55,
forma il combinato, esegue un KS, la correzione pubblica mean-only e
una BR Standard con estrazione grado0. Il decoder espone soltanto
−1/0/+1 o un valore fuori alfabeto: **−1 significa Left, +1 Right**.

| Left / Right | Vincitore atteso | Candidata | Riferimento sulle cifre |
|---|---|---|---|
| 0 / 0 | Left, pareggio | −1, corretto | Corretto |
| 0 / 1 | Left | −1, corretto | Corretto |
| 1 / 0 | Right | +1, corretto | Corretto |
| 16 / 15 | Right | +1, corretto | Corretto |
| 15 / 16 | Left | −1, corretto | Corretto |
| 255 / 0 | Right | +1, corretto | Corretto |
| 0 / 255 | Left | −1, corretto | Corretto |
| 255 / 255 | Left, pareggio | −1, corretto | Corretto |

Il programma avrebbe interrotto la sequenza al primo errore dopo un
riferimento corretto. Ha completato tutti gli otto casi, exit0
`PRIMITIVE_PASS_8_CASES`. La revisione indipendente conferma dieci record,
ordine, oracoli, identità di sorgenti/compilatore/binario e impronte opache.
La famiglia è diversa da quella del tentativo ternario: questo risultato
non è un confronto appaiato e non dimostra la causa del suo fallimento.

## Cosa resta da verificare

La prova usa cifre fresche, non quelle estratte da Head. Il nuovo controllo
composto, il refresh, PFKS, il torneo e l'esito0/ID non sono stati eseguiti.
Il [controllo della sorgente](../../benchmark/binary-comparator-20261004/CONTRACT.md)
verifica soltanto l'interfaccia ideale con il refresh. L'emissione e il
trasporto delle cifre55 devono rispettare anche il feedback di Head e
il confronto con soglie comuni o diverse: questi passaggi non sono ancora
integrati. Il runtime mantenuto e i suoi tempi restano una consegna distinta.

Il [piano delle interfacce](../../benchmark/binary-comparator-20261004/HEAD55_PLAN.md)
individua come emettere e trasportare middle/low55 senza duplicare le lane,
codificando nello stesso modo anche le soglie pubbliche. Richiede due
moltiplicazioni interne dei carry di Head e l'aggiornamento dei costruttori
e dei confronti: l'errore dei carry viene amplificato. Il confronto nuovo
richiede due LUT distinte e una correzione mean-only sul combinato, che
il vecchio callee raw non applica. Anche questo lavoro e i contatori vanno
aggiornati. La [revisione del piano](../../benchmark/binary-comparator-20261004/HEAD_PLAN_REVIEW.md)
ha reso esplicito questo obbligo prima dell'implementazione. Il piano resta
da implementare e verificare con cifrati reali.

Otto esiti corretti non stabiliscono una probabilità di fallimento;
l'encoding55 non eredita il p-fail del parametro standard. Nessun tempo
di processo viene usato come misura di latenza o speedup.

[Otto casi](../../benchmark/binary-comparator-20261004/samples.csv),
[record originali](../../benchmark/binary-comparator-20261004/rows.jsonl),
[riepilogo](../../benchmark/binary-comparator-20261004/SUMMARY.json),
[protocollo e sorgente](../../benchmark/binary-comparator-20261004/README.md),
[revisione indipendente](../../benchmark/binary-comparator-20261004/RESULT_REVIEW.md).
Le chiavi restano soltanto nell'archivio locale; qui sono incluse le loro
dimensioni e impronte.
