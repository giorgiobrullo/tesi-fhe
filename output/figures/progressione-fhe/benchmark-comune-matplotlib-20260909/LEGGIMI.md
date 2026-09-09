# Progressione FHE: stile Matplotlib

Restyling del grafico del 9 settembre: gli stessi 12 punti, le stesse mediane e gli stessi intervalli interquartili, senza nuove misurazioni. La figura riprende il formato compatto della precedente versione scientifica: 10,5 x 5,6 pollici, titolo semplice, assi standard, linea blu e note brevi.

Restano due tratti continui e un solo stacco, che cambia compito e dimensioni. La scala dei tempi e' logaritmica ed e' indicata sull'asse. Le barre mostrano la dispersione interquartile (Type 7), non intervalli di confidenza. La croce rossa conserva il precedente errore irrisolto di Head generale: i nuovi 45/45 risultati corretti non lo risolvono. Il tempo di quel punto resta descrittivo e non qualifica un miglioramento exact.

- `progressione.png`: 3150 x 1680 pixel, 300 dpi.
- `progressione-email.png`: 1260 x 672 pixel, 120 dpi.
- `progressione.svg`: vettoriale.
- [PDF vettoriale](../../../pdf/progressione-fhe-benchmark-comune-matplotlib-20260909.pdf).
- `dati.json` e `punti.csv`: copie byte per byte dei dati accettati.

[Metodo completo, risultati e limiti](../benchmark-comune-20260909/LEGGIMI.md). [Tutte le osservazioni exact](../benchmark-comune-20260909/osservazioni-exact.csv). [Tutte le osservazioni dei prototipi](../benchmark-comune-20260909/osservazioni-prototipi.csv).

Nessun benchmark e' stato ripetuto. I sorgenti nativi e gli artefatti precedenti sono preservati.

## Rigenerazione dal repository

Dalla radice, nell'ambiente Python con Matplotlib:

```sh
python -B benchmark/figure_common_benchmark.py --output .local/grafico-pubblico
```

La destinazione deve essere nuova. Il comando verifica l'impronta dei dati
accettati e produce PNG, SVG e PDF senza nuove misure FHE. Il disegno è quello
del generatore originale; i percorsi di ingresso/uscita sono portabili.
I manifest EXPORT originali conservano le impronte della consegna locale;
RENDER.json descrive soltanto la nuova esportazione. I PDF/SVG possono avere
metadati differenti tra esecuzioni o versioni delle librerie.

I percorsi e gli hash negli EXPORT e nei dati originali identificano la provenienza locale. Per l’ambito del materiale incluso vedere [riproducibilità](../../../../docs/riproducibilita.md).
