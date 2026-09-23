# 00–04: dai primi cifrati allo scambio client/server

Questi cinque programmi piccoli servono a capire **che cosa deve fare il server
senza vedere la query**. Non usano ancora foto né decidono chi sia una persona.
Si eseguono separatamente; il numero indica il passaggio, non una versione
completa del programma precedente.

| Prova | Prima → dopo | Cosa verifica |
|---|---|---|
| [00](00_hello_concrete.py) | Numeri in chiaro → somma di due interi cifrati. | Compilazione, chiavi, cifratura, valutazione e decifratura nello stesso processo. |
| [01](01_op_con_pbs.py) | Somma semplice → confronto fra tipi di operazione. | Conta i *PBS*, le operazioni crittografiche costose: somma e prodotto per costante ne richiedono zero nei circuiti provati, prodotto fra cifrati e tabella no. |
| [02](02_distanza_quadrata.py) | Due numeri → due vettori interamente cifrati. | Calcola e controlla la distanza quadratica, ma i quadrati richiedono prodotti fra cifrati. |
| [03](03_galleria_in_chiaro.py) | Entrambi i vettori cifrati → query cifrata e template pubblico. | Confronta tre formule: mettere il template in chiaro **non basta** se si calcola ancora `(a-b)²`; la forma espansa evita quei PBS. |
| [04](04_client_server.py) | Tutto in un processo → ruoli separati e dati serializzati. | Il client conserva la chiave segreta; il server riceve ingresso cifrato e chiave di valutazione. Il circuito dimostrativo è `3*x+1`, non il riconoscimento facciale. |

Nel passo 03 il server calcola `‖b‖² − 2a·b` per la query `a` e il template
pubblico `b`. La distanza quadratica completa aggiungerebbe `‖a‖²`, uguale
per tutti i template di **quella query**: toglierlo non cambia quale score è
minimo. Per una soglia assoluta, invece, bisogna tenere conto del termine
tolto; questo verrà affrontato nei circuiti successivi.

Il [passo 05](05_pca/README.md) applica per la prima volta lo schema a vettori
ricavati da foto: il server restituisce ancora **tutti** i punteggi cifrati e
il client sceglie il minimo. Il [passo 06](06_argmin_soglia/README.md) porta
la scelta nel circuito. Questi esempi iniziali non misurano la latenza della
demo finale.

Per rieseguirne uno, dalla radice del repository:

```sh
uv run python experiments/03_galleria_in_chiaro.py
```

Sostituire `03_galleria_in_chiaro.py` con il nome dell'altro programma.
