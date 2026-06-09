"""
Esperimento 00 -- hello world di Concrete (FHE).

L'esempio più semplice possibile, lo stesso della quick-start ufficiale di Zama:
si compila una funzione Python (`x + y`) in un circuito che la calcola su interi
cifrati, e si verifica che il risultato decifrato sia corretto. Serve a vedere
l'intera catena e a fissare il vocabolario usato in tutti gli esperimenti:

  compile  server, una tantum: traduce la funzione in circuito FHE e ne fissa i parametri
  keygen   client, una tantum: genera le chiavi per quei parametri (segreta + di valutazione)
  encrypt  client, con la chiave segreta: cifra gli input
  run      server, con la chiave di valutazione: calcola sul cifrato  <-- costo per query
  decrypt  client, con la chiave segreta: apre il risultato

La chiave segreta resta sul client e serve a cifrare e decifrare; la chiave di
valutazione va al server, che con quella calcola sul cifrato ma non può decifrare.

Per compile e keygen (il secondo dipende dal primo):
- l'`inputset` è un campione di input plausibili (non un training set): durante il
  `compile` Concrete ci gira sopra la funzione per dedurre l'intervallo -- e quindi i
  bit -- di ogni valore, dimensiona il circuito intero e ne fissa i parametri
  crittografici. Un valore a runtime fuori da quei range darebbe un risultato sbagliato.
- `keygen` genera poi le chiavi su misura per quei parametri (una volta sola): la
  segreta del client e, derivata da essa, quella di valutazione del server.

In questo hello world gira tutto in un processo solo senza separazione esplicita.

Esegui con:  uv run python experiments/00_hello_concrete.py
"""

from concrete import fhe

from utils_fhe import timed


@fhe.compiler({"x": "encrypted", "y": "encrypted"})
def add(x, y):
    return x + y


def main() -> None:
    print("Hello, Concrete — somma di due interi cifrati\n")

    inputset = [(i, j) for i in range(8) for j in range(8)]   # campione per i range (v. docstring)

    circuit, ms = timed(lambda: add.compile(inputset)); print(f"  compile  {ms:8.2f} ms")
    # keygen mette le chiavi DENTRO `circuit` (encrypt/run/decrypt le useranno da lì);
    # con `_,` scartiamo solo il valore di ritorno e teniamo il tempo.
    _, ms = timed(circuit.keygen);                      print(f"  keygen   {ms:8.2f} ms")

    x, y = 3, 5
    enc, ms = timed(lambda: circuit.encrypt(x, y));     print(f"  encrypt  {ms:8.2f} ms")
    res, ms = timed(lambda: circuit.run(enc));          print(f"  run      {ms:8.2f} ms")
    dec, ms = timed(lambda: circuit.decrypt(res));      print(f"  decrypt  {ms:8.2f} ms")

    print(f"\n  -> {x} + {y} = {dec}  (atteso {x + y})  {'OK' if dec == x + y else 'ERRORE'}")
    print(f"  PBS nel circuito: {circuit.statistics['programmable_bootstrap_count']} "
          f"(una somma è economica, nessun bootstrapping -- vedi Esp. 01)")


if __name__ == "__main__":
    main()
