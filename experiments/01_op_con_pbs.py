"""
Esperimento 01 -- operazioni economiche vs care (da dove viene il costo FHE).

Sotto TFHE/Concrete non tutte le operazioni costano uguale. Alcune sono quasi
gratis mentre altre richiedono un *programmable bootstrapping* (PBS), l'operazione cara
il cui costo domina tutto il resto. In questo esperimento contiamo
i PBS che Concrete inserisce nel circuito
(`circuit.statistics["programmable_bootstrap_count"]`) e cronometriamo la `run`.

  economico (0 PBS)  cifrato + cifrato,  cifrato × costante in chiaro
  caro (PBS)         cifrato × cifrato,  funzione non lineare (qui x² via tabella)

Esegui con:  uv run python experiments/01_op_con_pbs.py
"""

from concrete import fhe

from utils_fhe import timed

VALORI = list(range(8))                       # interi 0..7 (3 bit)
INPUTSET_2 = [(i, j) for i in VALORI for j in VALORI]


def misura(nome: str, compiler, inputset, args: tuple) -> None:
    circuit, _ = timed(lambda: compiler.compile(inputset))
    circuit.keygen()
    enc = circuit.encrypt(*args)
    circuit.run(enc)                          # riscaldamento, scartato
    _, ms = timed(lambda: circuit.run(enc))
    pbs = circuit.statistics["programmable_bootstrap_count"]
    print(f"  {nome:<36} PBS={pbs:<2} run={ms:8.2f} ms")


def main() -> None:
    print("Operazioni economiche vs care (conteggio PBS + tempo della run)\n")

    @fhe.compiler({"x": "encrypted", "y": "encrypted"})
    def somma(x, y):                          # cifrato + cifrato
        return x + y

    @fhe.compiler({"x": "encrypted"})
    def per_costante(x):                      # cifrato × numero noto
        return 3 * x

    @fhe.compiler({"x": "encrypted", "y": "encrypted"})
    def prodotto(x, y):                       # cifrato × cifrato
        return x * y

    quadrato = fhe.LookupTable([v * v for v in VALORI])

    @fhe.compiler({"x": "encrypted"})
    def non_lineare(x):                       # x² via tabella (funzione non lineare)
        return quadrato[x]

    print("economiche:")
    misura("cifrato + cifrato", somma, INPUTSET_2, (3, 5))
    misura("cifrato × costante", per_costante, VALORI, (3,))
    print("care:")
    misura("cifrato × cifrato", prodotto, INPUTSET_2, (3, 5))
    misura("x² (funzione non lineare, tabella)", non_lineare, VALORI, (3,))

    print("\n  -> le operazioni economiche hanno 0 PBS; quelle care ne hanno >0.")

if __name__ == "__main__":
    main()
