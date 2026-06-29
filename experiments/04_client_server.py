"""
Esperimento 04: separazione client/server (il pattern di deploy ufficiale).

Fin qui (00–03) abbiamo guardato *cosa* si calcola sotto FHE e *quanto* costa,
tenendo tutto in un processo solo. Qui separiamo
client e server, seguendo la deploy guide di Concrete.

  chi fa cosa:
      server  compila il circuito, lo salva, espone le "client specs"
      client  ricostruisce dalle specs, genera le chiavi, cifra, decifra
  cosa attraversa il filo (tutto serializzato in byte):
      server -> client   client specs (parametri pubblici del circuito)
      client -> server   chiave di valutazione + input cifrato
      server -> client   risultato cifrato

La chiave segreta non compare mai in quell'elenco: resta sul client. Il server
calcola alla cieca con la sola chiave di valutazione. È lo stesso modello del
prototipo (05) ma isolato dalla logica di riconoscimento.

Esegui con:  uv run python experiments/04_client_server.py
"""

import tempfile
from pathlib import Path

from concrete import fhe

from utils_fhe import timed


@fhe.compiler({"x": "encrypted"})
def punteggio(x):
    return 3 * x + 1                          # cifrato × costante + costante -> 0 PBS


def main() -> None:
    print("Separazione client/server (pattern di deploy ufficiale di Concrete)\n")

    # ===== SERVER (setup) =====================================================
    # Il server possiede il calcolo: compila e salva il circuito. compile non tocca
    # alcun segreto; sceglie i parametri crittografici e produce le "client specs".
    circuit, ms = timed(lambda: punteggio.compile(list(range(64))))
    print(f"[server] compile          {ms:7.2f} ms")

    with tempfile.TemporaryDirectory() as d:
        server_zip = str(Path(d) / "server.zip")
        circuit.server.save(server_zip)
        server = fhe.Server.load(server_zip)
        specs_bytes = server.client_specs.serialize()
        print(f"[server] client specs   {len(specs_bytes):7d} byte  ->  client")

        # ===== CLIENT (setup + cifratura) =====================================
        # Ricostruisce il circuito dalle sole specs pubbliche; la chiave SEGRETA la
        # genera qui e non esce mai. Al server manda solo la chiave di valutazione.
        client = fhe.Client(fhe.ClientSpecs.deserialize(specs_bytes))
        _, ms = timed(client.keys.generate)
        print(f"[client] keygen           {ms:7.2f} ms  (segreta resta qui)")
        ek_bytes = client.evaluation_keys.serialize()
        x = 10
        arg_bytes = client.encrypt(x).serialize()
        print(f"[client] eval keys      {len(ek_bytes):7d} byte  ->  server")
        print(f"[client] input cifrato  {len(arg_bytes):7d} byte  ->  server")

        # ===== SERVER (valutazione alla cieca) ================================
        ek = fhe.EvaluationKeys.deserialize(ek_bytes)
        arg = fhe.Value.deserialize(arg_bytes)
        res, ms = timed(lambda: server.run(arg, evaluation_keys=ek))
        res_bytes = res.serialize()
        print(f"[server] run              {ms:7.2f} ms")
        print(f"[server] risultato cif. {len(res_bytes):7d} byte  ->  client")

        # ===== CLIENT (decifratura) ===========================================
        out = client.decrypt(fhe.Value.deserialize(res_bytes))

    atteso = 3 * x + 1
    print(f"\n  -> punteggio({x}) = {out}  (atteso {atteso})  "
          f"{'OK' if out == atteso else 'ERRORE'}")


if __name__ == "__main__":
    main()
