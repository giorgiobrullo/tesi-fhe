"""Lato server: tiene la galleria in chiaro e calcola il match sul cifrato.

Il server non vede mai il volto né l'esito: riceve solo byte (chiave di valutazione
+ probe cifrato) e restituisce byte (punteggi cifrati), che solo il client può
decifrare. Il plumbing è generico: la galleria è già un insieme di vettori interi,
indipendentemente dalla tecnica di embedding. Il circuito viene dalla fonte unica
`core.matching`; lo si può sostituire (es. col circuito argmin+soglia del gradino
06) passando un altro costruttore, senza cambiare questo plumbing.
"""

from concrete import fhe

from core import matching


class Server:
    def __init__(self, galleria_q, costruisci_circuito=matching.circuito_distanza) -> None:
        self._circuito = costruisci_circuito(galleria_q)

    def client_specs(self) -> bytes:
        """Parametri pubblici del circuito da spedire al client (nessun segreto):
        gli bastano per ricostruire il circuito, generare le chiavi e cifrare."""
        return self._circuito.server.client_specs.serialize()

    def match(self, probe_cifrato: bytes, eval_keys: bytes) -> bytes:
        """Riceve probe cifrato + chiave di valutazione (byte), calcola sul cifrato
        e restituisce il risultato cifrato (byte). Alla cieca: senza la chiave
        segreta il server non può decifrare né l'ingresso né l'uscita."""
        ek = fhe.EvaluationKeys.deserialize(eval_keys)
        probe = fhe.Value.deserialize(probe_cifrato)
        return self._circuito.server.run(probe, evaluation_keys=ek).serialize()
