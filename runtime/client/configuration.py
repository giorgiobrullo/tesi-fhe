"""Explicit file locations and circuit-bound client configuration."""
from dataclasses import dataclass
import hashlib
from pathlib import Path

from . import protocol


@dataclass(frozen=True)
class ClientConfiguration:
    runtime: Path
    binary: Path
    keys: Path

    def load(self) -> dict:
        config = protocol.strict_json((self.runtime / "config.json").read_bytes())
        circuit = (self.runtime / "CIRCUIT_CONTRACT.json").read_bytes()
        if hashlib.sha256(circuit).hexdigest() != config["contratto_esatto"]["circuit_sha256"]:
            raise RuntimeError("configurazione non vincolata al circuito locale")
        return config

    @property
    def assets(self) -> Path:
        return next(parent for parent in self.runtime.parents
                    if (parent / "RESEARCH_STATE.md").is_file()
                    and (parent / "experiments/08_cnn/embedding.py").is_file())
