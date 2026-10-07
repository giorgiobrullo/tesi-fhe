"""Read-only frozen evidence bindings, with no bytecode writes to old directories."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q, U, DEGREES, DELTA = 1 << 64, 1 << 52, 4096, 1 << 59


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for pin in pins:
        assert (
            hashlib.sha256((ROOT / pin["path"]).read_bytes()).hexdigest()
            == pin["sha256"]
        ), pin["path"]
    return pins


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def a126_safe_residues(c=1, bit=0):
    assert c in range(-4, 2) and bit in (0, 1)
    body = struct.unpack(
        "<2048Q",
        (
            ROOT
            / "tmp/a126-refresh-schedule-gate/artifacts/fused_candidate_zero_body.u64le"
        ).read_bytes(),
    )
    expected = (int(c == 1) * DELTA, int(c == 1 and bit == 0) * DELTA)
    nominal = (c + 6 * bit) * (DELTA // U)

    def sample(address, degree):
        cycle, index = divmod(address + degree, 2048)
        return ((-1 if cycle % 2 else 1) * body[index]) % Q

    return {
        r
        for r in range(DEGREES)
        if tuple(sample(nominal + r, d) for d in (0, 768)) == expected
    }


def intervals(residues):
    out = []
    for r in sorted(residues):
        if out and out[-1][1] + 1 == r:
            out[-1][1] = r
        else:
            out.append([r, r])
    return out
