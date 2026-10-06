import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for pin in pins:
        assert (
            hashlib.sha256((ROOT / pin["path"]).read_bytes()).hexdigest()
            == pin["sha256"]
        ), pin["path"]
    return pins


def load(relative_path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def a126_live_safe():
    q = 1 << 64
    body = struct.unpack(
        "<2048Q",
        (
            ROOT
            / "tmp/a126-refresh-schedule-gate/artifacts/fused_candidate_zero_body.u64le"
        ).read_bytes(),
    )
    expected = (1 << 59, 1 << 59)

    def sample(address, degree):
        cycle, index = divmod(address + degree, 2048)
        return ((-1 if cycle % 2 else 1) * body[index]) % q

    return {
        r
        for r in range(4096)
        if tuple(sample(128 + r, d) for d in (0, 768)) == expected
    }
