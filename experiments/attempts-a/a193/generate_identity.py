"""Generate/verify A193 completion identity without compiling or launching anything."""

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE.parent / "a193-live-worker-clock-gate"
PRESERVED = [
    "worker_clock.c", "protocol.h", "arm_clock.h", "native_replay.py",
    "model.py", "test_model.py",
]
INPUTS = PRESERVED + [
    "UPSTREAM_PINS.json", "generate_identity.py", "verify.py", "synthetic.py",
    "test_native.py",
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expected():
    for name in PRESERVED:
        if (HERE / name).read_bytes() != (ORIGINAL / name).read_bytes():
            raise ValueError(f"original source changed in completion: {name}")
    upstream = json.loads((HERE / "UPSTREAM_PINS.json").read_bytes())["files"]
    for path, value in upstream.items():
        if digest(Path(path).read_bytes()) != value:
            raise ValueError(f"cached input drift: {path}")
    data = {
        "schema": "a193.completed-source-inputs.v1",
        "files": {name: digest((HERE / name).read_bytes()) for name in INPUTS},
        "unchanged_original_files": {
            str(ORIGINAL / name): digest((ORIGINAL / name).read_bytes())
            for name in PRESERVED
        },
    }
    manifest = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    source_id = digest(manifest)
    header = (
        '#ifndef A193_SOURCE_IDENTITY_H\n#define A193_SOURCE_IDENTITY_H\n'
        f'#define A193_SOURCE_ID "{source_id}"\n#endif\n'
    ).encode()
    return manifest, header, source_id


def verify():
    manifest, header, source_id = expected()
    for name, value in [("SOURCE_INPUTS.json", manifest), ("source_identity.h", header)]:
        if (HERE / name).read_bytes() != value:
            raise ValueError(f"source/header binding drift: {name}")
    return source_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    manifest, header, source_id = expected()
    if args.write:
        for name, value in [("SOURCE_INPUTS.json", manifest), ("source_identity.h", header)]:
            path = HERE / name
            if path.exists():
                if path.read_bytes() != value:
                    raise ValueError(f"refuse to replace an existing identity: {name}")
            else:
                path.write_bytes(value)
    else:
        verify()
    print(source_id)


if __name__ == "__main__":
    main()
