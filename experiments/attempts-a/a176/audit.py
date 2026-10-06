"""Local source binding and strict utilities; never launches native work."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a155-common-mask-egress-margin-control"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def same(a, b, why):
    need(type(a) is type(b) and a == b, why)
    if isinstance(b, dict):
        for k in b:
            same(a[k], b[k], why)
    elif isinstance(b, (list, tuple)):
        for x, y in zip(a, b):
            same(x, y, why)


def fields(row, expected):
    for k, v in expected.items():
        same(row.get(k), v, "field " + k)


def parse(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, "duplicate JSON key")
            out[k] = v
        return out

    def bad(_):
        raise ValueError("nonfinite JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def old_helpers():
    saved = {k: sys.modules.get(k) for k in ("common", "legacy")}
    try:
        common = load("a176_old_common", OLD / "runtime-validation/common.py")
        sys.modules["common"] = common
        legacy = load("a176_old_legacy", OLD / "runtime-validation/legacy.py")
        sys.modules["legacy"] = legacy
        margin = load("a176_old_margin", OLD / "runtime-validation/validate.py")
        return common, legacy, margin
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def source_check():
    origins = parse((HERE / "ORIGIN_PINS.json").read_bytes())
    for path, h in origins["files"].items():
        same(sha(path), h, "origin changed")
    pins = parse((HERE / "SOURCE_PINS.json").read_bytes())["files"]
    for row in pins:
        same(sha(row["path"]), row["sha256"], "cached source changed")
    for name in (
        "src/crypto.rs",
        "src/model.rs",
        "src/zero_pool.rs",
        "src/margin_controls.rs",
        "PROFILE.json",
        "SOURCE_PINS.json",
    ):
        same(
            (HERE / name).read_bytes(), (OLD / name).read_bytes(), "frozen core changed"
        )
    prefix = (OLD / "src/main.rs").read_bytes().split(b"\nfn main() {")[0]
    same(
        (HERE / "src/main.rs").read_bytes(),
        prefix + b'\n\ninclude!("expansion.rs");\n',
        "helper prefix changed",
    )
    for name in ("Cargo.toml", "Cargo.lock"):
        s = (
            (HERE / name)
            .read_text()
            .replace(
                "a176-common-mask-c1-expansion-gate",
                "a155-common-mask-egress-margin-control",
            )
        )
        same(s, (OLD / name).read_text(), "dependency changed")
    return dict(
        origin_pins=len(origins["files"]),
        cached_pins=len(pins),
        four_modules_identical=True,
        helper_prefix_identical=True,
        typechecked=False,
        fhe_executed=False,
    )


def freeze_check():
    source_check()
    for manifest in ("SOURCE_MANIFEST.json", "MANIFEST.json"):
        for name, h in parse((HERE / manifest).read_bytes())["files"].items():
            same(sha(HERE / name), h, "frozen file changed")
    same(
        (HERE / "SOURCE_DIGEST.txt").read_text().strip(),
        sha(HERE / "SOURCE_MANIFEST.json"),
        "source identity",
    )
    return dict(
        source_sha256=sha(HERE / "SOURCE_MANIFEST.json"),
        manifest_sha256=sha(HERE / "MANIFEST.json"),
    )


if __name__ == "__main__":
    print(json.dumps(source_check(), sort_keys=True))
