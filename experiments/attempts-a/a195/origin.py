"""Exact A192 producer-label successor mapping; no native calls or raw replay."""

from pathlib import Path
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NEEDLE = "                        address,\n                        0,\n                    );"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(raw, kind):
    if kind == "identical":
        return raw
    require(
        kind
        in {
            "identity_only",
            "identity_and_observer_keyset",
            "identity_and_origin_check",
        },
        "declared origin transformation",
    )
    text = raw.decode().replace("A192", "A195").replace("a192", "a195")
    text = text.replace("run192", "run195")
    if kind == "identity_and_observer_keyset":
        require(text.count(NEEDLE) == 1, "one original observer literal")
        text = text.replace(NEEDLE, NEEDLE.replace("0,", "keyset,"))
    if kind == "identity_and_origin_check":
        before = "def source_check():\n"
        require(text.count(before) == 1, "one source-check hook")
        text = text.replace(
            before, before + "    import origin\n\n    origin.verify()\n"
        )
    return text.encode()


def producer_label(source):
    calls = re.findall(
        r"coefficient_observer::observe\(\s*event\.switched\.as_ref\(\),"
        r"\s*small_secret\.as_ref\(\),\s*small_phase,\s*address,\s*([^,]+),\s*\)",
        source,
    )
    require(calls == ["keyset"], "observer consumes actual outer keyset")
    require(source.count("for keyset in 0..3usize {") == 1, "fixed three-key loop")
    require("let keyset" not in source, "no shadowed keyset")
    require(
        source.index("for keyset in 0..3usize {")
        < source.index("for fixture_index in 0..fixture_count {")
        < source.index("coefficient_observer::observe("),
        "observer lies inside key-major fixture loop",
    )
    require('"keyset":keyset,"case":fixture_index' in source, "event identity")
    require(
        '"keyset":0' not in source and '"case":0' not in source, "no fixed event labels"
    )


def verify():
    info = json.loads((HERE / "A192_ORIGIN.json").read_bytes())
    old = Path(info["origin_dir"])
    raw = (old / "SOURCE_MANIFEST.json").read_bytes()
    require(digest(raw) == info["source_sha256"], "frozen A192 source identity")
    require(
        raw == (HERE / "A192_SOURCE_MANIFEST.json").read_bytes(),
        "captured origin manifest",
    )
    manifest = json.loads(raw)
    for name, expected in manifest["files"].items():
        require(
            digest((old / name).read_bytes()) == expected, "frozen A192 leaf " + name
        )
    for name, row in info["files"].items():
        raw = (old / name).read_bytes()
        require(digest(raw) == row["origin_sha256"], "mapped origin " + name)
        require(
            (HERE / name).read_bytes() == transform(raw, row["transform"]),
            "exact successor " + name,
        )
    for name, expected in info["preserved_evidence"].items():
        require(
            digest(Path(name).read_bytes()) == expected,
            "preserved original evidence " + name,
        )
    producer_label((HERE / "src/gate.rs").read_text())
    return {
        "status": "EXACT_PRODUCER_LABEL_SUCCESSOR",
        "mapped_files": len(info["files"]),
        "byte_identical_files": sum(
            x["transform"] == "identical" for x in info["files"].values()
        ),
        "old_source_sha256": info["source_sha256"],
        "coefficients_checker_relaxed": False,
        "crypto_arithmetic_changed": False,
        "old_runtime_success_inherited": False,
        "actual_a195_runtime": False,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
