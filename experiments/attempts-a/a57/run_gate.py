#!/usr/bin/env python3
"""Fail-closed static and future component-FHE gate for isolated A41."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time
from types import ModuleType


ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE_ROOT = ROOT / "tmp" / "a57-a41-fhe-gate-design"
A41_ROOT = ROOT / "tmp" / "a41-combined-two-lwe-prototype"
PLAN_FILE = GATE_ROOT / "a41-gate-plan.json"
PIN_MANIFEST = GATE_ROOT / "a41-inputs.sha256"
TARGET_DIR = ROOT / "tmp" / "a38-combined-prototype" / "target"
TARGET_BINARY = TARGET_DIR / "release" / "a41_combined_two_lwe_prototype"
RESULTS_ROOT = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"
OUTPUT_STEM_RE = re.compile(
    r"exact_id_a41_component_gate_2026-09-02_gate[0-9]{2}"
)

EXPECTED_SOURCE_HASHES = {
    "tmp/a41-combined-two-lwe-prototype/.cargo/config.toml": (
        "8ea425180afe0e2fc0cd930d9a5dbd4da07aebe14263eeec4d6df9c7ab996a20"
    ),
    "tmp/a41-combined-two-lwe-prototype/Cargo.toml": (
        "011c4ba3851492ebb7198e63fc28eadeecf18cfb25ebe69a434717b4adf67cb8"
    ),
    "tmp/a41-combined-two-lwe-prototype/Cargo.lock": (
        "fe4b80f3495010bd4e5e16215ffd51ff04fdfffd0d5097c1b11a78233cc40689"
    ),
    "tmp/a41-combined-two-lwe-prototype/src/lib.rs": (
        "4b9fd53658be45c9f6870f77b3c7b934336941d4781ce31755cc699dec938514"
    ),
    "tmp/a41-combined-two-lwe-prototype/src/private_argmin.rs": (
        "8c9675e0019e106ad673e16e1a06ceed8ced35256d4b444335708cb87cfdfd35"
    ),
    "tmp/a41-combined-two-lwe-prototype/src/bin/a41_combined_two_lwe_prototype.rs": (
        "991b9a5c7db8d0b9243933fe202b6cd0f6d9a05deb9ea5101ce1e8f8d8036668"
    ),
    "tmp/a41-combined-two-lwe-prototype/a41_clear_and_count_model.py": (
        "e2edd204f3ada5fb0730b0213fed435833255b67c205345f311483fcbcd08b43"
    ),
    "tmp/a41-combined-two-lwe-prototype/tests/test_a41_clear_and_count_model.py": (
        "ce39bcd0cdfccb34c7f91ecfda0f42630d7f9e9460769e6b439602873e18e378"
    ),
    "tmp/a41-combined-two-lwe-prototype/README.md": (
        "30a064c9d80b068bcaf349f3b927ece11b3cb687168d9dcc1b7d30eb4f9af7df"
    ),
    "tmp/a38-combined-prototype/src/private_argmin.rs": (
        "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79"
    ),
    "experiments/14_pipeline_tfhe_rs/results/exact_id_a38_combined_component_fhe_2026-09-02.md": (
        "184f4b08a03b8d71f999466df8127bfb0afd7baa10c4f732934cdd59f01b0229"
    ),
    "experiments/14_pipeline_tfhe_rs/results/exact_id_a41_combined_two_lwe_static_2026-09-02.md": (
        "fa65c5e21ccd4687e29c13801f28870355835abea2260fd271d6c75a189ae55c"
    ),
    "experiments/14_pipeline_tfhe_rs/results/exact_id_formal_pfail_path_2026-09-02.md": (
        "2a7162be9025f1e0e5388eca8a056da69395ee5c354f75f4cdfe27db4f563f92"
    ),
}

GATE_SUPPORT_PATHS = {
    "tmp/a57-a41-fhe-gate-design/README.md",
    "tmp/a57-a41-fhe-gate-design/a41-gate-plan.json",
    "tmp/a57-a41-fhe-gate-design/run_gate.py",
    "tmp/a57-a41-fhe-gate-design/test_gate.py",
}

RUST_SOURCES = (
    A41_ROOT / "src" / "lib.rs",
    A41_ROOT / "src" / "private_argmin.rs",
    A41_ROOT / "src" / "bin" / "a41_combined_two_lwe_prototype.rs",
)

EXPECTED_DRY_PLAN = (
    "PLAN,variant=a41_combined_two_lwe,implemented=true,"
    "component_fhe_validated=false,N127_BR=3655,N127_KS=3274,"
    "N127_marginals=4206,wire_output_lwes=2,root_delta_log=59,"
    "client_reconstruction=low+16*high,linear_postprocessing=false"
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_repository_file(relative: str) -> pathlib.Path:
    candidate = pathlib.PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"unsafe pinned path: {relative!r}")
    path = ROOT.joinpath(*candidate.parts).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise RuntimeError(f"pinned path escapes repository: {relative!r}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"pinned A41 input missing: {relative}")
    return path


def pinned_inputs() -> dict[str, str]:
    if not PIN_MANIFEST.is_file():
        raise FileNotFoundError(f"A41 pin manifest missing: {PIN_MANIFEST}")
    records: dict[str, str] = {}
    for line_number, line in enumerate(PIN_MANIFEST.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise RuntimeError(f"malformed pin manifest line {line_number}")
        expected, relative = match.groups()
        if relative in records:
            raise RuntimeError(f"duplicate pinned path: {relative}")
        actual = sha256_file(safe_repository_file(relative))
        if actual != expected:
            raise RuntimeError(
                f"pinned A41 input changed: {relative}: "
                f"expected={expected}, actual={actual}"
            )
        records[relative] = actual
    expected_paths = set(EXPECTED_SOURCE_HASHES) | GATE_SUPPORT_PATHS
    if set(records) != expected_paths:
        raise RuntimeError(
            "A41 pin manifest has incomplete or extra scope: "
            f"missing={sorted(expected_paths - set(records))}, "
            f"extra={sorted(set(records) - expected_paths)}"
        )
    critical_mismatches = {
        path: {"expected": expected, "observed": records.get(path)}
        for path, expected in EXPECTED_SOURCE_HASHES.items()
        if records.get(path) != expected
    }
    if critical_mismatches:
        raise RuntimeError(f"A41 critical provenance mismatch: {critical_mismatches}")
    return records


def load_json_object(path: pathlib.Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object")
    return value


def load_model() -> ModuleType:
    path = A41_ROOT / "a41_clear_and_count_model.py"
    spec = importlib.util.spec_from_file_location("_a57_a41_model", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load pinned A41 model: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def integer_fields(record: dict[str, object], names: tuple[str, ...]) -> tuple[int, ...]:
    values = tuple(record.get(name) for name in names)
    if any(type(value) is not int for value in values):
        raise RuntimeError(f"non-integer gate fields {names}: {values}")
    return values  # type: ignore[return-value]


def expected_cases(plan: dict[str, object], suite: str) -> dict[str, dict[str, int]]:
    if suite == "focused":
        section = plan.get("focused_large_suite")
        if not isinstance(section, dict) or not isinstance(section.get("cases"), dict):
            raise RuntimeError("focused A41 plan is incomplete")
        result: dict[str, dict[str, int]] = {}
        for name, raw_record in section["cases"].items():
            if not isinstance(name, str) or not isinstance(raw_record, dict):
                raise RuntimeError("focused A41 case is malformed")
            gallery_size, code, low, high = integer_fields(
                raw_record, ("gallery_size", "code", "low", "high")
            )
            result[name] = {
                "gallery_size": gallery_size,
                "code": code,
                "low": low,
                "high": high,
            }
        if section.get("expected_cases") != len(result):
            raise RuntimeError("focused A41 case count is inconsistent")
        return result

    if suite != "small":
        raise ValueError(f"unknown A41 suite: {suite}")
    section = plan.get("small_suite")
    if not isinstance(section, dict):
        raise RuntimeError("small A41 plan is incomplete")
    high_categories = section.get("high_category_cases")
    additional = section.get("additional_cases")
    if not isinstance(high_categories, dict) or not isinstance(additional, dict):
        raise RuntimeError("small A41 case definitions are incomplete")
    first, last, accepted_through, gallery_size = integer_fields(
        high_categories, ("first", "last", "accepted_through", "gallery_size")
    )
    if (first, last, accepted_through, gallery_size) != (0, 15, 3, 1):
        raise RuntimeError("small A41 high-category sweep is non-canonical")
    result = {}
    for high in range(first, last + 1):
        code = int(high <= accepted_through)
        result[f"n1_high_category_{high}"] = {
            "gallery_size": 1,
            "code": code,
            "low": code,
            "high": 0,
        }
    for name, raw_record in additional.items():
        if not isinstance(name, str) or not isinstance(raw_record, dict):
            raise RuntimeError("additional small A41 case is malformed")
        gallery_size, code, low, high = integer_fields(
            raw_record, ("gallery_size", "code", "low", "high")
        )
        result[name] = {
            "gallery_size": gallery_size,
            "code": code,
            "low": low,
            "high": high,
        }
    if section.get("expected_cases") != len(result):
        raise RuntimeError("small A41 case count is inconsistent")
    return result


def validate_plan(plan: dict[str, object], model: ModuleType) -> dict[str, object]:
    if (
        plan.get("schema_version") != 1
        or plan.get("candidate") != "A41 terminal-only two-LWE"
        or plan.get("scope") != "isolated component FHE gate"
    ):
        raise RuntimeError("A41 gate plan identity is non-canonical")
    terminal = plan.get("terminal_representation")
    expected_terminal = {
        "wire_output_lwes": 2,
        "root_delta_log": 59,
        "low_plaintext": "code mod 16",
        "high_plaintext": "floor(code / 16)",
        "client_reconstruction": "low + 16 * high",
        "linear_encrypted_postprocessing": False,
        "valid_code_range": [0, 128],
        "semantics": "0=reject; i+1=first exact nearest accepted identity",
    }
    if terminal != expected_terminal:
        raise RuntimeError("A41 terminal representation plan is non-canonical")
    anchors = plan.get("count_anchors")
    if not isinstance(anchors, dict):
        raise RuntimeError("A41 count anchors missing")
    observed_anchors = {}
    for gallery_size in (127, 128):
        counts = model.a41_counts(gallery_size)
        observed = {
            "blind_rotations": counts.blind_rotations,
            "key_switches": counts.key_switches,
            "output_marginals": counts.output_marginals,
        }
        if anchors.get(f"N{gallery_size}") != observed:
            raise RuntimeError(f"A41 N={gallery_size} count anchor mismatch")
        observed_anchors[f"N{gallery_size}"] = observed
    probability = plan.get("probability_boundary")
    if (
        not isinstance(probability, dict)
        or probability.get("end_to_end_pfail_certificate") is not False
        or "conditional only" not in str(probability.get("terminal_pfail"))
    ):
        raise RuntimeError("A41 p-fail boundary is not explicit or fail-closed")
    expected_cases(plan, "small")
    expected_cases(plan, "focused")
    return {
        "terminal_representation": terminal,
        "count_anchors": observed_anchors,
        "probability_boundary": probability,
    }


def validate_source_shape() -> None:
    core = (A41_ROOT / "src" / "private_argmin.rs").read_text()
    harness = (
        A41_ROOT / "src" / "bin" / "a41_combined_two_lwe_prototype.rs"
    ).read_text()
    core_tokens = (
        "pub struct PrivateArgminTwoLweOutput",
        "pub low_nibble: Lwe",
        "pub high_nibble: Lwe",
        "PrivateArgminError::TwoLweRequiresAlignedUniformFastPath",
        "AlignedWireFormat::TwoP16Digits => bool_delta",
        "AlignedWireFormat::TwoP16Digits if slot <= 8 => slot",
        "debug_assert!(output.code.is_none())",
        "let code = if wire_format == AlignedWireFormat::SingleCode",
    )
    harness_tokens = (
        EXPECTED_DRY_PLAN,
        "private_argmin_two_lwe_with_trace",
        "let code = low + 16 * high;",
        "trace.final_code.is_none()",
        'name: "n127_all_reject"',
        'name: "n128_tail_tie_first_127"',
        "last_identity_case(127)",
        "last_identity_case(128)",
        "secret_material_persisted=false",
    )
    missing_core = [token for token in core_tokens if token not in core]
    missing_harness = [token for token in harness_tokens if token not in harness]
    if missing_core or missing_harness:
        raise RuntimeError(
            f"A41 source shape mismatch: core={missing_core}, harness={missing_harness}"
        )


def static_validation(*, exhaustive: bool) -> dict[str, object]:
    pins = pinned_inputs()
    plan = load_json_object(PLAN_FILE, "A41 gate plan")
    model = load_model()
    plan_summary = validate_plan(plan, model)
    validate_source_shape()
    boundary_results = {
        "reject_N128": model.evaluate((0,) * 128).code,
        "ID127": model.evaluate((0,) * 126 + (1, 0)).code,
        "ID128": model.evaluate((0,) * 127 + (1,)).code,
        "tail_tie": model.evaluate((0,) * 126 + (1, 1)).code,
    }
    if boundary_results != {
        "reject_N128": 0,
        "ID127": 127,
        "ID128": 128,
        "tail_tie": 127,
    }:
        raise RuntimeError(f"A41 reconstruction boundary mismatch: {boundary_results}")
    exhaustive_summary = model.validate() if exhaustive else None
    return {
        "status": "PASS",
        "scope": "static_only_no_cargo_no_keygen_no_fhe",
        "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
        "pinned_files": len(pins),
        "source_sha256": {
            path: pins[path] for path in sorted(EXPECTED_SOURCE_HASHES)
        },
        **plan_summary,
        "boundary_reconstruction": boundary_results,
        "exhaustive_clear_model": exhaustive_summary,
    }


def cargo_commands() -> list[tuple[str, list[str], pathlib.Path]]:
    common = ["--locked", "--offline", "--release", "--features", "diagnostic-trace"]
    return [
        (
            "rustfmt",
            ["rustfmt", "--edition", "2021", "--check", *map(str, RUST_SOURCES)],
            ROOT,
        ),
        ("lib-tests", ["cargo", "test", *common, "--lib"], A41_ROOT),
        (
            "harness-tests",
            [
                "cargo",
                "test",
                *common,
                "--bin",
                "a41_combined_two_lwe_prototype",
            ],
            A41_ROOT,
        ),
        (
            "build",
            [
                "cargo",
                "build",
                *common,
                "--bin",
                "a41_combined_two_lwe_prototype",
            ],
            A41_ROOT,
        ),
        ("dry-plan", [str(TARGET_BINARY)], ROOT),
        ("small-fhe", [str(TARGET_BINARY), "--run", "--small-only"], ROOT),
        (
            "focused-fhe",
            [
                str(TARGET_BINARY),
                "--run",
                "--case=n127_last_identity",
                "--case=n128_last_identity",
                "--case=n128_tail_tie_first_127",
                "--case=n127_all_reject",
            ],
            ROOT,
        ),
    ]


def artifact_paths(stem: pathlib.Path) -> dict[str, pathlib.Path]:
    labels = [label for label, _, _ in cargo_commands()]
    paths = {
        label: stem.with_name(f"{stem.name}-{label}.log") for label in labels
    }
    paths["summary"] = stem.with_suffix(".json")
    return paths


def validate_output_stem(value: pathlib.Path) -> pathlib.Path:
    stem = value.resolve()
    if (
        stem.parent != RESULTS_ROOT
        or stem.suffix
        or OUTPUT_STEM_RE.fullmatch(stem.name) is None
    ):
        raise RuntimeError(
            "--output-stem must be an extensionless collision-scoped A41 gate stem "
            f"under {RESULTS_ROOT}"
        )
    collisions = [path for path in artifact_paths(stem).values() if path.exists()]
    if collisions:
        raise FileExistsError(
            "A41 gate artifacts already exist; use the next _gateNN stem: "
            + ", ".join(str(path) for path in collisions)
        )
    return stem


def parse_fields(line: str, prefix: str) -> dict[str, str]:
    if not line.startswith(prefix):
        raise RuntimeError(f"line does not start with {prefix!r}: {line!r}")
    fields: dict[str, str] = {}
    for item in line.split(",")[1:]:
        if "=" not in item:
            raise RuntimeError(f"malformed A41 output field: {item!r}")
        name, value = item.split("=", 1)
        if not name or name in fields:
            raise RuntimeError(f"duplicate/empty A41 output field: {name!r}")
        fields[name] = value
    return fields


def validate_fhe_output(
    text: str,
    expected: dict[str, dict[str, int]],
    model: ModuleType,
) -> dict[str, object]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    key_lines = [line for line in lines if line.startswith("KEY,")]
    summary_lines = [line for line in lines if line.startswith("SUMMARY,")]
    pass_lines = [line for line in lines if line.startswith("PASS,case=")]
    if len(key_lines) != 1 or len(summary_lines) != 1 or len(pass_lines) != len(expected):
        raise RuntimeError(
            "A41 FHE output cardinality mismatch: "
            f"keys={len(key_lines)}, summaries={len(summary_lines)}, "
            f"passes={len(pass_lines)}, expected={len(expected)}"
        )
    key_fields = parse_fields(key_lines[0], "KEY,")
    if (
        key_fields.get("ephemeral") != "true"
        or key_fields.get("secret_material_persisted") != "false"
    ):
        raise RuntimeError("A41 harness did not attest ephemeral in-memory keys")
    summary_fields = parse_fields(summary_lines[0], "SUMMARY,")
    if summary_fields != {
        "status": "PASS",
        "cases": str(len(expected)),
        "keys": "ephemeral_in_memory",
        "secret_material_persisted": "false",
    }:
        raise RuntimeError(f"A41 FHE summary mismatch: {summary_fields}")

    observed: dict[str, dict[str, int]] = {}
    for line in pass_lines:
        fields = parse_fields(line, "PASS,case=")
        name = fields.get("case")
        if not name or name in observed or name not in expected:
            raise RuntimeError(f"unexpected or duplicate A41 fixture: {name!r}")
        numeric_names = (
            "N",
            "code",
            "low",
            "high",
            "pbs",
            "ks",
            "marginals",
            "wire_lwes",
            "root_delta_log",
        )
        try:
            numeric = {field: int(fields[field]) for field in numeric_names}
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"malformed numeric A41 fixture: {name}") from exc
        case_expected = expected[name]
        if any(
            numeric[field] != case_expected[field]
            for field in ("code", "low", "high")
        ) or numeric["N"] != case_expected["gallery_size"]:
            raise RuntimeError(
                f"A41 fixture oracle mismatch for {name}: {numeric}, {case_expected}"
            )
        counts = model.a41_counts(numeric["N"])
        if (
            numeric["pbs"],
            numeric["ks"],
            numeric["marginals"],
        ) != (counts.blind_rotations, counts.key_switches, counts.output_marginals):
            raise RuntimeError(f"A41 structural counts mismatch for {name}: {numeric}")
        if (
            numeric["code"] != numeric["low"] + 16 * numeric["high"]
            or not 0 <= numeric["low"] <= 15
            or not 0 <= numeric["high"] <= 8
            or numeric["wire_lwes"] != 2
            or numeric["root_delta_log"] != 59
            or fields.get("linear_postprocessing") != "false"
        ):
            raise RuntimeError(f"A41 terminal reconstruction mismatch for {name}")
        observed[name] = numeric
    if set(observed) != set(expected):
        raise RuntimeError("A41 FHE output omitted one or more expected fixtures")
    return {
        "cases": len(observed),
        "case_results": observed,
        "ephemeral_key_attested": True,
        "two_lwe_exact_reconstruction_verified": True,
    }


def run_command(
    label: str,
    command: list[str],
    cwd: pathlib.Path,
    log_path: pathlib.Path,
    environment: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed = time.perf_counter() - started
    log_path.write_text(
        json.dumps({"label": label, "command": command, "cwd": str(cwd)})
        + "\n--- stdout ---\n"
        + result.stdout
        + "\n--- stderr ---\n"
        + result.stderr
    )
    return result, elapsed


def execute_gate(output_stem: pathlib.Path) -> int:
    stem = validate_output_stem(output_stem)
    static_before = static_validation(exhaustive=True)
    plan = load_json_object(PLAN_FILE, "A41 gate plan")
    model = load_model()
    paths = artifact_paths(stem)
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    environment["CARGO_NET_OFFLINE"] = "true"
    started = dt.datetime.now(dt.timezone.utc)
    command_records = []
    outputs: dict[str, str] = {}
    success = False
    failure: str | None = None
    binary = None
    validations: dict[str, object] = {}
    try:
        for label, command, cwd in cargo_commands():
            result, elapsed = run_command(
                label, command, cwd, paths[label], environment
            )
            command_records.append(
                {
                    "label": label,
                    "command": command,
                    "cwd": str(cwd),
                    "exit_code": result.returncode,
                    "elapsed_s": round(elapsed, 6),
                    "log": str(paths[label]),
                    "log_sha256": sha256_file(paths[label]),
                }
            )
            outputs[label] = result.stdout
            if result.returncode != 0:
                raise RuntimeError(f"A41 gate step failed: {label}")
            if label == "build":
                pinned_inputs()
                if not TARGET_BINARY.is_file():
                    raise FileNotFoundError(
                        f"compiled A41 binary missing: {TARGET_BINARY}"
                    )
                binary = {
                    "path": str(TARGET_BINARY),
                    "bytes": TARGET_BINARY.stat().st_size,
                    "sha256": sha256_file(TARGET_BINARY),
                }

        dry_lines = [line.strip() for line in outputs["dry-plan"].splitlines() if line.strip()]
        if dry_lines != [EXPECTED_DRY_PLAN]:
            raise RuntimeError(f"A41 dry plan mismatch: {dry_lines}")
        validations["small"] = validate_fhe_output(
            outputs["small-fhe"], expected_cases(plan, "small"), model
        )
        validations["focused"] = validate_fhe_output(
            outputs["focused-fhe"], expected_cases(plan, "focused"), model
        )
        static_after = static_validation(exhaustive=False)
        if static_after["source_sha256"] != static_before["source_sha256"]:
            raise RuntimeError("A41 sources changed during compile/FHE gate")
        success = True
    except Exception as exc:  # preserve bounded diagnostics for a failed future run
        failure = f"{type(exc).__name__}: {exc}"

    finished = dt.datetime.now(dt.timezone.utc)
    summary = {
        "schema_version": 1,
        "success": success,
        "failure": failure,
        "scope": "A41 isolated component FHE; no service/wire integration",
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "wall_s": round((finished - started).total_seconds(), 6),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "static_before": static_before,
        "compiled_binary": binary,
        "commands": command_records,
        "validations": validations,
        "terminal_representation_result": (
            "exact on observed fixtures" if success else "not established"
        ),
        "terminal_pfail_result": (
            "conditional nominal p16 union bound only; not measured by fixtures"
        ),
        "end_to_end_pfail_certificate": False,
    }
    paths["summary"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if success else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-only", action="store_true")
    modes.add_argument("--print-run-plan", action="store_true")
    modes.add_argument("--run", action="store_true")
    parser.add_argument("--output-stem", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.run != (arguments.output_stem is not None):
        parser.error("--run requires --output-stem, and --output-stem is run-only")
    return arguments


def main() -> int:
    arguments = parse_args()
    if arguments.verify_only:
        print(json.dumps(static_validation(exhaustive=True), indent=2, sort_keys=True))
        return 0
    if arguments.print_run_plan:
        static_validation(exhaustive=False)
        print(
            json.dumps(
                [
                    {"label": label, "command": command, "cwd": str(cwd)}
                    for label, command, cwd in cargo_commands()
                ],
                indent=2,
            )
        )
        return 0
    return execute_gate(arguments.output_stem)


if __name__ == "__main__":
    raise SystemExit(main())
