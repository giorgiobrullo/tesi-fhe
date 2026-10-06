"""Frozen P0 public-tuple adapter for A156's conditional ideal model only."""

import argparse
from datetime import datetime, timedelta
from fractions import Fraction
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError("A163 refuses optimized Python")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODEL_DIR = ROOT / "tmp/a156-initial-ks-joint-mgf"
PUBLIC_KEYS = {
    "schema",
    "tfhe_version",
    "input_kind",
    "public_offset_words",
    "first_low_bit",
    "reference_degree",
    "safe_lifts",
    "input_mask_words",
    "digits_descending",
    "remainder_words",
    "subgroup_g",
    "template",
}
TEMPLATE = [0] * 512
for _i, _v in ((0, 1), (1, -1), (255, 1), (511, 1)):
    TEMPLATE[_i] = _v
RUNTIME_NAMES = (
    "trace.json",
    "before-ks.json",
    "key-binding.json",
    "prepared.json",
    "started.json",
    "completed.json",
    "exit.json",
    "child.json",
)


def need(condition, label):
    if not condition:
        raise ValueError(label)


def same(got, wanted, label):
    need(type(got) is type(wanted), label + ": type")
    if type(wanted) is dict:
        need(got.keys() == wanted.keys(), label + ": keys")
        for key in wanted:
            same(got[key], wanted[key], label + "." + key)
    elif type(wanted) is list:
        need(len(got) == len(wanted), label + ": length")
        for i, value in enumerate(wanted):
            same(got[i], value, f"{label}[{i}]")
    else:
        need(got == wanted, label)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_number(_):
    raise ValueError("floating/nonfinite JSON values forbidden")


def decode(text):
    return json.loads(
        text,
        object_pairs_hook=pairs,
        parse_float=reject_number,
        parse_constant=reject_number,
    )


def private(path, directory=False):
    need(not path.is_symlink(), "symlink refused")
    need(path.is_dir() if directory else path.is_file(), "missing private path")
    need(
        path.stat().st_mode & 0o777 == (0o700 if directory else 0o600),
        "private mode required",
    )


def read(path, sensitive=False):
    if sensitive:
        private(path)
    return decode(path.read_text())


def verify_pins():
    pins = read(HERE / "SOURCE_PINS.json")["sources"]
    for name, digest in pins.items():
        same(sha(Path(name)), digest, "source pin " + name)
    return len(pins)


def load_model():
    verify_pins()
    sys.path.insert(0, str(MODEL_DIR))
    spec = importlib.util.spec_from_file_location(
        "a163_frozen_a156", MODEL_DIR / "model.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.verify_sources()
    same(
        list(module.LAMBDAS),
        [Fraction(1, 4), Fraction(1, 2), Fraction(1), Fraction(2)],
        "frozen lambda grid",
    )
    return module


def public_context(public, model, synthetic=False):
    need(type(public) is dict and public.keys() == PUBLIC_KEYS, "public schema keys")
    constants = dict(
        schema="a156.initial-low-ks.public.v1",
        tfhe_version="1.7.0",
        input_kind="synthetic" if synthetic else "client_observed_public_input",
        public_offset_words=1 << 62,
        first_low_bit=1,
        reference_degree=3072,
        safe_lifts=[-1024, 1023],
        template=TEMPLATE,
    )
    for key, value in constants.items():
        same(public[key], value, "public " + key)
    for key in ("input_mask_words", "remainder_words", "digits_descending"):
        need(type(public[key]) is list and len(public[key]) == 2048, "geometry " + key)
    for word in public["input_mask_words"]:
        need(
            type(word) is int and 0 <= word < 1 << 64 and word % 16 == 0,
            "native shifted word",
        )
    for remainder in public["remainder_words"]:
        need(type(remainder) is int, "integer remainder")
    for row in public["digits_descending"]:
        need(type(row) is list and len(row) == 5, "descending five levels")
        need(all(type(d) is int and -4 <= d <= 4 for d in row), "signed native digits")
    need(type(public["subgroup_g"]) is int, "integer subgroup")
    context = model.native_context(public)
    same(
        list(context.input_noise_coefficients),
        [-16 * t for t in TEMPLATE],
        "input coefficients",
    )
    same(context.theta, 0, "center theta")
    return context


def encoded(value):
    if isinstance(value, Fraction):
        return str(value)
    if type(value) is dict:
        return {k: encoded(v) for k, v in value.items()}
    if type(value) in (list, tuple):
        return [encoded(v) for v in value]
    return value


def calculate(public, model, synthetic=False):
    context = public_context(public, model, synthetic)
    result = model.bound(context, model.LAMBDAS)
    result.update(
        adapter_schema="a163.conditional-p0-evaluation.v1",
        evidence_kind="SYNTHETIC_COEFFICIENT_TEST"
        if synthetic
        else "ACTUAL_PUBLIC_TUPLE_CONDITIONAL_MODEL",
        interpretation="Counterfactual ideal-model bound at the observed public coefficients: leaving the registered first-LUT safe lifted interval under A156 premises, conditional only on the fixed pre-feedback input mask/template.",
        selected_observed_success_is_not_a_conditioning_event=True,
        native_decode_failure_bound=False,
        fixed_key_bound=False,
        finite_sampler_bound=False,
        full_pipeline_bound=False,
        actual_p_fail=None,
        missing_runtime_premises=[
            "Both independent fair binary secrets remain independent of the fixed pre-feedback input mask.",
            "Input GLWE and KSK row noises are mutually independent exact centered real Gaussians with the pinned binary64 sigma values, nearest-rounded to integer lifts, independent of secrets and masks.",
            "All KSK row mask coordinates are iid uniform native words conditional on that input mask, both secrets, and every noise value.",
            "Transfer to the finite implementation requires a justified comparison/domination or replacement model, with computational, rejection/abort and compiled rounding terms. A finite sampler cannot literally equal this unbounded Gaussian iid law; no transfer result is present.",
        ],
    )
    return encoded(result)


def expected_validation(public, validation):
    need(type(validation) is dict, "validation object")
    same(validation["a156_public_input"], public, "export equals saved replay")
    true_fields = (
        "public_coefficients_and_domains_pass",
        "phase_component_modular_closure_pass",
        "native_first_bit_decode_pass",
        "conditional_lut_address_pass",
        "selected_prefix_gate_pass",
        "actual_public_product_and_sample_pass",
        "used_row_contribution_replay_pass",
        "source_order_does_not_attest_runtime_chronology",
    )
    false_fields = (
        "independently_attested_client_aggregates",
        "actual_secret_key_membership_attested",
        "full_n4_evaluation",
        "blind_rotation_consumed",
        "ideal_gaussian_integer_lifts_attested",
        "independently_attested_row_decryption",
        "producer_full_n4_scope",
    )
    same(validation["status"], "CONDITIONAL_CLIENT_ARITHMETIC_CLOSURE", "replay status")
    for key in true_fields:
        same(validation[key], True, key)
    for key in false_fields:
        same(validation[key], False, key)
    same(validation["actual_sampler_p_fail"], None, "no actual sampler bound")
    address, lift = validation["direct_address"], validation["displacement_lift"]
    need(type(address) is int and type(lift) is int, "address/lift integer")
    need(2048 <= address < 4096 and address == (3072 + lift) % 4096, "saved address")
    expected_keys = set(true_fields + false_fields) | {
        "status",
        "actual_sampler_p_fail",
        "a156_public_input",
        "direct_address",
        "displacement_lift",
        "runtime_files_sha256",
    }
    need(validation.keys() == expected_keys, "saved replay exact schema")


def runtime_input(producer, run, binary_digest, model):
    registry = read(HERE / "PRODUCERS.json")["producers"]
    need(producer in registry, "producer not preregistered")
    config = registry[producer]
    base = Path(config["directory"])
    need(
        run.is_absolute() and run == run.resolve() and run.parent == base / "runs",
        "canonical producer run",
    )
    need(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", run.name) is not None, "run ID"
    )
    private(run.parent, True)
    private(run, True)
    manifest = read(base / "SOURCE_MANIFEST.json")
    manifest_id = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    same(manifest_id, config["source_sha256"], "registered producer source")
    for name, digest in manifest.items():
        same(sha(base / name), digest, "producer source leaf")
    same(
        (base / "candidate/SOURCE_DIGEST.txt").read_text().strip(),
        manifest_id,
        "embedded source",
    )
    need(re.fullmatch("[0-9a-f]{64}", binary_digest) is not None, "binary digest")
    binary = base / config["binary_relative"]
    same(sha(binary), binary_digest, "actual binary")
    public = read(run / "a156-public-input.json", True)
    validation = read(run / "validation.json", True)
    public_context(public, model)
    expected_validation(public, validation)
    for name in RUNTIME_NAMES:
        private(run / name)
    hashes = {name: sha(run / name) for name in RUNTIME_NAMES}
    same(validation["runtime_files_sha256"], hashes, "saved replay binds raw files")
    records = {
        name: read(run / name, True)
        for name in (
            "trace.json",
            "key-binding.json",
            "prepared.json",
            "started.json",
            "completed.json",
            "exit.json",
            "child.json",
        )
    }
    prepared, started, exit_record, child = (
        records[name]
        for name in (
            "prepared.json",
            "started.json",
            "exit.json",
            "child.json",
        )
    )
    for envelope in (
        prepared,
        started,
        exit_record,
        child,
        records["key-binding.json"],
        records["trace.json"]["bindings"],
    ):
        for key, value in dict(
            run_id=run.name, source_sha256=manifest_id, binary_sha256=binary_digest
        ).items():
            same(envelope[key], value, "envelope " + key)
    same(
        prepared["command"],
        [str(binary), "--run-authorized", str(run), run.name],
        "command",
    )
    same(prepared["status"], "PREPARED", "prepared")
    for key, value in dict(
        timed_benchmark=False,
        no_automatic_retries=True,
        workload_check_is_external_root_obligation=True,
    ).items():
        same(prepared[key], value, key)
    same(started["schema"], config["started_schema"], "producer started schema")
    same(started["timed_benchmark"], False, "untimed")
    same(started["secret_material_persisted"], False, "no raw secret file")
    same(exit_record["exit_code"], 0, "terminal exit")
    same(exit_record["status"], "EXITED", "terminal status")
    for key in ("binary_unchanged", "source_unchanged"):
        same(exit_record[key], True, key)
    pid = started["pid"]
    need(type(pid) is int and pid > 0, "child PID")
    same(child["child_pid"], pid, "child launch PID")
    same(exit_record["child_pid"], pid, "child exit PID")
    times = [
        datetime.fromisoformat(x)
        for x in (
            prepared["prepared_at_utc"],
            child["started_at_utc"],
            exit_record["exited_at_utc"],
        )
    ]
    need(
        all(t.utcoffset() == timedelta(0) for t in times) and times == sorted(times),
        "UTC lifecycle order",
    )
    for name in ("stdout.log", "stderr.log"):
        private(run / name)
        hashes[name] = sha(run / name)
        same(
            exit_record[name.replace(".log", "_sha256")],
            hashes[name],
            "terminal log hash",
        )
    same(
        records["completed.json"],
        dict(
            status="P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS",
            ordinary_ks=1,
            configured_ms=1,
            blind_rotations=0,
            actual_sampler_p_fail=None,
            independent_replay_pending=True,
        ),
        "P0 completion",
    )
    trace = records["trace.json"]
    same(trace["schema"], "a158.first_low_ks_trace.v1", "trace schema")
    same(trace["kind"], "client_observed", "trace kind")
    same(trace["bindings"]["configuration"], "Standard", "switch configuration")
    same(
        trace["bindings"]["parameter_fingerprint"],
        config["parameter_fingerprint"],
        "parameters",
    )
    same(
        trace["fixture"], read(base / "candidate/FIXTURE.json"), "fixed source fixture"
    )
    ct = trace["ciphertexts"]["ks_input"]
    words = ct["words_hex"]
    need(type(words) is list and len(words) == 2049, "public KS ciphertext geometry")
    need(
        all(type(x) is str and re.fullmatch("[0-9a-f]{16}", x) for x in words),
        "native hex",
    )
    native = [int(x, 16) for x in words]
    same(
        hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in native)).hexdigest(),
        ct["sha256"],
        "KS ciphertext digest",
    )
    same(native[:-1], public["input_mask_words"], "export uses actual KS input mask")
    provenance = dict(
        producer=producer,
        run_id=run.name,
        source_sha256=manifest_id,
        binary_sha256=binary_digest,
        supplied_record_binding_pass=True,
        operating_system_execution_attested=False,
        independent_phase_replay_performed=False,
        saved_replay_record_consistency_only=True,
        observed_prefix_pass_not_model_premise=True,
        raw_files_sha256=hashes,
        public_export_sha256=sha(run / "a156-public-input.json"),
        saved_replay_sha256=sha(run / "validation.json"),
    )
    return public, validation, provenance


def write_new(path, value):
    data = (json.dumps(encoded(value), indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def verify_freeze():
    manifest = read(HERE / "MANIFEST.json")["files"]
    for name, digest in manifest.items():
        same(sha(HERE / name), digest, "adapter freeze " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("plan")
    actual = sub.add_parser("evaluate")
    actual.add_argument("--producer", required=True)
    actual.add_argument("--run", type=Path, required=True)
    actual.add_argument("--binary-sha256", required=True)
    actual.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    verify_freeze()
    model = load_model()
    if args.mode == "plan":
        print(
            json.dumps(
                dict(
                    status="FROZEN_CONDITIONAL_ADAPTER_ONLY",
                    actual_p_fail=None,
                    actual_data_read=False,
                    rules_sha256=sha(HERE / "RULES.json"),
                )
            )
        )
        return
    output = args.output_dir
    need(
        output.is_absolute()
        and output == output.resolve()
        and output.parent == HERE / "artifacts"
        and not output.exists(),
        "new owned output directory",
    )
    private(output.parent, True)
    # Exclusive receipt precedes data access. A failed attempt remains visible and cannot
    # be overwritten. It is not automatic retry authorization or a global one-run lock.
    output.mkdir(mode=0o700)
    write_new(
        output / "ATTEMPT.json",
        dict(
            status="STARTED",
            producer=args.producer,
            run=str(args.run),
            adapter_manifest_sha256=sha(HERE / "MANIFEST.json"),
        ),
    )
    public, validation, provenance = runtime_input(
        args.producer, args.run, args.binary_sha256, model
    )
    write_new(
        output / "INPUTS.json",
        dict(
            public_input=public,
            provenance=provenance,
            saved_validation=validation,
            rules=read(HERE / "RULES.json"),
        ),
    )
    result = calculate(public, model)
    result["provenance"] = provenance
    result["adapter_manifest_sha256"] = sha(HERE / "MANIFEST.json")
    result["inputs_sha256"] = sha(output / "INPUTS.json")
    write_new(output / "RESULT.json", result)
    write_new(
        output / "COMPLETED.json",
        dict(
            status="CONDITIONAL_EVALUATION_COMPLETE",
            result_sha256=sha(output / "RESULT.json"),
            inputs_sha256=sha(output / "INPUTS.json"),
            actual_p_fail=None,
        ),
    )
    print(
        json.dumps(
            dict(
                status="CONDITIONAL_EVALUATION_COMPLETE",
                actual_p_fail=None,
                result_sha256=sha(output / "RESULT.json"),
            )
        )
    )


if __name__ == "__main__":
    main()
