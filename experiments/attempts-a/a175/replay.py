"""A175 source-bound raw structure/arithmetic replay; no launcher or OS attestation."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
import model as m  # noqa: E402 - disable bytecode before loading task modules

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = HERE.parent / "a169-low-correction-b0-b1-repair"
OLD_SCHEMA = "a169.low_b0_b1_direct_scale.v1"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def frozen_producer():
    # These frozen modules use absolute sibling imports. Restore caller modules
    # after construction; function globals retain their original model objects.
    names = ("model", "arithmetic", "a175_frozen_producer_validator")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        load_module("model", OLD / "runtime-validation/model.py")
        load_module("arithmetic", OLD / "runtime-validation/arithmetic.py")
        return load_module(names[2], OLD / "runtime-validation/validate.py")
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def source_check():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for path, expected in pins["files"].items():
        m.eq(sha(path), expected, "frozen input " + path)
    source_id = sha(HERE / "SOURCE_MANIFEST.json")
    m.eq(
        (HERE / "candidate/SOURCE_DIGEST.txt").read_text().strip(),
        source_id,
        "embedded A175 source",
    )
    files = json.loads((HERE / "SOURCE_MANIFEST.json").read_text())["files"]
    for path, expected in files.items():
        m.eq(sha(HERE / path), expected, "A175 leaf " + path)
    old = frozen_producer()
    old.verify_sources()
    old.verify_arithmetic_reuse()
    old.verify_validator_manifest()
    return source_id, files


def plan_record():
    expected = dict(
        schema=m.SCHEMA,
        record="consumer_plan",
        stage="smoke",
        keysets=1,
        producer_schema=OLD_SCHEMA,
        consumer_arms=list(m.ARMS),
        scores=28,
        consumer_states_per_arm_per_score=28,
        consumer_calls=1568,
        candidate_encryptions=784,
        consumer_ks=1568,
        consumer_traced_br=1568,
        consumer_stock_br=1568,
        consumer_samples=3136,
        producer_br=1988,
        producer_ks=1792,
        producer_samples_including_score_extraction=2884,
        total_br=5124,
        total_ks=3360,
        total_samples=6020,
        total_records=17703,
        candidate_provenance="fresh_client_lwe_not_prior_selector_round",
        first_key_only=True,
        automatic_retry=False,
        automatic_expansion=False,
        native_zero_mask_branch_retained=True,
        stock_equivalence_required=True,
        p_fail_certified=False,
        latency_claim_allowed=False,
    )
    return expected


def check_plan(row):
    m.eq(row, plan_record(), "exact A175 preregistered plan")


def bind_observation_aliases(row, aliases):
    """Same public ciphertext and key domain must retain the same client relation."""
    for name in (
        "candidate_lwe",
        "weighted_lwe",
        "encoded_lwe",
        "post_ks_lwe",
        "output_lwe",
    ):
        node = row[name]
        domain = "small" if name == "post_ks_lwe" else "big"
        key = (domain, node["sha256"])
        value = (node["phase"], node["client_mask_dot"])
        if key in aliases:
            m.eq(value, aliases[key], "same ciphertext/key domain client relation")
        else:
            aliases[key] = value


def verify_rows(rows, source_id, source_files, binary, child_pid, exit_code):
    m.integer(child_pid, 1, (1 << 31) - 1, "root-supplied actual child PID")
    m.integer(exit_code, 0, 1, "completed exit code")
    m.eq(len(rows), 17703, "complete raw cardinality")
    check_plan(rows[0])
    producer_rows = list(rows[1:4])
    key = rows[4]
    key_expected = dict(
        schema=m.SCHEMA,
        record="consumer_keyset",
        keyset=0,
        process_id=child_pid,
        big_dimension=2048,
        small_dimension=859,
        ks_base_log=3,
        ks_level_count=5,
        consumer_source_sha256=source_files["candidate/src/actual_consumer.rs"],
        retained_br_source_sha256=source_files["candidate/src/retained_br.rs"],
        candidate_encryption_noise="A44 glwe_noise_distribution under flattened GLWE binary key",
        candidate_provenance="fresh_client_lwe_not_prior_selector_round",
        key_membership_attested=False,
        key_sensitive_client_local_only=True,
    )
    for name, expected in key_expected.items():
        m.eq(key[name], expected, "keyset " + name)
    for name in ("ksk_sha256", "fourier_bsk_sha256"):
        m.digest(key[name])
    cursor = 5
    failures = [[0] * 6 for _ in range(2)]
    case_failures = [0, 0]
    candidate_hashes = set()
    observation_aliases = {}
    failed = []
    old = frozen_producer()
    for scene in m.SCENES:
        for x in m.SCORES:
            identity = dict(keyset=0, scene=scene, x=x)
            group = rows[cursor : cursor + 575]
            cursor += 575
            producer_rows.extend(group)
            phases = {
                (r["arm"], r["stage"]): (r["ciphertext_sha256"], int(r["phase"]))
                for r in group
                if r["record"] == "phase"
            }
            local = [[0] * 6 for _ in range(2)]
            for bit in range(8):
                for candidate in m.candidates(bit):
                    shared = None
                    for arm_index, arm in enumerate(m.ARMS):
                        row = rows[cursor]
                        cursor += 1
                        fields = dict(identity, arm=arm, bit=bit, candidate=candidate)
                        producer = phases[(arm, old.m.weighted_stage(arm, bit))]
                        gates = m.check_consumer(row, fields, producer)
                        bind_observation_aliases(row, observation_aliases)
                        if shared is None:
                            shared = row["candidate_lwe"]
                            h = shared["sha256"]
                            m.need(
                                h not in candidate_hashes,
                                "distinct ciphertext for each registered client encryption",
                            )
                            candidate_hashes.add(h)
                        else:
                            m.eq(
                                row["candidate_lwe"],
                                shared,
                                "same actual candidate paired between arms",
                            )
                        for index, gate in enumerate(gates):
                            local[arm_index][index] += not gate
                            failures[arm_index][index] += not gate
                        if not all(gates):
                            failed.append(
                                dict(
                                    fields,
                                    failed_gates=[
                                        name
                                        for name, gate in zip(m.GATE_NAMES, gates)
                                        if not gate
                                    ],
                                )
                            )
            case_row = rows[cursor]
            cursor += 1
            m.eq(
                case_row,
                dict(
                    identity,
                    schema=m.SCHEMA,
                    record="consumer_case",
                    consumers=56,
                    candidate_encryptions=28,
                    failure_counts=local,
                    gate_order=list(m.GATE_NAMES),
                    all_consumer_gates_pass=not any(n for arm in local for n in arm),
                ),
                "exact consumer case summary",
            )
            for arm_index in range(2):
                case_failures[arm_index] += any(local[arm_index])
    producer_rows.append(rows[cursor])
    cursor += 1
    m.eq(len(producer_rows), 16104, "complete unchanged six-arm producer projection")
    # Explicit metadata rebinding only: original replay function/code and all
    # producer rows stay unchanged. It verifies this A175 compiled producer ID,
    # rather than falsely identifying this new execution as an old A169 run.
    old.SOURCE_ID = source_id
    producer = old.replay(producer_rows, binary, source_files)
    producer_pass = producer["summary"]["repair_b0_b1_gate_pass"]
    actual_pass = not any(n for arm in failures for n in arm)
    complete_pass = producer_pass and actual_pass
    final = rows[cursor]
    cursor += 1
    m.eq(cursor, len(rows), "no trailing raw records")
    expected_final = dict(
        schema=m.SCHEMA,
        record="consumer_summary",
        status="PASS_A175_ACTUAL_CONSUMER"
        if complete_pass
        else "FAIL_A175_ACTUAL_CONSUMER",
        cases=28,
        consumer_calls=1568,
        candidate_encryptions=784,
        producer_gate_pass=producer_pass,
        actual_consumer_gate_pass=actual_pass,
        complete_gate_pass=complete_pass,
        failure_counts=failures,
        case_failures=case_failures,
        total_br=5124,
        total_ks=3360,
        total_samples=6020,
        process_id=child_pid,
        candidate_is_previous_selector_output=False,
        full_exact_id_validated=False,
        actual_p_fail=None,
        latency_claim_allowed=False,
    )
    m.eq(final, expected_final, "complete producer/consumer conjunction")
    m.eq(exit_code, 0 if complete_pass else 1, "reported actual child exit")
    m.eq(len(candidate_hashes), 784, "registered encryption ciphertext cardinality")
    return dict(
        status="PASS_A175_RECORD_ARITHMETIC"
        if complete_pass
        else "VALID_COMPLETED_A175_NEGATIVE",
        complete_gate_pass=complete_pass,
        expected_exit_code=exit_code,
        records=len(rows),
        producer_gate_pass=producer_pass,
        actual_consumer_gate_pass=actual_pass,
        producer_projection=producer,
        consumer_failure_counts=failures,
        consumer_case_failures=case_failures,
        failed_consumers=failed,
        candidate_ciphertext_hashes_distinct=784,
        key_hashes={name: key[name] for name in ("ksk_sha256", "fourier_bsk_sha256")},
        source_id=source_id,
        binary_sha256=binary,
        reported_child_pid=child_pid,
        ledger=dict(
            BR=5124,
            KS=3360,
            samples=6020,
            client_lwe_encryptions=784,
            client_glwe_encryptions=28,
        ),
        actual_consumed_degree_receipt_checked=True,
        stock_equality_requires_source_execution_attestation=True,
        source_order_and_key_membership_independently_attested=False,
        client_aggregates_independently_attested=False,
        ks_row_error_independently_measured=False,
        candidate_is_previous_selector_output=False,
        launch_envelope_independently_verified=False,
        full_exact_id_validated=False,
        actual_p_fail=None,
        latency_claim_allowed=False,
    )


def private(path, directory=False):
    path = Path(path).absolute()
    for p in (path, *path.parents):
        m.need(not p.is_symlink(), "symbolic path refused")
    mode = path.stat().st_mode
    m.need(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), "private path kind")
    m.eq(stat.S_IMODE(mode), 0o700 if directory else 0o600, "private mode")
    return path


def parse(text):
    def obj(pairs):
        result = {}
        for k, v in pairs:
            m.need(k not in result, "duplicate JSON field")
            result[k] = v
        return result

    def nonfinite(value):
        raise ValueError("nonfinite JSON: " + value)

    return json.loads(text, object_pairs_hook=obj, parse_constant=nonfinite)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--raw-sha256")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--child-pid", type=int)
    parser.add_argument("--exit-code", type=int, choices=(0, 1))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.raw is None:
        m.need(
            all(v is None for v in vars(args).values()),
            "noargs plan or complete explicit inputs",
        )
        print(
            json.dumps(
                dict(
                    status="SOURCE_ONLY_RAW_REPLAY_PLAN",
                    records=17703,
                    launch_envelope_required_separately=True,
                    cryptography_executed=False,
                )
            )
        )
        return
    m.need(
        all(v is not None for v in vars(args).values()),
        "all raw/source/binary/PID/exit/output bindings required",
    )
    private(args.raw.parent, True)
    private(args.raw)
    private(args.output.parent, True)
    m.need(
        not args.output.exists() and not args.output.is_symlink(),
        "exclusive fresh output",
    )
    raw = args.raw.read_bytes()
    m.eq(
        hashlib.sha256(raw).hexdigest(),
        m.digest(args.raw_sha256),
        "captured raw bytes match supplied hash",
    )
    m.need(raw.endswith(b"\n"), "complete final raw line")
    lines = raw.decode().splitlines()
    m.need(all(line.strip() for line in lines), "no omitted blank records")
    source_id, files = source_check()
    result = verify_rows(
        [parse(line) for line in lines],
        source_id,
        files,
        m.digest(args.binary_sha256),
        args.child_pid,
        args.exit_code,
    )
    result["raw_sha256"] = args.raw_sha256
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, indent=2, allow_nan=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(
        json.dumps({k: result[k] for k in ("status", "complete_gate_pass", "records")})
    )


if __name__ == "__main__":
    main()
