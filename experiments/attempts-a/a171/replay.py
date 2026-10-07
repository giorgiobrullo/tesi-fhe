"""A171 D1 record arithmetic and control projection, not a launch-envelope verifier."""

import copy
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("A171 requires Python assertions enabled")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q = 1 << 64
U = 1 << 40
MASK = Q - 1
N = 2048
ORDERS = list(itertools.permutations(range(4)))
COUNTS = dict(
    pfks=4,
    rotations=4,
    polynomial_permutations=8,
    glwe_additions=3,
    ks=1,
    br=1,
    samples=4,
    lwe_subtractions=4,
    lwe_addbacks=4,
    **{"pass": True},
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(value, reason):
    if not value:
        raise ValueError(reason)


def eq(x, y, reason):
    need(type(x) is type(y), reason)
    if isinstance(y, dict):
        need(x.keys() == y.keys(), reason)
        for key in y:
            eq(x[key], y[key], reason)
    elif isinstance(y, list):
        need(len(x) == len(y), reason)
        for xx, yy in zip(x, y):
            eq(xx, yy, reason)
    else:
        need(x == y, reason)


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def hash_words(words):
    return hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in words)).hexdigest()


def words(values, size):
    need(type(values) is list and len(values) == size, "word array length")
    need(all(type(x) is int and 0 <= x < Q for x in values), "native word types")
    return values


def decimal(value):
    need(type(value) is str, "decimal string")
    x = int(value)
    eq(str(x), value, "canonical signed decimal")
    return x


def digit(word):
    # TFHE0.11 24x1: exact half-base is positive, unlike an always-centered port.
    rounded = ((word + U // 2) & MASK) & ~(U - 1)
    d = rounded >> 40
    return d if d <= 1 << 23 else d - (1 << 24)


def ms(word):
    return ((word + (1 << 51)) >> 52) % 4096


def weight(degree, lane):
    z = (degree - (12 + lane) * 128) % 4096
    if z <= 63 or z >= 4096 - 63:
        return 1
    if 2048 - 63 <= z <= 2048 + 63:
        return -1
    return 0


def input_check(row, message):
    w = words(row["words"], 2049)
    eq(row["sha256"], hash_words(w), "input ciphertext words/hash")
    eq(row["message_phase"], message, "native message")
    phase = words([row["phase"]], 1)[0]
    eq(row["error"], signed(phase - message), "observed input error")
    rho = decimal(row["rho_decimal"])
    # Necessary support, not a proof that the aggregate used the alleged key.
    rem = [signed((digit(x) * U) - x) for x in w]
    need(
        rem[-1] - sum(max(0, x) for x in rem[:-1])
        <= rho
        <= rem[-1] - sum(min(0, x) for x in rem[:-1]),
        "binary-secret rho envelope",
    )
    eq(row["rounded_phase"], (phase + rho) % Q, "rounded phase")
    eq(row["digits"], [digit(x) for x in w], "actual public row digits")
    eq(row["levels"], [1], "actual row level")
    eq(row["body_digits"], [digit(w[-1])], "body row digit")
    return w


def check_block(
    rows, spec, control_audit, output_audits, original_pfks, original_acc=None
):
    """Nine D1 records; public words crosschecked, secret-derived phases trusted."""
    eq(len(rows), 9, "D1 block cardinality")
    name = spec["name"]
    for row in rows:
        eq(row["fixture"], name, "D1 fixture")
    for j, row in enumerate(rows[:4]):
        eq(row["record"], "d1_difference_pfks", "D1 input record order")
        eq(row["term"], j, "D1 input lane")
        eq(row["key_family"], "window", "same functional key")
        function = [0] * 2048
        for z in range(-63, 64):
            function[z % 2048] = 1 if z >= 0 else Q - 1
        eq(row["function_sha256"], hash_words(function), "actual signed W0")
        delta = 1 << (56 if j == 3 else 59)
        lm, rm = spec["left"][j] * delta, spec["right"][j] * delta
        left, right, diff = (row[k] for k in ("left", "right", "difference"))
        lw, rw, dw = (
            input_check(left, lm),
            input_check(right, rm),
            input_check(diff, (rm - lm) % Q),
        )
        eq(
            dw,
            [(rr - ll) % Q for rr, ll in zip(rw, lw)],
            "actual right-minus-left words",
        )
        eq(
            diff["phase"],
            (right["phase"] - left["phase"]) % Q,
            "difference phase linearity",
        )
        eq(
            diff["error"],
            signed(right["error"] - left["error"]),
            "correlated input error",
        )
        eq(
            row["nonlinear_digit_count"],
            sum(
                d != rr - ll
                for d, rr, ll in zip(diff["digits"], right["digits"], left["digits"])
            ),
            "nonlinear row coefficients",
        )
        eq(
            row["rho_difference_discrepancy_decimal"],
            str(
                decimal(diff["rho_decimal"])
                - decimal(right["rho_decimal"])
                + decimal(left["rho_decimal"])
            ),
            "difference rho discrepancy",
        )
        eq(
            row["difference_native_half_slot_diagnostic"],
            abs(diff["error"]) < delta // 2,
            "delta margin diagnostic",
        )
        eq(
            row["difference_native_decode_diagnostic"],
            ((diff["phase"] + delta // 2) % Q) // delta == ((rm - lm) % Q) // delta,
            "delta decode diagnostic",
        )
        for flag, value in dict(
            difference_words_pass=True,
            difference_phase_pass=True,
            difference_error_pass=True,
            difference_native_pass_is_prerequisite=False,
            primitive_row_errors_independently_measured=False,
            independent_noise_assumed=False,
        ).items():
            eq(row[flag], value, flag)
        for side, old in [(left, original_pfks[j]), (right, original_pfks[j + 4])]:
            for new_key, old_key in [
                ("sha256", "input_sha256"),
                ("phase", "input_phase"),
                ("message_phase", "input_message_phase"),
                ("error", "input_error"),
                ("rho_decimal", "rounding_rho_decimal"),
                ("rounded_phase", "rounded_input_phase"),
            ]:
                eq(side[new_key], old[old_key], "same actual D2 input " + new_key)
            eq(
                hash_words([d % Q for d in side["digits"]]),
                old["public_digit_words_sha256"],
                "same original row digits",
            )
    acc = rows[4]
    eq(acc["record"], "d1_accumulator", "accumulator order")
    control = words(acc["control_words"], 860)
    eq(acc["control_sha256"], hash_words(control), "actual control words")
    words([acc["input_control_phase"], acc["post_ks_control_phase"]], 2)
    eq(acc["control_sha256"], control_audit["sha256"], "same actual D2 control")
    eq(acc["post_ks_control_phase"], control_audit["phase"], "same control phase")
    eq(acc["modulus_switched_body"], ms(control[-1]), "actual body MS")
    eq(
        acc["modulus_switched_masks"],
        [ms(x) for x in control[:-1]],
        "actual coefficientwise mask MS",
    )
    mask_sum = acc["secret_weighted_modulus_switched_mask_sum"]
    need(type(mask_sum) is int and 0 <= mask_sum < 4096, "client mask sum")
    effective = (ms(control[-1]) - mask_sum) % 4096
    eq(acc["actual_effective_rotation_degree"], effective, "actual address closure")
    error = (effective - spec["control"] * 128) % 4096
    if error > 2048:
        error -= 4096
    eq(acc["actual_effective_rotation_error"], error, "support displacement")
    eq(acc["support_ok"], abs(error) <= 63, "actual support")
    eq(
        acc["rounded_phase_degree_diagnostic"],
        ms(acc["post_ks_control_phase"]),
        "phase-only diagnostic",
    )
    eq(
        acc["actual_ks_aggregate_error"],
        signed(acc["post_ks_control_phase"] - acc["input_control_phase"]),
        "control KS phase increment",
    )
    eq(acc["exact_all_words_assembly_pass"], True, "source all-word assembly check")
    eq(acc["client_aggregate_key_membership_attested"], False, "client trust boundary")
    if original_acc is not None:
        for field in [
            "input_control_sha256",
            "input_control_phase",
            "post_ks_control_phase",
            "actual_ks_aggregate_error",
            "modulus_switched_body",
            "secret_weighted_modulus_switched_mask_sum",
            "actual_effective_rotation_degree",
            "actual_effective_rotation_error",
            "rounded_phase_degree_diagnostic",
            "support_ok",
        ]:
            eq(
                acc[field],
                original_acc[field],
                "same actual D2 support witness " + field,
            )
    expected = spec["left"] if spec["control"] == 4 else spec["right"]
    for j, row in enumerate(rows[5:]):
        eq(row["record"], "d1_noise_lane", "D1 lane order")
        eq(row["lane"], j, "D1 sample lane")
        native_fields = [
            "delta",
            "expected_phase",
            "ideal_correction",
            "ideal_final",
            "exact_pre_br_phase_reconstructed",
            "actual_pre_br_phase",
            "raw_correction_phase",
            "left_phase",
            "output_phase",
        ]
        words([row[field] for field in native_fields], len(native_fields))
        delta = 1 << (56 if j == 3 else 59)
        degree = effective + 128 * j
        eq(row["delta"], delta, "output scale")
        eq(
            row["actual_pre_br_virtual_degree"],
            degree,
            "actual negacyclic sample address",
        )
        eq(row["expected_phase"], expected[j] * delta, "selected output")
        weights = [weight(degree, t) for t in range(4)]
        terms = rows[:4]
        ideal = (
            sum(weights[t] * terms[t]["difference"]["message_phase"] for t in range(4))
            % Q
        )
        eq(row["ideal_correction"], ideal, "difference LUT body")
        eq(
            row["ideal_final"],
            (ideal + terms[j]["left"]["message_phase"]) % Q,
            "left ideal addback",
        )
        eq(
            row["transmitted_difference_error"],
            signed(sum(weights[t] * terms[t]["difference"]["error"] for t in range(4))),
            "difference error transmission",
        )
        eq(
            row["transmitted_difference_rho"],
            signed(
                sum(
                    weights[t] * decimal(terms[t]["difference"]["rho_decimal"])
                    for t in range(4)
                )
            ),
            "actual difference rounding transmission",
        )
        contributions = row["term_contributions"]
        eq(len(contributions), 4, "four actual PFKS terms")
        for t, c in enumerate(contributions):
            eq(c["term"], t, "PFKS term identity")
            eq(c["message_window_weight"], weights[t], "negacyclic LUT weight")
            words([c["exact_pfks_phase_contribution"]], 1)
            key_term = c["aggregate_key_error_contribution"]
            need(
                type(key_term) is int and -Q // 2 <= key_term < Q // 2,
                "canonical signed key contribution",
            )
        eq(
            row["aggregate_pfks_key_error"],
            signed(sum(c["aggregate_key_error_contribution"] for c in contributions)),
            "same-family key errors",
        )
        eq(
            row["exact_pre_br_phase_reconstructed"],
            sum(c["exact_pfks_phase_contribution"] for c in contributions) % Q,
            "exact PFKS phase assembly",
        )
        eq(
            (
                ideal
                + row["transmitted_difference_error"]
                + row["transmitted_difference_rho"]
                + row["aggregate_pfks_key_error"]
            )
            % Q,
            row["exact_pre_br_phase_reconstructed"],
            "PFKS decomposition closure",
        )
        eq(
            row["actual_pre_br_phase"],
            row["exact_pre_br_phase_reconstructed"],
            "direct exact assembly",
        )
        eq(row["exact_assembly_residual"], 0, "no FFT")
        eq(
            row["br_and_numeric_residual"],
            signed(row["raw_correction_phase"] - row["actual_pre_br_phase"]),
            "BR residual",
        )
        eq(row["left_phase"], terms[j]["left"]["phase"], "actual original left")
        eq(
            row["left_addback_input_error"],
            terms[j]["left"]["error"],
            "correlated left error",
        )
        raw, out = (
            words(row["raw_correction_words"], 2049),
            words(row["output_words"], 2049),
        )
        eq(
            out,
            [(rr + ll) % Q for rr, ll in zip(raw, terms[j]["left"]["words"])],
            "all-word original left addback",
        )
        eq(row["raw_correction_sha256"], hash_words(raw), "raw correction hash")
        eq(row["output_sha256"], hash_words(out), "actual final hash")
        eq(output_audits[j]["sha256"], row["output_sha256"], "consumed output identity")
        eq(output_audits[j]["phase"], row["output_phase"], "consumed output phase")
        eq(
            row["output_phase"],
            (row["raw_correction_phase"] + row["left_phase"]) % Q,
            "phase addback",
        )
        eq(row["addback_arithmetic_residual"], 0, "exact LWE addback")
        eq(
            row["support_message_residual"],
            signed(row["ideal_final"] - row["expected_phase"]),
            "support message residual",
        )
        keys = [
            "support_message_residual",
            "transmitted_difference_error",
            "transmitted_difference_rho",
            "aggregate_pfks_key_error",
            "exact_assembly_residual",
            "br_and_numeric_residual",
            "left_addback_input_error",
            "addback_arithmetic_residual",
        ]
        numbers = [row[k] for k in keys]
        need(
            all(type(x) is int and -Q // 2 <= x < Q // 2 for x in numbers),
            "centered error types",
        )
        eq(
            row["semantic_error"],
            signed(row["output_phase"] - row["expected_phase"]),
            "final semantic error",
        )
        eq(signed(sum(numbers)), row["semantic_error"], "eight-term modular closure")
        eq(
            row["centered_terms_unwrapped_sum_decimal"],
            str(sum(numbers)),
            "lift is only centered-term sum",
        )
        eq(
            row["strict_half_slot_pass"],
            abs(row["semantic_error"]) < delta // 2,
            "strict final margin",
        )
        for flag, value in dict(
            closure_pass=True,
            addback_all_words_pass=True,
            p_fail_proven=False,
            left_and_difference_errors_independent=False,
            native_difference_decode_is_not_a_consumer_gate=True,
        ).items():
            eq(row[flag], value, flag)
    return True


def verify_records(rows):
    """Actual A171 source/322-row binding, then checked A137 control projection."""
    source_check()
    old = load_module("a171_pinned_a167_successor", HERE / "control_oracle.py")
    sys.path.insert(0, str(ROOT / "tmp/a137-pfks-runtime-error-observer"))
    try:
        arithmetic = load_module(
            "a171_pinned_a137_arithmetic_successor", HERE / "control_arithmetic.py"
        )
    finally:
        sys.path.pop(0)
    need(len(rows) in [322, 323], "exact complete A171 count")
    meta = rows[0]
    for k, v in dict(
        record="meta",
        artifact="A171",
        ciphertext_words_persisted=True,
        d1_shares_actual_window_key=True,
    ).items():
        eq(meta[k], v, "actual A171 meta " + k)
    actual_files = {
        "main_source_sha256": "candidate/src/main.rs",
        "observer_source_sha256": "candidate/src/observer.rs",
        "d1_source_sha256": "candidate/src/d1.rs",
        "lockfile_sha256": "candidate/Cargo.lock",
        "preregistration_sha256": "PREREGISTRATION.json",
    }
    for field, name in actual_files.items():
        eq(
            meta[field],
            hashlib.sha256((HERE / name).read_bytes()).hexdigest(),
            "actual A171 embedded source",
        )
    offset, pid = meta["order_offset"], meta["process_id"]
    need(type(offset) is int and 0 <= offset < 3, "offset")
    projection = [copy.deepcopy(meta)]
    projection[0].update(artifact="A137", ciphertext_words_persisted=False)
    for field, name in [
        ("main_source_sha256", "src/main.rs"),
        ("observer_source_sha256", "src/observer.rs"),
        ("lockfile_sha256", "Cargo.lock"),
        ("preregistration_sha256", "PREREGISTRATION.json"),
    ]:
        projection[0][field] = old.digest(old.A137 / name)
    d1_passed = 0
    cases = []
    for f, spec in enumerate(old.SPECS):
        block = rows[1 + 40 * f : 1 + 40 * (f + 1)]
        lanes, direct_pfks, d1_rows, case = (
            block[:4],
            block[4:12],
            block[30:39],
            block[39],
        )
        eq(case["arm_order"], list(ORDERS[f + 8 * offset]), "actual four-arm schedule")
        check_block(
            d1_rows,
            spec,
            case["control_phase_audit"],
            [x["direct_d1"] for x in lanes],
            direct_pfks,
            block[12],
        )
        eq(case["d1_counters"], COUNTS, "actual D1 ledger")
        eq(case["d1_control_bitwise_equal"], True, "same KS object bytes")
        eq(case["d1_observer_pass"], True, "D1 observer arithmetic")
        expected = spec["left"] if spec["control"] == 4 else spec["right"]
        output_checks = [
            old.audit_phase(
                lanes[j]["direct_d1"], expected[j], 1 << (56 if j == 3 else 59)
            )
            and lanes[j]["direct_d1"]["decoded"] == lanes[j]["scalar"]["decoded"]
            for j in range(4)
        ]
        output_pass = all(output_checks)
        eq(case["d1_ok"], output_pass, "D1 final native/consumer agreement")
        label = old.classification(
            case["support_ok"],
            case["prerequisites_ok"] and case["direct_class"] == "pass",
            output_pass,
        )
        eq(case["d1_class"], label, "D1 current-key control prerequisite")
        d1_passed += int(label == "pass")
        for row in block[4:30]:
            if row["record"] == "noise_lane":
                arithmetic.validate_noise_lane(row)
        projected = copy.deepcopy(block[:30] + [case])
        projected[-1]["arm_order"] = old.ORDERS[(f + 2 * offset) % 6]
        projection.extend(projected)
        cases.append(dict(fixture=spec["name"], d1_class=label))
    summary = rows[321]
    eq(summary["d1_passed"], d1_passed, "D1 total")
    eq(
        summary["primitives_per_fixture"],
        dict(pfks=28, ks=7, br=7, samples=16),
        "whole experiment primitive ledger",
    )
    passed = (
        d1_passed == 8
        and summary["direct_passed"] == 8
        and summary["observer_failures"] == 0
    )
    eq(
        summary["status"],
        "PASS_D1_SINGLE_KEY_COMPONENT" if passed else "FAIL_D1_COMPONENT",
        "D1 gate status",
    )
    eq(summary["artifact"], "A171", "summary producer")
    projected_summary = copy.deepcopy(summary)
    projected_summary.update(
        artifact="A137",
        status="PASS_DIRECT_SINGLE_KEY_COMPONENT"
        if summary["direct_passed"] == 8
        else "FAIL_DIRECT_COMPONENT",
    )
    projection.append(projected_summary)
    if summary["direct_passed"] != 8:
        projection.append(
            dict(
                record="fatal",
                artifact="A137",
                reason=f"direct arm passed {summary['direct_passed']}/8 cases",
                performance_interpretation_allowed=False,
            )
        )
    checked_controls = old.check_rows(projection, offset, pid)
    arithmetic.validate_rows(projection)
    if passed:
        eq(len(rows), 322, "success has no fatal")
    else:
        eq(len(rows), 323, "complete negative preserves fatal")
        for k, v in dict(
            record="fatal",
            artifact="A171",
            reason=f"D1 arm passed {d1_passed}/8 cases; D2 direct passed {summary['direct_passed']}",
            performance_interpretation_allowed=False,
        ).items():
            eq(rows[-1][k], v, "negative fatal " + k)
    return dict(
        status="PASS_D1_RECORD_ARITHMETIC" if passed else "VALID_COMPLETED_D1_NEGATIVE",
        expected_exit_code=0 if passed else 1,
        cases=cases,
        control_projection=checked_controls,
        d1_passed=d1_passed,
        records=len(rows),
        source_primitive_counts=dict(PFKS=224, KS=56, BR=56, samples=128),
        launch_envelope_independently_verified=False,
        secret_membership_attested=False,
        primitive_row_errors_independently_measured=False,
        actual_p_fail=None,
        performance_claim=False,
    )


def source_check():
    manifest = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for pin in manifest["sources"]:
        path = Path(pin["path"])
        if not path.is_absolute():
            path = ROOT / path
        eq(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            pin["sha256"],
            "source pin " + str(path),
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.raw, args.raw.parent):
        need(not path.is_symlink(), "no symbolic sensitive evidence")
        need(path.stat().st_mode & 0o077 == 0, "owner-only sensitive evidence")
    old = load_module(
        "a171_json",
        ROOT / "tmp/a167-a137-execution-readiness/runtime-validation/verify.py",
    )
    rows = [
        old.load(line) for line in args.raw.read_text().splitlines() if line.strip()
    ]
    result = verify_records(rows)
    result["raw_sha256"] = hashlib.sha256(args.raw.read_bytes()).hexdigest()
    need(
        args.output.parent.is_dir() and not args.output.parent.is_symlink(),
        "existing report directory",
    )
    need(args.output.parent.stat().st_mode & 0o077 == 0, "private report directory")
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
