"""Read preserved smoke logs; private arithmetic diagnosis, never a cryptographic rerun."""

import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE.parent
PARENT = VALIDATOR.parent
Q, U, DELTA59 = 1 << 64, 1 << 52, 1 << 59


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, data):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def main():
    for path, expected in json.loads((HERE / "SOURCE_PINS.json").read_text())[
        "files"
    ].items():
        assert sha(Path(path)) == expected, path
    run = PARENT / "runs/smoke-key1"
    rows = [
        json.loads(line) for line in (run / "stdout.jsonl").read_text().splitlines()
    ]
    replay = json.loads(
        (VALIDATOR / "artifacts/smoke-key1-validation.json").read_text()
    )
    assert replay["status"] == "PASS_RECORD_CONSISTENCY"
    result = []
    for case in replay["candidate_failed_cases"]:
        selected = [
            row
            for row in rows
            if all(row.get(k) == case[k] for k in ("keyset", "scene", "x", "arm"))
        ]
        phases = {row["stage"]: row for row in selected if row["record"] == "phase"}
        failures = [
            row
            for row in selected
            if row["record"] == "consumer_scalar_phase" and not row["pass"]
        ]
        assert {(row["bit"], row["level"]) for row in failures} == {(1, 6)}
        assert [row["candidate"] for row in failures] == [0, 1]
        native = next(
            row
            for row in selected
            if row["record"] == "weighted_bit" and row["bit"] == 1
        )
        margin = next(
            row
            for row in selected
            if row["record"] == "weighted_p16_margin" and row["bit"] == 1
        )
        correction_error = int(phases["full.pbs_correction_b1"]["signed_error"])
        weighted_error = int(phases["full.correction_x256_b1"]["signed_error"])
        assert weighted_error == correction_error * 256
        assert int(phases["full.pbs_raw_b1"]["signed_error"]) == correction_error
        assert native["pass"] and not margin["inside_open_half_slot"]
        assert abs(weighted_error) < 1 << 60 and abs(weighted_error) > 1 << 58
        e = int(phases["full.ks_b1"]["signed_error"])
        # Source-conditioned binary-small-key bound. Every native MS mask residue
        # lies in [-U/2,U/2); at most859 can contribute. This does not observe them.
        z_low, z_high = -859 * (U // 2), 859 * (U // 2 - 1)
        displacement_bounds = [(e + z + U // 2) // U for z in (z_low, z_high)]
        address_bounds = [1024 + d for d in displacement_bounds]
        assert 0 <= address_bounds[0] <= address_bounds[1] < 2048
        controls = []
        for arm in ("baseline_dual", "shift_initial_only"):
            arm_rows = [
                row
                for row in rows
                if row.get("arm") == arm
                and all(row.get(k) == case[k] for k in ("keyset", "scene", "x"))
            ]
            arm_case = next(row for row in arm_rows if row["record"] == "case")
            control_margin = next(
                row
                for row in arm_rows
                if row["record"] == "weighted_p16_margin" and row["bit"] == 1
            )
            low = next(
                row
                for row in arm_rows
                if row["record"] == "phase" and row["stage"] == "score.low"
            )
            assert arm_case["pass"]
            controls.append(
                dict(
                    arm=arm,
                    case_pass=True,
                    b1_error_in_delta59=control_margin["error_in_delta59"],
                    initial_low_error_words=low["signed_error"],
                )
            )
        result.append(
            dict(
                case=case,
                bit=1,
                level=6,
                native_scale_log=61,
                correction_scale_log=53,
                correction_error_words=str(correction_error),
                weighted_error_words=str(weighted_error),
                exact_multiplication=256,
                native_error_in_delta61=weighted_error / 2**61,
                weighted_error_in_delta59=weighted_error / DELTA59,
                initial_full_error_words=phases["score.full"]["signed_error"],
                b1_residual_error_words=phases["full.residual_before_b1"][
                    "signed_error"
                ],
                b1_actual_ks_phase_error_words=str(e),
                source_conditioned_all_binary_small_keys_ms_displacement_bounds=displacement_bounds,
                source_conditioned_raw_constant_lut_address_bounds=address_bounds,
                actual_ms_coefficients_observed=False,
                correct_first_half_constant_plateau_proved_under_source_geometry=True,
                scalar_mismatches=[
                    dict(
                        candidate=row["candidate"],
                        actual=row["actual"],
                        expected=row["expected"],
                        input_in_delta59=int(row["input_torus"]) / DELTA59,
                    )
                    for row in failures
                ],
                controls=controls,
            )
        )
    assert [(row["case"]["scene"], row["case"]["x"]) for row in result] == [
        ("dense_nonzero", 16),
        ("dense_nonzero", 17),
    ]
    final = dict(
        status="SAMPLED_NOISY_CORRECTION_AMPLIFICATION_WITH_SCALAR_CONSUMER_FAILURE",
        run_stdout_sha256=sha(run / "stdout.jsonl"),
        replay_sha256=sha(VALIDATOR / "artifacts/smoke-key1-validation.json"),
        cases=result,
        actual_consumed_consumer_pbs=False,
        composed_exact_id_failure_observed=False,
        universal_noise_failure_rate_established=False,
        initial_shift_route_rejected=False,
        exact_native_word_phase_values_private=True,
        fresh_crypto_rerun=False,
        next_repairs_are_unexecuted=True,
    )
    write_new(HERE / "RESULT.json", final)
    print(
        json.dumps(
            dict(
                status=final["status"],
                cases=[
                    dict(
                        x=row["case"]["x"],
                        bit=row["bit"],
                        level=row["level"],
                        weighted_error_in_delta59=row["weighted_error_in_delta59"],
                        source_conditioned_ms_address_bounds=row[
                            "source_conditioned_raw_constant_lut_address_bounds"
                        ],
                    )
                    for row in result
                ],
            )
        )
    )


if __name__ == "__main__":
    main()
