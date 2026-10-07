import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import check_static  # noqa: E402 - local test import after explicit path setup
from run_gate import busy  # noqa: E402
from validate import validate_records  # noqa: E402


def synthetic_records():
    static = check_static.check()
    expected = dict(static, binary_sha256="b" * 64, process_id=151)
    # Independent frozen A147 arithmetic: real synthetic key words, no claimed fresh runtime.
    spec = importlib.util.spec_from_file_location(
        "a147_model", ROOT.parent / "a147-pfks-key-row-witness/model.py"
    )
    model = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = model
    spec.loader.exec_module(model)
    secret, out_secret = [1, 0], [[1, 0, 1, 1, 0, 0, 1, 0]]
    polynomial = [1, 1, 0, 0, 0, 0, 0, -1]
    key, _ = model.synthetic_key(secret, out_secret, 1, polynomial, 8, 2)
    samples = model.measure(
        key, secret, out_secret, 1, polynomial, [1] + [0] * 7, [0], 8, 2
    )
    payload = [(3 << 56) + (5 << 48), (11 << 56) + (13 << 48), (7 << 56) + (17 << 48)]
    p = model.contract(samples, [payload], [0])
    output = model.pfks_ciphertext(key, payload, 8, 2)
    original = model.observed_aggregate(output, payload, secret, out_secret, samples, 0)
    changed = output.copy()
    changed[-8] = (changed[-8] + 1) & model.MASK
    mutated = model.observed_aggregate(changed, payload, secret, out_secret, samples, 0)
    assert original == p["modular"] and mutated == (original + 1) & model.MASK
    pred = {
        name: str(p[name])
        for name in ["modular", "centered", "lifted", "wrap_quotient"]
    }
    pred["distinct_nonzero_row_functionals"] = len(p["coefficients"])
    key_id, payload_id = samples.key_id, model.words_hash(payload)
    rows = [
        dict(
            record="meta",
            artifact="A151",
            tfhe="0.11.3",
            evidence_kind="SYNTHETIC_REPLAY",
            **{
                k: expected[k]
                for k in [
                    "source_id",
                    "binary_sha256",
                    "params_sha256",
                    "observer_sha256",
                    "process_id",
                ]
            },
        ),
        dict(
            record="key_bound",
            key_sha256=key_id,
            function_sha256=expected["function_sha256"],
            scalar_function="identity",
            effective_function="W0_radius63",
            row_levels=2049,
            pfks_base_log=24,
            pfks_levels=1,
            key_words=2049 * 4096,
            base_parameters_equal=True,
        ),
        dict(
            record="rows_measured",
            key_sha256=key_id,
            kernel_sha256=expected["kernel_sha256"],
            row_levels=2049,
            targets=[0],
            payload_exists=False,
            pfks_output_exists=False,
            raw_row_data_persisted=False,
            samples_client_memory_only=True,
        ),
        dict(
            record="prediction_before_pfks",
            key_sha256=key_id,
            payload_sha256=payload_id,
            fixture="accept_threshold_left",
            fixture_index=2,
            payload_side="left",
            payload_lane=0,
            message=3,
            delta_log=59,
            target=0,
            nontrivial_payload=True,
            prediction=pred,
            pfks_calls_so_far=0,
        ),
        dict(
            record="comparison",
            key_sha256=key_id,
            payload_sha256=payload_id,
            output_sha256=model.words_hash(output),
            changed_output_sha256=model.words_hash(changed),
            observed_aggregate=str(original),
            changed_observed_aggregate=str(mutated),
            positive_equal=True,
            changed_output_equal=False,
            prediction_fixed=True,
            observed_changes_by_one=True,
            key_unchanged=True,
            payload_unchanged=True,
            prediction_after=copy.deepcopy(pred),
            pfks_calls=1,
            other_server_crypto_calls=0,
        ),
        dict(
            record="summary",
            status="PASS_ONE_PAYLOAD_ROW_IDENTITY",
            row_levels=2049,
            targets=1,
            payloads=1,
            pfks_calls=1,
            changed_output_control_pass=True,
            tails="OPEN",
            covariance="OPEN",
            support_and_final_correctness="NOT_TESTED_no_BR_selector_or_scan",
        ),
    ]
    return rows, expected


class GateTests(unittest.TestCase):
    def test_frozen_source_order_and_literal_observer_copy(self):
        self.assertEqual(check_static.check()["source_pins"], 17)

    def test_complete_synthetic_private_stream(self):
        rows, expected = synthetic_records()
        self.assertEqual(
            validate_records(rows, expected, synthetic=True)["status"],
            "SYNTHETIC_REPLAY_PASS",
        )
        with self.assertRaises(AssertionError):
            validate_records(rows, expected)

    def test_order_partial_duplicate_and_pid_binding(self):
        rows, expected = synthetic_records()
        for broken in [
            rows[:-1],
            rows + rows[-1:],
            rows[:2] + [rows[3], rows[2]] + rows[4:],
        ]:
            with self.assertRaises(AssertionError):
                validate_records(broken, expected, synthetic=True)
        with self.assertRaises(AssertionError):
            validate_records(rows, dict(expected, process_id=152), synthetic=True)

    def test_mutated_bindings_counts_or_false_flags_reject(self):
        rows, expected = synthetic_records()
        mutations = [
            (0, "source_id", "a" * 64),
            (0, "binary_sha256", "a" * 64),
            (0, "params_sha256", "a" * 64),
            (1, "function_sha256", "a" * 64),
            (1, "pfks_base_log", 23),
            (1, "row_levels", 2048),
            (2, "pfks_output_exists", True),
            (2, "payload_exists", True),
            (2, "key_sha256", "a" * 64),
            (3, "payload_lane", 1),
            (3, "message", 0),
            (3, "pfks_calls_so_far", 1),
            (4, "payload_sha256", "a" * 64),
            (4, "prediction_fixed", False),
            (4, "changed_output_equal", True),
            (4, "changed_observed_aggregate", "0"),
            (4, "pfks_calls", 2),
            (5, "targets", 2),
        ]
        for index, field, value in mutations:
            broken = copy.deepcopy(rows)
            broken[index][field] = value
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    validate_records(broken, expected, synthetic=True)

    def test_centered_lift_and_fixed_prediction_reject(self):
        rows, expected = synthetic_records()
        for index, field in [(3, "prediction"), (4, "prediction_after")]:
            broken = copy.deepcopy(rows)
            broken[index][field]["lifted"] = str(
                int(broken[index][field]["lifted"]) + 1
            )
            with self.assertRaises(AssertionError):
                validate_records(broken, expected, synthetic=True)

    def test_process_preflight_supplied_text_only(self):
        self.assertTrue(
            busy(
                "45916 45914 python tmp/a124-a66-thread-sweep/a124_driver.py --guard cpu",
                151,
            )
        )
        self.assertTrue(
            busy("7 1 target-a151-only/release/a151_pfks_independent_row_gate", 151)
        )
        self.assertFalse(
            busy(
                "151 1 python run_gate.py --binary target-a151-only/release/a151_pfks_independent_row_gate",
                151,
            )
        )


if __name__ == "__main__":
    unittest.main()
