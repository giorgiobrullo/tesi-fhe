"""Synthetic full-stream and corruption checks, not ciphertext evidence."""

import copy
import hashlib
import unittest

from check import ARMS, FIXTURES, HERE, evaluate
from replay import replay, sha

BINARY = "0" * 64


def synthetic_records():
    records = [
        dict(
            record="plan",
            synthetic=True,
            stage="padding_flags_n4",
            suite="single2",
            selected_fixture_indices=[2],
            fixtures=FIXTURES,
            arms=[a["name"] for a in ARMS],
            br_ks_per_fixture=[55, 63, 55, 63, 55, 55],
            keysets=1,
        ),
        dict(
            record="provenance",
            synthetic=True,
            binary_sha256=BINARY,
            source_sha256=sha(HERE / "src/main.rs"),
            tables_sha256=sha(HERE / "src/a34_tables.rs"),
            lock_sha256=sha(HERE / "Cargo.lock"),
            params="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            parameter_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        ),
    ]
    full = [
        hashlib.sha256(f"SYNTHETIC/full/{i}".encode()).hexdigest() for i in range(4)
    ]
    low = [hashlib.sha256(f"SYNTHETIC/low/{i}".encode()).hexdigest() for i in range(4)]
    for index, arm in enumerate(ARMS):
        result, graph = evaluate(FIXTURES[2], arm)
        for event in graph.generated:
            records.append(dict(event, record="event", keyset=0, case=2, arm=index))
        case = dict(
            record="case",
            synthetic=True,
            keyset=0,
            case=2,
            arm=index,
            scores=FIXTURES[2],
            arm_name=arm["name"],
            padding_flags=arm["padding"],
            actual_final_output_log=63 if arm["wrong_final"] else 59,
            required_final_output_log=59,
            full_sha256=full,
            packed_low_sha256=low,
            input_full_errors=["0"] * 4,
            input_packed_low_errors=["0"] * 4,
            flag_phase_words=result["final_phase_words"],
            br=result["pbs_ks"],
            ks=result["pbs_ks"],
            not_a53_or_service=True,
            **{
                k: result[k]
                for k in (
                    "low51",
                    "middle51",
                    "top60",
                    "flags",
                    "expected_flags",
                    "low51_errors",
                    "middle51_errors",
                    "top60_errors",
                    "native_decode_pass",
                    "composed_a34_a135_pass",
                )
            },
        )
        case["pass"] = result["native_decode_pass"] and result["composed_a34_a135_pass"]
        records.append(case)
    records.append(
        dict(
            record="summary",
            synthetic=True,
            status="BOUNDED_PADDING_COMPOSED_GATE_PASS",
            positive_arm_failures=[0] * 4,
            negative_arm_failures_detected_by_key=[[1, 1]],
            selected_fixture_indices=[2],
            case_count=1,
            p_fail_certified=False,
            a53_service_validated=False,
            latency_claim_allowed=False,
        )
    )
    return records


class ReplayChecks(unittest.TestCase):
    def test_complete_declared_synthetic_stream(self):
        result = replay(synthetic_records(), BINARY)
        self.assertTrue(result["functional_gate_pass"])
        self.assertEqual(result["cases_checked"], 6)
        self.assertEqual(result["events_checked"], 346)
        self.assertEqual(result["status"], "SYNTHETIC_REPLAY")
        self.assertFalse(result["noise_improvement_established"])

    def test_mutations_cannot_promote_false_trace_or_scope(self):
        records = synthetic_records()
        for kind in (
            "body",
            "phase",
            "padding",
            "final_scale",
            "summary",
            "missing_arm",
            "full_scope",
        ):
            changed = copy.deepcopy(records)
            event = next(x for x in changed if x["record"] == "event")
            case = next(x for x in changed if x["record"] == "case")
            if kind == "body":
                event["body_sha256"] = "f" * 64
            elif kind == "phase":
                case["flag_phase_words"][2] = str(1 << 63)
            elif kind == "padding":
                case["padding_flags"] = True
            elif kind == "final_scale":
                case["required_final_output_log"] = 63
            elif kind == "summary":
                changed[-1]["negative_arm_failures_detected_by_key"] = [[1, 0]]
            elif kind == "missing_arm":
                changed = [r for r in changed if r.get("arm") != 5]
            else:
                changed[0]["suite"] = "full8"
                changed[0]["selected_fixture_indices"] = list(range(8))
            with self.assertRaises((AssertionError, KeyError), msg=kind):
                replay(changed, BINARY)

    def test_missing_summary_and_wrong_binary(self):
        records = synthetic_records()
        with self.assertRaises(AssertionError):
            replay(records[:-1], BINARY)
        with self.assertRaises(AssertionError):
            replay(records, "1" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
