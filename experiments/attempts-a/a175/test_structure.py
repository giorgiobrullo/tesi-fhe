"""Full schedule/projection tests with explicitly mocked NEW word arithmetic.

The separate test_gate.py exercises the real small word checker. Here the frozen
A169 synthetic six-arm records are replayed by its unchanged arithmetic oracle;
new consumer payloads are metadata stubs, never simulated FHE or runtime evidence.
"""

import copy
import hashlib
import sys
import unittest
from unittest.mock import patch

import model as m
import replay as r

SOURCE = "1" * 64
BINARY = "2" * 64
FILES = {
    name: "3" * 64
    for name in (
        "candidate/src/diagnostic.rs",
        "candidate/src/frozen_extract.rs",
        "candidate/Cargo.lock",
        "candidate/src/actual_consumer.rs",
        "candidate/src/retained_br.rs",
    )
}


def original_fixture():
    old = r.frozen_producer()
    old.SOURCE_ID = SOURCE
    previous = {
        name: sys.modules.get(name)
        for name in ("model", "arithmetic", "validate", "a175_structure_old_synthetic")
    }
    try:
        sys.modules.update(model=old.m, arithmetic=old.a, validate=old)
        factory = r.load_module(
            "a175_structure_old_synthetic", r.OLD / "runtime-validation/synthetic.py"
        )
        return factory.make_records(FILES, BINARY)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def fixture():
    original = original_fixture()
    key = dict(
        schema=m.SCHEMA,
        record="consumer_keyset",
        keyset=0,
        process_id=123,
        ksk_sha256="4" * 64,
        fourier_bsk_sha256="5" * 64,
        big_dimension=2048,
        small_dimension=859,
        ks_base_log=3,
        ks_level_count=5,
        consumer_source_sha256=FILES["candidate/src/actual_consumer.rs"],
        retained_br_source_sha256=FILES["candidate/src/retained_br.rs"],
        candidate_encryption_noise="A44 glwe_noise_distribution under flattened GLWE binary key",
        candidate_provenance="fresh_client_lwe_not_prior_selector_round",
        key_membership_attested=False,
        key_sensitive_client_local_only=True,
    )
    rows = [r.plan_record(), *original[:3], key]
    index = 3
    for scene in m.SCENES:
        for x in m.SCORES:
            rows.extend(original[index : index + 575])
            index += 575
            identity = dict(keyset=0, scene=scene, x=x)
            for bit in range(8):
                for c in m.candidates(bit):
                    candidate = {
                        "sha256": hashlib.sha256(
                            repr((scene, x, bit, c)).encode()
                        ).hexdigest()
                    }
                    for arm in m.ARMS:
                        rows.append(
                            dict(
                                identity,
                                schema=m.SCHEMA,
                                record="actual_consumer",
                                arm=arm,
                                bit=bit,
                                candidate=c,
                                candidate_lwe=candidate,
                                gates=[True] * 6,
                            )
                        )
            rows.append(
                dict(
                    identity,
                    schema=m.SCHEMA,
                    record="consumer_case",
                    consumers=56,
                    candidate_encryptions=28,
                    failure_counts=[[0] * 6 for _ in range(2)],
                    gate_order=list(m.GATE_NAMES),
                    all_consumer_gates_pass=True,
                )
            )
    rows.append(original[-1])
    rows.append(
        dict(
            schema=m.SCHEMA,
            record="consumer_summary",
            status="PASS_A175_ACTUAL_CONSUMER",
            cases=28,
            consumer_calls=1568,
            candidate_encryptions=784,
            producer_gate_pass=True,
            actual_consumer_gate_pass=True,
            complete_gate_pass=True,
            failure_counts=[[0] * 6 for _ in range(2)],
            case_failures=[0, 0],
            total_br=5124,
            total_ks=3360,
            total_samples=6020,
            process_id=123,
            candidate_is_previous_selector_output=False,
            full_exact_id_validated=False,
            actual_p_fail=None,
            latency_claim_allowed=False,
        )
    )
    return rows


def mock_words(row, identity, producer):
    for key, value in dict(identity, schema=m.SCHEMA, record="actual_consumer").items():
        m.eq(row[key], value, "mock metadata " + key)
    m.digest(producer[0])
    return row["gates"]


class StructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = fixture()

    def verify(self, rows, exit_code=0):
        with (
            patch.object(m, "check_consumer", side_effect=mock_words),
            patch.object(r, "bind_observation_aliases"),
        ):
            return r.verify_rows(rows, SOURCE, FILES, BINARY, 123, exit_code)

    def test_full_order_and_unchanged_producer_replay(self):
        result = self.verify(self.rows)
        self.assertTrue(result["complete_gate_pass"])
        self.assertEqual(result["records"], 17703)
        self.assertFalse(result["launch_envelope_independently_verified"])
        self.assertFalse(result["candidate_is_previous_selector_output"])

    def test_omitted_final_case_cannot_complete(self):
        with self.assertRaises(ValueError):
            self.verify(self.rows[:-632])

    def test_swapped_state_or_arm_is_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[580], rows[581] = rows[581], rows[580]
        with self.assertRaises(ValueError):
            self.verify(rows)

    def test_pair_must_share_actual_candidate(self):
        rows = copy.deepcopy(self.rows)
        rows[581]["candidate_lwe"] = {"sha256": "f" * 64}
        with self.assertRaises(ValueError):
            self.verify(rows)

    def test_one_failed_consumer_cannot_hide_in_summary(self):
        rows = copy.deepcopy(self.rows)
        rows[580]["gates"][1] = False
        with self.assertRaises(ValueError):
            self.verify(rows)

    def test_consistent_completed_negative_is_preserved(self):
        rows = copy.deepcopy(self.rows)
        rows[580]["gates"][1] = False
        rows[636]["failure_counts"][0][1] = 1
        rows[636]["all_consumer_gates_pass"] = False
        final = rows[-1]
        final.update(
            status="FAIL_A175_ACTUAL_CONSUMER",
            actual_consumer_gate_pass=False,
            complete_gate_pass=False,
            case_failures=[1, 0],
        )
        final["failure_counts"][0][1] = 1
        result = self.verify(rows, 1)
        self.assertFalse(result["complete_gate_pass"])
        self.assertEqual(result["status"], "VALID_COMPLETED_A175_NEGATIVE")

    def test_nested_bool_alias_count_is_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[-1]["failure_counts"][0][0] = False
        with self.assertRaises(ValueError):
            self.verify(rows)

    def test_old_producer_failure_cannot_be_relabelled(self):
        rows = copy.deepcopy(self.rows)
        rows[-2]["repair_b0_b1_gate_pass"] = False
        with self.assertRaises(Exception):
            self.verify(rows)


if __name__ == "__main__":
    unittest.main()
