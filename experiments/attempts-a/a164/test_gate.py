"""Synthetic public-chain and record mutations. No key, executable or process."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit
from audit import HERE, a158
from replay import private, verify_envelope, verify_records
import run_gate


def synthetic_chain(error=0, displacement64=False):
    """Clear arithmetic fixture with all-zero large key, all-one small key, eta=0.

    It has actual native shapes but no sampled keys or encryption. The result is
    tagged client_observed solely to exercise the future schema; not runtime evidence.
    """
    from synthetic import make_record

    record, binding = make_record()
    record["kind"] = "client_observed"
    q, u = a158.Q, a158.U
    assert error % 16 == 0
    plaintext = [0] * 2048
    for i, v in [(0, 1), (1, -2), (255, 2), (511, -1)]:
        plaintext[i] = v * (1 << 52) % q
        plaintext[1024 + i] = v * (1 << 60) % q
    plaintext[1024] = (plaintext[1024] - error // 16) % q
    # Public mask with sparse but nonzero coefficients; body is exact plaintext
    # under the synthetic all-zero large key. No iid or sampler premise.
    packed = [(19 * i * (1 << 40) + 7) % q for i in range(2048)] + plaintext
    product = [0] * 4096
    template = a158.fixture()["template"]
    for block in range(2):
        for i, word in enumerate(packed[block * 2048 : (block + 1) * 2048]):
            for coordinate, t in enumerate(template):
                if t:
                    degree = i + 511 - coordinate
                    product[block * 2048 + degree % 2048] = (
                        product[block * 2048 + degree % 2048]
                        + (-1 if degree >= 2048 else 1) * word * (-2 * t)
                    ) % q
    low = [
        product[1535 - i] if i <= 1535 else -product[2048 + 1535 - i] % q
        for i in range(2048)
    ]
    low += [(product[2048 + 1535] + 1037 * (1 << 60)) % q]
    kin = [8 * x % q for x in low]
    assert low[-1] == (1029 * (1 << 60) + error // 8) % q
    assert kin[-1] == ((1 << 63) + error) % q
    mask = (
        [u // 2 - 1] * 128 + [0] * 730 + [3 * u]
        if displacement64
        else [0] * 858 + [3 * u]
    )
    A = sum(mask) % q
    D = sum(a158.degree(x) for x in mask)
    Z = sum(a158.signed(x - a158.degree(x) * u) for x in mask)
    post = mask + [(kin[-1] + A) % q]
    centered = mask + [(post[-1] + (1 << 62)) % q]
    record["ciphertexts"] = {
        k: a158.ct_record(v)
        for k, v in dict(
            score_low=low,
            ks_input=kin,
            post_ks=post,
            centered_input=centered,
            returned_lazy_base=centered,
        ).items()
    }
    record["actual_mask_degrees"] = [a158.degree(x) for x in mask]
    record["actual_body_degree"] = a158.degree(centered[-1])
    rows = []
    g = q
    for i, a in enumerate(kin[:-1]):
        for j, d in enumerate(a158.a156.decompose(a, q, 3, 5)[0]):
            if d:
                g = min(g, abs(d) & -abs(d))
                rows.append(
                    dict(
                        input_index=i,
                        level=5 - j,
                        storage_index=j,
                        digit=d,
                        row_words_sha256=hashlib.sha256(
                            f"synthetic row {i} {j}".encode()
                        ).hexdigest(),
                        eta_centered_lift=0,
                        contribution_lift=0,
                    )
                )
    record["subgroup_g"] = g
    record["initial_noise_terms_client"] = [
        dict(coefficient_index=1024 + i, epsilon_lift=-error // 16 if i == 0 else 0)
        for i, t in enumerate(template)
        if t
    ]
    address = (a158.degree(centered[-1]) - D) % 4096
    lift = (error + Z + u // 2) // u
    record["client"] = dict(
        low_phase_words=low[-1],
        large_input_mask_dot_words=0,
        input_phase_words=kin[-1],
        input_probe_weighted_noise_low_lift=error // 8,
        input_probe_weighted_noise_shifted_lift=error,
        large_remainder_lift=0,
        row_noise_signed_sum_direct_lift=0,
        row_noise_signed_sum_inferred_words=0,
        small_mask_dot_words=A,
        post_phase_words=kin[-1],
        small_weighted_ms_degrees=D,
        small_weighted_ms_residues_lift=Z,
        centered_phase_words=(kin[-1] + (1 << 62)) % q,
        direct_address=address,
        displacement_lift=lift,
    )
    record["native_first_bit_decode_pass"] = ((kin[-1] + (1 << 62)) % q) >> 63 == 1
    record["conditional_lut_address_pass"] = address >= 2048
    before = dict(
        bindings=binding,
        packed_query=a158.ct_record(packed),
        product=a158.ct_record(product),
        score_low=record["ciphertexts"]["score_low"],
        ks_input=record["ciphertexts"]["ks_input"],
        initial_noise_terms_client=record["initial_noise_terms_client"],
        input_noise_lift=error,
        large_remainder_lift=0,
        row_noise_signed_sum_direct_lift=0,
        subgroup_g=g,
        used_rows=rows,
        ks_calls_so_far=0,
        post_ks_exists=False,
    )
    prepared = {
        key: binding[key] for key in ("run_id", "source_sha256", "binary_sha256")
    }
    started = dict(
        prepared,
        schema="a164.prefix.started.v1",
        pid=123,
        timed_benchmark=False,
        secret_material_persisted=False,
    )
    completed = dict(
        status="P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS",
        ordinary_ks=1,
        configured_ms=1,
        blind_rotations=0,
        actual_sampler_p_fail=None,
        independent_replay_pending=True,
    )
    return record, before, binding, prepared, started, completed


class Prefix(unittest.TestCase):
    def test_import_only_successor(self):
        self.assertEqual(audit.verify_import_only_successor(), 17)

    @classmethod
    def setUpClass(cls):
        cls.good = synthetic_chain()

    def test_source_lock_and_single_prefix_order(self):
        self.assertEqual(audit.verify_origins(), 21)
        source = (HERE / "candidate/src/main.rs").read_text()
        self.assertEqual(
            source.count("keyswitch_lwe_ciphertext(ksk, &input, &mut post)"), 1
        )
        self.assertEqual(source.count(".lwe_ciphertext_modulus_switch::<usize, _>"), 1)
        self.assertEqual(source.count("encrypt_glwe_ciphertext("), 1)
        self.assertNotIn("blind_rotate_assign(", source)
        self.assertLess(
            source.index("measure_before_ks(ksk"),
            source.index("keyswitch_lwe_ciphertext(ksk"),
        )
        self.assertIn("MonomialDegree(1535)", source)
        self.assertIn("Cleartext(8)", source)

    def test_complete_synthetic_public_chain(self):
        result = verify_records(*self.good)
        self.assertTrue(result["selected_prefix_gate_pass"])
        self.assertTrue(result["actual_public_product_and_sample_pass"])
        self.assertIsNone(result["actual_sampler_p_fail"])
        self.assertFalse(result["actual_secret_key_membership_attested"])

    def test_native_pass_cannot_hide_ms_failure(self):
        args = synthetic_chain(error=1000 * a158.U, displacement64=True)
        result = a158.verify(args[0], args[2])
        self.assertTrue(result["native_first_bit_decode_pass"])
        self.assertFalse(result["conditional_lut_address_pass"])
        with self.assertRaises(AssertionError):
            verify_records(*args)

    def test_public_producer_mutations_even_with_rehashed_words(self):
        for field, index in [
            ("packed_query", 17),
            ("product", 2000),
            ("product", 2048 + 1535),
        ]:
            args = deepcopy(self.good)
            words = a158.words(args[1][field], 4096)
            words[index] ^= 1
            args[1][field] = a158.ct_record(words)
            with self.assertRaises(AssertionError):
                verify_records(*args)

    def test_used_row_value_order_and_sum_mutations(self):
        for key in (
            "input_index",
            "level",
            "storage_index",
            "digit",
            "eta_centered_lift",
            "contribution_lift",
        ):
            args = deepcopy(self.good)
            args[1]["used_rows"][0][key] += 1
            with self.assertRaises(AssertionError):
                verify_records(*args)
        args = deepcopy(self.good)
        args[1]["used_rows"].pop()
        with self.assertRaises(AssertionError):
            verify_records(*args)

    def test_premeasurement_binding_and_scope_mutations(self):
        for field in (
            "input_noise_lift",
            "large_remainder_lift",
            "row_noise_signed_sum_direct_lift",
            "subgroup_g",
            "ks_calls_so_far",
        ):
            args = deepcopy(self.good)
            args[1][field] += 1
            with self.assertRaises(AssertionError):
                verify_records(*args)
        for number in (2, 3, 4):
            args = deepcopy(self.good)
            args[number]["source_sha256"] = "a" * 64
            with self.assertRaises(AssertionError):
                verify_records(*args)
        args = deepcopy(self.good)
        args[5]["blind_rotations"] = 1
        with self.assertRaises(AssertionError):
            verify_records(*args)

    def test_frozen_checker_detects_aggregate_and_ms_mutations(self):
        for field in self.good[0]["client"]:
            args = deepcopy(self.good)
            args[0]["client"][field] += 1
            with self.assertRaises(AssertionError):
                verify_records(*args)
        args = deepcopy(self.good)
        args[0]["actual_mask_degrees"][0] += 1
        with self.assertRaises(AssertionError):
            verify_records(*args)

    def test_noargs_never_starts_child(self):
        with (
            patch("run_gate.subprocess.Popen", side_effect=AssertionError("no child")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_gate.main([]), 0)

    def test_exclusive_private_evidence(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "evidence.json"
            run_gate.write_new(path, {"value": 1})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                run_gate.write_new(path, {"value": 2})
            self.assertEqual(json.loads(path.read_text()), {"value": 1})

    def envelope(self):
        run = HERE / "runs" / "synthetic-envelope"
        binding = dict(run_id=run.name, source_sha256="1" * 64, binary_sha256="2" * 64)
        prepared = dict(
            binding,
            status="PREPARED",
            prepared_at_utc="2026-09-05T04:00:00+00:00",
            timed_benchmark=False,
            no_automatic_retries=True,
            workload_check_is_external_root_obligation=True,
            command=[
                str(HERE / "candidate/target-a164-only/release/a164_first_ks_prefix"),
                "--run-authorized",
                str(run),
                run.name,
            ],
        )
        records = {
            "prepared.json": prepared,
            "child.json": dict(
                binding, child_pid=123, started_at_utc="2026-09-05T04:00:01+00:00"
            ),
            "started.json": dict(pid=123),
            "exit.json": dict(
                binding,
                child_pid=123,
                exit_code=0,
                status="EXITED",
                binary_unchanged=True,
                source_unchanged=True,
                exited_at_utc="2026-09-05T04:00:02+00:00",
            ),
        }
        return run, "2" * 64, "1" * 64, records

    def test_envelope_hash_pid_run_mutations(self):
        verify_envelope(*self.envelope())
        for name in ("child.json", "exit.json"):
            for key in ("source_sha256", "binary_sha256", "run_id", "child_pid"):
                args = self.envelope()
                args[3][name][key] = 999 if key == "child_pid" else "a" * 64
                with self.assertRaises(AssertionError):
                    verify_envelope(*args)

    def test_envelope_command_and_chronology_mutations(self):
        for name, key in (
            ("prepared.json", "prepared_at_utc"),
            ("child.json", "started_at_utc"),
        ):
            args = self.envelope()
            args[3][name][key] = "2026-09-05T05:00:00+00:00"
            with self.assertRaises(AssertionError):
                verify_envelope(*args)
        args = self.envelope()
        args[3]["prepared.json"]["command"][0] = "/wrong/binary"
        with self.assertRaises(AssertionError):
            verify_envelope(*args)

    def test_private_read_side_rejects_mode_and_symlink(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "record.json"
            run_gate.write_new(path, {})
            private(path)
            path.chmod(0o644)
            with self.assertRaises(AssertionError):
                private(path)
            path.chmod(0o600)
            alias = path.parent / "alias"
            alias.symlink_to(path)
            with self.assertRaises(AssertionError):
                private(alias)


if __name__ == "__main__":
    unittest.main(verbosity=2)
