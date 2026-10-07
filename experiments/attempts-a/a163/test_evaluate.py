"""Exact synthetic adapter tests; no actual producer records or keys."""

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import evaluate as gate


def public_fixture(model, g=1):
    public = model.synthetic_native_record(g)
    public.pop("provenance")
    public.update(first_low_bit=1, reference_degree=3072, template=list(gate.TEMPLATE))
    return public


def validation_fixture(public):
    return dict(
        status="CONDITIONAL_CLIENT_ARITHMETIC_CLOSURE",
        public_coefficients_and_domains_pass=True,
        phase_component_modular_closure_pass=True,
        native_first_bit_decode_pass=True,
        conditional_lut_address_pass=True,
        selected_prefix_gate_pass=True,
        direct_address=3072,
        displacement_lift=0,
        a156_public_input=public,
        independently_attested_client_aggregates=False,
        actual_secret_key_membership_attested=False,
        full_n4_evaluation=False,
        blind_rotation_consumed=False,
        actual_sampler_p_fail=None,
        ideal_gaussian_integer_lifts_attested=False,
        actual_public_product_and_sample_pass=True,
        used_row_contribution_replay_pass=True,
        independently_attested_row_decryption=False,
        source_order_does_not_attest_runtime_chronology=True,
        producer_full_n4_scope=False,
        runtime_files_sha256={},
    )


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = gate.load_model()

    def test_fixed_coefficients(self):
        context = gate.public_context(public_fixture(self.model), self.model, True)
        self.assertEqual(
            [x for x in context.input_noise_coefficients if x], [-16, 16, -16, -16]
        )
        self.assertEqual(sum(c * c for c in context.input_noise_coefficients), 1024)
        self.assertEqual(sum(abs(c) for c in context.input_noise_coefficients), 64)
        self.assertEqual(context.safe_lifts, (-1024, 1023))
        self.assertEqual(context.theta, 0)

    def test_exact_upstream_crosscheck_fixed_grid(self):
        public = public_fixture(self.model)
        result = gate.calculate(public, self.model, True)
        reference = gate.encoded(self.model.bound(self.model.native_context(public)))
        for key in reference:
            self.assertEqual(result[key], reference[key])
        self.assertEqual(result["evidence_kind"], "SYNTHETIC_COEFFICIENT_TEST")
        self.assertIsNone(result["actual_p_fail"])
        for tail in result["tails"]:
            self.assertEqual(
                [r["lambda_per_degree"] for r in tail["attempts"]],
                ["1/4", "1/2", "1", "2"],
            )

    def test_subgroup_zero_branch_and_all_supported_groups(self):
        for g in (1, 2, 4, 1 << 64):
            context = gate.public_context(
                public_fixture(self.model, g), self.model, True
            )
            self.assertEqual(context.subgroup, g)
            if g == 1 << 64:
                self.assertEqual(context.residue_mean, 0)
                self.assertEqual(
                    self.model.subgroup_mgf_upper(context, Fraction(1)).exact(), 1
                )

    def test_malformed_public_rejections(self):
        mutations = [
            lambda p: p.update(first_low_bit=True),
            lambda p: p.update(first_low_bit=0),
            lambda p: p.update(reference_degree=1024),
            lambda p: p.update(public_offset_words=1 << 61),
            lambda p: p.update(safe_lifts=[-63, 63]),
            lambda p: p.update(sigma=0),
            lambda p: p["template"].__setitem__(0, -1),
            lambda p: p["template"].__setitem__(2, False),
            lambda p: p["input_mask_words"].__setitem__(0, 1),
            lambda p: p["input_mask_words"].pop(),
            lambda p: p["digits_descending"][0].__setitem__(1, False),
            lambda p: p["digits_descending"][0].reverse(),
            lambda p: p["digits_descending"][0].pop(),
            lambda p: p["remainder_words"].__setitem__(0, 0),
            lambda p: p.update(subgroup_g=2),
            lambda p: p.update(input_kind="client_observed_public_input"),
        ]
        for mutate in mutations:
            public = public_fixture(self.model)
            mutate(public)
            with self.assertRaises((ValueError, AssertionError)):
                gate.public_context(public, self.model, True)

    def test_json_strictness(self):
        for text in ('{"a":1,"a":1}', '{"a":0.0}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                gate.decode(text)
        with self.assertRaises(ValueError):
            gate.same([0, [1]], [False, [True]], "nested aliases")

    def test_no_synthetic_actual_transfer(self):
        public = public_fixture(self.model)
        with self.assertRaises(ValueError):
            gate.public_context(public, self.model, False)

    def test_validation_rejects_overclaim_and_false_pass(self):
        public = public_fixture(self.model)
        validation = validation_fixture(public)
        gate.expected_validation(public, validation)
        for key, value in (
            ("actual_sampler_p_fail", "1/100"),
            ("ideal_gaussian_integer_lifts_attested", True),
            ("blind_rotation_consumed", True),
            ("selected_prefix_gate_pass", False),
            ("direct_address", True),
            ("extra", 1),
        ):
            bad = deepcopy(validation)
            bad[key] = value
            with self.assertRaises(ValueError):
                gate.expected_validation(public, bad)

    def test_private_exclusive_output(self):
        with tempfile.TemporaryDirectory(dir=gate.HERE / "artifacts") as name:
            directory = Path(name)
            path = directory / "record.json"
            gate.write_new(path, {"x": 1})
            gate.private(path)
            with self.assertRaises(FileExistsError):
                gate.write_new(path, {"x": 2})
            link = directory / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                gate.read(link, True)

    def test_synthetic_envelope_and_binding_mutations(self):
        # A fake producer exists only in this temporary test directory. It exercises
        # record binding, not A164 execution, row decryption, or secret membership.
        with tempfile.TemporaryDirectory(dir=gate.HERE / "artifacts") as name:
            base = Path(name)
            candidate = base / "candidate"
            candidate.mkdir()
            (candidate / "source.rs").write_text("SYNTHETIC_NO_CRYPTO\n")
            manifest = {"candidate/source.rs": gate.sha(candidate / "source.rs")}
            source = hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            (base / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest))
            (candidate / "SOURCE_DIGEST.txt").write_text(source + "\n")
            (candidate / "FIXTURE.json").write_text(json.dumps({"synthetic": True}))
            binary = candidate / "fake-binary"
            binary.write_bytes(b"SYNTHETIC_NOT_EXECUTABLE")
            binary_hash = gate.sha(binary)
            runs = base / "runs"
            runs.mkdir(mode=0o700)
            run = runs / "synthetic"
            run.mkdir(mode=0o700)
            public = public_fixture(self.model)
            public["input_kind"] = "client_observed_public_input"
            binding = dict(
                run_id=run.name,
                source_sha256=source,
                binary_sha256=binary_hash,
                configuration="Standard",
                parameter_fingerprint="fake-parameter",
            )
            native = public["input_mask_words"] + [0]
            ct = dict(
                words_hex=[f"{x:016x}" for x in native],
                sha256=hashlib.sha256(
                    b"".join(x.to_bytes(8, "little") for x in native)
                ).hexdigest(),
            )
            records = {
                "trace.json": dict(
                    schema="a158.first_low_ks_trace.v1",
                    kind="client_observed",
                    bindings=binding,
                    fixture={"synthetic": True},
                    ciphertexts={"ks_input": ct},
                ),
                "before-ks.json": {"synthetic": True},
                "key-binding.json": binding,
                "prepared.json": dict(
                    **binding,
                    status="PREPARED",
                    timed_benchmark=False,
                    no_automatic_retries=True,
                    workload_check_is_external_root_obligation=True,
                    command=[str(binary), "--run-authorized", str(run), run.name],
                    prepared_at_utc="2026-09-05T00:00:00+00:00",
                ),
                "started.json": dict(
                    **binding,
                    schema="synthetic.started",
                    pid=1,
                    timed_benchmark=False,
                    secret_material_persisted=False,
                ),
                "completed.json": dict(
                    status="P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS",
                    ordinary_ks=1,
                    configured_ms=1,
                    blind_rotations=0,
                    actual_sampler_p_fail=None,
                    independent_replay_pending=True,
                ),
                "exit.json": dict(
                    **binding,
                    status="EXITED",
                    exit_code=0,
                    child_pid=1,
                    source_unchanged=True,
                    binary_unchanged=True,
                    exited_at_utc="2026-09-05T00:00:02+00:00",
                    stdout_sha256=hashlib.sha256(b"").hexdigest(),
                    stderr_sha256=hashlib.sha256(b"").hexdigest(),
                ),
                "child.json": dict(
                    **binding, child_pid=1, started_at_utc="2026-09-05T00:00:01+00:00"
                ),
            }
            for key, value in records.items():
                gate.write_new(run / key, value)
            for key in ("stdout.log", "stderr.log"):
                (run / key).write_bytes(b"")
                (run / key).chmod(0o600)
            validation = validation_fixture(public)
            validation["runtime_files_sha256"] = {
                key: gate.sha(run / key) for key in gate.RUNTIME_NAMES
            }
            gate.write_new(run / "validation.json", validation)
            gate.write_new(run / "a156-public-input.json", public)
            registry = dict(
                producers={
                    "synthetic": dict(
                        directory=str(base),
                        source_sha256=source,
                        binary_relative="candidate/fake-binary",
                        started_schema="synthetic.started",
                        parameter_fingerprint="fake-parameter",
                    )
                }
            )
            original_read = gate.read

            def fake_read(path, sensitive=False):
                if path == gate.HERE / "PRODUCERS.json":
                    return registry
                return original_read(path, sensitive)

            with patch.object(gate, "read", side_effect=fake_read):
                _, _, provenance = gate.runtime_input(
                    "synthetic", run, binary_hash, self.model
                )
                self.assertFalse(provenance["operating_system_execution_attested"])
                for field, value in (
                    ("source_sha256", "0" * 64),
                    ("binary_sha256", "1" * 64),
                ):
                    saved = records["prepared.json"][field]
                    records["prepared.json"][field] = value
                    (run / "prepared.json").write_text(
                        json.dumps(records["prepared.json"])
                    )
                    validation["runtime_files_sha256"]["prepared.json"] = gate.sha(
                        run / "prepared.json"
                    )
                    (run / "validation.json").write_text(json.dumps(validation))
                    with self.assertRaises(ValueError):
                        gate.runtime_input("synthetic", run, binary_hash, self.model)
                    records["prepared.json"][field] = saved
                # Even a correspondingly rehashed bad exit cannot be accepted.
                (run / "prepared.json").write_text(json.dumps(records["prepared.json"]))
                records["exit.json"]["exit_code"] = False
                (run / "exit.json").write_text(json.dumps(records["exit.json"]))
                validation["runtime_files_sha256"] = {
                    key: gate.sha(run / key) for key in gate.RUNTIME_NAMES
                }
                (run / "validation.json").write_text(json.dumps(validation))
                with self.assertRaises(ValueError):
                    gate.runtime_input("synthetic", run, binary_hash, self.model)


if __name__ == "__main__":
    unittest.main(verbosity=2)
