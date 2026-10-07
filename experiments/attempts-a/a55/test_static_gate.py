from __future__ import annotations

import importlib.util
import os
import pathlib
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE_FILE = pathlib.Path(__file__).with_name("run_gate.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("_a55_a38_gate", GATE_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A55 gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class A38DockerGateStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()

    def test_canonical_contract_and_isolation(self) -> None:
        self.assertEqual(self.gate.EXPECTED_N, "127")
        self.assertEqual(self.gate.EXPECTED_PBS, "3655")
        self.assertEqual(self.gate.EXPECTED_PATH, "a38_combined")
        self.assertEqual(self.gate.PROJECT, "thesis-a38-frozen-a55")
        self.assertEqual(self.gate.BASE_URL, "http://127.0.0.1:18038")

    def test_identity_and_all_pins_are_current(self) -> None:
        identity, identity_records = self.gate.load_identity_manifest()
        self.assertEqual(identity["contract"]["pbs_per_query"], 3655)
        self.assertEqual(identity["contract"]["path"], "a38_combined")
        self.assertEqual(
            identity_records["tmp/a38-combined-prototype/varco_demo"],
            "f4cdc28f92ffae8d34c207a06896299015aca2673fce14a959cc3bea34dc1e02",
        )
        pinned = self.gate.pinned_input_hashes()
        self.assertTrue(set(identity_records).issubset(pinned))
        self.gate.validate_static_layout(pinned)

    def test_images_compile_only_frozen_a38_service_source(self) -> None:
        for dockerfile in (
            self.gate.SERVER_DOCKERFILE,
            self.gate.CLIENT_DOCKERFILE,
        ):
            text = dockerfile.read_text()
            self.assertIn(
                "COPY tmp/a38-combined-prototype/source/experiments/14_pipeline_tfhe_rs",
                text,
            )
            self.assertNotIn("COPY experiments/14_pipeline_tfhe_rs", text)
            self.assertNotIn("COPY demo/chiavi", text)
            self.assertNotIn("COPY datasets", text)
            self.assertNotIn("COPY .insightface", text)

    def test_output_names_are_collision_scoped(self) -> None:
        accepted = (
            "demo_e2e_exact_id_a38_frozen_2026-09-02_gate01.csv",
            "demo_e2e_exact_id_a38_frozen_2026-09-02T235959Z.csv",
        )
        rejected = (
            "demo_e2e_exact_id_a38_frozen_2026-09-02.csv",
            "demo_e2e_exact_id_a33_frozen_2026-09-02_gate01.csv",
            "../demo_e2e_exact_id_a38_frozen_2026-09-02_gate01.csv",
        )
        for name in accepted:
            self.assertIsNotNone(self.gate.OUTPUT_NAME_RE.fullmatch(name))
        for name in rejected:
            self.assertIsNone(self.gate.OUTPUT_NAME_RE.fullmatch(name))

    def test_canonical_arguments_pass_static_validation(self) -> None:
        output = ROOT / "benchmark/results/demo_e2e_exact_id_a38_frozen_2026-09-02_gate99.csv"
        self.assertFalse(output.exists())
        self.assertFalse(output.with_suffix(".json").exists())
        arguments = [
            "--base-url",
            self.gate.BASE_URL,
            "--preload",
            "--expect-n",
            self.gate.EXPECTED_N,
            "--expect-pbs",
            self.gate.EXPECTED_PBS,
            "--positivi",
            "3",
            "--negativi",
            "3",
            "--docker-project",
            self.gate.PROJECT,
            "--docker-compose-file",
            str(self.gate.COMPOSE_FILE),
            "--require-docker-provenance",
            "--require-calibration-cache",
            "--output",
            str(output),
        ]
        with mock.patch.dict(
            os.environ, {"A38_MODEL_CACHE": str(ROOT)}, clear=False
        ):
            self.gate.validate_gate_arguments(arguments)
            wrong_pbs = list(arguments)
            wrong_pbs[wrong_pbs.index("--expect-pbs") + 1] = "3654"
            with self.assertRaisesRegex(RuntimeError, "--expect-pbs"):
                self.gate.validate_gate_arguments(wrong_pbs)


if __name__ == "__main__":
    unittest.main()
