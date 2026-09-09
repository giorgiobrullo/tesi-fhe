"""Lightweight evidence-contract tests; no model, Docker build or FHE execution."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "demo_e2e_evidence_under_test", ROOT / "benchmark" / "demo_e2e.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("impossibile importare benchmark/demo_e2e.py")
demo_e2e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_e2e)


class DemoE2EEvidenceTest(unittest.TestCase):
    def state(self, n: int = 2) -> dict[str, object]:
        config = json.loads((ROOT / "demo" / "config.json").read_text())
        return {
            "client": {"config": config, "modello_caricato": True},
            "server": {
                "iscritti": n,
                "nomi": [f"sintetico_{index}" for index in range(n)],
                "soglie": [config["T_sintetico_digiface"]] * n,
                "chiave": True,
                "chiave_sha256": "a" * 64,
                "dim": config["dim"],
                "soglia_default": config["T"],
                "epoch": 9,
                "revision": 11,
                "dominio": {"l": -987, "u": 2329, "larghezza": 3317},
                "dominio_esecuzione": {
                    "l": -1019,
                    "u": 2329,
                    "larghezza": 3349,
                },
                "percorso_argmin": "a38_combined",
                "contratto_esatto": dict(demo_e2e.EXACT_SERVER_WIRE_CONTRACT),
            },
        }

    def row(self, correct: bool) -> dict[str, object]:
        return {
            "trial": 0,
            "indice_sintetico": 7,
            "atteso": "aperto",
            "esito": "aperto" if correct else "negato",
            "identita_attesa": "sintetico_7",
            "identita_restituita": "sintetico_7" if correct else None,
            "esito_corretto": correct,
            "identita_corretta": correct,
            "corretto": correct,
            "pbs": 5600,
        }

    def test_contract_is_checked_against_constants_not_only_client_server_agreement(
        self,
    ) -> None:
        state = self.state()
        state["client"]["config"]["contratto_esatto"]["output_mode"] = 1
        state["server"]["contratto_esatto"]["output_mode"] = 1

        with self.assertRaisesRegex(RuntimeError, "non canonico"):
            demo_e2e.validate_exact_contract(state)

    def test_stable_state_rejects_wrong_n_or_per_identity_thresholds(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "atteso N=3"):
            demo_e2e.stable_state_snapshot(self.state(n=2), expected_n=3)

        state = self.state()
        state["server"]["soglie"][1] += 1
        with self.assertRaisesRegex(RuntimeError, "soglie live non canoniche"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

    def test_stable_state_snapshot_is_deterministic_and_includes_gallery_version(
        self,
    ) -> None:
        state = self.state()
        first = demo_e2e.stable_state_snapshot(state, expected_n=2)
        second = demo_e2e.stable_state_snapshot(copy.deepcopy(state), expected_n=2)

        self.assertEqual(first, second)
        self.assertEqual(first["server"]["epoch"], 9)
        self.assertEqual(first["server"]["revision"], 11)

        state["client"]["modello_caricato"] = False
        with self.assertRaisesRegex(RuntimeError, "modello caricato dopo il preload"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

    def test_a38_execution_plan_is_derived_from_threshold_and_tight_domain(
        self,
    ) -> None:
        tight = dict(demo_e2e.EXPECTED_SYNTHETIC_CAUCHY_DOMAIN)

        execution, path = demo_e2e.expected_execution_plan([4, 4], tight)
        self.assertEqual(
            execution, {"l": -1019, "u": 2329, "larghezza": 3349}
        )
        self.assertEqual(path, demo_e2e.A38_ALIGNED_PATH)

        execution, path = demo_e2e.expected_execution_plan([4, 5], tight)
        self.assertEqual(execution, tight)
        self.assertEqual(path, demo_e2e.A29_GENERAL_PATH)

        execution, path = demo_e2e.expected_execution_plan([37], tight)
        self.assertEqual(execution, tight)
        self.assertEqual(path, demo_e2e.A29_GENERAL_PATH)

        execution, path = demo_e2e.expected_execution_plan([-743], tight)
        self.assertEqual(
            execution, {"l": -1766, "u": 2329, "larghezza": 4096}
        )
        self.assertEqual(path, demo_e2e.A38_ALIGNED_PATH)

        execution, path = demo_e2e.expected_execution_plan([-744], tight)
        self.assertEqual(execution, tight)
        self.assertEqual(path, demo_e2e.A29_GENERAL_PATH)

        execution, path = demo_e2e.expected_execution_plan([demo_e2e.I64_MIN], tight)
        self.assertEqual(execution, tight)
        self.assertEqual(path, demo_e2e.A29_GENERAL_PATH)

        with self.assertRaisesRegex(RuntimeError, "soglie non valide"):
            demo_e2e.expected_execution_plan([demo_e2e.I64_MAX + 1], tight)

    def test_stable_state_rejects_missing_or_tampered_execution_metadata(
        self,
    ) -> None:
        for field in ("dominio", "dominio_esecuzione", "percorso_argmin"):
            with self.subTest(missing=field):
                state = self.state()
                del state["server"][field]
                with self.assertRaisesRegex(RuntimeError, "stato server incompleto"):
                    demo_e2e.stable_state_snapshot(state, expected_n=2)

        state = self.state()
        state["server"]["dominio"] = {
            "l": -988,
            "u": 2329,
            "larghezza": 3318,
        }
        with self.assertRaisesRegex(RuntimeError, "dominio Cauchy live diverso"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

        state = self.state()
        configured = state["client"]["config"]["dominio_score_cauchy"][
            "galleria_sintetica_base"
        ]
        configured.update({"lower": -988, "width": 3318})
        with self.assertRaisesRegex(RuntimeError, "configurato non canonico"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

        state = self.state()
        state["server"]["dominio_esecuzione"] = {
            "l": -1020,
            "u": 2329,
            "larghezza": 3350,
        }
        with self.assertRaisesRegex(RuntimeError, "piano derivato indipendentemente"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

        state = self.state()
        state["server"]["percorso_argmin"] = "a29_general"
        with self.assertRaisesRegex(RuntimeError, "percorso argmin live diverso"):
            demo_e2e.stable_state_snapshot(state, expected_n=2)

    def test_expected_n_and_pbs_are_required_cli_evidence(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as missing,
        ):
            demo_e2e.parse_args([])
        self.assertEqual(missing.exception.code, 2)

        parsed = demo_e2e.parse_args(
            ["--preload", "--expect-n", "127", "--expect-pbs", "5600"]
        )
        self.assertEqual(parsed.expect_n, 127)
        self.assertEqual(parsed.expect_pbs, 5600)

        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as preload_missing,
        ):
            demo_e2e.parse_args(["--expect-n", "127", "--expect-pbs", "5600"])
        self.assertEqual(preload_missing.exception.code, 2)

        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as docker_missing,
        ):
            demo_e2e.parse_args(
                [
                    "--expect-n",
                    "127",
                    "--expect-pbs",
                    "5600",
                    "--preload",
                    "--require-docker-provenance",
                ]
            )
        self.assertEqual(docker_missing.exception.code, 2)

    def test_manifest_parser_is_strict_and_rejects_duplicate_paths(self) -> None:
        valid = (
            f"{'a' * 64}  src/lib.rs\n"
            f"{'b' * 64}  src/private_argmin.rs\n"
        )
        self.assertEqual(
            demo_e2e.parse_build_manifest(valid),
            {
                "src/lib.rs": "a" * 64,
                "src/private_argmin.rs": "b" * 64,
            },
        )
        with self.assertRaisesRegex(RuntimeError, "duplicato"):
            demo_e2e.parse_build_manifest(
                valid + f"{'c' * 64}  src/lib.rs\n"
            )
        with self.assertRaisesRegex(RuntimeError, "SHA-256 non valido"):
            demo_e2e.parse_build_manifest("not-a-hash  src/lib.rs\n")

    def test_preload_binding_ignores_only_expected_runtime_deltas(self) -> None:
        before = {
            "project": "evidence",
            "services": {
                service: {
                    "container_id": service,
                    "image_id": f"image-{service}",
                    "runtime_model": None,
                    "runtime_packages": None,
                    "docker_diff_sha256": "before",
                }
                for service in ("server", "client")
            },
        }
        after = copy.deepcopy(before)
        after["services"]["client"]["runtime_model"] = {"sha256": "a" * 64}
        after["services"]["client"]["runtime_packages"] = {"numpy": "1.26.4"}
        after["services"]["client"]["docker_diff_sha256"] = "after"

        self.assertEqual(
            demo_e2e.docker_static_binding(before),
            demo_e2e.docker_static_binding(after),
        )
        after["services"]["client"]["container_id"] = "replacement"
        self.assertNotEqual(
            demo_e2e.docker_static_binding(before),
            demo_e2e.docker_static_binding(after),
        )

    def test_semantic_mismatch_preserves_csv_and_json_then_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "evidence.csv"
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = demo_e2e.write_results(
                    output, [self.row(correct=False)], {"expected": {"n": 127}}
                )

            self.assertEqual(exit_code, 1)
            self.assertTrue(output.is_file())
            report = json.loads(output.with_suffix(".json").read_text())
            self.assertIs(report["success"], False)
            self.assertEqual(report["semantic_failure_count"], 1)
            self.assertEqual(report["semantic_failures"][0]["trial"], 0)
            self.assertEqual(report["csv_sha256"], demo_e2e.sha256_file(output))

    def test_semantic_success_returns_zero_and_records_no_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "evidence.csv"
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = demo_e2e.write_results(
                    output, [self.row(correct=True)], {}
                )

            report = json.loads(output.with_suffix(".json").read_text())
            self.assertEqual(exit_code, 0)
            self.assertIs(report["success"], True)
            self.assertEqual(report["semantic_failures"], [])

    def test_dockerfiles_embed_service_sources_in_the_image_manifest(self) -> None:
        server = (ROOT / "demo" / "server" / "Dockerfile").read_text()
        client = (ROOT / "demo" / "client" / "Dockerfile").read_text()

        for source in (
            "src/bin/varco_demo.rs",
            "src/lib.rs",
            "src/private_argmin.rs",
            "demo/server/Dockerfile",
            "target/release/varco_demo",
        ):
            self.assertIn(source, server)
        for source in (
            "src/bin/varco_demo.rs",
            "src/lib.rs",
            "src/private_argmin.rs",
            "demo/client/Dockerfile",
            "demo/client/app.py",
            "demo/config.json",
            "experiments/08_cnn/embedding.py",
            "target/release/varco_demo",
        ):
            self.assertIn(source, client)
        self.assertIn("build-provenance.sha256", server)
        self.assertIn("build-provenance.sha256", client)
        self.assertIn(
            'CMD ["/bin/sh", "-c", "exec /usr/local/bin/varco_demo serve '
            '$PORTA $DIM $SOGLIA"]',
            server,
        )
        self.assertIn(
            'CMD ["/usr/local/bin/uvicorn", "demo.client.app:app", '
            '"--host", "0.0.0.0", "--port", "8000"]',
            client,
        )
        for name, value in demo_e2e.EXPECTED_CLIENT_ENVIRONMENT.items():
            self.assertIn(f"{name}={value}", client)
        self.assertIn("WORKDIR /app", client)


if __name__ == "__main__":
    unittest.main()
