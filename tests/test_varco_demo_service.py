"""Regressioni end-to-end del servizio Rust usato dalla demo.

Il contratto testato e' l'identificazione open-set esatta: il server calcola il primo argmin,
confronta il suo score soltanto con la soglia associata al vincitore e restituisce un unico LWE.
Il plaintext di quell'LWE e' ``0`` per il rifiuto oppure ``indice + 1`` per un'identita' accettata.

I test non caricano il modello facciale ne' dataset. Generano pero' chiavi TFHE reali e i casi che
invocano ``/varco`` eseguono davvero il circuito cifrato, quindi sono intenzionalmente piu' lenti
dei test focalizzati in ``tests/test_demo_client.py``.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "14_pipeline_tfhe_rs"
CONFIG_PATH = ROOT / "demo" / "config.json"


class ExactDemoConfigurationTest(unittest.TestCase):
    """Controlli statici eseguibili anche mentre il seam Rust viene integrato."""

    def test_config_declares_the_exact_fixed_wire_contract(self) -> None:
        config = json.loads(CONFIG_PATH.read_text())
        self.assertEqual(config["decisione"], "exact_argmin_then_selected_threshold")
        self.assertNotIn("log_delta", config)
        self.assertEqual(
            config["contratto_esatto"],
            {
                "wire_version": 2,
                "probe_layout": 1,
                "score_delta_log": 52,
                "low_mod16_offset": 1024,
                "low_mod16_delta_log": 60,
                "output_mode": 2,
                "code_delta_log": 56,
                "codice": "0=rifiuto; i+1=identita_accettata",
                "un_solo_lwe": True,
                "score_bits": 12,
                "probe_norm2_max": 1024,
                "score_domain_width_max": 4096,
                "tie_break": "primo_indice_galleria",
                "selezione_soglia": "solo_del_vincitore_argmin",
            },
        )

    def test_docker_launch_does_not_pass_the_removed_delta_argument(self) -> None:
        dockerfile = (ROOT / "demo" / "server" / "Dockerfile").read_text()
        env_file = (ROOT / "demo" / "config.env").read_text()
        self.assertNotIn("LOG_DELTA", dockerfile)
        self.assertNotIn("$LOG_DELTA", dockerfile)
        self.assertNotIn("LOG_DELTA=", env_file)
        self.assertIn("varco_demo serve $PORTA $DIM $SOGLIA", dockerfile)


class VarcoDemoServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads(CONFIG_PATH.read_text())
        cls.dim = int(cls.config["dim"])
        cls.default_threshold = int(cls.config["T"])
        configured = os.environ.get("VARCO_DEMO_BIN")
        cls.binary = (
            pathlib.Path(configured)
            if configured
            else CRATE / "target" / "release" / "varco_demo"
        )
        if configured is None:
            subprocess.run(
                ["cargo", "build", "--release", "--bin", "varco_demo"],
                cwd=CRATE,
                check=True,
            )

        cls.tempdir = tempfile.TemporaryDirectory(prefix="varco-demo-test-")
        cls.temp = pathlib.Path(cls.tempdir.name)
        cls.keys = cls.temp / "keys"
        subprocess.run(
            [cls.binary, "keygen", cls.keys],
            check=True,
            capture_output=True,
            text=True,
        )

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.server = subprocess.Popen(
            [
                cls.binary,
                "serve",
                str(cls.port),
                str(cls.dim),
                str(cls.default_threshold),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(100):
            try:
                status, _ = cls.request("GET", "/stato", timeout=2)
                if status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("the exact varco demo server did not start")

        status, body = cls.request("GET", "/stato")
        state = json.loads(body)
        if (state["dim"], state["soglia_default"]) != (
            cls.dim,
            cls.default_threshold,
        ):
            raise RuntimeError(f"server/config mismatch: {state!r}")

        status, body = cls.request(
            "POST", "/chiave", (cls.keys / "server.key").read_bytes()
        )
        if status != 200:
            raise RuntimeError(f"evaluation-key upload failed: HTTP {status}: {body!r}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop_server(cls.server)
        cls.tempdir.cleanup()

    @staticmethod
    def stop_server(server: subprocess.Popen[str]) -> None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        if server.stdout is not None:
            server.stdout.close()
        if server.stderr is not None:
            server.stderr.close()

    @classmethod
    def request(
        cls,
        method: str,
        path: str,
        body: bytes = b"",
        content_type: str = "application/octet-stream",
        timeout: int = 600,
    ) -> tuple[int, bytes]:
        status, data, _ = cls.request_with_headers(
            method, path, body, content_type, timeout
        )
        return status, data

    @classmethod
    def request_with_headers(
        cls,
        method: str,
        path: str,
        body: bytes = b"",
        content_type: str = "application/octet-stream",
        timeout: int = 600,
    ) -> tuple[int, bytes, dict[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=timeout)
        connection.request(
            method, path, body=body, headers={"Content-Type": content_type}
        )
        response = connection.getresponse()
        data = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, data, headers

    @classmethod
    def request_declared_length_without_body(
        cls, method: str, path: str, declared_length: int
    ) -> tuple[int, bytes]:
        with socket.create_connection(("127.0.0.1", cls.port), timeout=5) as sock:
            request = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Length: {declared_length}\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read()
            return response.status, body

    def setUp(self) -> None:
        status, body = self.request("POST", "/reset")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIs(payload["ok"], True)

    def state(self) -> dict[str, object]:
        status, body = self.request("GET", "/stato")
        self.assertEqual(status, 200)
        return json.loads(body)

    def enroll(
        self,
        name: str,
        template: list[int],
        threshold: int | None = None,
    ) -> tuple[int, dict[str, object]]:
        header = name if threshold is None else f"{name}\t{threshold}"
        body = (header + "\n" + " ".join(map(str, template))).encode()
        status, response = self.request("POST", "/iscrivi", body, "text/plain")
        return status, json.loads(response)

    def encrypt(self, probe: list[int], name: str = "probe") -> bytes:
        probe_path = self.temp / f"{name}.txt"
        output_path = self.temp / f"{name}.ct"
        probe_path.write_text(" ".join(map(str, probe)))
        output_path.unlink(missing_ok=True)
        subprocess.run(
            [self.binary, "encrypt", self.keys, probe_path, output_path],
            check=True,
            capture_output=True,
            text=True,
        )
        return output_path.read_bytes()

    def decrypt(self, ciphertext: bytes) -> dict[str, object]:
        path = self.temp / "result.ct"
        path.write_bytes(ciphertext)
        result = subprocess.run(
            [self.binary, "decrypt", self.keys, path],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout.strip().splitlines()[-1])

    def query(
        self, probe: list[int], name: str
    ) -> tuple[dict[str, object], bytes, dict[str, str], dict[str, object]]:
        before = self.state()
        status, encrypted_result, headers = self.request_with_headers(
            "POST", "/varco", self.encrypt(probe, name)
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Varco-Contract"], "exact-open-set-id-v2")
        self.assertGreater(int(headers["X-Pbs"]), 0)
        decrypted = self.decrypt(encrypted_result)
        self.assertEqual(decrypted["galleria_epoch"], before["epoch"])
        self.assertEqual(decrypted["galleria_revision"], before["revision"])
        self.assertEqual(decrypted["iscritti"], before["iscritti"])
        self.assert_single_lwe_output(encrypted_result)
        return decrypted, encrypted_result, headers, before

    def assert_single_lwe_output(self, ciphertext: bytes) -> None:
        self.assertEqual(len(ciphertext) % 8, 0)
        header_words = struct.unpack_from("<Q", ciphertext, 0)[0]
        self.assertEqual(header_words, 8)
        header = struct.unpack_from("<8Q", ciphertext, 8)
        self.assertEqual(header[1], 2)  # wire version
        self.assertEqual(header[2], 2)  # exact-ID mode
        self.assertEqual(header[7], self.config["contratto_esatto"]["code_delta_log"])
        body_words = len(ciphertext) // 8 - 1 - header_words
        self.assertEqual(body_words, header[6])

    def assert_result(
        self, decrypted: dict[str, object], *, authorized: bool, index: int | None
    ) -> None:
        self.assertIs(decrypted["autorizzato"], authorized)
        self.assertEqual(decrypted["indice"], index)
        self.assertEqual(
            decrypted["codice"], index + 1 if authorized and index is not None else 0
        )
        self.assertNotIn("score", decrypted)
        self.assertNotIn("distanza", decrypted)
        self.assertNotIn("conteggio", decrypted)

    def test_server_advertises_the_same_exact_contract_as_config(self) -> None:
        state = self.state()
        contract = state["contratto_esatto"]
        expected = self.config["contratto_esatto"]
        for key in (
            "wire_version",
            "probe_layout",
            "score_delta_log",
            "low_mod16_offset",
            "low_mod16_delta_log",
            "output_mode",
            "code_delta_log",
            "codice",
            "un_solo_lwe",
        ):
            with self.subTest(key=key):
                self.assertEqual(contract[key], expected[key])
        self.assertEqual(state["iscritti"], 0)
        self.assertIsNone(state["dominio"])
        self.assertIsNone(state["dominio_esecuzione"])
        self.assertIsNone(state["percorso_argmin"])
        self.assertIs(state["chiave"], True)
        self.assertEqual(
            state["chiave_sha256"],
            hashlib.sha256((self.keys / "server.key").read_bytes()).hexdigest(),
        )

    def test_evaluation_key_upload_is_idempotent_but_replacement_is_rejected(
        self,
    ) -> None:
        raw_key = (self.keys / "server.key").read_bytes()
        expected = hashlib.sha256(raw_key).hexdigest()

        status, body = self.request("POST", "/chiave", raw_key)
        response = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIs(response["idempotente"], True)
        self.assertEqual(response["chiave_sha256"], expected)

        status, body = self.request("POST", "/chiave", b"different-key")
        self.assertEqual(status, 409)
        self.assertIn("diversa", json.loads(body)["errore"])
        self.assertEqual(self.state()["chiave_sha256"], expected)

    @unittest.skipUnless(os.name == "posix", "Unix permission bits required")
    def test_keygen_uses_private_directory_and_secret_key_permissions(self) -> None:
        self.assertEqual(stat.S_IMODE(self.keys.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.keys / "client.key").stat().st_mode), 0o600)

    def test_oversize_content_length_is_rejected_before_reading_the_body(self) -> None:
        # Nessun body viene inviato: una risposta immediata prova che il server controlla il
        # Content-Length prima di allocare o attendere il payload dichiarato.
        for path in ("/chiave", "/varco", "/iscrivi", "/reset"):
            with self.subTest(path=path):
                status, body = self.request_declared_length_without_body(
                    "POST", path, 1_000_000_000
                )
                self.assertEqual(status, 413)
                self.assertIn("corpo troppo grande", json.loads(body)["errore"])
        self.assertEqual(self.request("GET", "/stato")[0], 200)

    def test_enrollment_uses_the_complete_cauchy_score_domain(self) -> None:
        one = [1] + [0] * (self.dim - 1)
        status, response = self.enroll("one", one, threshold=1)
        self.assertEqual((status, response["ok"]), (200, True))
        self.assertEqual(response["dominio"], {"l": -63, "u": 65, "larghezza": 129})
        self.assertEqual(
            response["dominio_esecuzione"],
            {"l": -1022, "u": 65, "larghezza": 1088},
        )
        self.assertEqual(response["percorso_argmin"], "a38_combined")

        too_wide = [3] * 200 + [0] * (self.dim - 200)
        status, response = self.enroll("unsafe", too_wide)
        self.assertEqual(status, 400)
        self.assertIn("dominio globale", str(response["errore"]))
        self.assertIn("massimo 4096", str(response["errore"]))
        self.assertEqual(self.state()["nomi"], ["one"])

    def test_enrollment_is_versioned_atomic_and_keeps_names_valid_json(self) -> None:
        name = 'a"b\\c'
        zero = [0] * self.dim
        before = self.state()
        status, first = self.enroll(name, zero, threshold=-1)
        self.assertEqual((status, first["indice"]), (200, 0))
        status, second = self.enroll(name, zero, threshold=0)
        self.assertEqual((status, second["indice"]), (200, 0))
        after = self.state()
        self.assertEqual(after["nomi"], [name])
        self.assertEqual(after["soglie"], [0])
        self.assertEqual(after["iscritti"], 1)
        self.assertEqual(after["revision"], before["revision"] + 2)

        invalid = [4] + [0] * (self.dim - 1)
        status, response = self.enroll("invalid", invalid)
        self.assertEqual(status, 400)
        self.assertIn("fuori dal dominio", str(response["errore"]))
        self.assertEqual(self.state()["revision"], after["revision"])

    def test_encrypt_cli_enforces_coordinate_and_norm_bounds(self) -> None:
        cases = (
            ("short", [0] * (self.dim - 1), f"esattamente {self.dim} coefficienti"),
            ("range", [4] + [0] * (self.dim - 1), "fuori dal dominio dichiarato"),
            (
                "norm",
                [3] * 113 + [2, 2] + [0] * (self.dim - 115),
                "norma quadratica del probe 1025 oltre il massimo 1024",
            ),
        )
        for name, probe, message in cases:
            with self.subTest(name=name):
                probe_path = self.temp / f"invalid-{name}.txt"
                output_path = self.temp / f"invalid-{name}.ct"
                probe_path.write_text(" ".join(map(str, probe)))
                output_path.unlink(missing_ok=True)
                result = subprocess.run(
                    [self.binary, "encrypt", self.keys, probe_path, output_path],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output_path.exists())

        boundary = [3] * 113 + [2] + [0] * (self.dim - 114)  # ||q||^2 = 1021
        self.assertTrue(self.encrypt(boundary, "norm-boundary"))

    def test_exact_nearest_identity_is_returned(self) -> None:
        far = [1] + [0] * (self.dim - 1)
        nearest = [0] * self.dim
        self.assertEqual(self.enroll("far", far, threshold=100)[0], 200)
        self.assertEqual(self.enroll("nearest", nearest, threshold=0)[0], 200)

        decrypted, _, _, _ = self.query([0] * self.dim, "nearest-id")
        self.assert_result(decrypted, authorized=True, index=1)

    def test_only_the_nearest_templates_threshold_controls_rejection(self) -> None:
        nearest = [0] * self.dim
        farther = [1] + [0] * (self.dim - 1)
        self.assertEqual(self.enroll("nearest-rejects", nearest, threshold=-1)[0], 200)
        self.assertEqual(self.enroll("farther-accepts", farther, threshold=100)[0], 200)

        # any_match accetterebbe tramite il secondo template. Il contratto finale deve invece
        # rifiutare: prima seleziona il minimo (indice 0), poi applica soltanto la sua soglia.
        decrypted, _, _, _ = self.query([0] * self.dim, "winner-threshold")
        self.assert_result(decrypted, authorized=False, index=None)
        self.assertEqual(self.state()["percorso_argmin"], "a29_general")

    def test_a38_rejected_prefix_cannot_resurrect_and_exact_id_is_returned(
        self,
    ) -> None:
        one = [1] + [0] * (self.dim - 1)
        zero = [0] * self.dim
        self.assertEqual(self.enroll("rejected-first", one, threshold=0)[0], 200)
        self.assertEqual(self.enroll("accepted-second", zero, threshold=0)[0], 200)
        state = self.state()
        self.assertEqual(state["percorso_argmin"], "a38_combined")
        self.assertEqual(state["dominio"], {"l": -63, "u": 65, "larghezza": 129})
        self.assertEqual(
            state["dominio_esecuzione"],
            {"l": -1023, "u": 65, "larghezza": 1089},
        )

        decrypted, _, headers, _ = self.query(zero, "a38-no-resurrection")
        self.assertEqual(int(headers["X-Pbs"]), 60)
        self.assert_result(decrypted, authorized=True, index=1)

    def test_a38_uniform_gallery_can_reject_without_releasing_an_id(self) -> None:
        zero = [0] * self.dim
        self.assertEqual(self.enroll("first", zero, threshold=-1)[0], 200)
        self.assertEqual(self.enroll("second", zero, threshold=-1)[0], 200)
        self.assertEqual(self.state()["percorso_argmin"], "a38_combined")

        decrypted, _, headers, _ = self.query(zero, "a38-all-reject")
        self.assertEqual(int(headers["X-Pbs"]), 60)
        self.assert_result(decrypted, authorized=False, index=None)

    def test_equal_scores_choose_the_first_gallery_index(self) -> None:
        zero = [0] * self.dim
        self.assertEqual(self.enroll("first", zero, threshold=0)[0], 200)
        self.assertEqual(self.enroll("second", zero, threshold=0)[0], 200)

        decrypted, _, _, _ = self.query(zero, "first-tie")
        self.assert_result(decrypted, authorized=True, index=0)
        self.assertEqual(self.state()["percorso_argmin"], "a38_combined")

    def test_odd_gallery_size_can_return_its_last_identity(self) -> None:
        templates: list[list[int]] = []
        for coordinate in (3, 2, 1):
            template = [0] * self.dim
            template[0] = coordinate
            templates.append(template)
        for index, template in enumerate(templates):
            self.assertEqual(self.enroll(f"g{index}", template, threshold=-1)[0], 200)

        probe = [0] * self.dim
        probe[0] = 1
        # score = ||g||^2 - 2<g,q>: [3, 0, -1], quindi vince l'ultimo ed e' incluso.
        decrypted, _, headers, _ = self.query(probe, "odd-last")
        self.assertEqual(int(headers["X-Pbs"]), 85)
        self.assertEqual(self.state()["percorso_argmin"], "a38_combined")
        self.assert_result(decrypted, authorized=True, index=2)

    def test_probe_wire_is_strict_and_malformed_inputs_do_not_stop_service(
        self,
    ) -> None:
        self.assertEqual(self.enroll("zero", [0] * self.dim)[0], 200)
        valid = bytearray(self.encrypt([0] * self.dim, "wire-valid"))

        cases: list[tuple[str, bytes, str]] = []
        bad_magic = valid.copy()
        struct.pack_into("<Q", bad_magic, 8, 0)
        cases.append(("magic", bytes(bad_magic), "magic del probe"))

        bad_scale = valid.copy()
        struct.pack_into("<Q", bad_scale, 8 * (1 + 6), 53)
        cases.append(("scale", bytes(bad_scale), "scale del probe incompatibili"))
        cases.append(
            ("truncated", bytes(valid[:-8]), "corpo del probe di lunghezza errata")
        )

        for name, payload, message in cases:
            with self.subTest(name=name):
                status, body = self.request("POST", "/varco", payload)
                self.assertEqual(status, 400)
                self.assertIn(message, json.loads(body)["errore"])
                self.assertEqual(self.request("GET", "/stato")[0], 200)


if __name__ == "__main__":
    unittest.main()
