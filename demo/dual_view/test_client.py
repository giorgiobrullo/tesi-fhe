"""In-process client tests: fake crypto/network, synthetic tiny pictures only."""
import asyncio
import base64
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from PIL import Image

from demo.dual_view import client


def data_url(image_format="PNG", size=(8, 8)):
    stream = io.BytesIO()
    Image.new("RGB", size, "#8090a0").save(stream, format=image_format)
    mime = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}[image_format]
    return f"data:{mime};base64," + base64.b64encode(stream.getvalue()).decode()


async def asgi_request(app, method, path, body=b"", headers=None):
    received = False
    messages = []

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    request_headers = {"host": "127.0.0.1:8006", **(headers or {})}
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
             "query_string": b"", "root_path": "", "client": ("127.0.0.1", 12345),
             "server": ("127.0.0.1", 8006),
             "headers": [(name.lower().encode(), value.encode()) for name, value in request_headers.items()]}
    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    response = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return start["status"], json.loads(response) if response else None


class FakePipeline:
    def __init__(self):
        self.events = []
        self.accepted = True
        self.error = None
        self.header_error = False
        self.decode_error = False
        self.installed = False
        self.count = 2

    verify_vector = client.AccessPipeline.verify_vector

    def server_status(self):
        raw, _ = self.srv("/stato")
        state = json.loads(raw)
        return state, {"iscritti": state["iscritti"]}

    def assicura_chiave(self):
        self.events.append("ensure_eval_key")
        if self.error:
            raise self.error
        self.installed = True

    def valida_fingerprint_chiave(self, state):
        if not state["chiave"]:
            raise RuntimeError("key mismatch /private/key-path")

    def valida_fingerprint_g4(self, state):
        pass

    def srv(self, path, data=None):
        self.events.append(path)
        if self.error:
            raise self.error
        if path == "/stato":
            return json.dumps({"chiave": self.installed, "iscritti": self.count,
                               "nomi": ["PRIVATE NAME"], "chiave_sha256": "PRIVATE HASH"}).encode(), {}
        if path == "/varco":
            if data != b"encrypted-probe":
                raise AssertionError("Only encrypted probes may reach the gateway")
            return b"encrypted-output", {"X-Tempo-Ms": "1987.25", "X-Request-Id": "request-123"}
        raise AssertionError("Unexpected network or administrative route: " + path)

    def da_dataurl(self, value):
        self.events.append("decode_image")
        return types.SimpleNamespace(shape=(8, 8, 3))

    def embedding_fuso(self, images):
        self.events.append("embedding")
        return [0] * 512, {"embedding_ms": 10, "frame": len(images)}

    def snapshot_galleria(self):
        self.events.append("snapshot")
        return {"query_profile": "head51", "iscritti": self.count, "nomi": ("PRIVATE NAME", "OTHER")}

    def cifra(self, query, profile):
        self.events.append("encrypt")
        if profile != "head51":
            raise AssertionError("Wrong packed query profile")
        return b"encrypted-probe", {}

    def valida_header_varco(self, headers, snapshot):
        self.events.append("validate_headers")
        if self.header_error:
            raise RuntimeError("stale header")
        return {name.lower(): value for name, value in headers.items()}

    def decifra(self, data):
        self.events.append("decrypt")
        return {"autorizzato": self.accepted, "indice": 0 if self.accepted else None,
                "codice": 1 if self.accepted else 0}

    def identita_da_esito(self, decoded, snapshot):
        self.events.append("validate_output")
        if self.decode_error:
            raise RuntimeError("stale gallery /private/keys")
        return "PRIVATE NAME" if decoded["autorizzato"] else None


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.binary = self.directory / "fake-binary"
        self.binary.write_bytes(b"not executable")
        self.keys = self.directory / "keys"
        self.keys.mkdir()
        for name in ("client.key", "server.key"):
            (self.keys / name).write_bytes(b"fake local test data")
        self.key_before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.keys.iterdir()}
        self.original = FakePipeline()
        self.settings = client.ClientSettings(self.binary, self.keys)
        self.runtime = client.AccessRuntime(self.settings, loader=lambda _: self.original, model_check=lambda: None)
        self.runtime.initialize()
        self.original.events.clear()
        self.app = client.create_app(self.runtime)
        self.picture = data_url()

    def tearDown(self):
        self.temporary.cleanup()

    def request(self, payload=None, method="POST", path="/api/accesso", raw=None, headers=None):
        if raw is None:
            raw = json.dumps(payload if payload is not None else {"frames": [self.picture]}).encode()
        return asyncio.run(asgi_request(self.app, method, path, raw,
                           {"content-type": "application/json", **(headers or {})}))

    def test_status_exposes_only_safe_projection(self):
        status, body = self.request(method="GET", path="/api/stato")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"pronto": True, "iscritti": 2, "frame_richiesti": 3})

    def test_positive_result_hides_identity_and_preserves_request_id(self):
        status, body = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"esito", "tempi_ms", "richiesta_id"})
        self.assertEqual(body["esito"], "aperto")
        self.assertEqual(body["richiesta_id"], "request-123")
        self.assertEqual(set(body["tempi_ms"]), {"endpoint", "server"})
        self.assertEqual(body["tempi_ms"]["server"], 1987.25)
        self.assertEqual(self.original.events,
                         ["decode_image", "embedding", "ensure_eval_key", "snapshot", "encrypt",
                          "/varco", "validate_headers", "decrypt", "validate_output"])
        self.assertNotIn("PRIVATE", json.dumps(body))

    def test_negative_result_is_successful_denial_without_identity(self):
        self.original.accepted = False
        status, body = self.request()
        self.assertEqual((status, body["esito"]), (200, "negato"))
        self.assertNotIn("indice", body)
        self.assertNotIn("identita", body)

    def test_rejects_extra_names_ids_or_synthetic_selectors(self):
        for name, value in (("nome", "Person"), ("id", 1), ("sintetico", 0)):
            with self.subTest(name=name):
                self.assertEqual(self.request({"frames": [self.picture], name: value})[0], 400)
        self.assertEqual(self.original.events, [])

    def test_count_json_and_path_rejections_precede_pipeline(self):
        for payload in ({"frames": []}, {"frames": [self.picture] * 4}, {"frames": "bad"},
                        {"frames": [None]}, {"frames": ["/private/photo.png"]}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertEqual(self.request(payload)[0], 400)
        self.assertEqual(self.request(raw=b'{"frames":[],"frames":[]}')[0], 400)
        self.assertEqual(self.request(raw=b'{"frames":[NaN]}')[0], 400)
        self.assertNotIn("embedding", self.original.events)

    def test_mime_actual_format_and_base64_are_checked(self):
        for value in (self.picture.replace("image/png", "image/jpeg"), "data:image/png;base64,invalid!",
                      self.picture.replace("image/png", "image/gif")):
            self.assertEqual(self.request({"frames": [value]})[0], 400)
        for format in ("JPEG", "PNG", "WEBP"):
            client.validate_frame(data_url(format))

    def test_frame_size_pixel_and_request_bounds(self):
        with mock.patch.object(client, "MAX_FRAME_BYTES", 8):
            self.assertEqual(self.request()[0], 400)
        with mock.patch.object(client, "MAX_PIXELS", 10):
            self.assertEqual(self.request()[0], 400)
        with mock.patch.object(client, "MAX_BODY_BYTES", 5):
            self.assertEqual(self.request()[0], 413)
        self.assertEqual(self.request(headers={"content-length": str(client.MAX_BODY_BYTES + 1)})[0], 413)

    def test_rejects_foreign_browser_origin_but_accepts_local_client(self):
        self.assertEqual(self.request(headers={"origin": "https://foreign.example"})[0], 403)
        self.assertEqual(self.request(headers={"origin": self.settings.origin})[0], 200)

    def test_legacy_admin_and_documentation_routes_absent(self):
        for path in ("/api/iscrivi", "/api/precarica", "/api/verifica", "/api/galleria", "/reset", "/docs", "/openapi.json"):
            self.assertEqual(self.request(path=path)[0], 404)

    def test_missing_existing_key_fails_without_creation_or_mode_change(self):
        (self.keys / "server.key").unlink()
        self.runtime.initialize()
        self.assertFalse(self.runtime.status()["pronto"])
        self.assertFalse((self.keys / "server.key").exists())
        self.assertNotIn("ensure_eval_key", self.original.events)

    def test_startup_and_access_preserve_existing_key_bytes_and_modes(self):
        self.request()
        after = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.keys.iterdir()}
        self.assertEqual(after, self.key_before)

    def test_header_mismatch_prevents_decryption(self):
        self.original.header_error = True
        self.assertEqual(self.request()[0], 503)
        self.assertNotIn("decrypt", self.original.events)

    def test_stale_decrypted_result_is_sanitized(self):
        self.original.decode_error = True
        status, body = self.request()
        self.assertEqual(status, 503)
        self.assertEqual(body, {"errore": client.UNAVAILABLE})
        self.assertNotIn("private", json.dumps(body))

    def test_no_face_has_distinct_safe_error(self):
        self.original.embedding_fuso = mock.Mock(side_effect=ValueError("nessun volto rilevato"))
        status, body = self.request()
        self.assertEqual(status, 422)
        self.assertIn("Nessun volto", body["errore"])
        self.assertNotIn("encrypt", self.original.events)

    def test_busy_query_serializes_work_and_status_uses_cache(self):
        before = dict(self.runtime.cached_status)
        with self.runtime.lock:
            self.assertEqual(self.request()[0], 409)
            self.assertEqual(self.runtime.status(), before)
        self.assertEqual(self.original.events, [])

    def test_gateway_rejects_admin_routes_without_network(self):
        gateway = client.LocalGateway(self.settings.gateway)
        gateway.opener = mock.Mock(side_effect=AssertionError("network forbidden"))
        for path, data in (("/reset", b"x"), ("/iscrivi", b"x"), ("/client-key", b"secret"), ("/varco", b"")):
            with self.assertRaises(client.AccessError):
                gateway(path, data)
        gateway.opener.open.assert_not_called()

    def test_gateway_preserves_ciphertext_and_request_headers(self):
        gateway = client.LocalGateway(self.settings.gateway)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"encrypted-output"
        response.headers = {"X-Request-Id": "request-123", "X-Tempo-Ms": "2000"}
        gateway.opener = mock.Mock()
        gateway.opener.open.return_value = response
        body, headers = gateway("/varco", b"encrypted-probe")
        request = gateway.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, self.settings.gateway + "/varco")
        self.assertEqual(request.data, b"encrypted-probe")
        self.assertEqual(body, b"encrypted-output")
        self.assertEqual(headers["X-Request-Id"], "request-123")

    def test_real_pipeline_loader_keeps_clients_independent_without_loading_legacy_app(self):
        other_keys = self.directory / "other-keys"
        other_keys.mkdir()
        for name in ("client.key", "server.key"):
            (other_keys / name).write_bytes(b"another local key")
        other = client.ClientSettings(self.binary, other_keys, gateway="http://127.0.0.1:8015/fhe")
        left = client.load_pipeline(self.settings)
        right = client.load_pipeline(other)
        self.assertIsNot(left, right)
        self.assertEqual((left.settings.keys, right.settings.keys), (self.keys, other_keys))
        self.assertEqual((left.srv.url, right.srv.url), (self.settings.gateway, other.gateway))
        self.assertNotEqual(left.fingerprint_chiave_locale(), right.fingerprint_chiave_locale())
        left.config["modello"] = "only left"
        self.assertNotEqual(left.config["modello"], right.config["modello"])

    def test_real_pipeline_loader_rejects_absent_keys_without_creating_them(self):
        missing = self.directory / "absent-keys"
        settings = client.ClientSettings(self.binary, missing)
        with self.assertRaises(RuntimeError):
            client.load_pipeline(settings)
        self.assertFalse(missing.exists())

    def test_direct_old_backend_configuration_is_rejected(self):
        settings = client.ClientSettings(self.binary, self.keys, gateway="http://127.0.0.1:9004")
        with self.assertRaises(client.AccessError):
            settings.validate()


if __name__ == "__main__":
    unittest.main()
