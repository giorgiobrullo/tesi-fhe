"""In-process admin/gateway tests with a fake backend and temporary own stores."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import io
import json
import pathlib
import tempfile
import threading
import unittest
import uuid
from unittest import mock

from PIL import Image

from demo.dual_view import enrollment, gallery, server


def picture(image_format="PNG", size=(8, 8)) -> bytes:
    stream = io.BytesIO()
    Image.new("RGB", size, "#73949b").save(stream, format=image_format)
    return stream.getvalue()


def data_url(image_format="PNG", size=(8, 8)) -> str:
    mime = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}[image_format]
    return f"data:{mime};base64," + base64.b64encode(picture(image_format, size)).decode()


def entry(name="Persona di prova") -> dict:
    return {"id": str(uuid.uuid4()), "nome": name, "soglia": 273,
            "vettore": [1] * 32 + [0] * 480, "foto_file": None, "origine": "sintetico"}


async def asgi_request(app, method, path, body=b"", headers=None):
    received = False
    finished = asyncio.Event()
    messages = []

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            finished.set()

    request_headers = {"host": "127.0.0.1:8005", "content-length": str(len(body)), **(headers or {})}
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": method, "scheme": "http", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 8005),
             "headers": [(key.lower().encode(), value.encode()) for key, value in request_headers.items()]}
    await asyncio.wait_for(app(scope, receive, send), timeout=5)
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(message.get("body", b"") for message in messages
                             if message["type"] == "http.response.body")
    response_headers = {key.decode().lower(): value.decode() for key, value in start["headers"]}
    return start["status"], response_headers, response_body


class FakeBackend:
    def __init__(self):
        self.rows = []
        self.calls = []
        self.key = True
        self.enroll_count = 0
        self.fail_enrollment_at = None
        self.fail_all_enrollments = False
        self.fail_queries = False
        self.bad_contract = False
        self.query_started = threading.Event()
        self.query_release = None

    def request(self, method, path, data=None, content_type="application/octet-stream"):
        self.calls.append((method, path, data))
        if (method, path) == ("GET", "/stato"):
            contract = copy.deepcopy(server.EXPECTED_CONTRACT)
            if self.bad_contract:
                contract["circuit_sha256"] = "another circuit"
            state = {"dim": 512, "iscritti": len(self.rows), "nomi": [row["id"] for row in self.rows],
                     "soglie": [row["soglia"] for row in self.rows], "chiave": self.key,
                     "chiave_sha256": "public-evaluation-key-fingerprint",
                     "contratto_esatto": contract, "epoch": 1, "revision": 1}
            return server.BackendResponse(200, json.dumps(state).encode(), {"Content-Type": "application/json"})
        if (method, path) == ("POST", "/reset"):
            self.rows = []
            return server.BackendResponse(200, b'{"ok":true}', {})
        if (method, path) == ("POST", "/iscrivi"):
            self.enroll_count += 1
            if self.fail_all_enrollments or self.enroll_count == self.fail_enrollment_at:
                return server.BackendResponse(400, b'{"errore":"fake enrollment failure"}', {})
            header, vector = data.decode().split("\n")
            identifier, threshold = header.split("\t")
            self.rows.append({"id": identifier, "soglia": int(threshold),
                              "vettore": [int(value) for value in vector.split()]})
            return server.BackendResponse(200, b'{"ok":true}', {})
        if (method, path) == ("POST", "/chiave"):
            self.key = True
            return server.BackendResponse(200, b'{"ok":true}', {"Content-Type": "application/json"})
        if (method, path) == ("POST", "/varco"):
            self.query_started.set()
            if self.query_release is not None:
                if not self.query_release.wait(timeout=3):
                    raise AssertionError("Test did not release its fake query")
            if self.fail_queries:
                raise OSError("private filesystem path must not be returned")
            return server.BackendResponse(200, b"opaque-encrypted-answer", {
                "Content-Type": "application/octet-stream", "X-Tempo-Ms": "123.4",
                "X-Varco-Contract": server.EXPECTED_CONTRACT["http_contract"],
                "Access-Control-Allow-Origin": "*", "Connection": "close",
            })
        raise AssertionError((method, path))


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temporary.name)
        self.store = gallery.GalleryStore(self.directory)
        self.first = entry()
        self.store.replace([self.first])
        self.backend = FakeBackend()
        self.enroller = mock.Mock(return_value=([1] * 32 + [0] * 480, picture("JPEG")))
        self.app = server.create_app(self.store, self.backend, self.enroller)
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.backend.calls.clear()
        self.backend.enroll_count = 0

    async def asyncTearDown(self):
        await self.lifespan.__aexit__(None, None, None)
        self.temporary.cleanup()

    async def request(self, method, path, value=None, body=None, headers=None):
        extra = dict(headers or {})
        if value is not None:
            body = json.dumps(value).encode()
            extra["content-type"] = "application/json"
        return await asgi_request(self.app, method, path, body or b"", extra)

    async def test_startup_uses_own_store_and_public_projection_only(self):
        self.assertEqual(self.backend.rows[0]["id"], self.first["id"])
        code, _, raw = await self.request("GET", "/api/stato")
        self.assertEqual(code, 200)
        state = json.loads(raw)
        self.assertEqual(state, {"pronto": True, "iscritti": 1, "richieste": 0,
                                 "in_corso": 0, "ultima_durata_ms": None})
        code, _, raw = await self.request("GET", "/api/galleria")
        self.assertEqual(code, 200)
        row = json.loads(raw)["iscritti"][0]
        self.assertEqual(set(row), {"id", "nome", "soglia", "foto_url", "origine", "indice"})
        self.assertEqual(row["indice"], 1)
        self.assertNotIn("vettore", raw.decode())
        self.assertNotIn("chiave", raw.decode())

    async def test_enrollment_rename_threshold_and_delete_persist(self):
        code, _, raw = await self.request("POST", "/api/iscritti", {"nome": "Ada", "frames": [data_url()]})
        self.assertEqual(code, 200, raw)
        added = json.loads(raw)["iscritto"]
        identifier = added["id"]
        self.assertEqual((added["soglia"], added["origine"], added["indice"]), (273, "registrato", 2))
        self.assertTrue((self.store.photos / (identifier + ".jpg")).is_file())
        self.assertEqual(len(gallery.GalleryStore(self.directory).entries()), 2)
        code, _, raw = await self.request("PATCH", f"/api/iscritti/{identifier}", {"nome": "Ada nuova", "soglia": -5})
        self.assertEqual(code, 200, raw)
        self.assertEqual(json.loads(raw)["iscritto"]["id"], identifier)
        self.assertEqual(self.backend.rows[1]["soglia"], -5)
        code, headers, raw = await self.request("GET", f"/api/foto/{identifier}")
        self.assertEqual((code, headers["content-type"]), (200, "image/jpeg"))
        self.assertEqual(raw, picture("JPEG"))
        code, _, raw = await self.request("DELETE", f"/api/iscritti/{identifier}")
        self.assertEqual((code, json.loads(raw)["totale"]), (200, 1))
        self.assertFalse((self.store.photos / (identifier + ".jpg")).exists())
        self.assertEqual(self.store.entries(), [self.first])

    async def test_same_display_names_do_not_upsert_other_ids(self):
        code, _, raw = await self.request("POST", "/api/iscritti", {"nome": self.first["nome"], "frames": [data_url()]})
        self.assertEqual(code, 200, raw)
        self.assertEqual(len({row["id"] for row in self.backend.rows}), 2)

    async def test_invalid_full_domain_is_rejected_before_reset_or_photo_write(self):
        before = self.store.gallery_path.read_bytes()
        self.enroller.return_value = ([3] * 512, picture("JPEG"))
        code, _, raw = await self.request("POST", "/api/iscritti", {"nome": "Troppo largo", "frames": [data_url()]})
        self.assertEqual(code, 400, raw)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.store.gallery_path.read_bytes(), before)
        self.assertFalse(self.store.photos.exists())

    async def test_partial_rebuild_failure_restores_backend_store_and_photo_set(self):
        before = self.store.gallery_path.read_bytes()
        self.backend.fail_enrollment_at = 2
        code, _, raw = await self.request("POST", "/api/iscritti", {"nome": "Rollback", "frames": [data_url()]})
        self.assertEqual(code, 503, raw)
        self.assertIn("ripristinata", json.loads(raw)["errore"])
        self.assertEqual(self.store.gallery_path.read_bytes(), before)
        self.assertEqual([row["id"] for row in self.backend.rows], [self.first["id"]])
        self.assertEqual(list(self.store.photos.iterdir()), [])
        self.assertTrue(self.app.state.coordinator.synced)

    async def test_failed_rollback_closes_gateway_without_losing_persisted_gallery(self):
        before = self.store.gallery_path.read_bytes()
        self.backend.fail_all_enrollments = True
        code, _, raw = await self.request("PATCH", f"/api/iscritti/{self.first['id']}", {"soglia": 42})
        self.assertEqual(code, 503, raw)
        self.assertFalse(self.app.state.coordinator.synced)
        self.assertEqual(self.store.gallery_path.read_bytes(), before)
        calls = len(self.backend.calls)
        code, _, _ = await self.request("POST", "/fhe/varco", body=b"encrypted-query")
        self.assertEqual(code, 503)
        self.assertEqual(len(self.backend.calls), calls)
        code, _, raw = await self.request("GET", "/api/stato")
        self.assertFalse(json.loads(raw)["pronto"])

    async def test_persistence_failure_rolls_backend_back(self):
        before = self.store.gallery_path.read_bytes()
        with mock.patch.object(self.store, "replace", side_effect=OSError("disk unavailable")):
            code, _, raw = await self.request("PATCH", f"/api/iscritti/{self.first['id']}", {"soglia": 42})
        self.assertEqual(code, 503, raw)
        self.assertEqual(self.store.gallery_path.read_bytes(), before)
        self.assertEqual(self.backend.rows[0]["soglia"], self.first["soglia"])

    async def test_raw_gateway_preserves_cipher_and_contract_without_outcomes_or_frames(self):
        ciphertext = b"opaque-encrypted-probe"
        code, headers, raw = await self.request("POST", "/fhe/varco", body=ciphertext)
        self.assertEqual((code, raw), (200, b"opaque-encrypted-answer"))
        self.assertEqual(headers["x-varco-contract"], server.EXPECTED_CONTRACT["http_contract"])
        self.assertEqual(headers["x-tempo-ms"], "123.4")
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertNotIn("connection", headers)
        self.assertTrue(headers["x-request-id"])
        code, _, raw = await self.request("GET", "/api/richieste")
        event = json.loads(raw)["richieste"][0]
        self.assertEqual(event["id"], headers["x-request-id"])
        self.assertEqual(event["impronta"], hashlib.sha256(ciphertext).hexdigest())
        self.assertEqual((event["stato"], event["byte_richiesta"], event["byte_risposta"]),
                         ("completata", len(ciphertext), len(b"opaque-encrypted-answer")))
        self.assertEqual(set(event), {"id", "ora", "stato", "durata_ms", "byte_richiesta", "byte_risposta", "impronta"})
        persisted = self.store.events_path.read_bytes()
        for forbidden in (ciphertext, b"opaque-encrypted-answer", b"frames", b"esito", b"autorizzato", b"nome", b"chiave"):
            self.assertNotIn(forbidden, persisted)
        self.assertEqual(gallery.GalleryStore(self.directory).requests()["totale"], 1)

    async def test_query_failure_is_sanitized_and_recorded(self):
        self.backend.fail_queries = True
        code, headers, raw = await self.request("POST", "/fhe/varco", body=b"cipher")
        self.assertEqual(code, 503)
        self.assertNotIn(b"private", raw)
        self.assertTrue(headers["x-request-id"])
        self.assertEqual(self.store.requests()["richieste"][0]["stato"], "errore")

    async def test_admin_and_queries_are_serialized_while_feed_stays_readable(self):
        self.backend.query_release = threading.Event()
        task = asyncio.create_task(self.request("POST", "/fhe/varco", body=b"cipher"))
        self.assertTrue(await asyncio.to_thread(self.backend.query_started.wait, 1))
        mutation = asyncio.create_task(self.request("PATCH", f"/api/iscritti/{self.first['id']}", {"soglia": 99}))
        await asyncio.sleep(0.03)
        self.assertFalse(any(path == "/reset" for _, path, _ in self.backend.calls))
        code, _, raw = await self.request("GET", "/api/richieste")
        self.assertEqual((code, json.loads(raw)["richieste"][0]["stato"]), (200, "in_elaborazione"))
        self.backend.query_release.set()
        self.assertEqual((await task)[0], 200)
        self.assertEqual((await mutation)[0], 200)
        self.assertEqual(self.backend.rows[0]["soglia"], 99)

    async def test_foreign_origins_and_extra_fields_cannot_mutate(self):
        for origin in ("http://127.0.0.1:8006", "https://other.example", "null"):
            code, _, _ = await self.request("PATCH", f"/api/iscritti/{self.first['id']}", {"nome": "Changed"},
                                             headers={"origin": origin})
            self.assertEqual(code, 403)
        for value in ({"nome": "A", "frames": [data_url()], "vettore": [0] * 512},
                      {"nome": "A", "frames": [data_url()], "soglia": True},
                      {"nome": "A\nB", "frames": [data_url()]}):
            self.assertEqual((await self.request("POST", "/api/iscritti", value))[0], 400)
        self.assertEqual(self.backend.calls, [])
        self.enroller.assert_not_called()

    async def test_image_body_limits_and_duplicate_json_precede_model_and_backend(self):
        invalid = [[], [data_url()] * 4, ["/private/local.png"],
                   ["data:image/png;base64,AA=="], [data_url().replace("image/png", "image/jpeg")]]
        for frames in invalid:
            self.assertEqual((await self.request("POST", "/api/iscritti", {"nome": "A", "frames": frames}))[0], 400)
        code, _, _ = await self.request("POST", "/api/iscritti", body=b'{"nome":"a","nome":"b","frames":[]}',
                                         headers={"content-type": "application/json"})
        self.assertEqual(code, 400)
        code, _, _ = await self.request("POST", "/fhe/varco", body=b"x" * (server.MAX_PROBE_BODY + 1))
        self.assertEqual(code, 413)
        code, _, _ = await self.request("POST", "/fhe/chiave", headers={"content-length": str(server.MAX_KEY_BODY + 1)})
        self.assertEqual(code, 413)
        self.assertEqual(self.backend.calls, [])
        self.enroller.assert_not_called()

    async def test_key_upload_is_evaluation_only_and_not_in_request_feed(self):
        code, _, _ = await self.request("POST", "/fhe/chiave", body=b"fake-evaluation-key")
        self.assertEqual(code, 200)
        self.assertEqual(self.store.requests()["totale"], 0)
        for path in ("/fhe/client.key", "/fhe/reset", "/fhe/iscrivi", "/api/reset", "/api/accesso"):
            self.assertEqual((await self.request("POST", path, body=b"unused"))[0], 404)

    async def test_missing_rows_and_photos_are_not_local_file_reads(self):
        identifier = str(uuid.uuid4())
        self.assertEqual((await self.request("PATCH", f"/api/iscritti/{identifier}", {"nome": "A"}))[0], 404)
        self.assertEqual((await self.request("DELETE", f"/api/iscritti/{identifier}"))[0], 404)
        self.assertEqual((await self.request("GET", f"/api/foto/{identifier}"))[0], 404)
        self.assertEqual(self.backend.calls, [])

    async def test_external_gallery_change_fails_closed(self):
        self.backend.rows.clear()
        self.assertEqual((await self.request("GET", "/fhe/stato"))[0], 503)
        self.assertFalse(self.app.state.coordinator.synced)
        self.assertEqual(self.store.entries(), [self.first])


class BoundaryTests(unittest.TestCase):
    def test_only_the_explicit_owned_port_can_be_mutated(self):
        for url in ("http://127.0.0.1:9003", "http://127.0.0.1:9004", "http://localhost:9005",
                    "https://127.0.0.1:9005", "http://127.0.0.1:9005/path", "http://example.com:9005"):
            with self.assertRaises(ValueError):
                server.HTTPBackend(url, owned=True)
        with self.assertRaises(server.BackendUnavailable):
            server.HTTPBackend("http://127.0.0.1:9005", owned=False).request("POST", "/reset", b"")

    def test_static_formats_and_dimension_bounds(self):
        for image_format in ("JPEG", "PNG", "WEBP"):
            self.assertEqual(enrollment.decode_frames([data_url(image_format)])[0].shape, (8, 8, 3))
        for size in ((4097, 1), (2001, 2000)):
            with self.assertRaises(ValueError):
                enrollment.decode_frames([data_url(size=size)])
        animated = io.BytesIO()
        Image.new("RGB", (8, 8), "red").save(animated, format="PNG", save_all=True,
                    append_images=[Image.new("RGB", (8, 8), "blue")], duration=10, loop=0)
        with self.assertRaises(ValueError):
            enrollment.image_from_bytes(animated.getvalue(), "PNG")

    def test_store_rejects_photo_paths_invalid_coordinates_and_duplicate_ids(self):
        item = entry()
        for field, value in (("foto_file", "../../outside.jpg"), ("vettore", [True] * 512),
                             ("soglia", 1 << 63), ("id", "not-an-id")):
            proposed = {**item, field: value}
            with self.assertRaises(ValueError):
                gallery.validate_entries([proposed])
        with self.assertRaises(ValueError):
            gallery.validate_entries([item, item])

    def test_missing_models_do_not_start_downloads_or_import_client(self):
        processor = enrollment.EnrollmentProcessor()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(pathlib.Path, "home", return_value=pathlib.Path(directory)):
                with mock.patch.object(enrollment.importlib.util, "spec_from_file_location") as loader:
                    with self.assertRaisesRegex(RuntimeError, "modelli locali"):
                        processor._model()
                    loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
