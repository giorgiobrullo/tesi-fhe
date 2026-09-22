"""HTTP and worker tests with injected engines; no models, keys or native process."""
from __future__ import annotations

import asyncio
import base64
import copy
import io
import json
import threading
import unittest

from PIL import Image

from .app import COOKIE, MAX_BODY, create_app
from .timeline import clock_ns


def image_frame():
    output = io.BytesIO()
    Image.new("RGB", (8, 8), (60, 90, 120)).save(output, format="JPEG")
    return "data:image/jpeg;base64," + base64.b64encode(output.getvalue()).decode(), output.getvalue()


async def request(app, method, path, *, cookie=None, payload=None, raw=None, headers=None):
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
    values = {"host": "127.0.0.1:8010", "content-length": str(len(body))}
    if cookie:
        values["cookie"] = cookie
    if method not in {"GET", "HEAD", "OPTIONS"}:
        values.update({"origin": "http://127.0.0.1:8010", "content-type": "application/json"})
    for key, value in (headers or {}).items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    messages = []
    consumed = False
    completed = asyncio.Event()

    async def receive():
        nonlocal consumed
        if not consumed:
            consumed = True
            return {"type": "http.request", "body": body, "more_body": False}
        await completed.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            completed.set()

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": method, "scheme": "http", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 8010),
             "headers": [(k.encode(), v.encode()) for k, v in values.items()]}
    await asyncio.wait_for(app(scope, receive, send), timeout=3)
    start = next(m for m in messages if m["type"] == "http.response.start")
    response_headers = {k.decode(): v.decode() for k, v in start["headers"]}
    content = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    parsed = json.loads(content) if "application/json" in response_headers.get("content-type", "") else content
    return start["status"], response_headers, parsed


class FakeEnroller:
    def __init__(self):
        self.calls = 0
        self.vector = [1] * 32 + [0] * 480
        self.photo = image_frame()[1]

    def __call__(self, frames):
        self.calls += 1
        if any(frame.shape != (8, 8, 3) for frame in frames):
            raise AssertionError("Frames must pass through the real bounded decoder")
        return list(self.vector), self.photo


class FakeEngines:
    def __init__(self):
        self.calls = []
        self.release = threading.Event()
        self.release.set()
        self.fail = False
        self.mutate = False
        self.available = True
        self.closed = False

    def info(self):
        return [{"id": "attuale", "nome": "Attuale", "pronto": self.available}]

    def verify(self, query, entries, engine, progress):
        self.calls.append((engine, copy.deepcopy(query), copy.deepcopy(entries)))
        start = clock_ns()
        progress("cifratura")
        spans = [{"kind": "encryption", "start_ns": start, "end_ns": clock_ns()}]
        start = clock_ns()
        progress("elaborazione")
        if not self.release.wait(timeout=5):
            raise RuntimeError("Test worker did not release")
        if self.fail:
            raise RuntimeError("private-path-and-sensitive-diagnostics")
        if self.mutate:
            query[0] = 999
            entries[0]["nome"] = "Mutated by engine"
            entries[0]["vettore"][0] = 999
        spans.append({"kind": "fhe", "start_ns": start, "end_ns": clock_ns()})
        start = clock_ns()
        progress("decifratura")
        spans.append({"kind": "decryption", "start_ns": start, "end_ns": clock_ns()})
        return {"motore": engine, "esito": "aperto", "selected_id": 1,
                "spans_ns": spans,
                "tempi_ms": {"cifratura": 1, "server": 2, "decifratura": 1, "totale": 4}}

    def close(self):
        self.closed = True


class AppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engines = FakeEngines()
        self.enroller = FakeEnroller()
        self.now = [1_800_000_000.0]
        self.app = create_app(engines=self.engines, enroller=self.enroller,
                              clock=lambda: self.now[0], max_sessions=2, queue_capacity=1)
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.frame = image_frame()[0]

    async def asyncTearDown(self):
        self.engines.release.set()
        await self.lifespan.__aexit__(None, None, None)
        self.assertTrue(self.engines.closed)

    async def session(self):
        status, headers, body = await request(self.app, "GET", "/api/stato")
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=lax", headers["set-cookie"])
        return headers["set-cookie"].split(";", 1)[0]

    async def enroll(self, cookie, name="Ada", threshold=20):
        status, _, body = await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                       payload={"nome": name, "soglia": threshold, "frames": [self.frame]})
        self.assertEqual(status, 201, body)
        return body["iscritto"]

    async def submit(self, cookie, engine="attuale"):
        return await request(self.app, "POST", "/api/accesso", cookie=cookie,
                             payload={"frames": [self.frame], "motore": engine})

    async def rows(self, cookie):
        status, _, body = await request(self.app, "GET", "/api/richieste", cookie=cookie)
        self.assertEqual(status, 200, body)
        return body["richieste"]

    async def wait_for(self, predicate):
        for _ in range(100):
            if predicate():
                return
            await asyncio.sleep(.01)
        self.fail("Worker did not reach the expected state")

    def assert_public_timeline(self, row):
        def inspect(value):
            if isinstance(value, dict):
                self.assertFalse({"_timeline", "origin_ns", "start_ns", "end_ns", "spans_ns"} & value.keys())
                for item in value.values():
                    inspect(item)
            elif isinstance(value, list):
                for item in value:
                    inspect(item)

        inspect(row)
        timeline = row["timeline"]
        spans = {span["id"]: span for span in timeline["spans"]}
        self.assertEqual(len(spans), len(timeline["spans"]))
        self.assertEqual(spans["job"]["start_ms"], 0)
        for span in spans.values():
            self.assertGreaterEqual(span["start_ms"], 0)
            if span["end_ms"] is not None:
                self.assertGreaterEqual(span["end_ms"], span["start_ms"])
                self.assertLessEqual(span["end_ms"], timeline["elapsed_ms"])
            if span["parent_id"] is not None:
                parent = spans[span["parent_id"]]
                self.assertGreaterEqual(span["start_ms"], parent["start_ms"])
                if parent["end_ms"] is not None:
                    self.assertIsNotNone(span["end_ms"])
                    self.assertLessEqual(span["end_ms"], parent["end_ms"])
        return spans

    async def test_timeline_tracks_queue_running_and_current_engine_then_stays_fixed(self):
        cookie = await self.session()
        await self.enroll(cookie)
        session = next(iter(self.app.state.service.sessions.values()))
        expiry = session.expires
        self.engines.release.clear()
        first_id = (await self.submit(cookie))[2]["richiesta_id"]
        await self.wait_for(lambda: len(self.engines.calls) == 1)
        running = (await self.rows(cookie))[0]
        spans = self.assert_public_timeline(running)
        self.assertIsNone(spans["job"]["end_ms"])
        self.assertIsNone(spans["attuale"]["end_ms"])
        self.assertIsNotNone(spans["queue"]["end_ms"])
        self.assertIsNotNone(spans["prepare"]["end_ms"])
        self.assertNotIn("a28", spans)
        self.assertFalse(any("/" in identifier for identifier in spans))
        await asyncio.sleep(.01)
        self.assertGreater((await self.rows(cookie))[0]["timeline"]["elapsed_ms"],
                           running["timeline"]["elapsed_ms"])
        self.assertEqual(session.expires, expiry)  # Polling does not extend the session.
        self.assertEqual((await self.submit(cookie))[0], 202)
        queued = (await self.rows(cookie))[0]
        self.assertEqual(queued["stato"], "in_attesa")
        queued_spans = self.assert_public_timeline(queued)
        self.assertEqual(set(queued_spans), {"job", "queue"})
        self.assertTrue(all(span["end_ms"] is None for span in queued_spans.values()))
        self.engines.release.set()
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        complete = next(row for row in await self.rows(cookie) if row["id"] == first_id)
        self.assertEqual(complete["stato"], "completata")
        spans = self.assert_public_timeline(complete)
        self.assertTrue(all(span["end_ms"] is not None for span in spans.values()))
        self.assertEqual(spans["job"]["end_ms"], complete["timeline"]["elapsed_ms"])
        self.assertEqual(spans["queue"]["end_ms"], spans["prepare"]["start_ms"])
        self.assertLessEqual(spans["prepare"]["end_ms"], spans["attuale"]["start_ms"])
        self.assertNotIn("a28", spans)
        previous = spans["attuale"]["start_ms"]
        for kind in ("encryption", "fhe", "decryption"):
            phase = spans[f"attuale/{kind}"]
            self.assertEqual((phase["parent_id"], phase["engine"]), ("attuale", "attuale"))
            self.assertGreaterEqual(phase["start_ms"], previous)
            previous = phase["end_ms"]
        self.assertEqual([call[0] for call in self.engines.calls], ["attuale", "attuale"])
        await asyncio.sleep(.01)
        repeated = next(row for row in await self.rows(cookie) if row["id"] == first_id)
        self.assertEqual(repeated["timeline"], complete["timeline"])

    async def test_invalid_import_is_atomic_and_reports_error_without_exposing_absolute_times(self):
        cookie = await self.session()
        await self.enroll(cookie)
        original = self.engines.verify

        def invalid_phases(*args):
            result = original(*args)
            result["spans_ns"][1]["start_ns"] = 0
            return result

        self.engines.verify = invalid_phases
        self.assertEqual((await self.submit(cookie))[0], 202)
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        row = (await self.rows(cookie))[0]
        self.assertEqual(row["stato"], "errore")
        spans = self.assert_public_timeline(row)
        self.assertEqual(spans["job"]["status"], "error")
        self.assertTrue(all(span["end_ms"] is not None for span in spans.values()))
        self.assertFalse(any("/" in identifier for identifier in spans))
        self.assertNotIn("risultati", row)

    async def test_disabled_engines_are_rejected_before_queue_and_embedding(self):
        cookie = await self.session()
        await self.enroll(cookie)
        for engine in ("a28", "confronto", "unknown", None, 17, {}):
            with self.subTest(engine=engine):
                self.assertEqual((await self.submit(cookie, engine))[0], 400)
        self.assertEqual(self.enroller.calls, 1)
        self.assertEqual(self.engines.calls, [])
        self.assertTrue(self.app.state.service.queue.empty())
        self.assertEqual(await self.rows(cookie), [])
        status = (await request(self.app, "GET", "/api/stato", cookie=cookie))[2]
        self.assertEqual([engine["id"] for engine in status["motori"]], ["attuale"])

    async def test_sessions_gallery_photos_requests_and_capacity_are_isolated(self):
        first, second = await self.session(), await self.session()
        self.assertNotEqual(first, second)
        entry = await self.enroll(first)
        self.assertEqual((await request(self.app, "GET", "/api/galleria", cookie=second))[2]["totale"], 0)
        self.assertEqual((await request(self.app, "GET", entry["foto_url"], cookie=second))[0], 404)
        self.assertEqual((await request(self.app, "DELETE", "/api/galleria/" + entry["id"], cookie=second))[0], 404)
        self.assertEqual((await request(self.app, "GET", entry["foto_url"], cookie=first))[2], self.enroller.photo)
        self.assertEqual((await self.submit(first))[0], 202)
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        self.assertEqual(await self.rows(second), [])
        self.assertEqual((await self.rows(first))[0]["stato"], "completata")
        self.assertEqual((await request(self.app, "GET", "/api/stato"))[0], 503)

    async def test_current_engine_keeps_submitted_snapshot_during_mutations(self):
        cookie = await self.session()
        entry = await self.enroll(cookie)
        self.engines.release.clear()
        self.engines.mutate = True
        self.assertEqual((await self.submit(cookie))[0], 202)
        await self.wait_for(lambda: len(self.engines.calls) == 1)
        self.assertEqual((await self.rows(cookie))[0]["stato"], "elaborazione")
        self.assertEqual((await request(self.app, "GET", "/api/stato", cookie=cookie))[0], 200)
        self.assertEqual((await request(self.app, "PATCH", "/api/galleria/" + entry["id"], cookie=cookie,
                                       payload={"nome": "Changed", "soglia": -900}))[0], 200)
        self.assertEqual((await request(self.app, "DELETE", "/api/galleria/" + entry["id"], cookie=cookie))[0], 200)
        self.engines.release.set()
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        self.assertEqual(self.enroller.calls, 2)  # One enrollment and one verification probe.
        self.assertEqual(len(self.engines.calls), 1)
        self.assertEqual(self.engines.calls[0][2][0]["nome"], "Ada")
        self.assertEqual(self.engines.calls[0][2][0]["soglia"], 20)
        row = (await self.rows(cookie))[0]
        self.assertEqual(row["stato"], "completata")
        self.assertEqual(row["iscritti"], 1)  # The submitted gallery survives later deletion.
        self.assertEqual([r["selected_name"] for r in row["risultati"]], ["Ada"])
        self.assertEqual(row["tempi_ms"], row["risultati"][0]["tempi_ms"])
        self.assertGreaterEqual(row["attesa_ms"], 0)
        self.assertGreaterEqual(row["preparazione_ms"], 0)
        self.assertGreaterEqual(row["tempo_complessivo_ms"], row["attesa_ms"])

    async def test_serial_queue_bounds_and_errors_remain_observable(self):
        cookie = await self.session()
        await self.enroll(cookie)
        self.engines.release.clear()
        self.assertEqual((await self.submit(cookie))[0], 202)
        await self.wait_for(lambda: len(self.engines.calls) == 1)
        self.assertEqual((await self.submit(cookie))[0], 202)
        self.assertEqual((await self.submit(cookie))[0], 429)
        rows = await self.rows(cookie)
        self.assertEqual([r["stato"] for r in rows], ["in_attesa", "elaborazione"])
        self.assertEqual(self.enroller.calls, 2)
        self.engines.fail = True
        self.engines.release.set()
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        rows = await self.rows(cookie)
        self.assertEqual(len(self.engines.calls), 2)
        self.assertTrue(all(r["stato"] == "errore" for r in rows))
        self.assertTrue(all("esito" not in r for r in rows))
        self.assertNotIn("private-path", json.dumps(rows))
        for row in rows:
            spans = self.assert_public_timeline(row)
            self.assertEqual(spans["job"]["status"], "error")
            self.assertEqual(spans["attuale"]["status"], "error")
            self.assertTrue(all(span["end_ms"] is not None for span in spans.values()))
        self.assertEqual([row["timeline"] for row in await self.rows(cookie)],
                         [row["timeline"] for row in rows])

    async def test_expired_queued_work_cannot_recreate_or_write_session(self):
        cookie = await self.session()
        entry = await self.enroll(cookie)
        self.engines.release.clear()
        await self.submit(cookie)
        await self.wait_for(lambda: len(self.engines.calls) == 1)
        await self.submit(cookie)
        self.now[0] += 3601
        self.assertEqual((await request(self.app, "GET", "/api/richieste", cookie=cookie))[0], 401)
        self.engines.release.set()
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        self.assertEqual(len(self.engines.calls), 1)
        self.assertEqual(self.app.state.service.sessions, {})
        new_cookie = await self.session()
        self.assertNotEqual(cookie, new_cookie)
        self.assertEqual((await request(self.app, "GET", entry["foto_url"], cookie=new_cookie))[0], 404)
        self.assertEqual(await self.rows(new_cookie), [])

    async def test_rejected_submission_preserves_full_history(self):
        cookie = await self.session()
        await self.enroll(cookie)
        for _ in range(128):
            self.assertEqual((await self.submit(cookie))[0], 202)
            await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        self.engines.release.clear()
        try:
            self.assertEqual((await self.submit(cookie))[0], 202)
            await self.wait_for(lambda: len(self.engines.calls) == 129)
            self.assertEqual((await self.submit(cookie))[0], 202)
            before = [row["id"] for row in await self.rows(cookie)]
            self.assertEqual(len(before), 128)
            self.assertEqual((await self.submit(cookie))[0], 429)
            self.assertEqual([row["id"] for row in await self.rows(cookie)], before)
        finally:
            self.engines.release.set()
            await asyncio.wait_for(self.app.state.service.queue.join(), 2)

    async def test_origin_host_session_and_http_method_checks(self):
        payload = {"nome": "Ada", "soglia": 20, "frames": [self.frame]}
        self.assertEqual((await request(self.app, "POST", "/api/galleria", payload=payload))[0], 401)
        cookie = await self.session()
        for headers in ({"origin": "https://outside.example"}, {"origin": None},
                        {"sec-fetch-site": "same-site"}, {"host": "outside.example"}):
            result = await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                   payload=payload, headers=headers)
            self.assertEqual(result[0], 403)
        self.assertEqual((await request(self.app, "PUT", "/api/galleria", cookie=cookie, payload=payload))[0], 405)
        self.assertEqual(self.enroller.calls, 0)

    async def test_strict_bodies_invalid_images_and_domain_errors(self):
        cookie = await self.session()
        for raw in (b'{"nome":"A","nome":"B","soglia":2,"frames":[]}',
                    b'{"nome":"A","soglia":NaN,"frames":[]}', b'[]'):
            self.assertEqual((await request(self.app, "POST", "/api/galleria", cookie=cookie, raw=raw))[0], 400)
        self.assertEqual((await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                       payload={}, headers={"content-length": str(MAX_BODY + 1)}))[0], 413)
        self.assertEqual((await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                       payload={}, headers={"content-type": "text/plain"}))[0], 415)
        self.assertEqual((await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                       payload={"nome": "A", "soglia": True, "frames": [self.frame]}))[0], 400)
        result = await request(self.app, "POST", "/api/galleria", cookie=cookie,
                               payload={"nome": "A", "soglia": 20, "frames": ["data:image/jpeg;base64,AAAA"]})
        self.assertEqual(result[0], 400)
        await self.enroll(cookie)
        self.enroller.vector = [3] * 512
        self.assertEqual((await self.submit(cookie))[0], 202)
        await asyncio.wait_for(self.app.state.service.queue.join(), 2)
        failed = (await self.rows(cookie))[0]
        self.assertEqual(failed["stato"], "errore")
        spans = self.assert_public_timeline(failed)
        self.assertEqual(spans["prepare"]["status"], "error")
        self.assertNotIn("attuale", spans)
        self.assertEqual(self.engines.calls, [])

    async def test_unavailable_engine_is_rejected_before_embedding(self):
        cookie = await self.session()
        self.assertEqual((await self.submit(cookie))[0], 409)
        await self.enroll(cookie)
        self.engines.available = False
        self.assertEqual((await self.submit(cookie))[0], 503)
        self.assertEqual(self.enroller.calls, 1)
        self.assertFalse((await request(self.app, "GET", "/api/stato", cookie=cookie))[2]["pronto"])
        self.assertEqual(await self.rows(cookie), [])


if __name__ == "__main__":
    unittest.main()
