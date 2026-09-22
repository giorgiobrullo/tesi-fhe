"""Public navigation, bounded session admission and lifecycle regressions."""
import asyncio
import os
import threading
import unittest
import uuid
from unittest.mock import patch

from .app import DEFAULT_MAX_SESSIONS, READ_ONLY_IDLE_SECONDS, create_app, session_limit
from .default_gallery import DefaultGallery
from .test_app import FakeEngines, FakeEnroller, image_frame, request
from .test_events import Stream


def gallery(size=1):
    entries = [{"id": str(uuid.UUID(int=index + 1)), "nome": f"Person {index}",
                "soglia": 273, "vettore": [1] * 32 + [0] * 480,
                "foto_file": str(uuid.UUID(int=index + 1)) + ".jpg", "origine": "registrato"}
               for index in range(size)]
    return DefaultGallery(entries=entries, photos={entry["id"]: image_frame()[1] for entry in entries})


async def bootstrap(app, cookie=None):
    status, headers, _ = await request(app, "GET", "/api/stato", cookie=cookie)
    if status != 200:
        raise AssertionError(f"Bootstrap failed: {status}")
    return headers.get("set-cookie", cookie).split(";", 1)[0]


class SessionConfigurationTests(unittest.TestCase):
    def test_limits_reject_malformed_or_unbounded_configuration(self):
        for value in (0, -1, 4097, True, 1.5, None, "", "0", "-1", "1.0", " 512",
                      "512 ", "+512", "1e3", "99999", "9" * 10000, "５１２", "512\n"):
            with self.subTest(value=str(value)[:30]), self.assertRaises(ValueError):
                session_limit(value)
        self.assertEqual(session_limit("4096"), 4096)
        self.assertEqual(session_limit(1), 1)

    def test_invalid_environment_fails_before_any_lifespan_or_worker(self):
        with patch.dict(os.environ, {"VARCO_WEB_MAX_SESSIONS": "unbounded"}):
            with self.assertRaisesRegex(ValueError, "limite delle sessioni"):
                create_app()
            create_app(max_sessions=1024)  # Explicit configuration overrides the environment.


class NavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_document_navigation_and_passive_requests_allocate_no_session(self):
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), max_sessions=1,
                         public_origin="https://varco.example")
        async with app.router.lifespan_context(app):
            for site in ("cross-site", "same-site", "none"):
                for method in ("GET", "HEAD"):
                    headers = {"host": "varco.example", "sec-fetch-site": site,
                               "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}
                    status, response_headers, body = await request(app, method, "/", headers=headers)
                    self.assertEqual(status, 200)
                    self.assertNotIn("set-cookie", response_headers)
                    self.assertIn("text/html", response_headers["content-type"])
                    if method == "HEAD":
                        self.assertEqual(body, b"")
            self.assertEqual(app.state.service.sessions, {})
            status, headers, _ = await request(app, "GET", "/api/stato", headers={"host": "varco.example"})
            self.assertEqual(status, 200)
            self.assertIn("Secure", headers["set-cookie"])
            self.assertEqual(len(app.state.service.sessions), 1)
            self.assertEqual((await request(app, "GET", "/", headers={"host": "varco.example"}))[0], 200)

    async def test_navigation_exception_does_not_open_api_frames_or_mutations(self):
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), public_origin="https://varco.example")
        async with app.router.lifespan_context(app):
            base = {"host": "varco.example", "sec-fetch-site": "cross-site",
                    "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}
            for method, path, overrides in (
                    ("GET", "/api/stato", {}), ("GET", "/api/foto/any", {}),
                    ("GET", "/api/eventi", {}), ("POST", "/api/accesso", {"origin": "https://varco.example"}),
                    ("POST", "/", {"origin": "https://varco.example"}),
                    ("GET", "/", {"sec-fetch-dest": "iframe"}),
                    ("GET", "/", {"sec-fetch-mode": "cors"}),
                    ("GET", "/", {"host": "outside.example"}),
                    ("GET", "/", {"origin": "https://outside.example"})):
                with self.subTest(method=method, path=path, overrides=overrides):
                    status, _, _ = await request(app, method, path, headers=base | overrides)
                    self.assertEqual(status, 403)
            self.assertEqual(app.state.service.sessions, {})


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_512_visitors_share_defaults_and_expired_or_reclaimed_sessions_do_not_clear_them(self):
        now = [1000.0]
        seeds = gallery(120)
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), default_gallery=seeds,
                         clock=lambda: now[0], max_sessions=DEFAULT_MAX_SESSIONS)
        async with app.router.lifespan_context(app):
            cookies = [await bootstrap(app) for _ in range(512)]
            service = app.state.service
            self.assertEqual(len(service.sessions), 512)
            self.assertEqual(len(set(cookies)), 512)
            for session in service.sessions.values():
                self.assertIs(session.entries, seeds.entries)
                self.assertIs(session.photos, seeds.photos)
            self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
            now[0] += READ_ONLY_IDLE_SECONDS
            await bootstrap(app)
            self.assertEqual(len(service.sessions), 512)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=cookies[0]))[0], 401)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=cookies[1]))[2]["totale"], 120)
            now[0] += 3600
            renewed = await bootstrap(app)
            self.assertEqual(len(service.sessions), 1)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=renewed))[2]["totale"], 120)
            self.assertEqual(len(seeds.photos), 120)

    async def test_recent_http_activity_defers_reclamation_but_never_renews_fixed_expiry(self):
        now = [1000.0]
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), clock=lambda: now[0], max_sessions=1)
        async with app.router.lifespan_context(app):
            cookie = await bootstrap(app)
            session = next(iter(app.state.service.sessions.values()))
            expiry = session.expires
            now[0] += READ_ONLY_IDLE_SECONDS - 1
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=cookie))[0], 200)
            now[0] += 1
            self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
            self.assertEqual(session.expires, expiry)
            now[0] += READ_ONLY_IDLE_SECONDS
            self.assertNotEqual(await bootstrap(app), cookie)

    async def test_personal_edits_deletions_enrollment_and_results_are_never_capacity_evicted(self):
        for action in ("edit", "delete", "enroll", "result", "error"):
            with self.subTest(action=action):
                now = [1000.0]
                seeds, engines = gallery(), FakeEngines()
                app = create_app(engines=engines, enroller=FakeEnroller(), default_gallery=seeds,
                                 clock=lambda: now[0], max_sessions=1)
                async with app.router.lifespan_context(app):
                    cookie = await bootstrap(app)
                    path = "/api/galleria/" + seeds.entries[0]["id"]
                    if action == "edit":
                        self.assertEqual((await request(app, "PATCH", path, cookie=cookie,
                                                       payload={"nome": "Changed", "soglia": 99}))[0], 200)
                    elif action == "delete":
                        self.assertEqual((await request(app, "DELETE", path, cookie=cookie))[0], 200)
                    elif action == "enroll":
                        self.assertEqual((await request(app, "POST", "/api/galleria", cookie=cookie,
                                                       payload={"nome": "Added", "soglia": 273,
                                                                "frames": [image_frame()[0]]}))[0], 201)
                    else:
                        engines.fail = action == "error"
                        self.assertEqual((await request(app, "POST", "/api/accesso", cookie=cookie,
                                                       payload={"frames": [image_frame()[0]], "motore": "attuale"}))[0], 202)
                        await asyncio.wait_for(app.state.service.queue.join(), 2)
                    now[0] += READ_ONLY_IDLE_SECONDS + 1
                    self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
                    self.assertEqual((await request(app, "GET", "/api/galleria", cookie=cookie))[0], 200)
                    self.assertEqual(seeds.entries[0]["nome"], "Person 0")
                    self.assertEqual(len(seeds.photos), 1)
                    now[0] = 4600.0  # Fixed one-hour TTL still applies to protected data.
                    fresh = await bootstrap(app)
                    self.assertNotEqual(fresh, cookie)
                    self.assertEqual((await request(app, "GET", "/api/galleria", cookie=fresh))[2]["totale"], 1)

    async def test_queued_and_running_enrollment_are_protected_and_failures_release_reservation(self):
        gate, entered = threading.Event(), threading.Event()

        def blocked_enroller(_frames):
            entered.set()
            if not gate.wait(2):
                raise AssertionError("Test enroller was not released")
            raise ValueError("No face")

        now = [1000.0]
        app = create_app(engines=FakeEngines(), enroller=blocked_enroller,
                         clock=lambda: now[0], max_sessions=2, queue_capacity=1)
        async with app.router.lifespan_context(app):
            first, second = await bootstrap(app), await bootstrap(app)
            payload = {"nome": "Added", "soglia": 273, "frames": [image_frame()[0]]}
            tasks = []
            try:
                tasks.append(asyncio.create_task(request(app, "POST", "/api/galleria", cookie=first, payload=payload)))
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(entered.is_set())
                tasks.append(asyncio.create_task(request(app, "POST", "/api/galleria", cookie=second, payload=payload)))
                for _ in range(100):
                    if app.state.service.queue.qsize() == 1:
                        break
                    await asyncio.sleep(.01)
                self.assertEqual(app.state.service.queue.qsize(), 1)
                self.assertEqual((await request(app, "POST", "/api/galleria", cookie=second, payload=payload))[0], 429)
                self.assertEqual([s.pending_jobs for s in app.state.service.sessions.values()], [1, 1])
                now[0] += READ_ONLY_IDLE_SECONDS + 1
                self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
            finally:
                gate.set()
                results = await asyncio.gather(*tasks)
            self.assertEqual([r[0] for r in results], [400, 400])
            self.assertTrue(all(s.pending_jobs == 0 for s in app.state.service.sessions.values()))
            await bootstrap(app)  # Failed enrollment retained no personal data; its slot can be reclaimed.

    async def test_running_and_queued_verifications_keep_both_sessions_and_their_history(self):
        now = [1000.0]
        engines = FakeEngines()
        engines.release.clear()
        app = create_app(engines=engines, enroller=FakeEnroller(), default_gallery=gallery(),
                         clock=lambda: now[0], max_sessions=2, queue_capacity=1)
        async with app.router.lifespan_context(app):
            first, second = await bootstrap(app), await bootstrap(app)
            payload = {"frames": [image_frame()[0]], "motore": "attuale"}
            try:
                self.assertEqual((await request(app, "POST", "/api/accesso", cookie=first, payload=payload))[0], 202)
                for _ in range(100):
                    if engines.calls:
                        break
                    await asyncio.sleep(.01)
                self.assertEqual(len(engines.calls), 1)
                self.assertEqual((await request(app, "POST", "/api/accesso", cookie=second, payload=payload))[0], 202)
                now[0] += READ_ONLY_IDLE_SECONDS + 1
                self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
                self.assertEqual([s.pending_jobs for s in app.state.service.sessions.values()], [1, 1])
                self.assertTrue(all(not s.modified for s in app.state.service.sessions.values()))
            finally:
                engines.release.set()
                await asyncio.wait_for(app.state.service.queue.join(), 2)
            self.assertEqual((await request(app, "GET", "/api/stato"))[0], 503)
            for cookie in (first, second):
                body = (await request(app, "GET", "/api/richieste", cookie=cookie))[2]
                self.assertEqual(body["richieste"][0]["stato"], "completata")

    async def test_sse_does_not_keep_read_only_session_alive_and_reconnect_receives_fresh_snapshot(self):
        now = [1000.0]
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), default_gallery=gallery(),
                         clock=lambda: now[0], max_sessions=1)
        async with app.router.lifespan_context(app):
            cookie = await bootstrap(app)
            session = next(iter(app.state.service.sessions.values()))
            stream = await Stream(app, cookie).open()
            try:
                for _ in range(3):
                    await stream.next()
                now[0] += READ_ONLY_IDLE_SECONDS
                app.state.service.events.notify(session.token)
                await asyncio.sleep(.01)
                self.assertEqual(session.last_seen, 1000.0)
                fresh = await bootstrap(app)
                self.assertNotEqual(cookie, fresh)
                self.assertEqual((await stream.next())[0], "scaduta")
                await asyncio.wait_for(stream.task, 2)
                self.assertEqual(app.state.service.events.subscriptions, {})
                replacement = await Stream(app, fresh).open()
                try:
                    initial = [await replacement.next() for _ in range(3)]
                    self.assertEqual([row[0] for row in initial], ["stato", "galleria", "richieste"])
                    self.assertEqual(initial[1][1]["totale"], 1)
                    self.assertEqual(initial[2][1]["totale"], 0)
                finally:
                    await replacement.close()
            finally:
                await stream.close()


if __name__ == "__main__":
    unittest.main()
