"""Bounded JSON ingestion with cancellation, disconnect and deadline cleanup."""
import asyncio
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from starlette.datastructures import Headers
from starlette.requests import ClientDisconnect

from .app import ApiError, MAX_BODY, MAX_BODY_READERS, Service, create_app, json_body
from .test_app import FakeEngines, FakeEnroller, request


class BodyRequest:
    def __init__(self, service, *, raw=b'{"value":1}', release=None, error=None):
        self.app = SimpleNamespace(state=SimpleNamespace(service=service))
        self.headers = Headers({"content-type": "application/json"})
        self.raw, self.release, self.error = raw, release, error
        self.started = asyncio.Event()

    async def stream(self):
        self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self.error is not None:
            raise self.error
        yield self.raw


class BodyLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = Service(FakeEngines(), FakeEnroller(), clock=time.time,
                               session_ttl=3600, max_sessions=512, queue_capacity=8)

    async def test_excess_readers_are_rejected_before_reading_and_success_releases_capacity(self):
        release = asyncio.Event()
        bodies = [BodyRequest(self.service, release=release) for _ in range(MAX_BODY_READERS)]
        tasks = [asyncio.create_task(json_body(body, {"value"})) for body in bodies]
        try:
            await asyncio.wait_for(asyncio.gather(*(body.started.wait() for body in bodies)), 2)
            excess = BodyRequest(self.service)
            with self.assertRaises(ApiError) as raised:
                await json_body(excess, {"value"})
            self.assertEqual(raised.exception.status, 429)
            self.assertFalse(excess.started.is_set())
            self.assertEqual(self.service.body_readers, MAX_BODY_READERS)
        finally:
            release.set()
            self.assertEqual(await asyncio.gather(*tasks), [{"value": 1}] * MAX_BODY_READERS)
        self.assertEqual(self.service.body_readers, 0)
        self.assertEqual(await json_body(BodyRequest(self.service), {"value"}), {"value": 1})

    async def test_cancellation_disconnect_malformed_and_size_errors_release_capacity(self):
        body = BodyRequest(self.service, release=asyncio.Event())
        pending = asyncio.create_task(json_body(body, {"value"}))
        await body.started.wait()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual(self.service.body_readers, 0)
        with self.assertRaises(ClientDisconnect):
            await json_body(BodyRequest(self.service, error=ClientDisconnect()), {"value"})
        self.assertEqual(self.service.body_readers, 0)
        for body, status in ((BodyRequest(self.service, raw=b"not json"), 400),
                             (BodyRequest(self.service, raw=b'{"wrong":1}'), 400)):
            with self.assertRaises(ApiError) as raised:
                await json_body(body, {"value"})
            self.assertEqual(raised.exception.status, status)
            self.assertEqual(self.service.body_readers, 0)
        declared = BodyRequest(self.service)
        declared.headers = Headers({"content-type": "application/json", "content-length": str(MAX_BODY + 1)})
        with self.assertRaises(ApiError) as raised:
            await json_body(declared, {"value"})
        self.assertEqual(raised.exception.status, 413)
        self.assertFalse(declared.started.is_set())
        with patch("demo.web.app.MAX_BODY", 4), self.assertRaises(ApiError) as raised:
            await json_body(BodyRequest(self.service, raw=b"12345"), {"value"})
        self.assertEqual(raised.exception.status, 413)
        self.assertEqual(self.service.body_readers, 0)

    async def test_timeout_returns_408_and_releases_capacity_without_waiting_real_deadline(self):
        with patch("demo.web.app.BODY_READ_TIMEOUT_SECONDS", 0), self.assertRaises(ApiError) as raised:
            await json_body(BodyRequest(self.service, release=asyncio.Event()), {"value"})
        self.assertEqual(raised.exception.status, 408)
        self.assertEqual(self.service.body_readers, 0)

    async def test_http_gate_is_shared_by_mutations_and_origin_checks_still_run_first(self):
        app = create_app(engines=FakeEngines(), enroller=FakeEnroller())
        async with app.router.lifespan_context(app):
            cookie = (await request(app, "GET", "/api/stato"))[1]["set-cookie"].split(";", 1)[0]
            release = asyncio.Event()
            bodies = [BodyRequest(app.state.service, release=release) for _ in range(MAX_BODY_READERS)]
            tasks = [asyncio.create_task(json_body(body, {"value"})) for body in bodies]
            try:
                await asyncio.wait_for(asyncio.gather(*(body.started.wait() for body in bodies)), 2)
                for method, path in (("POST", "/api/galleria"), ("POST", "/api/accesso"),
                                     ("PATCH", "/api/galleria/any")):
                    with self.subTest(method=method, path=path):
                        self.assertEqual((await request(app, method, path, cookie=cookie, payload={}))[0], 429)
                self.assertEqual((await request(app, "POST", "/api/accesso", cookie=cookie,
                                               payload={}, headers={"origin": "https://outside.example"}))[0], 403)
                self.assertEqual((await request(app, "GET", "/api/stato", cookie=cookie))[0], 200)
                self.assertEqual(app.state.service.queue.qsize(), 0)
            finally:
                release.set()
                await asyncio.gather(*tasks)
            self.assertEqual(app.state.service.body_readers, 0)


if __name__ == "__main__":
    unittest.main()
