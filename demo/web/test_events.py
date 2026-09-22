"""Real ASGI SSE streams with fake engines; no sockets, models or native processes."""
import asyncio
import json
import unittest
from unittest.mock import patch

from .app import create_app
from .events import EventHub
from .test_app import FakeEngines, FakeEnroller, image_frame, request


class Stream:
    def __init__(self, app, cookie, headers=None):
        self.app, self.cookie = app, cookie
        self.headers = headers or {}
        self.started = asyncio.Future()
        self.chunks = asyncio.Queue()
        self.disconnect = asyncio.Event()
        self.buffer = b""
        self.task = None

    async def open(self):
        values = {"host": "127.0.0.1:8010", "cookie": self.cookie, "accept": "text/event-stream"}
        values.update(self.headers)
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
                 "http_version": "1.1", "method": "GET", "scheme": "http", "path": "/api/eventi",
                 "raw_path": b"/api/eventi", "query_string": b"", "root_path": "",
                 "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 8010),
                 "headers": [(key.encode(), value.encode()) for key, value in values.items()]}
        consumed = False

        async def receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self.disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                self.started.set_result(message)
            elif message["type"] == "http.response.body":
                if message.get("body"):
                    await self.chunks.put(message["body"])
                if not message.get("more_body", False):
                    await self.chunks.put(None)

        self.task = asyncio.create_task(self.app(scope, receive, send))
        started = await asyncio.wait_for(asyncio.shield(self.started), 2)
        if started["status"] != 200:
            raise AssertionError(started)
        headers = {key.decode(): value.decode() for key, value in started["headers"]}
        assert headers["content-type"].startswith("text/event-stream")
        assert headers["cache-control"] == "no-store"
        assert headers["x-accel-buffering"] == "no"
        assert "set-cookie" not in headers
        return self

    async def next(self, timeout=2):
        async def read():
            while b"\n\n" not in self.buffer:
                chunk = await self.chunks.get()
                if chunk is None:
                    raise EOFError("Event stream closed")
                self.buffer += chunk
            frame, self.buffer = self.buffer.split(b"\n\n", 1)
            text = frame.decode()
            if text.startswith(":"):
                return "comment", text
            fields = dict(line.split(": ", 1) for line in text.splitlines())
            return fields["event"], json.loads(fields["data"])
        return await asyncio.wait_for(read(), timeout)

    async def until(self, name, predicate=lambda _: True, timeout=2):
        async def read():
            while True:
                kind, body = await self.next()
                if kind == name and predicate(body):
                    return body
        return await asyncio.wait_for(read(), timeout)

    async def close(self):
        self.disconnect.set()
        if self.task is not None:
            await asyncio.wait_for(self.task, 2)


class EventTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engines, self.enroller = FakeEngines(), FakeEnroller()
        self.now = [1_800_000_000.0]
        self.app = create_app(engines=self.engines, enroller=self.enroller, clock=lambda: self.now[0])
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.streams = []
        self.frame = image_frame()[0]

    async def asyncTearDown(self):
        self.engines.release.set()
        for stream in self.streams:
            await stream.close()
        await self.lifespan.__aexit__(None, None, None)

    async def session(self):
        status, headers, _ = await request(self.app, "GET", "/api/stato")
        self.assertEqual(status, 200)
        return headers["set-cookie"].split(";", 1)[0]

    async def stream(self, cookie):
        stream = Stream(self.app, cookie)
        self.streams.append(stream)
        await stream.open()
        return stream

    async def initial(self, stream):
        values = [await stream.next() for _ in range(3)]
        self.assertEqual([name for name, _ in values], ["stato", "galleria", "richieste"])
        return dict(values)

    async def enroll(self, cookie):
        status, _, body = await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                       payload={"nome": "Ada", "soglia": 273, "frames": [self.frame]})
        self.assertEqual(status, 201)
        return body["iscritto"]

    async def test_initial_snapshot_matches_rest_reconnect_and_disconnect_cleanup(self):
        cookie = await self.session()
        await self.enroll(cookie)
        stream = await self.stream(cookie)
        initial = await self.initial(stream)
        for name, body in initial.items():
            self.assertEqual(body, (await request(self.app, "GET", "/api/" + name, cookie=cookie))[2])
        await stream.close()
        self.assertEqual(self.app.state.service.events.subscriptions, {})
        reopened = await self.stream(cookie)
        self.assertEqual(await self.initial(reopened), initial)

    async def test_stalled_downstream_send_times_out_through_full_middleware_and_releases_subscription(self):
        cookie = await self.session()
        blocked = asyncio.Event()
        never = asyncio.Event()
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                 "http_version": "1.1", "method": "GET", "scheme": "http", "path": "/api/eventi",
                 "raw_path": b"/api/eventi", "query_string": b"", "root_path": "",
                 "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 8010),
                 "headers": [(b"host", b"127.0.0.1:8010"), (b"cookie", cookie.encode())]}

        async def receive():
            await never.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body":
                blocked.set()
                await never.wait()

        with patch("demo.web.events.SSE_SEND_TIMEOUT_SECONDS", .02):
            task = asyncio.create_task(self.app(scope, receive, send))
            try:
                await asyncio.wait_for(blocked.wait(), 1)
                self.now[0] += 3601
                self.app.state.service.expire()
                done, _ = await asyncio.wait({task}, timeout=1)
                self.assertIn(task, done, "The write deadline must end the response without test cancellation")
                self.assertFalse(task.cancelled())
                with self.assertRaises(TimeoutError):
                    await task
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(task.done())  # The outer response also ends, not merely its producer.
        self.assertEqual(self.app.state.service.events.subscriptions, {})
        self.assertEqual(self.app.state.service.sessions, {})

    async def test_healthy_heartbeat_stream_outlives_individual_write_deadline(self):
        cookie = await self.session()
        with patch("demo.web.events.SSE_SEND_TIMEOUT_SECONDS", .01), \
                patch("demo.web.app.HEARTBEAT_SECONDS", .01):
            stream = await self.stream(cookie)
            await self.initial(stream)
            for _ in range(5):
                self.assertEqual((await stream.next())[0], "comment")
            self.assertFalse(stream.task.done())
            self.assertEqual(len(self.app.state.service.events.subscriptions), 1)

    async def test_completion_is_pushed_without_another_get_or_timeline_timeout(self):
        cookie = await self.session()
        await self.enroll(cookie)
        stream = await self.stream(cookie)
        await self.initial(stream)
        self.engines.release.clear()
        with patch("demo.web.app.TIMELINE_SECONDS", 60), patch("demo.web.app.HEARTBEAT_SECONDS", 60):
            status, _, _ = await request(self.app, "POST", "/api/accesso", cookie=cookie,
                                         payload={"frames": [self.frame], "motore": "attuale"})
            self.assertEqual(status, 202)
            await stream.until("richieste", lambda b: b["richieste"][0]["stato"] == "elaborazione")
            self.engines.release.set()
            final = await stream.until("richieste", lambda b: b["richieste"][0]["stato"] == "completata")
        row = final["richieste"][0]
        self.assertEqual(row["risultati"][0]["selected_id"], 1)
        self.assertTrue(all(span["end_ms"] is not None for span in row["timeline"]["spans"]))
        self.assertNotIn("start_ns", json.dumps(final))
        self.assertNotIn("end_ns", json.dumps(final))

    async def test_gallery_changes_are_pushed_and_cross_session_isolated(self):
        first, second = await self.session(), await self.session()
        stream, other = await self.stream(first), await self.stream(second)
        await self.initial(stream)
        await self.initial(other)
        entry = await self.enroll(first)
        self.assertEqual((await stream.until("galleria"))["iscritti"][0]["nome"], "Ada")
        status, _, _ = await request(self.app, "PATCH", "/api/galleria/" + entry["id"], cookie=first,
                                     payload={"nome": "New name", "soglia": 12})
        self.assertEqual(status, 200)
        changed = await stream.until("galleria")
        self.assertEqual((changed["iscritti"][0]["nome"], changed["iscritti"][0]["soglia"]), ("New name", 12))
        self.assertEqual((await request(self.app, "DELETE", "/api/galleria/" + entry["id"], cookie=first))[0], 200)
        self.assertEqual((await stream.until("galleria"))["totale"], 0)
        with self.assertRaises(asyncio.TimeoutError):
            await other.next(timeout=.05)

    async def test_expiry_pushes_error_closes_and_never_renews_session(self):
        cookie = await self.session()
        stream = await self.stream(cookie)
        initial = await self.initial(stream)
        token = cookie.split("=", 1)[1]
        expiry = self.app.state.service.sessions[token].expires
        self.now[0] = expiry
        self.app.state.service.expire()
        kind, body = await stream.next()
        self.assertEqual(kind, "scaduta")
        self.assertEqual(set(body), {"errore"})
        self.assertNotIn(token, json.dumps(body))
        await asyncio.wait_for(stream.task, 2)
        self.assertEqual(self.app.state.service.sessions, {})
        self.assertEqual(self.app.state.service.events.subscriptions, {})
        self.assertEqual((await request(self.app, "GET", "/api/eventi", cookie=cookie))[0], 401)
        self.assertIn("scadenza", initial["stato"]["sessione"])

    async def test_origin_session_and_subscription_cap(self):
        self.assertEqual((await request(self.app, "GET", "/api/eventi"))[0], 401)
        cookie = await self.session()
        for headers in ({"host": "outside.example"}, {"origin": "https://outside.example"},
                        {"sec-fetch-site": "cross-site"}, {"sec-fetch-site": "same-site"}):
            self.assertEqual((await request(self.app, "GET", "/api/eventi", cookie=cookie, headers=headers))[0], 403)
        streams = [await self.stream(cookie) for _ in range(4)]
        for stream in streams:
            await self.initial(stream)
        self.assertEqual((await request(self.app, "GET", "/api/eventi", cookie=cookie))[0], 429)
        await streams[0].close()
        await self.initial(await self.stream(cookie))

    async def test_close_events_drains_streams_without_closing_jobs_or_renewing(self):
        cookie = await self.session()
        stream = await self.stream(cookie)
        await self.initial(stream)
        service = self.app.state.service
        service.close_events()
        service.close_events()
        await asyncio.wait_for(stream.task, 2)
        self.assertFalse(service.closing)
        self.assertEqual(service.events.subscriptions, {})
        self.assertEqual((await request(self.app, "GET", "/api/eventi", cookie=cookie))[0], 503)
        self.assertEqual((await request(self.app, "GET", "/api/stato", cookie=cookie))[0], 200)

    async def test_idle_heartbeat_and_running_timeline_tick_are_server_generated(self):
        cookie = await self.session()
        await self.enroll(cookie)
        with patch("demo.web.app.HEARTBEAT_SECONDS", .05), patch("demo.web.app.TIMELINE_SECONDS", .02):
            stream = await self.stream(cookie)
            await self.initial(stream)
            self.assertEqual((await stream.next())[0], "comment")
            self.engines.release.clear()
            await request(self.app, "POST", "/api/accesso", cookie=cookie,
                          payload={"frames": [self.frame], "motore": "attuale"})
            first = await stream.until("richieste", lambda b: b["richieste"][0]["stato"] == "elaborazione")
            second = await stream.until("richieste", lambda b: b["richieste"][0]["stato"] == "elaborazione")
            self.assertGreater(second["richieste"][0]["timeline"]["elapsed_ms"],
                               first["richieste"][0]["timeline"]["elapsed_ms"])
            self.assertIsNone(second["richieste"][0]["timeline"]["spans"][0]["end_ms"])


class NotificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_thread_wakeups_coalesce_and_notification_before_wait_is_not_lost(self):
        hub = EventHub()
        sub = hub.subscribe("token")
        with patch.object(sub.loop, "call_soon_threadsafe", wraps=sub.loop.call_soon_threadsafe) as schedule:
            await asyncio.to_thread(lambda: [hub.notify("token") for _ in range(100)])
            wakeups = [call for call in schedule.call_args_list if call.args[0] == sub._wake]
            self.assertEqual(len(wakeups), 1)
        await sub.wait(.5)
        self.assertTrue(sub.event.is_set())
        sub.consume()
        hub.notify("token")
        await sub.wait(.5)
        self.assertTrue(sub.event.is_set())
        hub.unsubscribe(sub)
        self.assertEqual(hub.subscriptions, {})


if __name__ == "__main__":
    unittest.main()
