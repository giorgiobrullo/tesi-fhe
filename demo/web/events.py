"""Bounded wakeups for session SSE streams; snapshots remain owned by the service."""
import asyncio
import json
import threading

from fastapi.responses import StreamingResponse

HEARTBEAT_SECONDS = 15
TIMELINE_SECONDS = 1
MAX_SUBSCRIPTIONS = 4
SSE_SEND_TIMEOUT_SECONDS = 60


class SSEWriteTimeoutMiddleware:
    """Bound each downstream write outside FastAPI's streaming middleware."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/api/eventi":
            return await self.app(scope, receive, send)

        async def bounded_send(message):
            async with asyncio.timeout(SSE_SEND_TIMEOUT_SECONDS):
                await send(message)

        # A failed write propagates so the HTTP server closes the stalled connection.
        # Cancellation unwinds the inner response and releases its subscription.
        await self.app(scope, receive, bounded_send)


class Subscription:
    def __init__(self, token):
        self.token = token
        self.loop = asyncio.get_running_loop()
        self.event = asyncio.Event()
        self.lock = threading.Lock()
        self.pending = False
        self.closed = False

    def notify(self):
        with self.lock:
            if self.closed or self.pending:
                return
            self.pending = True
            self.loop.call_soon_threadsafe(self._wake)

    def _wake(self):
        if not self.closed:
            self.event.set()

    def consume(self):
        with self.lock:
            self.pending = False
            self.event.clear()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            self.loop.call_soon_threadsafe(self.event.set)

    async def wait(self, timeout):
        try:
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass


class EventHub:
    def __init__(self):
        self.lock = threading.Lock()
        self.subscriptions = {}

    def subscribe(self, token):
        with self.lock:
            listeners = self.subscriptions.setdefault(token, set())
            if len(listeners) >= MAX_SUBSCRIPTIONS:
                raise ValueError("Troppe connessioni di aggiornamento aperte per questa sessione.")
            subscription = Subscription(token)
            listeners.add(subscription)
            return subscription

    def notify(self, token):
        with self.lock:
            for subscription in self.subscriptions.get(token, ()):
                subscription.notify()

    def unsubscribe(self, subscription):
        with self.lock:
            listeners = self.subscriptions.get(subscription.token)
            if listeners is not None:
                listeners.discard(subscription)
                if not listeners:
                    self.subscriptions.pop(subscription.token)
            subscription.close()

    def close(self):
        with self.lock:
            for listeners in self.subscriptions.values():
                for subscription in listeners:
                    subscription.close()
            self.subscriptions.clear()


def encode_event(name, body):
    data = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return f"event: {name}\ndata: {data}\n\n"


class EventResponse(StreamingResponse):
    """Release the subscription even if sending fails before the generator starts."""
    def __init__(self, content, hub, subscription):
        super().__init__(content, media_type="text/event-stream",
                         headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
        self.hub, self.subscription = hub, subscription

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.hub.unsubscribe(self.subscription)
