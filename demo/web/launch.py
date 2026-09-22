"""Run the web demo and its current native worker on loopback."""

import argparse
import os
from pathlib import Path

import uvicorn

from .app import DEFAULT_MAX_SESSIONS, create_app, normalize_public_origin, session_limit


class WebServer(uvicorn.Server):
    def __init__(self, app, **options):
        self.app = app
        super().__init__(uvicorn.Config(app, **options))

    async def shutdown(self, sockets=None):
        # Uvicorn drains connections before lifespan teardown. Release the
        # event streams first, while ordinary requests and jobs can finish.
        service = getattr(self.app.state, "service", None)
        if service is not None:
            service.close_events()
        await super().shutdown(sockets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, default=Path(__file__).parent / ".local")
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--native-port", type=int, default=9010)
    parser.add_argument("--max-sessions", type=session_limit,
                        default=os.environ.get("VARCO_WEB_MAX_SESSIONS", str(DEFAULT_MAX_SESSIONS)),
                        help="Numero massimo di sessioni in memoria, da 1 a 4096 (predefinito: 512).")
    parser.add_argument("--public-origin", type=normalize_public_origin,
                        default=os.environ.get("VARCO_WEB_PUBLIC_ORIGIN"),
                        help="Indirizzo HTTPS della demo dietro un proxy locale.")
    options = parser.parse_args()
    if not 1024 <= options.port <= 65535 or not 1024 <= options.native_port <= 65535 or options.port == options.native_port:
        parser.error("Scegli due porte distinte tra 1024 e 65535.")
    if not options.binary.is_file() or not os.access(options.binary, os.X_OK):
        parser.error(f"Binario non eseguibile: {options.binary}")
    if not all((options.keys / name).is_file() for name in ("client.key", "server.key")):
        parser.error("Genera prima la coppia di chiavi del runtime attuale.")
    os.environ.update({
        "VARCO_WEB_BINARY": str(options.binary.resolve()),
        "VARCO_WEB_KEYS": str(options.keys.resolve()),
        "VARCO_WEB_STATE": str(options.state_root.resolve()),
        "VARCO_WEB_NATIVE_PORT": str(options.native_port),
        "RAYON_NUM_THREADS": "16",
    })
    if options.public_origin is not None:
        os.environ["VARCO_WEB_PUBLIC_ORIGIN"] = options.public_origin
    WebServer(create_app(max_sessions=options.max_sessions), host="127.0.0.1", port=options.port, workers=1,
              proxy_headers=False, access_log=False, timeout_graceful_shutdown=240).run()


if __name__ == "__main__":
    main()
