"""Launcher configuration tests without starting servers or native workers."""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from . import launch


class LauncherTests(unittest.TestCase):
    def test_session_limit_defaults_environment_cli_override_and_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "current"
            binary.touch(mode=0o700)
            keys = root / "keys"
            keys.mkdir()
            for name in ("client.key", "server.key"):
                (keys / name).touch()
            base = ["varco-web", "--binary", str(binary), "--keys", str(keys)]
            for environment, options, expected in (
                    ({}, [], 512), ({"VARCO_WEB_MAX_SESSIONS": "1024"}, [], 1024),
                    ({"VARCO_WEB_MAX_SESSIONS": "1024"}, ["--max-sessions", "2048"], 2048),
                    ({"VARCO_WEB_MAX_SESSIONS": "invalid"}, ["--max-sessions", "1"], 1)):
                with self.subTest(environment=environment, options=options), \
                        patch.dict(os.environ, environment, clear=True), \
                        patch("sys.argv", base + options), \
                        patch.object(launch, "create_app") as create_app, \
                        patch.object(launch, "WebServer"):
                    launch.main()
                    create_app.assert_called_once_with(max_sessions=expected)
            for environment, options in (
                    ({"VARCO_WEB_MAX_SESSIONS": "0"}, []),
                    ({}, ["--max-sessions", "4097"]), ({}, ["--max-sessions", "2.5"]),
                    ({}, ["--max-sessions", "-1"]), ({}, ["--max-sessions", "1e3"])):
                with self.subTest(environment=environment, options=options), \
                        patch.dict(os.environ, environment, clear=True), \
                        patch("sys.argv", base + options), \
                        patch.object(launch, "WebServer") as server, \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    launch.main()
                server.assert_not_called()

    def test_current_only_launch_with_or_without_residual_a28_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "current"
            binary.touch(mode=0o700)
            keys = root / "keys"
            keys.mkdir()
            for name in ("client.key", "server.key"):
                (keys / name).touch()
            arguments = ["varco-web", "--binary", str(binary), "--keys", str(keys),
                         "--state-root", str(root / "state")]
            for environment in ({}, {"VARCO_A28_BINARY": "/missing/a28",
                                     "VARCO_A28_KEYS": "/missing/a28-keys"}):
                with self.subTest(environment=environment), \
                        patch.dict(os.environ, environment, clear=True), \
                        patch("sys.argv", arguments), patch.object(launch, "WebServer") as server:
                    launch.main()
                    server.assert_called_once_with(
                        server.call_args.args[0], host="127.0.0.1", port=8010,
                        workers=1, proxy_headers=False, access_log=False, timeout_graceful_shutdown=240,
                    )
                    server.return_value.run.assert_called_once_with()
                    self.assertEqual(os.environ["VARCO_WEB_BINARY"], str(binary.resolve()))
                    self.assertEqual(os.environ["VARCO_WEB_KEYS"], str(keys.resolve()))
                    self.assertEqual(os.environ["RAYON_NUM_THREADS"], "16")


class ShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_streams_close_before_uvicorn_waits_for_connections(self):
        app = launch.create_app()
        app.state.service = Mock()
        server = launch.WebServer(app)

        async def drain(sockets):
            app.state.service.close_events.assert_called_once_with()

        with patch.object(launch.uvicorn.Server, "shutdown", AsyncMock(side_effect=drain)) as shutdown:
            await server.shutdown()
            shutdown.assert_awaited_once_with(None)

    async def test_shutdown_after_failed_startup_has_no_service_to_close(self):
        server = launch.WebServer(launch.create_app())
        with patch.object(launch.uvicorn.Server, "shutdown", AsyncMock()) as shutdown:
            await server.shutdown()
            shutdown.assert_awaited_once_with(None)


if __name__ == "__main__":
    unittest.main()
