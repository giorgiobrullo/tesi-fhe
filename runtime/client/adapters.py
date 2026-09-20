"""Process and HTTP boundaries for the trusted client."""
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

from . import protocol


class RustRunner:
    def __init__(self, binary: Path):
        self.binary = binary

    def __call__(self, *args):
        result = subprocess.run(
            [str(self.binary), *map(str, args)], capture_output=True, text=True,
            timeout=600 if args[0] == "keygen" else 120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"{args[0]}: {result.stderr[:400]}")
        return protocol.strict_json(result.stdout.strip().splitlines()[-1])


class HttpTransport:
    def __init__(self, server: str):
        self.server = server.rstrip("/")

    def __call__(self, path, data=None, ctype="application/octet-stream", timeout=120):
        request = urllib.request.Request(
            self.server + path, data=data, method="POST" if data is not None else "GET",
            headers={"Content-Type": ctype} if data is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            body = error.read()
            try:
                detail = json.loads(body).get("errore", body.decode(errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                detail = body.decode(errors="replace")
            raise RuntimeError(f"server HTTP {error.code}: {detail}") from error
