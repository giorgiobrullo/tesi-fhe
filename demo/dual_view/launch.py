"""Start the three local demo roles without replacing an existing service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
PORTS = {"backend": 9005, "server": 8005, "client": 8006}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def process_identity(pid: int) -> dict[str, str] | None:
    values = {}
    for field in ("lstart", "args"):
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", field + "="],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        values[field] = result.stdout.strip()
    return values


def port_in_use(port: int) -> bool:
    with socket.socket() as connection:
        connection.settimeout(1)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def read_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=3) as response:
        return json.load(response)


def wait_ready(process: subprocess.Popen, url: str, *, require_ready: bool = False) -> dict:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Un servizio si è fermato; consultare il suo log locale.")
        try:
            state = read_json(url)
            empty_gallery = (
                state.get("iscritti") == 0
                and state.get("errore") == "La galleria non contiene ancora iscritti."
            )
            if not require_ready or state.get("pronto") is True or empty_gallery:
                return state
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError("Il servizio non è diventato pronto entro due minuti.")


def write_receipt(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def start(options: argparse.Namespace) -> None:
    binary = options.binary.resolve(strict=True)
    keys = options.keys.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("Specificare un binario eseguibile della demo composita22.")
    if not all((keys / name).is_file() for name in ("client.key", "server.key")):
        raise RuntimeError("Serve una coppia di chiavi client/server già generata.")
    binary_digest = sha256(binary)
    if options.expected_binary_sha256 and binary_digest != options.expected_binary_sha256:
        raise RuntimeError("Il binario non corrisponde all'impronta richiesta.")
    occupied = [port for port in PORTS.values() if port_in_use(port)]
    if occupied:
        raise RuntimeError(f"Porte già occupate: {occupied}. Nessun servizio è stato fermato.")

    state_root = options.state_root.resolve()
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_directory = state_root / ("run-" + time.strftime("%Y%m%d-%H%M%S"))
    run_directory.mkdir(mode=0o700)
    common = os.environ.copy()
    # Only the trusted client receives its key location or crypto executable.
    common.pop("VARCO_CHIAVI", None)
    common.pop("VARCO_BIN", None)
    common.pop("VARCO_SERVER", None)
    common.update(
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUNBUFFERED="1",
        RAYON_NUM_THREADS="16",
        VARCO_BACKEND_URL="http://127.0.0.1:9005",
        VARCO_DUAL_STATE=str(state_root / "server"),
        VARCO_DUAL_CLIENT_ORIGIN="http://127.0.0.1:8006",
        VARCO_DUAL_SERVER_ORIGIN="http://127.0.0.1:8005",
    )
    commands = {
        "backend": [str(binary), "serve", "9005", "512", "4"],
        "server": [sys.executable, "-B", "-m", "uvicorn", "demo.dual_view.server:app",
                   "--host", "127.0.0.1", "--port", "8005"],
        "client": [sys.executable, "-B", "-m", "uvicorn", "demo.dual_view.client:app",
                   "--host", "127.0.0.1", "--port", "8006"],
    }
    receipt = {
        "schema": "dual-view-launch.v1", "binary_sha256": binary_digest,
        "run_directory": str(run_directory), "roles": {}, "ready": False,
    }
    owned: list[subprocess.Popen] = []
    try:
        for role, command in commands.items():
            environment = common.copy()
            if role == "client":
                environment.update(
                    VARCO_BIN=str(binary), VARCO_CHIAVI=str(keys),
                    VARCO_SERVER="http://127.0.0.1:8005/fhe",
                )
            elif role == "server":
                environment["VARCO_DUAL_OWN_BACKEND"] = "1"
            log_path = run_directory / (role + ".log")
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    command, cwd=REPOSITORY, env=environment, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                )
            owned.append(process)
            path = "/stato" if role == "backend" else "/api/stato"
            receipt["roles"][role] = {
                "pid": process.pid, "identity": process_identity(process.pid),
                "port": PORTS[role], "log": str(log_path),
            }
            write_receipt(run_directory / "launch.json", receipt)
            wait_ready(process, f"http://127.0.0.1:{PORTS[role]}{path}", require_ready=role == "client")
            print(f"{role}: pronto su 127.0.0.1:{PORTS[role]}", flush=True)
        receipt["ready"] = True
        receipt["client_url"] = "http://127.0.0.1:8006/"
        receipt["server_url"] = "http://127.0.0.1:8005/"
        write_receipt(run_directory / "launch.json", receipt)
        write_receipt(state_root / "current.json", receipt)
        print(json.dumps({"client": receipt["client_url"], "server": receipt["server_url"]}))
    except BaseException:
        # These handles refer only to processes created by this invocation.
        for process in reversed(owned):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        receipt["startup_failed"] = True
        write_receipt(run_directory / "launch.json", receipt)
        raise


def current(options: argparse.Namespace, *, stop: bool = False) -> None:
    receipt_path = options.state_root / "current.json"
    if not receipt_path.is_file():
        raise RuntimeError("Non esiste una ricevuta di avvio in questa cartella locale.")
    receipt = json.loads(receipt_path.read_text())
    statuses = {}
    for role in ("client", "server", "backend"):
        record = receipt["roles"][role]
        actual = process_identity(record["pid"])
        matches = actual is not None and actual == record["identity"]
        statuses[role] = {"pid": record["pid"], "identity_matches": matches}
        if stop and matches:
            os.kill(record["pid"], signal.SIGTERM)
            statuses[role]["stop_requested"] = True
    print(json.dumps(statuses, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=HERE / ".local")
    commands = parser.add_subparsers(dest="command", required=True)
    starter = commands.add_parser("start")
    starter.add_argument("--binary", type=Path, required=True)
    starter.add_argument("--keys", type=Path, required=True)
    starter.add_argument("--expected-binary-sha256")
    commands.add_parser("status")
    commands.add_parser("stop")
    options = parser.parse_args()
    if options.command == "start":
        start(options)
    else:
        current(options, stop=options.command == "stop")


if __name__ == "__main__":
    main()
