#!/usr/bin/env python3
"""A74: local runtime gate for the isolated A67/A71 service binary.

The runner uses only loopback HTTP and caller-provided fresh temporary storage.  It
never serializes key bytes into its evidence JSON and removes the temporary tree in
``finally`` after stopping the server.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "tmp/a67-a62-service-materialization/target-a71/release/varco_demo"
SOURCE_ROOT = (
    REPO
    / "tmp/a67-a62-service-materialization/source/experiments/14_pipeline_tfhe_rs"
)

EXPECTED_BINARY_SHA256 = "35dd29890573790158d1174f391b83c607693183f663e79fbdfc69f658819021"
EXPECTED_SOURCE_SHA256 = {
    "src/lib.rs": "6023d1ca3594897b54b216f85580897aef5c4fe12c7245278f4b12e90f25116b",
    "src/private_argmin.rs": "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab",
    "src/a53_scan.rs": "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
    "src/a53_scan/fhe.rs": "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e",
    "src/bin/varco_demo.rs": "8ad76dc073be4fbe82725afbfb85cc5c3c5fb38e6398ddba0d04ad01955069a8",
    "Cargo.lock": "1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a",
}

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMS_FINGERPRINT = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
VARIANT_ID = "a62-a50-a53-radix15-group4-two-p16-v1"
CIRCUIT_SHA256 = "ee76afd8ad3f6ee48fb3da4806e52fee3edf9db773c4adbe2c986fe713789b79"
HTTP_CONTRACT = "exact-open-set-id-v4-a62-base15-two-lwe"

PROBE_MAGIC = int.from_bytes(b"VRCOPR62", "little")
OUTPUT_MAGIC = int.from_bytes(b"VRCOUT62", "little")
CLIENT_KEY_MAGIC = int.from_bytes(b"VRCCK62!", "little")
SERVER_KEY_MAGIC = int.from_bytes(b"VRCSK62!", "little")
A65_PROBE_MAGIC = int.from_bytes(b"VRCOPR44", "little")
A65_OUTPUT_MAGIC = int.from_bytes(b"VRCOUT44", "little")
A65_CLIENT_KEY_MAGIC = int.from_bytes(b"VRCCK44!", "little")
A65_SERVER_KEY_MAGIC = int.from_bytes(b"VRCSK44!", "little")
A38_PROBE_MAGIC = int.from_bytes(b"VRCOPRB2", "little")

EXPECTED_N = 16
EXPECTED_N16_COUNTS = {
    "blind_rotations": 431,
    "key_switches": 383,
    "output_marginals": 499,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


class EvidenceLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    def emit(self, message: str) -> None:
        line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {message}"
        print(line, file=sys.stderr, flush=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def rss_kib(pid: int) -> int | None:
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return int(result.stdout.strip().splitlines()[0])
    except ValueError:
        return None


def run_monitored(
    argv: list[str], *, timeout_s: float, redact: str
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    peak_rss = 0
    while process.poll() is None:
        observed = rss_kib(process.pid)
        if observed is not None:
            peak_rss = max(peak_rss, observed)
        if time.monotonic() - started > timeout_s:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            raise TimeoutError(f"command timed out after {timeout_s}s: {argv[:2]}")
        time.sleep(0.05)
    stdout, stderr = process.communicate()
    observed = rss_kib(process.pid)
    if observed is not None:
        peak_rss = max(peak_rss, observed)
    return {
        "returncode": process.returncode,
        "wall_s": round(time.monotonic() - started, 6),
        "peak_rss_kib": peak_rss,
        "stdout": stdout.replace(redact, "<ephemeral>").strip(),
        "stderr": stderr.replace(redact, "<ephemeral>").strip(),
    }


class RssSampler:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.peak_rss_kib = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self._stop.is_set():
            observed = rss_kib(self.pid)
            if observed is not None:
                self.peak_rss_kib = max(self.peak_rss_kib, observed)
            self._stop.wait(0.05)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_request_segments(
    port: int,
    method: str,
    path: str,
    segments: list[bytes | bytearray | memoryview] | None = None,
    *,
    timeout_s: float = 900,
    content_type: str = "application/octet-stream",
) -> dict[str, Any]:
    body_segments = segments or []
    content_length = sum(len(segment) for segment in body_segments)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_s)
    started = time.monotonic()
    try:
        conn.putrequest(method, path)
        conn.putheader("Content-Length", str(content_length))
        if content_length:
            conn.putheader("Content-Type", content_type)
        conn.endheaders()
        for segment in body_segments:
            conn.send(segment)
        response = conn.getresponse()
        body = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
        return {
            "status": response.status,
            "headers": headers,
            "body": body,
            "wall_s": round(time.monotonic() - started, 6),
        }
    finally:
        conn.close()


def wait_for_server(port: int, process: subprocess.Popen[bytes]) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness: {process.returncode}")
        try:
            response = http_request_segments(port, "GET", "/stato", timeout_s=1)
            if response["status"] == 200:
                return json.loads(response["body"])
        except (ConnectionError, OSError, TimeoutError):
            pass
        time.sleep(0.05)
    raise TimeoutError("loopback server did not become ready")


def unpack_ciphertext(blob: bytes | bytearray) -> tuple[list[int], bytes]:
    if len(blob) < 8 or len(blob) % 8:
        raise AssertionError("ciphertext is not a complete u64 stream")
    header_words = struct.unpack_from("<Q", blob, 0)[0]
    header_end = 8 + 8 * header_words
    if header_end > len(blob):
        raise AssertionError("declared header exceeds ciphertext")
    words = list(struct.unpack_from(f"<{header_words}Q", blob, 8))
    return words, bytes(blob[header_end:])


def pack_ciphertext(words: list[int], body: bytes) -> bytes:
    return struct.pack("<Q", len(words)) + struct.pack(f"<{len(words)}Q", *words) + body


def decode_header_binding(words: list[int], fixed_words: int) -> dict[str, str]:
    lengths = words[fixed_words : fixed_words + 4]
    if len(lengths) != 4:
        raise AssertionError("missing A62 binding lengths")
    cursor = fixed_words + 4
    decoded: list[str] = []
    for length in lengths:
        word_count = (length + 7) // 8
        raw = struct.pack(f"<{word_count}Q", *words[cursor : cursor + word_count])
        decoded.append(raw[:length].decode("ascii"))
        cursor += word_count
    if cursor != len(words):
        raise AssertionError("unexpected trailing bound-header words")
    return dict(zip(("params_id", "params_fingerprint", "variant_id", "circuit_sha256"), decoded))


def key_envelope_parts(data: bytes | bytearray) -> dict[str, Any]:
    if len(data) < 56:
        raise AssertionError("A62 key envelope is truncated")
    words = struct.unpack_from("<7Q", data, 0)
    lengths = words[2:6]
    offsets = []
    cursor = 56
    for length in lengths:
        offsets.append(cursor)
        cursor += length
    payload_end = cursor + words[6]
    if payload_end != len(data):
        raise AssertionError("A62 key envelope length mismatch")
    return {
        "magic": words[0],
        "version": words[1],
        "lengths": lengths,
        "offsets": offsets,
        "payload_offset": cursor,
        "payload_len": words[6],
    }


def patched_copy(data: bytes | bytearray, patches: list[tuple[int, bytes]]) -> bytes:
    mutated = bytearray(data)
    for offset, replacement in patches:
        mutated[offset : offset + len(replacement)] = replacement
    return bytes(mutated)


def make_a62_empty_bound_key(
    magic: int, *, mutate_field: int | None = None, version: int = 4
) -> bytes:
    fields = [
        bytearray(PARAMS_ID.encode()),
        bytearray(PARAMS_FINGERPRINT.encode()),
        bytearray(VARIANT_ID.encode()),
        bytearray(CIRCUIT_SHA256.encode()),
    ]
    if mutate_field is not None:
        fields[mutate_field][0] ^= 1
    words = [magic, version, *(len(field) for field in fields), 0]
    return struct.pack("<7Q", *words) + b"".join(bytes(field) for field in fields)


def make_a65_key_segments(
    magic: int, payload: memoryview
) -> list[bytes | memoryview]:
    header = struct.pack(
        "<5Q",
        magic,
        3,
        len(PARAMS_ID),
        len(PARAMS_FINGERPRINT),
        len(payload),
    )
    return [header, PARAMS_ID.encode(), PARAMS_FINGERPRINT.encode(), payload]


def make_a65_header(fixed: list[int], body: bytes) -> bytes:
    words = [
        *fixed,
        len(PARAMS_ID),
        len(PARAMS_FINGERPRINT),
    ]
    for value in (PARAMS_ID, PARAMS_FINGERPRINT):
        raw = value.encode()
        padded = raw + bytes((-len(raw)) % 8)
        words.extend(struct.unpack(f"<{len(padded) // 8}Q", padded))
    return pack_ciphertext(words, body)


def mutate_bound_header(
    blob: bytes, fixed_words: int, field_index: int
) -> bytes:
    words, body = unpack_ciphertext(blob)
    lengths = words[fixed_words : fixed_words + 4]
    word_index = fixed_words + 4
    for previous in lengths[:field_index]:
        word_index += (previous + 7) // 8
    words[word_index] ^= 1
    return pack_ciphertext(words, body)


def mutate_fixed_header(blob: bytes, index: int, value: int) -> bytes:
    words, body = unpack_ciphertext(blob)
    words[index] = value
    return pack_ciphertext(words, body)


def expect_http_reject(
    label: str, response: dict[str, Any], *, expected_status: int = 400
) -> dict[str, Any]:
    if response["status"] != expected_status:
        raise AssertionError(f"{label}: HTTP {response['status']}, expected {expected_status}")
    if "x-pbs" in response["headers"]:
        raise AssertionError(f"{label}: rejection unexpectedly exposed X-Pbs")
    decoded = response["body"].decode("utf-8", errors="replace")
    return {
        "label": label,
        "pass": True,
        "status": response["status"],
        "wall_s": response["wall_s"],
        "error": decoded,
        "pbs_header_absent": True,
    }


def expect_cli_reject(label: str, result: dict[str, Any]) -> dict[str, Any]:
    if result["returncode"] == 0:
        raise AssertionError(f"{label}: CLI unexpectedly accepted incompatible artifact")
    return {
        "label": label,
        "pass": True,
        "returncode": result["returncode"],
        "wall_s": result["wall_s"],
        "peak_rss_kib": result["peak_rss_kib"],
        "diagnostic": result["stderr"],
    }


def validate_contract(state: dict[str, Any]) -> None:
    contract = state["contratto_esatto"]
    expected = {
        "http_contract": HTTP_CONTRACT,
        "wire_version": 4,
        "output_lwes": 2,
        "digit_base": 15,
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
        "un_solo_lwe": False,
        "ricostruzione_client": "low+15*high",
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise AssertionError(f"contract {key}: {contract.get(key)!r} != {value!r}")


def validate_probe(blob: bytes) -> dict[str, Any]:
    words, body = unpack_ciphertext(blob)
    if words[:8] != [PROBE_MAGIC, 4, 1, 2048, 1, 512, 52, 60]:
        raise AssertionError(f"unexpected A62 probe fixed header: {words[:8]}")
    binding = decode_header_binding(words, 8)
    expected_binding = {
        "params_id": PARAMS_ID,
        "params_fingerprint": PARAMS_FINGERPRINT,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
    }
    if binding != expected_binding:
        raise AssertionError("probe binding mismatch")
    if len(body) != 2 * 2048 * 8:
        raise AssertionError(f"unexpected probe body size: {len(body)}")
    return {
        "bytes": len(blob),
        "header_words": len(words),
        "body_words": len(body) // 8,
        "binding": binding,
        "layout": "one GLWE, score+mod16 dual layout",
    }


def validate_output(blob: bytes) -> dict[str, Any]:
    words, body = unpack_ciphertext(blob)
    if words[0] != OUTPUT_MAGIC or words[1] != 4 or words[2] != 4:
        raise AssertionError(f"unexpected A62 output prefix: {words[:3]}")
    if words[5] != EXPECTED_N or words[7] != 59 or words[8] != 2 or words[9] != 15:
        raise AssertionError(f"unexpected A62 output contract fields: {words[:10]}")
    binding = decode_header_binding(words, 10)
    expected_binding = {
        "params_id": PARAMS_ID,
        "params_fingerprint": PARAMS_FINGERPRINT,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
    }
    if binding != expected_binding:
        raise AssertionError("output binding mismatch")
    lwe_size = words[6]
    if len(body) != 2 * lwe_size * 8:
        raise AssertionError("output does not contain exactly two equal-size LWE ciphertexts")
    return {
        "bytes": len(blob),
        "header_words": len(words),
        "lwe_size_words": lwe_size,
        "output_lwes": 2,
        "digit_base": 15,
        "binding": binding,
    }


def one_hot(index: int | None) -> list[int]:
    vector = [0] * 512
    if index is not None:
        vector[index] = 1
    return vector


def vector_text(vector: list[int]) -> str:
    return " ".join(str(value) for value in vector) + "\n"


def parse_cli_json(result: dict[str, Any], label: str) -> dict[str, Any]:
    if result["returncode"] != 0:
        raise AssertionError(f"{label} failed: {result['stderr']}")
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError as error:
        raise AssertionError(f"{label} did not emit JSON: {result['stdout']}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--command-log", type=Path, required=True)
    args = parser.parse_args()

    workdir = args.workdir.resolve()
    if not workdir.is_dir() or not workdir.name.startswith("a74-a67."):
        raise SystemExit("--workdir must be a fresh mktemp directory named a74-a67.*")
    evidence = EvidenceLog(args.command_log)
    result: dict[str, Any] = {
        "artifact": "A74 A67 local runtime gate",
        "date": "2026-09-02",
        "promotion": False,
        "scope": "local_loopback_no_docker",
        "status": "RUNNING",
    }
    server: subprocess.Popen[bytes] | None = None
    server_log_handle = None
    sampler: RssSampler | None = None

    try:
        evidence.emit("checking immutable A71 binary and A67 source provenance")
        binary_hash = sha256_file(BINARY)
        if binary_hash != EXPECTED_BINARY_SHA256:
            raise AssertionError(f"isolated A71 binary hash mismatch: {binary_hash}")
        source_hashes = {
            relative: sha256_file(SOURCE_ROOT / relative)
            for relative in EXPECTED_SOURCE_SHA256
        }
        if source_hashes != EXPECTED_SOURCE_SHA256:
            raise AssertionError("materialized A67 source hash mismatch")
        service_source = (SOURCE_ROOT / "src/bin/varco_demo.rs").read_text(encoding="utf-8")
        for literal in (
            "A44_PARAMS_ID",
            "A44_PARAMETER_FINGERPRINT_SHA256",
            VARIANT_ID,
            CIRCUIT_SHA256,
        ):
            if literal not in service_source:
                raise AssertionError(f"service source lacks binding literal: {literal}")
        core_source = (SOURCE_ROOT / "src/private_argmin.rs").read_text(encoding="utf-8")
        for literal in (PARAMS_ID, PARAMS_FINGERPRINT):
            if literal not in core_source:
                raise AssertionError(f"core source lacks parameter binding literal: {literal}")
        result["provenance"] = {
            "binary": str(BINARY.relative_to(REPO)),
            "binary_sha256": binary_hash,
            "source_sha256": source_hashes,
            "params_id": PARAMS_ID,
            "params_fingerprint_sha256": PARAMS_FINGERPRINT,
            "variant_id": VARIANT_ID,
            "circuit_sha256": CIRCUIT_SHA256,
        }

        keydir = workdir / "keys"
        evidence.emit("generating fresh ephemeral A44-parameter keypair")
        keygen = run_monitored(
            [str(BINARY), "keygen", str(keydir)], timeout_s=900, redact=str(workdir)
        )
        keygen_json = parse_cli_json(keygen, "keygen")
        result["keygen"] = {
            "wall_s": keygen["wall_s"],
            "reported_keygen_s": keygen_json["keygen_s"],
            "peak_rss_kib": keygen["peak_rss_kib"],
            "client_key_bytes": keygen_json["client_key_b"],
            "server_key_bytes": keygen_json["server_key_b"],
            "bindings_match": all(
                [
                    keygen_json["params_id"] == PARAMS_ID,
                    keygen_json["params_fingerprint_sha256"] == PARAMS_FINGERPRINT,
                    keygen_json["variant_id"] == VARIANT_ID,
                    keygen_json["circuit_sha256"] == CIRCUIT_SHA256,
                ]
            ),
        }
        if not result["keygen"]["bindings_match"]:
            raise AssertionError("keygen reported unexpected binding")

        client_key = bytearray((keydir / "client.key").read_bytes())
        server_key = bytearray((keydir / "server.key").read_bytes())
        client_parts = key_envelope_parts(client_key)
        server_parts = key_envelope_parts(server_key)
        if client_parts["magic"] != CLIENT_KEY_MAGIC or client_parts["version"] != 4:
            raise AssertionError("fresh client key envelope is not A62 wire v4")
        if server_parts["magic"] != SERVER_KEY_MAGIC or server_parts["version"] != 4:
            raise AssertionError("fresh server key envelope is not A62 wire v4")

        exact_probe_path = workdir / "probe-id16.txt"
        reject_probe_path = workdir / "probe-impostor.txt"
        exact_probe_path.write_text(vector_text(one_hot(15)), encoding="ascii")
        reject_probe_path.write_text(vector_text(one_hot(16)), encoding="ascii")

        evidence.emit("running client-key cross-format and wrong-binding rejects")
        client_negative: list[dict[str, Any]] = []
        client_payload = memoryview(client_key)[client_parts["payload_offset"] :]
        client_cases: list[tuple[str, bytes]] = [
            ("wire_v2_raw_client_key", bytes(client_payload)),
            (
                "a65_a44_base16_wire_v3_client_key",
                b"".join(
                    bytes(segment)
                    for segment in make_a65_key_segments(A65_CLIENT_KEY_MAGIC, client_payload)
                ),
            ),
            (
                "wire_v4_wrong_version_client_key",
                patched_copy(client_key, [(8, struct.pack("<Q", 2))]),
            ),
        ]
        for field_index, label in enumerate(
            ("wrong_params_id", "wrong_params_fingerprint", "wrong_variant", "wrong_circuit")
        ):
            offset = client_parts["offsets"][field_index]
            client_cases.append(
                (
                    f"wire_v4_{label}_client_key",
                    patched_copy(client_key, [(offset, bytes([client_key[offset] ^ 1]))]),
                )
            )
        for label, artifact in client_cases:
            case_dir = workdir / f"client-negative-{len(client_negative):02d}"
            case_dir.mkdir(mode=0o700)
            (case_dir / "client.key").write_bytes(artifact)
            command = run_monitored(
                [
                    str(BINARY),
                    "encrypt",
                    str(case_dir),
                    str(exact_probe_path),
                    str(case_dir / "should-not-exist.ct"),
                ],
                timeout_s=30,
                redact=str(workdir),
            )
            client_negative.append(expect_cli_reject(label, command))
        result["client_key_negative_gate"] = client_negative

        port = reserve_loopback_port()
        args.server_log.parent.mkdir(parents=True, exist_ok=True)
        server_log_handle = args.server_log.open("wb")
        evidence.emit("starting isolated A71 binary; all requests target 127.0.0.1")
        server = subprocess.Popen(
            [str(BINARY), "serve", str(port), "512", "0"],
            stdout=server_log_handle,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        sampler = RssSampler(server.pid)
        sampler.start()
        initial_state = wait_for_server(port, server)
        validate_contract(initial_state)
        if initial_state["chiave"] or initial_state["iscritti"] != 0:
            raise AssertionError("server did not start empty")

        evidence.emit("running server-key cross-format and wrong-binding rejects")
        server_negative: list[dict[str, Any]] = []
        server_payload = memoryview(server_key)[server_parts["payload_offset"] :]
        response = http_request_segments(
            port, "POST", "/chiave", [server_payload], timeout_s=900
        )
        server_negative.append(expect_http_reject("wire_v2_raw_server_key", response))
        response = http_request_segments(
            port,
            "POST",
            "/chiave",
            make_a65_key_segments(A65_SERVER_KEY_MAGIC, server_payload),
            timeout_s=900,
        )
        server_negative.append(
            expect_http_reject("a65_a44_base16_wire_v3_server_key", response)
        )
        response = http_request_segments(
            port,
            "POST",
            "/chiave",
            [make_a62_empty_bound_key(SERVER_KEY_MAGIC, version=2)],
        )
        server_negative.append(expect_http_reject("wire_v4_magic_wrong_version_server_key", response))
        for field_index, label in enumerate(
            ("wrong_params_id", "wrong_params_fingerprint", "wrong_variant", "wrong_circuit")
        ):
            response = http_request_segments(
                port,
                "POST",
                "/chiave",
                [make_a62_empty_bound_key(SERVER_KEY_MAGIC, mutate_field=field_index)],
            )
            server_negative.append(expect_http_reject(f"wire_v4_{label}_server_key", response))
        state_after_key_rejects = json.loads(
            http_request_segments(port, "GET", "/stato")["body"]
        )
        if state_after_key_rejects["chiave"]:
            raise AssertionError("a rejected key mutated server state")
        result["server_key_negative_gate"] = server_negative

        evidence.emit("installing the fresh valid A62-bound evaluation key")
        valid_key_response = http_request_segments(
            port, "POST", "/chiave", [server_key], timeout_s=900
        )
        if valid_key_response["status"] != 200:
            raise AssertionError(
                f"valid server key rejected: {valid_key_response['body'].decode(errors='replace')}"
            )
        valid_key_json = json.loads(valid_key_response["body"])
        result["valid_server_key_install"] = {
            "status": valid_key_response["status"],
            "wall_s": valid_key_response["wall_s"],
            "idempotent": valid_key_json["idempotente"],
            "bindings_match": all(
                [
                    valid_key_json["params_id"] == PARAMS_ID,
                    valid_key_json["params_fingerprint_sha256"] == PARAMS_FINGERPRINT,
                    valid_key_json["variant_id"] == VARIANT_ID,
                    valid_key_json["circuit_sha256"] == CIRCUIT_SHA256,
                ]
            ),
        }
        if result["valid_server_key_install"]["idempotent"]:
            raise AssertionError("first valid key install unexpectedly idempotent")
        if not result["valid_server_key_install"]["bindings_match"]:
            raise AssertionError("valid server-key response binding mismatch")

        evidence.emit("enrolling 16 one-hot identities under one aligned threshold")
        enrollment_started = time.monotonic()
        enrollments: list[dict[str, Any]] = []
        for index in range(EXPECTED_N):
            name = f"id{index + 1:02d}"
            body = f"{name}\t0\n{vector_text(one_hot(index))}".encode("ascii")
            response = http_request_segments(
                port,
                "POST",
                "/iscrivi",
                [body],
                content_type="text/plain",
            )
            if response["status"] != 200:
                raise AssertionError(
                    f"enrollment {name} failed: {response['body'].decode(errors='replace')}"
                )
            payload = json.loads(response["body"])
            if payload["indice"] != index or payload["percorso_argmin"] != "a62_a50_a53_radix15":
                raise AssertionError(f"enrollment {name} selected the wrong path")
            enrollments.append(
                {
                    "name": name,
                    "index": payload["indice"],
                    "revision": payload["galleria_revision"],
                    "path": payload["percorso_argmin"],
                }
            )
        result["enrollment"] = {
            "count": len(enrollments),
            "wall_s": round(time.monotonic() - enrollment_started, 6),
            "final_revision": enrollments[-1]["revision"],
            "all_a62_aligned_path": all(
                item["path"] == "a62_a50_a53_radix15" for item in enrollments
            ),
            "fixture": "id01..id16 use distinct one-hot coordinates 0..15; threshold=0",
        }

        exact_ct_path = workdir / "probe-id16.ct"
        reject_ct_path = workdir / "probe-impostor.ct"
        evidence.emit("encrypting valid ID16 and impostor probes")
        encrypted: dict[str, dict[str, Any]] = {}
        for label, plain_path, ct_path in (
            ("id16", exact_probe_path, exact_ct_path),
            ("impostor", reject_probe_path, reject_ct_path),
        ):
            command = run_monitored(
                [str(BINARY), "encrypt", str(keydir), str(plain_path), str(ct_path)],
                timeout_s=120,
                redact=str(workdir),
            )
            reported = parse_cli_json(command, f"encrypt {label}")
            validation = validate_probe(ct_path.read_bytes())
            encrypted[label] = {
                "wall_s": command["wall_s"],
                "reported_encrypt_ms": reported["encrypt_ms"],
                "peak_rss_kib": command["peak_rss_kib"],
                "wire": validation,
            }
        result["encryption"] = encrypted

        evidence.emit("running probe wire-v2/A65-v3/wrong-binding rejects before FHE")
        valid_probe = exact_ct_path.read_bytes()
        probe_words, probe_body = unpack_ciphertext(valid_probe)
        a65_probe = make_a65_header(
            [
                A65_PROBE_MAGIC,
                3,
                1,
                probe_words[3],
                probe_words[4],
                probe_words[5],
                probe_words[6],
                probe_words[7],
            ],
            probe_body,
        )
        wire_v2_probe = pack_ciphertext(
            [
                A38_PROBE_MAGIC,
                2,
                1,
                probe_words[3],
                probe_words[4],
                probe_words[5],
                probe_words[6],
                probe_words[7],
            ],
            probe_body,
        )
        probe_cases: list[tuple[str, bytes]] = [
            ("wire_v2_probe", wire_v2_probe),
            ("a65_a44_base16_wire_v3_probe", a65_probe),
            ("wire_v4_wrong_version_probe", mutate_fixed_header(valid_probe, 1, 2)),
            ("wire_v4_wrong_params_id_probe", mutate_bound_header(valid_probe, 8, 0)),
            (
                "wire_v4_wrong_params_fingerprint_probe",
                mutate_bound_header(valid_probe, 8, 1),
            ),
            ("wire_v4_wrong_variant_probe", mutate_bound_header(valid_probe, 8, 2)),
            ("wire_v4_wrong_circuit_probe", mutate_bound_header(valid_probe, 8, 3)),
            ("wire_v4_truncated_probe_body", valid_probe[:-8]),
        ]
        probe_negative: list[dict[str, Any]] = []
        for label, artifact in probe_cases:
            response = http_request_segments(port, "POST", "/varco", [artifact])
            probe_negative.append(expect_http_reject(label, response))
        result["probe_negative_gate"] = probe_negative

        evidence.emit("executing FHE query 1/2: enrolled ID16")
        fhe_results: dict[str, dict[str, Any]] = {}
        output_blobs: dict[str, bytes] = {}
        for label, ct_path, expected in (
            ("id16", exact_ct_path, {"code": 16, "low": 1, "high": 1, "index": 15}),
            ("impostor", reject_ct_path, {"code": 0, "low": 0, "high": 0, "index": None}),
        ):
            if label == "impostor":
                evidence.emit("executing FHE query 2/2: non-enrolled impostor")
            response = http_request_segments(
                port, "POST", "/varco", [ct_path.read_bytes()], timeout_s=900
            )
            if response["status"] != 200:
                raise AssertionError(
                    f"FHE {label} failed: {response['body'].decode(errors='replace')}"
                )
            headers = response["headers"]
            expected_headers = {
                "x-varco-contract": HTTP_CONTRACT,
                "x-varco-params-id": PARAMS_ID,
                "x-varco-params-fingerprint": PARAMS_FINGERPRINT,
                "x-varco-variant-id": VARIANT_ID,
                "x-varco-circuit-sha256": CIRCUIT_SHA256,
            }
            for name, value in expected_headers.items():
                if headers.get(name) != value:
                    raise AssertionError(f"FHE {label}: HTTP header {name} mismatch")
            if int(headers["x-pbs"]) != EXPECTED_N16_COUNTS["blind_rotations"]:
                raise AssertionError(f"FHE {label}: wrong structural PBS count")
            output_path = workdir / f"output-{label}.ct"
            output_path.write_bytes(response["body"])
            wire = validate_output(response["body"])
            decrypt = run_monitored(
                [str(BINARY), "decrypt", str(keydir), str(output_path)],
                timeout_s=120,
                redact=str(workdir),
            )
            decoded = parse_cli_json(decrypt, f"decrypt {label}")
            observed = {
                "code": decoded["codice"],
                "low": decoded["low"],
                "high": decoded["high"],
                "index": decoded["indice"],
            }
            if observed != expected:
                raise AssertionError(f"FHE {label}: {observed} != {expected}")
            if decoded["codice"] != decoded["low"] + 15 * decoded["high"]:
                raise AssertionError(f"FHE {label}: radix-15 reconstruction failed")
            if decoded["variant_id"] != VARIANT_ID or decoded["circuit_sha256"] != CIRCUIT_SHA256:
                raise AssertionError(f"FHE {label}: decrypted binding mismatch")
            fhe_results[label] = {
                "pass": True,
                "expected": expected,
                "observed": observed,
                "radix15_reconstruction": f"{decoded['low']} + 15*{decoded['high']} = {decoded['codice']}",
                "http_wall_s": response["wall_s"],
                "server_reported_ms": float(headers["x-tempo-ms"]),
                "pbs": int(headers["x-pbs"]),
                "decrypt_wall_s": decrypt["wall_s"],
                "decrypt_peak_rss_kib": decrypt["peak_rss_kib"],
                "wire": wire,
                "http_bindings_match": True,
            }
            output_blobs[label] = response["body"]
        result["small_fhe_gate"] = {
            "gallery_size": EXPECTED_N,
            "structural_counts": EXPECTED_N16_COUNTS,
            "queries": fhe_results,
            "claim_limit": "functional sample only; no end-to-end p-fail bound inferred",
        }

        evidence.emit("running output legacy/base16/wrong-binding/one-LWE rejects")
        valid_output = output_blobs["id16"]
        output_words, output_body = unpack_ciphertext(valid_output)
        lwe_bytes = output_words[6] * 8
        a65_output = make_a65_header(
            [
                A65_OUTPUT_MAGIC,
                3,
                3,
                output_words[3],
                output_words[4],
                output_words[5],
                output_words[6],
                output_words[7],
                2,
            ],
            output_body,
        )
        output_cases: list[tuple[str, bytes]] = [
            ("wire_v2_output", mutate_fixed_header(valid_output, 1, 2)),
            ("a65_a44_base16_wire_v3_output", a65_output),
            ("wire_v4_digit_base_16_output", mutate_fixed_header(valid_output, 9, 16)),
            ("wire_v4_wrong_params_id_output", mutate_bound_header(valid_output, 10, 0)),
            (
                "wire_v4_wrong_params_fingerprint_output",
                mutate_bound_header(valid_output, 10, 1),
            ),
            ("wire_v4_wrong_variant_output", mutate_bound_header(valid_output, 10, 2)),
            ("wire_v4_wrong_circuit_output", mutate_bound_header(valid_output, 10, 3)),
            (
                "wire_v4_declared_one_lwe_output",
                mutate_fixed_header(pack_ciphertext(output_words, output_body[:lwe_bytes]), 8, 1),
            ),
            (
                "wire_v4_truncated_two_lwe_output",
                pack_ciphertext(output_words, output_body[:lwe_bytes]),
            ),
        ]
        output_negative: list[dict[str, Any]] = []
        for label, artifact in output_cases:
            path = workdir / f"negative-output-{len(output_negative):02d}.ct"
            path.write_bytes(artifact)
            command = run_monitored(
                [str(BINARY), "decrypt", str(keydir), str(path)],
                timeout_s=30,
                redact=str(workdir),
            )
            output_negative.append(expect_cli_reject(label, command))
        result["output_negative_gate"] = output_negative

        final_state_response = http_request_segments(port, "GET", "/stato")
        final_state = json.loads(final_state_response["body"])
        validate_contract(final_state)
        if final_state["iscritti"] != EXPECTED_N or not final_state["chiave"]:
            raise AssertionError("final server state mismatch")
        result["final_state"] = {
            "gallery_size": final_state["iscritti"],
            "revision": final_state["revision"],
            "path": final_state["percorso_argmin"],
            "contract_validated": True,
        }
        result["negative_summary"] = {
            "client_key": len(client_negative),
            "server_key": len(server_negative),
            "probe": len(probe_negative),
            "output": len(output_negative),
            "total": len(client_negative)
            + len(server_negative)
            + len(probe_negative)
            + len(output_negative),
            "all_passed": True,
        }
        result["status"] = "PASS_LOCAL_RUNTIME_NOT_DOCKER_NOT_PROMOTED"
        evidence.emit("all local A74 gates passed; stopping server and cleaning ephemeral keys")
        return_code = 0
    except Exception as error:  # evidence must survive even when the gate fails
        result["status"] = "FAIL"
        result["failure"] = f"{type(error).__name__}: {error}".replace(
            str(workdir), "<ephemeral>"
        )
        evidence.emit(f"gate failed: {result['failure']}")
        return_code = 1
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        if sampler is not None:
            sampler.stop()
            result["server_peak_rss_kib"] = sampler.peak_rss_kib
        if server_log_handle is not None:
            server_log_handle.close()
        try:
            shutil.rmtree(workdir)
            result["ephemeral_cleanup"] = {
                "performed": True,
                "workdir_exists_after_cleanup": workdir.exists(),
                "key_material_retained": False,
            }
        except OSError as cleanup_error:
            result["ephemeral_cleanup"] = {
                "performed": False,
                "workdir_exists_after_cleanup": workdir.exists(),
                "key_material_retained": workdir.exists(),
                "error": str(cleanup_error).replace(str(workdir), "<ephemeral>"),
            }
            return_code = 1
            result["status"] = "FAIL_CLEANUP"
        write_json(args.output, result)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
