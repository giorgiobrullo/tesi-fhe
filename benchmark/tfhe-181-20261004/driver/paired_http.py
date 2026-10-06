"""Bounded current-build comparison; only the root agent may execute this driver.

Adapted from the preserved September 22 paired_http.py. No compilation or key
generation. Three pairs of supplied version-bound key directories are required.
One owned local service runs at a time; server and HTTP timers remain separate.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import time

SCENES = ("einstein", "curie", "turing")
KEY_BINDINGS = ("params_id", "params_fingerprint_sha256", "variant_id", "circuit_sha256")
FAMILY_COUNT, BLOCKS, MEASURED_REPS, WARMUPS_TOTAL = 3, 4, 2, 3


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_spec(spec):
    require(spec.get("schema") == "current-build-paired-http.v1", "wrong spec schema")
    for field, value in (("family_count", FAMILY_COUNT), ("blocks", BLOCKS),
                         ("measured_reps", MEASURED_REPS), ("warmups_total", WARMUPS_TOTAL)):
        require(type(spec.get(field)) is int and spec[field] == value, "wrong schedule: " + field)
    require(type(spec.get("rayon_threads")) is int and spec["rayon_threads"] > 0, "invalid thread count")
    require(isinstance(spec.get("compiler_identity"), str) and spec["compiler_identity"], "missing compiler identity")
    require(len(spec["arms"]) == 2, "exactly two version arms required")
    names = [arm["name"] for arm in spec["arms"]]
    require(len(set(names)) == 2 and all(name.replace("-", "").replace(".", "").isalnum() for name in names),
            "unsafe or duplicate arm name")
    require(len(spec["families"]) == FAMILY_COUNT, "exactly three key-family pairs required")
    ids = [family["id"] for family in spec["families"]]
    require(len(set(ids)) == FAMILY_COUNT and all(name.replace("-", "").isalnum() for name in ids),
            "unsafe or duplicate family id")
    for family in spec["families"]:
        require(family["origin"] in ("fresh", "reused"), "key origin must be explicit")
        require(len(family["arms"]) == 2, "each family needs baseline and candidate keys")
        require(all(settings.get("keygen_receipt") for settings in family["arms"]), "key roundtrip receipt required")
    paths = [spec["output"], spec["fixtures"]]
    for arm in spec["arms"]:
        paths.extend(arm[field] for field in ("runtime", "binary", "build_receipt"))
    for family in spec["families"]:
        for arm in family["arms"]:
            paths.extend(arm[field] for field in ("keydir", "keygen_receipt"))
    require(all(Path(path).is_absolute() for path in paths), "all paths must be absolute")


def schedule():
    return [(family, block, position, role)
            for family in range(FAMILY_COUNT) for block in range(BLOCKS)
            for position, role in enumerate((0, 1) if block % 2 == 0 else (1, 0))]


def summarize(rows, names):
    require(len(rows) == 216 and sum(row["phase"] == "measured" for row in rows) == 144,
            "incomplete bounded schedule")
    identities = {(row["family"], row["block"], row["arm"], row["scene"], row["phase"], row["repetition"])
                  for row in rows}
    require(len(identities) == len(rows), "duplicate sample identity")
    families = list(dict.fromkeys(row["family"] for row in rows))
    require(len(families) == FAMILY_COUNT, "incomplete key-family coverage")
    expected = {(family, block, name, scene, phase, repetition)
                for family in families for block in range(BLOCKS) for name in names for scene in SCENES
                for phase, repetitions in (("warmup", 1), ("measured", MEASURED_REPS))
                for repetition in range(repetitions)}
    require(identities == expected and all(row.get("correct") is True for row in rows),
            "incomplete or unvalidated request coverage")
    result = {}
    for scene in SCENES:
        family_results = []
        for family in families:
            arms = {}
            for name in names:
                server, wall = [], []
                for block in range(BLOCKS):
                    selected = [row for row in rows if row["family"] == family and row["block"] == block
                                and row["arm"] == name and row["scene"] == scene and row["phase"] == "measured"]
                    require(sorted(row["repetition"] for row in selected) == list(range(MEASURED_REPS)),
                            "missing measured repetition")
                    require(all(row.get("correct") is True for row in selected), "unvalidated measured result")
                    require(all(math.isfinite(row["elapsed_ms"]) and row["elapsed_ms"] > 0
                                and row["http_elapsed_ns"] > 0 for row in selected), "invalid measured timer")
                    server.append(statistics.median(row["elapsed_ms"] for row in selected))
                    wall.append(statistics.median(row["http_elapsed_ns"] / 1e6 for row in selected))
                arms[name] = {"block_server_median_ms": server, "block_http_median_ms": wall,
                              "median_server_ms": statistics.median(server), "median_http_ms": statistics.median(wall)}
            ratios = [arms[names[1]]["block_server_median_ms"][i] / arms[names[0]]["block_server_median_ms"][i]
                      for i in range(BLOCKS)]
            family_results.append({"family": family, "arms": arms, "candidate_over_baseline_block_ratios": ratios,
                                   "median_block_ratio": statistics.median(ratios)})
        result[scene] = {"families": family_results,
                         "median_family_ratio": statistics.median(item["median_block_ratio"] for item in family_results)}
    return {"scenes": result, "measured_calls": 144, "warmup_calls": 72, "owned_service_processes": 24,
            "blocks_per_family": BLOCKS, "key_family_pairs": FAMILY_COUNT, "fixed_scene_vectors": 3,
            "same_ciphertext_reused_within_version_family": True,
            "estimand": "Per scene and family: median of two requests per arm/block, candidate/baseline ratio per block, median of four block ratios; then median of three family ratios.",
            "limits": "One host and three fixed scenes. Keys are generated separately for the versions, not identical paired keys. Blocks, scenes and repetitions are not independent key families; reused keys are not fresh draws. No confidence interval, biometric accuracy, rare-error bound, full-pipeline or click-to-result claim."}


def sha(path, offset=0):
    with Path(path).open("rb") as stream:
        stream.seek(offset)
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def oracle(entries, query):
    require(len(query) == 512 and all(type(x) is int and -3 <= x <= 3 for x in query),
            "query coordinates outside head51")
    require(sum(x * x for x in query) <= 1024, "query norm outside head51")
    require(bool(entries), "empty gallery")
    scores = []
    for entry in entries:
        vector = entry["vettore"]
        require(len(vector) == 512 and all(type(x) is int and -3 <= x <= 3 for x in vector),
                "invalid template")
        require(type(entry["soglia"]) is int, "invalid threshold")
        scores.append(sum(x * x - 2 * x * y for x, y in zip(vector, query)))
    winner = min(range(len(scores)), key=scores.__getitem__)
    selected = winner + 1 if scores[winner] <= entries[winner]["soglia"] else 0
    return {"selected_id": selected, "winner_id": winner + 1,
            "scores": scores, "winner_score": scores[winner],
            "winner_threshold": entries[winner]["soglia"],
            "tied_minimum_ids": [i + 1 for i, score in enumerate(scores) if score == scores[winner]]}


def key_envelope(path, expected, magic):
    with path.open("rb") as stream:
        fixed = stream.read(56)
        require(len(fixed) == 56, "key envelope truncated")
        words = struct.unpack("<7Q", fixed)
        require(words[:2] == (int.from_bytes(magic, "little"), expected["wire_version"]),
                "key magic/wire mismatch")
        lengths = words[2:6]
        require(all(0 < length < 1024 for length in lengths), "key binding length invalid")
        require(56 + sum(lengths) + words[6] == path.stat().st_size, "key size mismatch")
        values = [stream.read(length).decode("ascii") for length in lengths]
        require(values == [expected[name] for name in KEY_BINDINGS], "key binding differs from runtime")
    return {"sha256": sha(path), "payload_sha256": sha(path, 56 + sum(lengths)),
            "bytes": path.stat().st_size, "payload_bytes": words[6]}


def payload_sha(data):
    require(len(data) >= 8 and len(data) % 8 == 0, "malformed wire output")
    header_words, = struct.unpack_from("<Q", data)
    start = (1 + header_words) * 8
    require(len(data) - start == 3 * 2049 * 8, "output is not three LWE payloads")
    return hashlib.sha256(data[start:]).hexdigest()


def parameter_metadata(runtime, config):
    source = (runtime / "core/src/private_argmin/contracts.rs").read_text()
    matches = re.findall(r'pub const A44_PARAMETER_CANONICAL: &str = "([^"\\]+)";', source)
    require(len(matches) == 1, "missing or ambiguous canonical parameter string")
    canonical = matches[0]
    require(hashlib.sha256(canonical.encode()).hexdigest() == config["params_fingerprint_sha256"],
            "canonical parameter fingerprint differs")
    fields = dict(field.split("=", 1) for field in canonical.split(";"))
    version = fields.pop("tfhe-rs")
    return {"tfhe_rs": version, "numerical_and_algorithm_parameters": fields,
            "canonical": canonical}


def inventory(runtime):
    result = {}
    for path in sorted(runtime.rglob("*")):
        relative = path.relative_to(runtime)
        if any(part in {"target", "__pycache__", ".git"} for part in relative.parts):
            continue
        require(not path.is_symlink(), "runtime snapshot contains symlink: " + str(relative))
        if path.is_file():
            result[str(relative)] = sha(path)
    return result


def load_protocol(runtime, index):
    package = f"migration_pilot_client_{index}"
    spec = importlib.util.spec_from_file_location(package, runtime / "client/__init__.py",
                                                 submodule_search_locations=[str(runtime / "client")])
    module = importlib.util.module_from_spec(spec)
    sys.modules[package] = module
    spec.loader.exec_module(module)
    sub = importlib.util.spec_from_file_location(package + ".protocol", runtime / "client/protocol.py")
    protocol = importlib.util.module_from_spec(sub)
    sys.modules[sub.name] = protocol
    sub.loader.exec_module(protocol)
    return protocol


class Pilot:
    def __init__(self, spec_path):
        self.spec_path = spec_path.resolve(strict=True)
        self.spec = json.loads(self.spec_path.read_text())
        validate_spec(self.spec)
        self.env = dict(os.environ, RAYON_NUM_THREADS=str(self.spec["rayon_threads"]), PYTHONDONTWRITEBYTECODE="1")
        self.output = Path(self.spec["output"]).resolve()
        self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.rows = []
        self.arms = []
        self.fixtures = Path(self.spec["fixtures"]).resolve(strict=True)
        self.input_pins = {}
        self.process = None
        self.logs = []
        self.active_directory = None
        self.reference_plan = None
        self.last_http_elapsed_ns = None
        for name in ("events.jsonl", "samples.jsonl"):
            (self.output / name).open("x", encoding="utf-8").close()

    def event(self, value):
        with (self.output / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value) + "\n")
        print(json.dumps(value), flush=True)

    def pin(self, path):
        path = path.resolve(strict=True)
        self.input_pins[str(path)] = sha(path)

    def prepare(self):
        self.pin(self.spec_path)
        manifest_path = self.fixtures / "MANIFEST.json"
        self.pin(manifest_path)
        manifest = json.loads(manifest_path.read_text())
        require(manifest["schema"] == "web-thread-scaling-fixtures.v1", "wrong fixture provenance")
        for name, pin in manifest["artifacts"].items():
            path = (self.fixtures / name).resolve(strict=True)
            require(path.is_relative_to(self.fixtures), "fixture path escapes directory")
            require(sha(path) == pin["sha256"] and path.stat().st_size == pin["bytes"],
                    "frozen fixture changed: " + name)
            self.pin(path)
        self.entries = json.loads((self.fixtures / "gallery.json").read_text())["entries"]
        require(len(self.entries) == 120, "pilot requires the fixed N120 gallery")
        require(len({entry["id"] for entry in self.entries}) == 120, "duplicate gallery id")
        bounds = []
        for entry in self.entries:
            norm = sum(x*x for x in entry["vettore"])
            radius = math.isqrt(1024 * norm)
            radius += radius * radius != 1024 * norm
            bounds.append((norm - 2 * radius, norm + 2 * radius))
        require(max(high for _, high in bounds) - min(low for low, _ in bounds) + 1 <= 4096,
                "gallery exceeds the Cauchy admission domain")
        self.probes = {}
        for name in SCENES:
            source = json.loads((self.fixtures / "probes" / (name + ".json")).read_text())
            actual = oracle(self.entries, source["query"])
            require(all(source["expected"][field] == value for field, value in actual.items()),
                    "independent plaintext oracle differs: " + name)
            self.probes[name] = {"query": source["query"], "oracle": actual}
        builds = []
        for settings in self.spec["arms"]:
            receipt_path = Path(settings["build_receipt"]).resolve(strict=True)
            self.pin(receipt_path)
            receipt = json.loads(receipt_path.read_text())
            require(receipt["compiler_identity"] == self.spec["compiler_identity"], "compiler identity differs")
            require(receipt["binary_sha256"] == sha(settings["binary"]), "build receipt binary differs")
            require(isinstance(receipt["build_settings"], dict) and receipt["build_settings"], "missing build settings")
            builds.append(receipt)
        require(builds[0]["build_settings"] == builds[1]["build_settings"], "build settings differ")
        for family_index, family in enumerate(self.spec["families"]):
            for role, key_settings in enumerate(family["arms"]):
                require(set(key_settings) == {"keydir", "keygen_receipt"}, "unexpected key-pair settings")
                settings = dict(self.spec["arms"][role], **key_settings)
                runtime = Path(settings["runtime"]).resolve(strict=True)
                binary = Path(settings["binary"]).resolve(strict=True)
                keys = Path(settings["keydir"]).resolve(strict=True)
                require(not self.output.is_relative_to(runtime) and not self.output.is_relative_to(keys),
                        "output must be outside runtime and key directories")
                config = json.loads((runtime / "config.json").read_text())["contratto_esatto"]
                require(sha(runtime / "CIRCUIT_CONTRACT.json") == config["circuit_sha256"], "circuit/config binding mismatch")
                require(config["runtime_mode"] == "public_parallel" and not config["g4_required"],
                        "expected selected public_parallel without G4")
                source_pins = inventory(runtime)
                for path in (binary, keys / "client.key", keys / "server.key"):
                    self.pin(path)
                receipt_path = Path(settings["keygen_receipt"]).resolve(strict=True)
                self.pin(receipt_path)
                receipt = json.loads(receipt_path.read_text())
                require(receipt.get("bundle_roundtrip_equal") is True and receipt.get("bundle_validation_pass") is True,
                        "keygen receipt does not report validated bundle roundtrip")
                require(receipt["server_envelope_sha256"] == sha(keys / "server.key"), "keygen receipt hash mismatch")
                require(all(receipt[field] == config[field] for field in KEY_BINDINGS), "keygen receipt binding mismatch")
                key_info = {name: key_envelope(keys / (name + ".key"), config, magic)
                            for name, magic in (("client", b"VRCCK17!"), ("server", b"VRCHD17!"))}
                parameters = parameter_metadata(runtime, config)
                require(parameters["tfhe_rs"] == ("1.7.0", "1.8.1")[role], "wrong TFHE version/order")
                arm = {"name": settings["name"], "family": family["id"], "family_index": family_index,
                       "role": role, "key_origin": family["origin"], "runtime": runtime, "binary": binary, "keys": keys,
                       "config": config, "source_pins": source_pins, "key_info": key_info, "parameters": parameters,
                       "binary_sha256": sha(binary), "protocol": load_protocol(runtime, len(self.arms)), "ciphertexts": {}}
                self.arms.append(arm)
        base = self.arms[0]
        contracts = [json.loads((arm["runtime"] / "CIRCUIT_CONTRACT.json").read_text()) for arm in self.arms]
        for index, arm in enumerate(self.arms):
            require(base["parameters"]["numerical_and_algorithm_parameters"] == arm["parameters"]["numerical_and_algorithm_parameters"],
                    "numerical/algorithm parameters differ")
            for field in ("query", "output", "selector_repair", "core_id_contract", "gallery"):
                require(contracts[0][field] == contracts[index][field], "circuit semantics differ: " + field)
            same_role = self.arms[arm["role"]]
            require(arm["source_pins"] == same_role["source_pins"] and arm["binary_sha256"] == same_role["binary_sha256"],
                    "runtime/build changed between key families")
        require(self.arms[0]["config"]["circuit_sha256"] != self.arms[1]["config"]["circuit_sha256"], "version-bound circuit identities coincide")
        require(self.arms[0]["config"]["params_fingerprint_sha256"] != self.arms[1]["config"]["params_fingerprint_sha256"],
                "version-bound parameter fingerprints coincide")
        for kind in ("client", "server"):
            require(len({arm["key_info"][kind]["payload_sha256"] for arm in self.arms}) == 6, "reused key payload across family arms")
        save(self.output / "PREPARED.json", {
            "schema": "current-build-paired-http-preflight.v1", "spec": self.spec,
            "driver_sha256": sha(Path(__file__)), "input_pins": self.input_pins,
            "host": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
            "arms": [{k: (str(v) if isinstance(v, Path) else v) for k, v in arm.items()
                      if k not in {"protocol", "ciphertexts"}} for arm in self.arms],
            "probes": self.probes, "schedule": schedule(), "build_receipts": builds,
            "key_origin_note": "Distinct payload hashes and supplied roundtrip receipts checked. Origin is recorded per family; reused families are not fresh independent repetitions.",
            "calls": {"warmup": 72, "measured": 144}, "owned_service_processes": 24,
            "timer": "X-Tempo-Ms: service evaluation::varco, rounded to 0.1 ms; HTTP wall time separately recorded",
            "scope": "Same fixed N120 gallery, scenes, numerical parameters, compiler/build settings, thread count and host; different version-bound keys and encryption randomness. No identical paired-key, confidence-bound or click-to-result claim."})
        for index, arm in enumerate(self.arms):
            folder = self.output / f"inputs-{index}"
            folder.mkdir()
            for name, probe in self.probes.items():
                plain = folder / (name + ".txt")
                with plain.open("x", encoding="utf-8") as stream:
                    stream.write(" ".join(map(str, probe["query"])) + "\n")
                ciphertext = folder / (name + ".probe.ct")
                require(not ciphertext.exists(), "ciphertext path already exists")
                result = self.cli(arm, folder, name + "-encrypt", ["encrypt", arm["keys"], plain, ciphertext, "head51"])
                require(result["query_profile"] == "head51", "encryption profile differs")
                arm["ciphertexts"][name] = ciphertext
                self.pin(ciphertext)

    def cli(self, arm, folder, label, arguments):
        command = [str(arm["binary"]), *map(str, arguments)]
        with (folder / (label + ".stdout")).open("xb") as stdout, (folder / (label + ".stderr")).open("xb") as stderr:
            result = subprocess.run(command, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=120)
        save(folder / (label + ".command.json"), {"command": command, "exit_code": result.returncode})
        require(result.returncode == 0, "native command failed: " + label)
        value = arm["protocol"].strict_json((folder / (label + ".stdout")).read_bytes())
        require(all(value.get(field) == arm["config"][field] for field in KEY_BINDINGS),
                "native CLI identity differs: " + label)
        return value

    def request(self, label, method, route, body=b"", content_type="application/octet-stream"):
        require(self.process is not None and self.process.poll() is None, "owned service exited")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=180)
        if isinstance(body, Path):
            source = body.open("rb")
            size = body.stat().st_size
            request_hash = sha(body)
        else:
            source, size = body, len(body)
            request_hash = hashlib.sha256(body).hexdigest()
        started = time.perf_counter_ns()
        try:
            connection.request(method, route, body=source,
                               headers={"Content-Length": str(size), "Content-Type": content_type})
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            headers = dict(response.getheaders())
            status = response.status
        finally:
            connection.close()
            if isinstance(body, Path):
                source.close()
        elapsed = time.perf_counter_ns() - started
        self.last_http_elapsed_ns = elapsed
        target = self.active_directory / (label + ".response.bin")
        with target.open("xb") as stream:
            stream.write(data)
        save(self.active_directory / (label + ".http.json"), {
            "method": method, "route": route, "request_sha256": request_hash, "request_bytes": size,
            "status": status, "headers": headers, "http_elapsed_ns": elapsed,
            "response_file": target.name, "response_sha256": sha(target), "response_bytes": len(data)})
        require(status == 200 and len(data) <= 1024 * 1024, "HTTP request failed: " + label)
        return data, headers, target

    def stop(self):
        process = self.process
        try:
            if process is not None:
                unexpected = process.poll() is not None
                if not unexpected:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                self.event({"event": "owned_service_stopped", "pid": process.pid,
                            "exit_code": process.returncode, "unexpected_prior_exit": unexpected})
                require(not unexpected, "owned service exited before cleanup")
        finally:
            if process is not None and process.poll() is not None:
                self.process = None
            for stream in self.logs:
                stream.close()
            self.logs = []

    def run_arm(self, family, block, position, role):
        arm = self.arms[family * 2 + role]
        folder = self.output / f"family-{family}-block-{block}-position-{position}-{arm['name']}"
        folder.mkdir()
        self.active_directory = folder
        entries, probes, ciphertexts = self.entries, self.probes, arm["ciphertexts"]
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.logs = [(folder / ("service." + name)).open("xb") for name in ("stdout", "stderr")]
        command = [str(arm["binary"]), "serve", str(self.port), "512", "273"]
        try:
            self.process = subprocess.Popen(command, env=self.env, stdin=subprocess.DEVNULL,
                                            stdout=self.logs[0], stderr=self.logs[1])
        except BaseException:
            self.stop()
            raise
        self.event({"event": "owned_service_started", "pid": self.process.pid,
                    "family": arm["family"], "block": block, "position": position, "arm": arm["name"], "command": command})
        pending = []
        try:
            deadline = time.monotonic() + 60
            ready = f"in ascolto su 127.0.0.1:{self.port}".encode()
            while ready not in (folder / "service.stdout").read_bytes():
                require(self.process.poll() is None, "owned service failed to start")
                require(time.monotonic() < deadline, "owned service startup timed out")
                time.sleep(.05)
            protocol, expected = arm["protocol"], arm["config"]
            data, _, _ = self.request("initial", "GET", "/stato")
            initial = protocol.strict_json(data)
            protocol.validate_status(initial, expected, allow_empty=True)
            require(initial["iscritti"] == 0 and not initial["chiave"], "new service is not empty")
            data, _, _ = self.request("install-key", "POST", "/chiave", arm["keys"] / "server.key")
            installed = protocol.strict_json(data)
            require(installed.get("ok") is True and installed.get("idempotente") is False, "key installation failed")
            require(installed["chiave_sha256"] == arm["key_info"]["server"]["sha256"], "installed key differs")
            for number, entry in enumerate(entries):
                require("\n" not in entry["id"] and "\t" not in entry["id"], "unsafe gallery name")
                body = (entry["id"] + "\t" + str(entry["soglia"]) + "\n" + " ".join(map(str, entry["vettore"])) + "\n").encode()
                data, _, _ = self.request(f"enroll-{number:03}", "POST", "/iscrivi", body, "text/plain; charset=utf-8")
                enrolled = protocol.strict_json(data)
                require(enrolled.get("ok") is True and enrolled["indice"] == number and enrolled["iscritti"] == number + 1,
                        "gallery enrollment differs")
            data, _, _ = self.request("ready-status", "GET", "/stato")
            state = protocol.strict_json(data)
            snapshot = protocol.validate_status(state, expected)
            require(state["nomi"] == [entry["id"] for entry in entries] and
                    state["soglie"] == [entry["soglia"] for entry in entries], "enrolled gallery differs")
            require(state["chiave_sha256"] == arm["key_info"]["server"]["sha256"], "status key differs")
            plan = {name: state[name] for name in ("conteggi", "execution_mode", "dominio", "dominio_esecuzione", "aligned_fast_path")}
            if self.reference_plan is None:
                self.reference_plan = plan
            require(plan == self.reference_plan, "public plan/counts differ between versions, families or blocks")
            scenes = SCENES if block % 2 == 0 else SCENES[::-1]
            for phase, repetitions in (("warmup", 1), ("measured", MEASURED_REPS)):
                for repetition in range(repetitions):
                    for scene in scenes:
                        label = f"{phase}-{repetition}-{scene}"
                        started = time.time_ns()
                        data, headers, output = self.request(label, "POST", "/varco", ciphertexts[scene])
                        http_elapsed_ns = self.last_http_elapsed_ns
                        normalized = protocol.validate_headers(headers, expected, snapshot)
                        require(normalized.get("content-type") == "application/octet-stream", "output content type differs")
                        milliseconds = float(normalized["x-tempo-ms"])
                        require(math.isfinite(milliseconds) and milliseconds > 0, "invalid server elapsed time")
                        pending.append({"family": arm["family"], "key_origin": arm["key_origin"],
                                        "block": block, "position": position, "arm": arm["name"], "scene": scene,
                                        "phase": phase, "repetition": repetition, "started_unix_ns": started,
                                        "elapsed_ms": milliseconds, "http_elapsed_ns": http_elapsed_ns,
                                        "output": str(output), "output_sha256": sha(output), "payload_sha256": payload_sha(data),
                                        "input_sha256": sha(ciphertexts[scene]), "counts": state["conteggi"],
                                        "server_key_sha256": state["chiave_sha256"], "binary_sha256": arm["binary_sha256"],
                                        "circuit_sha256": expected["circuit_sha256"]})
            data, _, _ = self.request("after-status", "GET", "/stato")
            require(protocol.validate_status(protocol.strict_json(data), expected) == snapshot,
                    "gallery changed during measured block")
        finally:
            self.stop()
        # Keep client initialization/decryption outside the service's timed runs.
        for row in pending:
            result = self.cli(arm, folder, f"{row['phase']}-{row['repetition']}-{row['scene']}-decrypt",
                              ["decrypt", arm["keys"], row["output"]])
            protocol.decode_identity(result, snapshot, expected)
            wanted = probes[row["scene"]]["oracle"]["selected_id"]
            require(result["codice"] == wanted, "FHE output differs from independent clear oracle")
            row.update(selected_id=result["codice"], expected_id=wanted,
                       digits=[result[name] for name in ("low", "middle", "high")], correct=True)
            self.rows.append(row)
            with (self.output / "samples.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row) + "\n")
        self.event({"event": "block_arm_validated", "family": arm["family"], "block": block, "arm": arm["name"], "calls": len(pending)})

    def run(self):
        faults, summary = [], None
        try:
            self.prepare()
            for family, block, position, role in schedule():
                self.run_arm(family, block, position, role)
            summary = summarize(self.rows, [arm["name"] for arm in self.spec["arms"]])
        except KeyboardInterrupt:
            faults.append("KeyboardInterrupt: measurement interrupted")
        except Exception as error:
            faults.append(f"{type(error).__name__}: {error}")
        finally:
            try:
                self.stop()
            except Exception as error:
                faults.append("cleanup: " + str(error))
            for path, pin in self.input_pins.items():
                try:
                    if not Path(path).is_file() or sha(path) != pin:
                        faults.append("input changed: " + path)
                except Exception as error:
                    faults.append(f"input check: {path}: {error}")
            for arm in self.arms:
                try:
                    if inventory(arm["runtime"]) != arm["source_pins"]:
                        faults.append("runtime sources changed: " + arm["name"])
                except Exception as error:
                    faults.append(f"runtime check: {arm['name']}: {error}")
            receipt = {"schema": "current-build-paired-http-complete.v1", "passed": not faults and summary is not None,
                       "faults": faults, "summary": summary, "completed_unix_ns": time.time_ns(),
                       "artifacts": {str(path.relative_to(self.output)): sha(path)
                                     for path in sorted(self.output.rglob("*")) if path.is_file()}}
            save(self.output / "COMPLETE.json", receipt)
            print(json.dumps({"passed": receipt["passed"], "faults": faults, "receipt": str(self.output / "COMPLETE.json")}), flush=True)
        return 0 if receipt["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    sys.dont_write_bytecode = True
    return Pilot(args.spec).run()


if __name__ == "__main__":
    raise SystemExit(main())
