"""Transport tests with simulated cryptography; no models or FHE required."""

import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from client import protocol
from client.configuration import ClientConfiguration
from client.pipeline import AccessPipeline
EXPECTED = json.loads((ROOT / "config.json").read_text())["contratto_esatto"]


def status(size=225, mode="uniform_sentinel", aligned=False):
    state = {"iscritti": size, "epoch": 11, "revision": 29, "dim": 512,
             "nomi": ["entry_" + str(i) for i in range(size)], "chiave": True,
             "chiave_sha256": "a" * 64, "soglia_default": 4,
             "contratto_esatto": copy.deepcopy(EXPECTED), "aligned_fast_path": aligned,
             "endpoint_domain_supported": bool(size)}
    state.update(g4_sha256="b" * 64 if EXPECTED["g4_required"] else None, g4_ready=True,
                 runtime_optimization={"mode":EXPECTED["runtime_mode"],"service_source_sha256":EXPECTED["service_source_sha256"],
                 "core_source_sha256":EXPECTED["core_source_sha256"],"rayon_threads":16,
                 "fft_plan_policy":"user-provided-dif4-polynomial2048-base1024-v1",
                 "compiler_profile":"opt3-cgu1-no-lto-generic-no-pgo","runtime_features":[],
                 "query_admission":"one_synchronous_query_per_process","shared_normalizers":"both",
                 "classic_comparators":"parallel3_cutoff4","id_cuts":"both","public_thresholds":True,
                 "public_digits":"repack","selector_parallel":True,"g4":EXPECTED["g4_required"],
                 "detector_only_alignment":True})
    if not size:
        state["soglie"] = []
        for name in ("dominio", "dominio_esecuzione", "percorso_argmin", "endpoint_fhe",
                     "execution_mode", "soglia_uniforme", "sentinel_score", "conteggi"):
            state[name] = None
        state["contratto_esatto"].update(query_profile=None, query_profile_id=0, score_delta_log=0)
        return state
    bounds = {"l": -900, "u": 2100, "larghezza": 3001}
    execution = {"l": -1019, "u": 2100, "larghezza": 3120} if aligned else dict(bounds)
    threshold = {"uniform_sentinel": 4, "uniform_all_reject": -(1 << 63),
                 "uniform_all_accept": (1 << 63) - 1, "mixed_winner_threshold": None}[mode]
    mixed = mode == "mixed_winner_threshold"
    state.update(soglie=([4] * (size - 1) + [273]) if mixed else [threshold] * size,
                 dominio=bounds, dominio_esecuzione=execution,
                 percorso_argmin="fast_mixed_winner_threshold" if mixed else "fast_uniform",
                 endpoint_fhe="head_mean_mixed_parallel" if mixed else "head_mean_uniform_parallel",
                 execution_mode=mode, soglia_uniforme=threshold,
                 sentinel_score=(threshold - execution["l"] + 1) if mode == "uniform_sentinel" else None,
                 conteggi=None)
    state["conteggi"] = protocol.composite_counts(protocol.operation_counts(size, mode), size, mode, state["soglie"], execution)
    return state


def decoded(code, size=225):
    return {"autorizzato": code != 0, "indice": code - 1 if code else None,
            "iscritti": size, "galleria_epoch": 11, "galleria_revision": 29,
            "codice": code, "low": code % 15, "middle": (code // 15) % 15, "high": code // 225,
            "query_profile": "head51", "query_profile_id": 2,
            **{name: EXPECTED[name] for name in protocol.IDENTITIES}}


def headers(state):
    return {"X-Varco-Contract": EXPECTED["http_contract"], "X-Varco-Params-Id": EXPECTED["params_id"],
            "X-Varco-Params-Fingerprint": EXPECTED["params_fingerprint_sha256"],
            "X-Varco-Variant-Id": EXPECTED["variant_id"], "X-Varco-Circuit-Sha256": EXPECTED["circuit_sha256"],
            "X-Varco-Query-Profile": "head51", "X-Tempo-Ms": "0.0",
            **{"X-" + header: str(state["conteggi"][name]) for header, name in
               (("Pbs", "br"), ("Ks", "ks"), ("Pfks", "pfks"), ("Marginals", "marginals"), ("Initial-Samples", "initial_samples"))}}


class PublicProtocolTests(unittest.TestCase):
    def test_admitted_sizes_modes_and_exact_count_anchors(self):
        for size in (1, 127, 128, 224, 225, 3374):
            for mode in ("uniform_sentinel", "uniform_all_accept", "uniform_all_reject", "mixed_winner_threshold"):
                if size == 1 and mode == "mixed_winner_threshold":
                    continue
                with self.subTest(size=size, mode=mode):
                    value = status(size, mode)
                    snap = protocol.validate_status(value, EXPECTED)
                    protocol.validate_headers(headers(value), EXPECTED, snap)
        self.assertEqual(protocol.operation_counts(1, "uniform_all_accept"),
                         dict(br=6, ks=4, marginals=6, pfks=0, initial_samples=1))
        self.assertEqual(protocol.operation_counts(3374, "mixed_winner_threshold"),
                         dict(br=43861, ks=30366, marginals=64103, pfks=30363, initial_samples=3374))
        self.assertEqual(set(protocol.operation_counts(1, "uniform_all_reject").values()), {0})

    def test_empty_status_allowed_only_for_setup(self):
        value = status(0)
        self.assertEqual(protocol.validate_status(value, EXPECTED, allow_empty=True)["iscritti"], 0)
        with self.assertRaises(RuntimeError):
            protocol.validate_status(value, EXPECTED)
        value["execution_mode"] = "uniform_all_reject"
        with self.assertRaises(RuntimeError):
            protocol.validate_status(value, EXPECTED, allow_empty=True)

    def test_three_digits_at_boundaries(self):
        for size, code in ((1, 0), (1, 1), (224, 224), (225, 225), (3374, 3374)):
            with self.subTest(size=size, code=code):
                snap = protocol.validate_status(status(size), EXPECTED)
                self.assertEqual(protocol.decode_identity(decoded(code, size), snap, EXPECTED),
                                 "entry_" + str(code - 1) if code else None)

    def test_missing_or_invalid_digit_rejected(self):
        snap = protocol.validate_status(status(), EXPECTED)
        for name in ("low", "middle", "high"):
            for value in (None, True, 1.0, -1, 15):
                with self.subTest(name=name, value=value):
                    result = decoded(225)
                    result[name] = value
                    with self.assertRaises(RuntimeError):
                        protocol.decode_identity(result, snap, EXPECTED)
        result = decoded(224)
        del result["middle"]
        with self.assertRaises(RuntimeError):
            protocol.decode_identity(result, snap, EXPECTED)

    def test_wrong_version_identity_or_code_rejected(self):
        snap = protocol.validate_status(status(), EXPECTED)
        mutations = [(name, "different") for name in protocol.IDENTITIES]
        mutations += [("query_profile", "legacy52"), ("query_profile_id", 1), ("query_profile_id", True),
                      ("galleria_epoch", 12), ("galleria_revision", 30), ("iscritti", 226),
                      ("codice", 226), ("codice", True), ("indice", 1), ("autorizzato", 1), ("high", 0)]
        for name, value in mutations:
            with self.subTest(name=name, value=value):
                result = decoded(225)
                result[name] = value
                with self.assertRaises(RuntimeError):
                    protocol.decode_identity(result, snap, EXPECTED)
        result = decoded(0)
        result["indice"] = 0
        with self.assertRaises(RuntimeError):
            protocol.decode_identity(result, snap, EXPECTED)

    def test_old_or_mixed_contract_rejected(self):
        for name, value in (("wire_version", 7), ("wire_version", 2), ("output_lwes", 2),
                            ("output_mode", 4), ("digit_base", 16), ("digit_delta_log", 58),
                            ("score_delta_log", 52), ("query_profile", "legacy52"),
                            ("query_profile_id", True), ("cauchy_coverage_required", 1),
                            ("max_gallery_size", 224), ("circuit_sha256", "0" * 64)):
            with self.subTest(name=name):
                value_state = status()
                value_state["contratto_esatto"][name] = value
                with self.assertRaises(RuntimeError):
                    protocol.validate_status(value_state, EXPECTED)

    def test_plan_negative_controls(self):
        mutations = [("iscritti", True), ("iscritti", 3375), ("epoch", -1),
                     ("endpoint_domain_supported", 1), ("aligned_fast_path", 1),
                     ("execution_mode", "a126"), ("endpoint_fhe", "a126"),
                     ("soglia_uniforme", 273), ("sentinel_score", 1024),
                     ("nomi", ["short"]), ("soglie", [4]), ("chiave_sha256", "A" * 64)]
        for name, value in mutations:
            with self.subTest(name=name):
                result = status()
                result[name] = value
                with self.assertRaises(RuntimeError):
                    protocol.validate_status(result, EXPECTED)
        for path, value in ((('dominio', 'larghezza'), True), (('dominio', 'u'), 9999),
                            (('conteggi', 'br'), True), (('conteggi', 'initial_samples'), 0)):
            result = status()
            result[path[0]][path[1]] = value
            with self.assertRaises(RuntimeError):
                protocol.validate_status(result, EXPECTED)

    def test_mixed_and_aligned_relationships(self):
        protocol.validate_status(status(128, aligned=True), EXPECTED)
        value = status(128, "mixed_winner_threshold")
        protocol.validate_status(value, EXPECTED)
        for name, wrong in (("soglia_uniforme", 4), ("aligned_fast_path", True),
                            ("sentinel_score", 1), ("soglie", [4] * 128)):
            altered = copy.deepcopy(value)
            altered[name] = wrong
            with self.assertRaises(RuntimeError):
                protocol.validate_status(altered, EXPECTED)

    def test_headers_are_case_insensitive_but_exact(self):
        value = status(1, "uniform_all_reject")
        snap = protocol.validate_status(value, EXPECTED)
        good = headers(value)
        protocol.validate_headers({k.lower(): v for k, v in good.items()}, EXPECTED, snap)
        for name in good:
            altered = dict(good)
            del altered[name]
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                protocol.validate_headers(altered, EXPECTED, snap)
        for name, wrong in (("X-Pbs", "1"), ("X-Ks", "0.0"), ("X-Tempo-Ms", "nan"),
                            ("X-Tempo-Ms", "-1"), ("X-Varco-Query-Profile", "legacy52")):
            altered = dict(good)
            altered[name] = wrong
            with self.assertRaises(RuntimeError):
                protocol.validate_headers(altered, EXPECTED, snap)

    def test_strict_json_duplicates_and_nonfinite(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', b'"\xff"'):
            with self.assertRaises(RuntimeError):
                protocol.strict_json(raw)


class ApplicationTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.keys = pathlib.Path(self.temporary.name) / "keys"
        self.keys.mkdir()
        for name in ("client.key", "server.key"):
            (self.keys / name).write_bytes(b"fake-test-key")
        self.runner = mock.Mock(side_effect=AssertionError("native execution forbidden in fake tests"))
        self.transport = mock.Mock(side_effect=AssertionError("network forbidden in fake tests"))
        settings = ClientConfiguration(ROOT, pathlib.Path("/fake-binary"), self.keys)
        self.pipeline = AccessPipeline(settings, self.transport, self.runner)
        self.pipeline.fingerprint_chiave_locale = lambda: "a" * 64
        self.pipeline.fingerprint_g4_locale = lambda: "b" * 64

    def verify(self, value=None, output=None, response_headers=None):
        value = status() if value is None else value
        output = decoded(225) if output is None else output
        response_headers = headers(value) if response_headers is None else response_headers
        events = []
        self.events = events

        def request(path, data=None, *args, **kwargs):
            events.append(path)
            if path == "/stato":
                return json.dumps(value).encode(), {}
            if path == "/varco":
                self.assertEqual(data, b"fake-query")
                return b"fake-three-root-output", response_headers
            raise AssertionError("unexpected request: " + path)

        def encrypt(vector, profile):
            events.append("encrypt")
            self.assertEqual(profile, "head51")
            return b"fake-query", {}

        def decrypt(raw):
            events.append("decrypt")
            self.assertEqual(raw, b"fake-three-root-output")
            return output

        self.pipeline.srv = request
        self.pipeline.cifra = encrypt
        self.pipeline.decifra = decrypt
        return self.pipeline.verify_vector([0] * 512)

    def test_actual_scheduler_snapshots_before_encryption_and_decodes_three_digits(self):
        result = self.verify()
        self.assertEqual(self.events, ["/stato", "/stato", "encrypt", "/varco", "decrypt"])
        self.assertEqual(result.identity, "entry_224")
        self.assertEqual(result.snapshot["conteggi"], status()["conteggi"])

    def test_zero_count_rejection_is_a_valid_api_result(self):
        result = self.verify(status(1, "uniform_all_reject"), decoded(0, 1))
        self.assertEqual((result.decoded["autorizzato"], result.identity, int(result.headers["x-pbs"])), (False, None, 0))

    def test_stale_ciphertext_never_releases_a_name(self):
        result = decoded(225)
        result["galleria_revision"] += 1
        with self.assertRaises(RuntimeError):
            self.verify(output=result)
        self.assertEqual(self.events[-1], "decrypt")

    def test_wrong_http_counts_reject_before_decryption(self):
        altered = headers(status())
        altered["X-Pbs"] = "0"
        with self.assertRaises(RuntimeError):
            self.verify(response_headers=altered)
        self.assertNotIn("decrypt", self.events)

    def test_wrong_installed_key_rejects_before_encrypt(self):
        altered = status()
        altered["chiave_sha256"] = "b" * 64
        with self.assertRaises(RuntimeError):
            self.verify(value=altered)
        self.assertEqual(self.events, ["/stato"])

    def test_legacy_profile_rejected_without_native_call(self):
        with self.assertRaises(RuntimeError):
            self.pipeline.cifra([0] * 512, "legacy52")
        self.pipeline._run.assert_not_called()

    def test_missing_or_incomplete_keys_never_regenerate_or_change_permissions(self):
        original = {path.name: (path.read_bytes(), path.stat().st_mode) for path in self.keys.iterdir()}
        self.pipeline.require_existing_keys()
        self.assertEqual(original, {path.name: (path.read_bytes(), path.stat().st_mode)
                                    for path in self.keys.iterdir()})
        for name in ("server.key", "client.key"):
            (self.keys / name).unlink()
            with self.assertRaises(RuntimeError):
                self.pipeline.require_existing_keys()
            self.assertFalse((self.keys / name).exists())
        self.runner.assert_not_called()
        self.transport.assert_not_called()

    def test_distinct_configs_keys_transports_and_runners_remain_isolated(self):
        other_keys = self.keys.parent / "other-keys"
        other_keys.mkdir()
        for name in ("client.key", "server.key"):
            (other_keys / name).write_bytes(b"other-fake-test-key")
        calls = [[], []]
        pipelines = []
        for index, keys in enumerate((self.keys, other_keys)):
            def runner(command, key_path, probe_path, output_path, profile, index=index):
                calls[index].append((command, key_path, profile))
                pathlib.Path(output_path).write_bytes(f"ciphertext-{index}".encode())
                return {}
            transport = mock.Mock(return_value=(f"server-{index}".encode(), {}))
            settings = ClientConfiguration(ROOT, pathlib.Path(f"/fake-binary-{index}"), keys)
            pipelines.append(AccessPipeline(settings, transport, runner))
        left, right = pipelines
        left.config["modello"] = "changed-only-on-left"
        left.gallery_snapshot = {"revision": 91}
        self.assertNotEqual(left.config["modello"], right.config["modello"])
        self.assertIsNone(right.gallery_snapshot)
        self.assertNotEqual(left.fingerprint_chiave_locale(), right.fingerprint_chiave_locale())
        for index, pipeline in enumerate(pipelines):
            self.assertEqual(pipeline.cifra([0] * 512, "head51")[0], f"ciphertext-{index}".encode())
            self.assertEqual(pipeline.srv("/stato")[0], f"server-{index}".encode())
            self.assertEqual(calls[index], [("encrypt", pipeline.settings.keys, "head51")])
        self.assertNotEqual(left._key_hash_cache, right._key_hash_cache)

    def test_bad_contract_rejects_before_key_upload(self):
        value = status(0)
        value.update(chiave=False, chiave_sha256=None)
        value["contratto_esatto"]["wire_version"] = 7
        self.pipeline.srv = mock.Mock(return_value=(json.dumps(value).encode(), {}))
        with self.assertRaises(RuntimeError):
            self.pipeline.assicura_chiave()
        self.assertEqual(self.pipeline.srv.call_args_list, [mock.call("/stato")])


if __name__ == "__main__":
    unittest.main()
