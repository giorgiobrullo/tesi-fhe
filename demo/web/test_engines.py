import itertools
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from .engines import A28Engine, CurrentEngine, EngineSet, clock_ns, validate_input, validate_spans


def entry(identifier, value=0, threshold=273):
    return {"id": identifier, "vettore": [value] + [0] * 511, "soglia": threshold}


class DomainTests(unittest.TestCase):
    def test_stalled_native_reader_times_out_and_is_closed(self):
        engine = A28Engine.__new__(A28Engine)
        engine.process = Mock()
        engine.process.poll.return_value = None
        engine.close = Mock()
        with patch("demo.web.engines.select.select", return_value=([], [], [])):
            with self.assertRaises(TimeoutError):
                engine.exchange({"padding": "x" * (1024 * 1024)}, timeout=.1)
        engine.close.assert_called_once_with()

    def test_startup_ignores_a28_environment_and_announces_only_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "current"
            binary.touch()
            keys = root / "keys"
            environment = {
                "VARCO_WEB_BINARY": str(binary), "VARCO_WEB_KEYS": str(keys),
                "VARCO_WEB_STATE": str(root / "state"), "VARCO_WEB_NATIVE_PORT": "9010",
                "VARCO_A28_BINARY": str(root / "absent-a28"),
                "VARCO_A28_KEYS": str(root / "absent-a28-keys"),
            }
            with patch.dict(os.environ, environment, clear=True), \
                    patch("demo.web.engines.CurrentEngine") as current, \
                    patch("demo.web.engines.A28Engine") as legacy:
                current.return_value.alive.return_value = True
                engines = EngineSet()
                current.assert_called_once_with(binary, keys, (root / "state").resolve(), 9010)
                legacy.assert_not_called()
                self.assertEqual(engines.info(), [{"id": "attuale", "nome": "Attuale", "pronto": True}])
                engines.close()
                current.return_value.close.assert_called_once_with()

    def test_disabled_engine_is_rejected_before_input_validation_or_worker(self):
        engines = EngineSet.__new__(EngineSet)
        engines.workers = {"a28": Mock()}
        with patch("demo.web.engines.validate_input") as validate:
            for identifier in ("a28", "confronto"):
                with self.assertRaisesRegex(RuntimeError, "non è disponibile"):
                    engines.verify([], [], identifier, lambda _: None)
            validate.assert_not_called()
        engines.workers["a28"].verify.assert_not_called()

    def test_first_minimum_uses_its_own_threshold(self):
        query = [0] * 512
        self.assertEqual(validate_input(query, [entry("first", threshold=-1), entry("second")]), 0)
        self.assertEqual(validate_input(query, [entry("first", threshold=0), entry("second")]), 1)

    def test_threshold_is_inclusive_and_scores_exclude_query_norm(self):
        query = [1] + [0] * 511
        self.assertEqual(validate_input(query, [entry("one", value=1, threshold=-1)]), 1)
        self.assertEqual(validate_input(query, [entry("one", value=1, threshold=-2)]), 0)

    def test_domain_checks_precede_native_execution(self):
        for query, gallery in (
            ([3] * 512, [entry("one")]),
            ([False] * 512, [entry("one")]),
            ([0] * 512, [entry("same"), entry("same")]),
            ([0] * 512, [entry("one", threshold=True)]),
            ([0] * 512, []),
            ([0] * 512, [entry(str(index)) for index in range(129)]),
        ):
            with self.subTest(query=query[:1], size=len(gallery)), self.assertRaises(ValueError):
                validate_input(query, gallery)

    def test_native_error_cannot_be_replaced_by_the_clear_answer(self):
        class WrongWorker:
            def alive(self):
                return True

            def verify(self, query, entries, progress):
                return {"selected_id": 0, "tempi_ms": {"server": 1}}

        engines = EngineSet.__new__(EngineSet)
        engines.lock = threading.Lock()
        engines.workers = {"attuale": WrongWorker()}
        with self.assertRaisesRegex(RuntimeError, "non coincide"):
            engines.verify([0] * 512, [entry("one")], "attuale", lambda _: None)


class TimingTests(unittest.TestCase):
    def test_shared_clock_is_explicit_and_rejects_failure(self):
        from . import engines
        with patch.object(engines.time, "clock_gettime_ns", return_value=123) as sample:
            self.assertEqual(clock_ns(), 123)
            sample.assert_called_once_with(engines.time.CLOCK_MONOTONIC)
        for value in (-1, True, 1.5):
            with patch.object(engines.time, "clock_gettime_ns", return_value=value):
                with self.assertRaisesRegex(RuntimeError, "Orologio"):
                    clock_ns()
        with patch.object(engines.time, "clock_gettime_ns", side_effect=OSError):
            with self.assertRaisesRegex(RuntimeError, "Orologio"):
                clock_ns()

    def test_current_intervals_enclose_actual_calls_without_replacing_native_duration(self):
        observed = []

        def point(kind):
            observed.append((kind, clock_ns()))

        engine = CurrentEngine.__new__(CurrentEngine)
        engine.set_gallery = lambda entries: point("setup")

        def encrypt(query, profile):
            self.assertEqual(profile, "head51")
            point("encryption")
            return b"ciphertext", {}

        def transport(path, ciphertext):
            self.assertEqual((path, ciphertext), ("/varco", b"ciphertext"))
            point("fhe")
            return b"result", {"x-tempo-ms": "987.6"}

        def decrypt(ciphertext):
            self.assertEqual(ciphertext, b"result")
            point("decryption")
            return {"codice": 1}

        engine.transport = transport
        engine.pipeline = SimpleNamespace(
            assicura_chiave=lambda: point("setup"),
            snapshot_galleria=lambda: {"query_profile": "head51"},
            cifra=encrypt, decifra=decrypt,
            valida_header_varco=lambda headers, snapshot: headers,
            identita_da_esito=lambda decoded, snapshot: point("decryption"),
        )
        with patch("demo.web.engines.time.clock_gettime_ns", side_effect=itertools.count(100, 10)):
            result = engine._verify([0] * 512, [entry("one")], lambda _: None)
        spans = result["spans_ns"]
        self.assertEqual([span["kind"] for span in spans], ["setup", "encryption", "fhe", "decryption"])
        for kind, timestamp in observed:
            span = next(span for span in spans if span["kind"] == kind)
            self.assertLess(span["start_ns"], timestamp)
            self.assertLess(timestamp, span["end_ns"])
        validate_spans(spans, 0, 1000)
        self.assertEqual(result["tempi_ms"]["server"], 987.6)

    def test_old_a28_has_no_invented_spans_and_new_a28_keeps_absolute_timestamps(self):
        engine = A28Engine.__new__(A28Engine)
        response = {"selected_id": 1, "timings_ms": {"encryption": 1, "server": 2, "decryption": 3},
                    "sizes": {}}
        engine.exchange = Mock(return_value=response)
        progress = Mock()
        result = engine.verify([0] * 512, [entry("one")], progress)
        self.assertEqual(result["spans_ns"], [])
        progress.assert_called_once_with("elaborazione")
        response["spans_ns"] = [{"kind": "fhe", "start_ns": 12345678901234567,
                                 "end_ns": 12345678901334567}]
        result = engine.verify([0] * 512, [entry("one")], lambda _: None)
        self.assertEqual(result["spans_ns"], response["spans_ns"])
        self.assertEqual(result["tempi_ms"], {"cifratura": 1, "server": 2, "decifratura": 3})

    def test_spans_reject_malformed_order_overlap_and_cross_clock_bounds(self):
        valid = {"kind": "fhe", "start_ns": 120, "end_ns": 150}
        invalid = [None, (), [None], [valid | {"extra": 1}], [valid | {"kind": "other"}],
                   [valid | {"start_ns": True}], [valid | {"start_ns": float("nan")}],
                   [valid | {"end_ns": 150.0}], [valid | {"start_ns": 99}],
                   [valid | {"end_ns": 201}], [valid | {"end_ns": 119}],
                   [valid, valid | {"start_ns": 140, "end_ns": 160, "kind": "decryption"}],
                   [valid, valid | {"start_ns": 160, "end_ns": 180, "kind": "encryption"}],
                   [valid, valid | {"start_ns": 160, "end_ns": 180}]]
        for spans in invalid:
            with self.subTest(spans=spans), self.assertRaisesRegex(RuntimeError, "intervalli"):
                validate_spans(spans, 100, 200)
        with self.assertRaises(RuntimeError):
            validate_spans([], 200, 100)
        base = 1 << 60
        spans = [valid | {"start_ns": base + 120, "end_ns": base + 150}]
        self.assertEqual(validate_spans(spans, base + 100, base + 200), spans)
        self.assertIsNot(validate_spans(spans, base + 100, base + 200)[0], spans[0])

    def test_engine_set_contains_native_intervals_in_its_own_os_clock_bounds(self):
        span = {"kind": "fhe", "start_ns": 120, "end_ns": 150}
        worker = SimpleNamespace(alive=lambda: True,
                                 verify=lambda *args: {"selected_id": 1, "tempi_ms": {"server": 2},
                                                       "spans_ns": [span]})
        engines = EngineSet.__new__(EngineSet)
        engines.lock = threading.Lock()
        engines.workers = {"attuale": worker}
        with patch("demo.web.engines.clock_ns", side_effect=[100, 200]):
            result = engines.verify([0] * 512, [entry("one")], "attuale", lambda _: None)
        self.assertEqual(result["spans_ns"], [span])
        span["start_ns"] = 99
        with patch("demo.web.engines.clock_ns", side_effect=[100, 200]):
            with self.assertRaisesRegex(RuntimeError, "intervalli"):
                engines.verify([0] * 512, [entry("one")], "attuale", lambda _: None)


if __name__ == "__main__":
    unittest.main()
