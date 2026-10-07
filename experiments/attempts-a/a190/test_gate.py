"""Bounded exact clear/source/synthetic checks only; no Cargo or native process invocation."""

import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import oracle as o
import replay as r
import synthetic as s
import binding as b
import run_gate

HERE = Path(__file__).resolve().parent


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = s.records()

    def test_complete_synthetic_record(self):
        result = r.verify(self.data, "a" * 64, "b" * 64, 123)
        self.assertTrue(result["gate_pass"])
        self.assertEqual(
            (result["semantic_checks"], result["support_checks"]), (1820, 336)
        )
        self.assertIsNone(result["actual_p_fail"])

    def test_fixed_fixture_feedback_ties_dead_and_signed_states(self):
        cm, _, flags = o.chain()
        ordinary, _ = o.ordinary()
        reset = o.chain(True)[2]
        self.assertEqual(flags, [1, 0, 1, 0])
        self.assertEqual(ordinary["round/7/output"], flags)
        self.assertEqual(reset, [0, 1, 0, 0])
        self.assertNotEqual(flags, reset)
        self.assertTrue(
            any(
                v < 0
                for k, row in ordinary.items()
                if k.endswith("/linear")
                for v in row
            )
        )
        self.assertEqual(len(cm), 428)
        self.assertEqual(len(o.ordinary()[1]), 48)

    def test_4096_clear_boundary_active_combinations(self):
        for bits in range(16):
            active = [(bits >> i) & 1 for i in range(4)]
            for value in range(256):
                values = [value, (value + 1) % 256, value, 0]
                live = [v for a, v in zip(active, values) if a]
                expected = [
                    int(bool(a) and bool(live) and v == min(live))
                    for a, v in zip(active, values)
                ]
                self.assertEqual(o.chain(False, active, values)[2], expected)
                self.assertEqual(
                    o.ordinary(active, values)[0]["round/7/output"], expected
                )

    def test_duplicate_json_and_bool_alias(self):
        with self.assertRaises(ValueError):
            r.parse(b'{"x":1,"x":1}\n')
        with self.assertRaises(ValueError):
            r.same([True], [1])
        with self.assertRaises(ValueError):
            r.verify(self.data[:-1], "a" * 64, "b" * 64, 123)

    def test_ciphertext_hash_canonical_and_phase_controls(self):
        node = self.data[2]["active"][0]
        for field, value in [
            ("phase", node["phase"] + 1),
            ("phase", True),
            ("sha256", "c" * 64),
        ]:
            mutated = copy.deepcopy(node)
            mutated[field] = value
            with self.assertRaises(ValueError):
                r.Checker().ct(mutated, "A44Big")

    def test_feedback_word_and_wrong_source_rejected(self):
        altered = copy.deepcopy(self.data[4])
        altered["checkpoints"][5]["states"][0]["words"][0] ^= 1
        with self.assertRaises(ValueError):
            r.chain(r.Checker(), altered, self.data[2], self.data[1]["family"])
        with self.assertRaises(ValueError):
            r.verify(self.data, "c" * 64, "b" * 64, 123)

    def test_ordinary_multiplier_and_count_controls(self):
        altered = copy.deepcopy(self.data[3])
        altered["ordinary_pbs"] = 47
        with self.assertRaises(ValueError):
            r.ordinary(r.Checker(), altered, self.data[2], self.data[1]["family"])
        altered = copy.deepcopy(self.data[3])
        altered["states"][1]["values"][0] = self.data[2]["bits"][0][0]
        with self.assertRaises(ValueError):
            r.ordinary(r.Checker(), altered, self.data[2], self.data[1]["family"])

    def test_phase_only_center_counterexample(self):
        # Same exact phase at CM center128; 128 near-half masks move actual MS to192.
        unit = 1 << 54
        mask = [unit // 2 - 1] * 128 + [0] * (772 - 128)
        words = mask + [(o.C + sum(mask)) % o.Q]
        node = s.Factory().ct(words, "CmSmall")
        checker = r.Checker()
        checker.ct(node, "CmSmall", expected=1, delta=o.C)
        checker.center(node, 1, o.C)
        self.assertEqual(node["phase"], o.C)
        self.assertEqual(node["coefficientwise"]["address"], 192)
        self.assertEqual(checker.semantic, [True])
        self.assertEqual(checker.support, [False])

    def test_source_prefix_and_U8_exact_helpers(self):
        old = HERE.parent / "a176-common-mask-c1-expansion-readiness/src"
        for name in ("crypto.rs", "model.rs", "zero_pool.rs"):
            self.assertTrue(
                (HERE / "src" / name).read_bytes().startswith((old / name).read_bytes())
            )
        u8 = (
            HERE.parent / "u8-large-gallery-score-gate/candidate/src/private_argmin.rs"
        ).read_text()
        new = (HERE / "src/ordinary.rs").read_text()
        for start, end in [
            ("fn sum_lwes(", "fn scale_lwe_signed("),
            ("fn scale_lwe_signed(", "fn radix5_exclusive_prefix_or"),
        ]:
            excerpt = u8[u8.index(start) : u8.index(end, u8.index(start) + 1)].strip()
            self.assertIn(excerpt, new)
        for line in [
            "a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);",
            "a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);",
        ]:
            self.assertIn(line, u8)
            self.assertIn(line, new)
        self.assertIn("[-1, -1, -1, -1, -1, 1, -1, -1]", new)
        persistent = (HERE / "src/persistent.rs").read_text()
        self.assertNotIn("run_round(", persistent)
        self.assertEqual(persistent.count("macro_rules! accepted"), 2)

    def test_source_pins_and_exact_lock_composition(self):
        for row in json.loads((HERE / "SOURCE_PINS.json").read_text())["inputs"]:
            self.assertEqual(b.sha(Path(row["path"]).read_bytes()), row["sha256"])
        import tomllib

        old = tomllib.loads(
            (
                HERE.parent / "a176-common-mask-c1-expansion-readiness/Cargo.lock"
            ).read_text()
        )["package"]
        new = tomllib.loads((HERE / "Cargo.lock").read_text())["package"]
        self.assertEqual(len(new), len(old) + 1)
        source = {(x["name"], x["version"]): x for x in old}
        for package in new:
            if package["name"].startswith("a190-"):
                self.assertEqual(
                    package["dependencies"], ["sha2", "serde_json", "tfhe"]
                )
            elif package["name"] == "sha2":
                self.assertEqual(package["version"], "0.10.9")
            else:
                self.assertEqual(package, source[(package["name"], package["version"])])

    def test_noargs_and_known_exit_postcheck_failure(self):
        with (
            patch("sys.argv", ["run_gate.py"]),
            patch.object(
                run_gate.subprocess,
                "Popen",
                side_effect=AssertionError("must not launch"),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_gate.main(), 0)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve()
            path.chmod(0o700)
            with (
                patch.object(b, "RUN", path),
                patch.object(b, "BINARY", path / "missing"),
                patch.object(b, "source", side_effect=ValueError("changed manifest")),
            ):
                run_gate.finish(123, 0, "a" * 64, "b" * 64)
            self.assertEqual(
                b.parse((path / "wait-complete.json").read_bytes())["exit_code"], 0
            )
            e = b.parse((path / "exit.json").read_bytes())
            self.assertFalse(e["source_unchanged"])
            self.assertFalse(e["binary_unchanged"])
            self.assertEqual(len(e["errors"]), 2)

    def test_captured_envelope_pid_utc_hash_and_missing_records(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            base.chmod(0o700)
            run = base / "first-n4"
            run.mkdir(mode=0o700)
            binary = base / "fake-binary"
            binary.write_bytes(b"SYNTHETIC_NOT_EXECUTABLE")
            bh = b.sha(binary.read_bytes())
            snap = base / "snapshot"
            snap.write_bytes(b"SYNTHETIC_NO_PROCESS_PROBE")
            source = "a" * 64
            clear = dict(
                schema="a190.root-clearance.v1",
                observed_at_utc="2026-01-01T00:00:00+00:00",
                active_workload_count=0,
                exclusive_root_authorization=True,
                source_sha256=source,
                binary_sha256=bh,
                process_snapshot_path=str(snap),
                process_snapshot_sha256=b.sha(snap.read_bytes()),
            )
            with (
                patch.object(b, "RUN", run),
                patch.object(b, "BINARY", binary),
                patch.object(b, "source", return_value=source),
            ):
                b.save(run / "clearance.json", clear)
                prepared = dict(
                    schema="a190.prepared.v1",
                    source=source,
                    binary=bh,
                    command=b.command(),
                    cwd=str(b.HERE),
                    environment=b.environment(source, bh),
                    driver_pid=321,
                    prepared_utc="2026-01-01T00:00:01+00:00",
                    clearance_sha256=b.sha((run / "clearance.json").read_bytes()),
                    run_path=str(run),
                    os_membership_attested=False,
                )
                child = dict(
                    schema="a190.child.v1",
                    source=source,
                    binary=bh,
                    pid=123,
                    started_utc="2026-01-01T00:00:02+00:00",
                )
                wait = dict(
                    schema="a190.wait-complete.v1",
                    source=source,
                    binary=bh,
                    pid=123,
                    exit_code=0,
                    reaped_utc="2026-01-01T00:00:03+00:00",
                )
                terminal = dict(
                    schema="a190.exit.v1",
                    source=source,
                    binary=bh,
                    pid=123,
                    exit_code=0,
                    terminal_utc="2026-01-01T00:00:04+00:00",
                    source_unchanged=True,
                    binary_unchanged=True,
                    errors=[],
                )
                for name, val in [
                    ("prepared.json", prepared),
                    ("child.json", child),
                    ("wait-complete.json", wait),
                    ("exit.json", terminal),
                ]:
                    b.save(run / name, val)
                for name, raw in [("stdout.jsonl", b"{}\n"), ("stderr.log", b"")]:
                    q = run / name
                    q.write_bytes(raw)
                    q.chmod(0o600)
                calls = {}
                read = b.read

                def once(path):
                    calls[path.name] = calls.get(path.name, 0) + 1
                    if calls[path.name] > 1:
                        raise AssertionError("second metadata read")
                    return read(path)

                with (
                    patch.object(
                        r,
                        "verify",
                        return_value=dict(native_gate_pass=True, gate_pass=True),
                    ),
                    patch.object(b, "read", side_effect=once),
                ):
                    result = b.verify_run()
                self.assertTrue(result["gate_pass"])
                self.assertEqual(set(calls.values()), {1})
                self.assertEqual(
                    result["binding"]["file_sha256"]["stdout.jsonl"], b.sha(b"{}\n")
                )
                for name, key, value in [
                    ("child.json", "pid", True),
                    ("exit.json", "terminal_utc", "2025-01-01T00:00:04+00:00"),
                    ("prepared.json", "binary", "c" * 64),
                ]:
                    q = run / name
                    prior = q.read_bytes()
                    val = b.parse(prior)
                    val[key] = value
                    q.write_text(json.dumps(val))
                    with patch.object(
                        r,
                        "verify",
                        side_effect=AssertionError("must reject before record replay"),
                    ):
                        with self.assertRaises(ValueError):
                            b.verify_run()
                    q.write_bytes(prior)
                (run / "interrupted.json").symlink_to(run / "missing")
                with self.assertRaises(ValueError):
                    b.verify_run()

    def test_coherent_affine_phase_counterfeits(self):
        def alter_all_aliases(root, chosen):
            domain, lane, digest = chosen["domain"], chosen["lane"], chosen["sha256"]
            seen = set()

            def walk(x):
                if id(x) in seen:
                    return
                if type(x) in (dict, list):
                    seen.add(id(x))
                if type(x) is dict:
                    if (
                        x.get("domain") == domain
                        and x.get("lane") == lane
                        and x.get("sha256") == digest
                        and "phase" in x
                    ):
                        x["phase"] = (x["phase"] + 1) % o.Q
                        x["mask_dot"] = (x["mask_dot"] - 1) % o.Q
                    for value in x.values():
                        walk(value)
                elif type(x) is list:
                    for value in x:
                        walk(value)

            walk(root)

        ordinary = self.data[3]
        nodes = [
            ordinary["states"][1]["values"][0],
            ordinary["events"][0]["input"],
            ordinary["states"][4]["values"][0],
            ordinary["events"][4]["input"],
        ]
        for chosen in nodes:
            changed = copy.deepcopy(ordinary)
            alter_all_aliases(changed, chosen)
            with self.assertRaisesRegex(ValueError, "same-key affine phase closure"):
                r.ordinary(r.Checker(), changed, self.data[2], self.data[1]["family"])
        common = self.data[4]
        for tag in [
            "round/0/update_big_sum/0",
            "round/0/z_input/0",
            "round/0/update_input/0",
            "round/0/pair_input/0",
            "round/0/any_big_sum",
        ]:
            chosen = next(
                x["ct"]
                for x in common["traces"]
                if x["tag"] == tag and x["ct"]["lane"] == 0
            )
            changed = copy.deepcopy(common)
            alter_all_aliases(changed, chosen)
            observed = next(
                x["ct"]
                for x in changed["traces"]
                if x["tag"] == tag and x["ct"]["lane"] == 0
            )
            # Words/hash/direct phase stay individually consistent; all matching aliases changed.
            r.Checker().ct(observed, chosen["domain"], 0)
            with self.assertRaisesRegex(ValueError, "same-key affine phase closure"):
                r.chain(r.Checker(), changed, self.data[2], self.data[1]["family"])


if __name__ == "__main__":
    unittest.main()
