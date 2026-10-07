import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import run_gate as b
import verify as v


class Tests(unittest.TestCase):
    def test_missing_negative_nested_alias_hash_and_fresh_replay_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp).resolve()
            here.chmod(0o700)
            run = here / "smoke"
            run.mkdir(mode=0o700)
            report = run / "validation.json"
            (here / "PASSING_FIRST.json").write_text(
                json.dumps(
                    dict(
                        status="INDEPENDENT_VALID_A187_FIRST_PASS",
                        gate_pass=True,
                        source_manifest_sha256="a" * 64,
                        raw_sha256="b" * 64,
                    )
                )
            )
            fresh = dict(
                gate_pass=True,
                source_id="c" * 64,
                key_hashes=[["d" * 64, "e" * 64]],
                records=1268,
                launch_binding=dict(
                    files_sha256={"stdout.jsonl": "f" * 64},
                    exited_at_utc="2026-09-05T00:00:01+00:00",
                ),
            )

            def save(value):
                report.write_text(json.dumps(value) + "\n")
                report.chmod(0o600)

            with (
                patch.object(b, "HERE", here),
                patch.object(b, "run_path", return_value=run),
                patch.object(v, "verify", return_value=fresh),
            ):
                with self.assertRaises(ValueError):
                    v.predecessor_binding("n4-full")
                save(fresh)
                bound = v.predecessor_binding("n4-full")
                self.assertEqual(bound["report_sha256"], b.digest(report))
                for mutate in [
                    lambda x: x.update(gate_pass=False),
                    lambda x: x.update(records=True),
                    lambda x: x["launch_binding"]["files_sha256"].update(
                        {"stdout.jsonl": "0" * 64}
                    ),
                    lambda x: x.update(key_hashes=[["z" * 64, "e" * 64]]),
                ]:
                    bad = copy.deepcopy(fresh)
                    mutate(bad)
                    save(bad)
                    with self.assertRaises(ValueError):
                        v.predecessor_binding("n4-full")
                save(fresh)
                report.chmod(0o644)
                with self.assertRaises(ValueError):
                    v.predecessor_binding("n4-full")

    def test_parent_checkpoint_remains_before_flush(self):
        text = (Path(b.__file__)).read_text()
        self.assertLess(
            text.index('save(run / "wait-complete.json", terminal)'),
            text.index("for name, handle in handles:"),
        )


if __name__ == "__main__":
    unittest.main()
