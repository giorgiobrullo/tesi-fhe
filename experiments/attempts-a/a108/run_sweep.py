"""Run each frozen A108 diagnostic once, preserving raw output and bindings."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent
ORIGINAL = PROJECT / "tmp/a108-packed-pfks-d2-k4"


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def native_processes():
    rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,comm="], text=True)
    matches = []
    for line in rows.splitlines():
        pid, parent, command = line.strip().split(None, 2)
        name = Path(command).name
        if name in {"cargo", "rustc"} or "/target" in command or "Tesi-FHE" in command:
            matches.append({"pid": int(pid), "parent": int(parent), "command": command})
    return {"utc": utc(), "matches": matches}


def check_bindings(binary, expected_binary):
    for entry in json.loads((ROOT / "SOURCE_BINDING.json").read_text())["original_artifacts"]:
        assert digest(Path(entry["path"])) == entry["sha256"], entry["path"]
    for name in ["Cargo.toml", "Cargo.lock", "src/main.rs"]:
        assert digest(ROOT / "source" / name) == digest(ORIGINAL / name), name
    assert digest(binary) == expected_binary, "binary changed"


def main():
    build = json.loads((ROOT / "build/result.json").read_text())
    assert build["exit_code"] == 0, "build did not pass"
    binary = Path(build["binary"])
    plan = json.loads((ROOT / "PLAN.json").read_text())
    env = {
        **os.environ,
        "RAYON_NUM_THREADS": "1",
        "A108_RUN_FHE": "I_ACKNOWLEDGE_A108_PACKED_D2_K4_FHE",
        "A108_PREREGISTRATION_SHA256": digest(ORIGINAL / "PREREGISTRATION.json"),
    }
    results = []
    for parameter in plan["schedule"]:
        check_bindings(binary, build["binary_sha256"])
        preflight = native_processes()
        save(ROOT / f"preflight-{parameter}.json", preflight)
        assert not preflight["matches"], "competing native workload; no launch"
        directory = ROOT / "runs" / parameter
        directory.mkdir(exist_ok=False)
        command = [str(binary), "--run-authorized", "--pfks", parameter]
        started = utc()
        tick = time.monotonic()
        observations = []
        with (directory / "stdout.jsonl").open("wb") as out, (directory / "stderr.log").open("wb") as err:
            child = subprocess.Popen(command, cwd=ROOT / "source", env=env, stdout=out, stderr=err)
            save(directory / "started.json", {
                "utc": started, "pid": child.pid, "controller_pid": os.getpid(),
                "command": command, "rayon_threads": 1,
                "binary_sha256": build["binary_sha256"],
            })
            print(f"Running {parameter}, pid {child.pid}", flush=True)
            while child.poll() is None:
                observation = native_processes()
                observation["other_matches"] = [x for x in observation["matches"] if x["pid"] != child.pid]
                observations.append(observation)
                time.sleep(0.5)
            code = child.returncode
        ended = utc()
        save(directory / "process-observations.json", observations)
        receipt = {
            "parameter": parameter, "pid": child.pid, "started": started, "ended": ended,
            "elapsed_seconds": time.monotonic() - tick, "exit_code": code,
            "stdout_sha256": digest(directory / "stdout.jsonl"),
            "stderr_sha256": digest(directory / "stderr.log"),
            "binary_sha256": digest(binary),
            "other_native_workload_observed": any(x["other_matches"] for x in observations),
            "timing_claim": False,
        }
        save(directory / "exit.json", receipt)
        check_bindings(binary, build["binary_sha256"])
        records = [json.loads(line) for line in (directory / "stdout.jsonl").read_text().splitlines()]
        summaries = [row for row in records if row.get("record") == "summary"]
        assert len(summaries) == 1 and summaries[0]["fixture_cases"] == 8, "incomplete raw stream"
        summary = summaries[0]
        assert code == (1 if summary["failed_cases"] else 0), "unexpected process exit"
        assert len(records) == (59 if code else 58), "unexpected record count"
        results.append({**receipt, "raw_records": len(records), "summary": summary})
        save(ROOT / "RUNS.json", results)
        print(f"Finished {parameter}: {summary['failed_cases']}/8 failed cases, {len(records)} records", flush=True)
        assert not receipt["other_native_workload_observed"], "other workload observed; stop before next launch"
    print("Five diagnostic runs complete; independent raw-log validation follows.", flush=True)


if __name__ == "__main__":
    main()
