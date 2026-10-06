from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys
Z = Path(__file__).resolve().parents[1]
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def put(value): (Z / "logs/CAPABILITIES.json").write_text(json.dumps(value, indent=2) + "\n")
assert sys.argv[1:] == []
assert not (Z / "logs/CAPABILITIES.json").exists(), "Existing invocation: never relaunch"
build = json.loads((Z / "logs/BUILD.json").read_text())
assert build["status"] == "terminal" and build["returncode"] == 0
binary = Path(build["binary_path"])
assert hashlib.sha256(binary.read_bytes()).hexdigest() == build["binary_sha256"]
assert (Z / "root/CODEGEN_SYMBOLS.json").exists(), "Frozen symbol identity must first be inspected"
command = [str(binary), "--capabilities"]
with (Z / "logs/capabilities.stdout").open("w") as out, (Z / "logs/capabilities.stderr").open("w") as err:
    process = subprocess.Popen(command, stdout=out, stderr=err, cwd=Z)
    result = {"started_utc": stamp(), "pid": process.pid, "parent_pid": os.getpid(), "command": command, "binary_sha256": build["binary_sha256"], "status": "running", "arithmetic_wrappers_invoked": False, "timing_performed": False}
    put(result)
    result.update(returncode=process.wait(), ended_utc=stamp(), status="terminal")
    put(result)
result["metadata"] = json.loads((Z / "logs/capabilities.stdout").read_text())
assert result["metadata"]["scope"] == "capabilities_only" and not result["metadata"]["arithmetic_called"] and not result["metadata"]["timing_performed"]
put(result)
print(json.dumps(result), flush=True)
raise SystemExit(result["returncode"])
