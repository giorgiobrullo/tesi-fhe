from pathlib import Path
import datetime, hashlib, json, os, shutil, subprocess, sys
U = Path(__file__).resolve().parents[1]
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(p, value): p.write_text(json.dumps(value, indent=2) + "\n")
def liveness(mode):
    live = []
    rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,etime=,comm=,args="], text=True).splitlines()
    for row in rows:
        p = row.strip().split(None, 4)
        if len(p) != 5: continue
        pid, parent, elapsed, comm, args = p
        base = Path(comm).name
        if int(pid) == os.getpid() or base in ("zsh", "ps"): continue
        if base in ("cargo", "rustc", "a124_driver.py") or (base.startswith("python") and any(t in args.lower() for t in ("a124", "benchmark", "current-"))) or (comm.startswith("/workspace/research/tmp/") and base != "python3.12"):
            live.append({"pid": int(pid), "command": comm, "args": args})
    put(U / f"root/PRE_{mode.upper()}_LIVENESS.json", {"observed_utc": stamp(), "recognized_competing_live": live, "global_idle_claim": False, "process_control": False})
    assert not live, "Do not run alongside existing owned workloads; leave them untouched"
assert len(sys.argv) == 2 and sys.argv[1] in ("build", "validate", "bench")
mode = sys.argv[1]
receipt = U / f"logs/{mode.upper()}.json"
assert not receipt.exists(), "Existing handle/receipt: wait or inspect, never relaunch"
review = U / "root/PREBUILD_REVIEW.md"
assert "PREBUILD_PASS" in review.read_text()
for v in json.loads((U / "root/ORIENTATION.json").read_text())["primary"].values(): assert sha(Path(v["path"])) == v["sha256"]
assert not any(os.environ.get(k) for k in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "CARGO_PROFILE_RELEASE_OPT_LEVEL"])
if mode == "build":
    names = ["probe/Cargo.toml", "probe/Cargo.lock", "probe/src/main.rs", "PROTOCOL.md", "root/EXACT_ORACLE.py", "root/ORACLE_SPEC.md", "root/SOURCE_SCOPE.md", "root/PREBUILD_REVIEW.md", "root/DRIVER.py"]
    put(U / "root/SOURCE_BUILD.json", {"observed_utc": stamp(), "files": {x: {"bytes": (U / x).stat().st_size, "sha256": sha(U / x)} for x in names}})
    command = ["/opt/homebrew/bin/cargo", "build", "--manifest-path", str(U / "probe/Cargo.toml"), "--release", "--offline", "--locked", "--jobs", "1", "--target-dir", str(U / "target")]
else:
    build = json.loads((U / "logs/BUILD.json").read_text())
    assert build["status"] == "terminal" and build["returncode"] == 0
    binary = Path(build["binary_path"])
    assert sha(binary) == build["binary_sha256"]
    for rel, v in json.loads((U / "root/SOURCE_BUILD.json").read_text())["files"].items(): assert sha(U / rel) == v["sha256"]
    if mode == "bench":
        validation = json.loads((U / "logs/VALIDATE.json").read_text())
        oracle = json.loads((U / "logs/ORACLE.json").read_text())
        assert validation["status"] == "terminal" and validation["returncode"] == 0
        assert oracle["status"] == "PASS" and oracle["input_sha256"] == sha(U / "logs/validate.stdout")
    command = [str(binary), "--" + mode]
liveness(mode)
with (U / f"logs/{mode}.stdout").open("w") as out, (U / f"logs/{mode}.stderr").open("w") as err:
    process = subprocess.Popen(command, cwd=U / "probe", stdout=out, stderr=err)
    result = {"started_utc": stamp(), "pid": process.pid, "parent_pid": os.getpid(), "command": command, "status": "running", "scope": mode, "keys_FHE": False}
    put(receipt, result)
    print(json.dumps(result), flush=True)
    result.update(returncode=process.wait(), ended_utc=stamp(), status="terminal")
    put(receipt, result)
if mode == "build" and result["returncode"] == 0:
    target = U / "bin/public-gate"
    assert not target.exists()
    shutil.copy2(U / "target/release/current-fcma-codegen-probe", target)
    result.update(binary_path=str(target), binary_bytes=target.stat().st_size, binary_sha256=sha(target))
else:
    result.update(stdout_sha256=sha(U / f"logs/{mode}.stdout"), stdout_bytes=(U / f"logs/{mode}.stdout").stat().st_size)
put(receipt, result)
print(json.dumps(result), flush=True)
raise SystemExit(result["returncode"])
