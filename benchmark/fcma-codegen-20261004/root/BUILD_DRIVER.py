from pathlib import Path
import datetime, hashlib, json, os, shutil, subprocess, sys
Z = Path(__file__).resolve().parents[1]
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def put(path, value): path.write_text(json.dumps(value, indent=2) + "\n")
if sys.argv[1:] != ["build"]: raise SystemExit("Only compile-only build mode is supported")
review = Z / "root/REVIEW.md"
assert review.exists(), "Independent prebuild review must be complete"
assert "PREBUILD_PASS" in review.read_text(), "No reviewed prebuild permission"
assert not (Z / "logs/BUILD.json").exists(), "Existing handle/result: never relaunch"
assert (Z / "probe/Cargo.lock").exists()
assert not any(os.environ.get(k) for k in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "CARGO_PROFILE_RELEASE_OPT_LEVEL"])
rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,etime=,comm=,args="], text=True).splitlines()
competing = []
for row in rows:
    p = row.strip().split(None, 4)
    if len(p) != 5: continue
    pid, parent, elapsed, comm, args = p
    base = Path(comm).name
    if int(pid) == os.getpid() or base in ("zsh", "ps"): continue
    if base in ("cargo", "rustc", "a124_driver.py") or (base.startswith("python") and any(t in args.lower() for t in ("a124", "benchmark", "current-"))) or (comm.startswith("/workspace/research/tmp/") and base != "python3.12"):
        competing.append({"pid": int(pid), "parent": int(parent), "elapsed": elapsed, "command": comm, "args": args})
put(Z / "root/PREBUILD_LIVENESS.json", {"observed_utc": stamp(), "recognized_competing_live": competing, "process_control": False, "global_idle_claim": False})
assert not competing, "Leave existing workloads untouched; do not build concurrently"
files = {str(p.relative_to(Z)): {"sha256": sha(p), "bytes": p.stat().st_size} for p in [Z / "probe/Cargo.toml", Z / "probe/Cargo.lock", Z / "probe/src/main.rs", review, Z / "PROTOCOL.md", Z / "root/FCMA_BOUND.md", Z / "root/HELPER_SOURCE.md", Path(__file__)]}
put(Z / "root/SOURCE_BUILD.json", {"observed_utc": stamp(), "files": files, "native_execution_planned": "metadata only, after frozen image inspection"})
command = ["/opt/homebrew/bin/cargo", "build", "--manifest-path", str(Z / "probe/Cargo.toml"), "--release", "--offline", "--locked", "--jobs", "1", "--target-dir", str(Z / "target")]
with (Z / "logs/build.stdout").open("w") as out, (Z / "logs/build.stderr").open("w") as err:
    process = subprocess.Popen(command, cwd=Z / "probe", stdout=out, stderr=err)
    result = {"started_utc": stamp(), "pid": process.pid, "parent_pid": os.getpid(), "command": command, "status": "running", "target_arithmetic_execution": False}
    put(Z / "logs/BUILD.json", result)
    print(json.dumps(result), flush=True)
    result.update(returncode=process.wait(), ended_utc=stamp(), status="terminal")
    put(Z / "logs/BUILD.json", result)
if result["returncode"] == 0:
    source = Z / "target/release/current-fcma-codegen-probe"
    target = Z / "bin/codegen-probe"
    assert source.exists() and not target.exists()
    shutil.copy2(source, target)
    result.update(binary_path=str(target), binary_bytes=target.stat().st_size, binary_sha256=sha(target))
    put(Z / "logs/BUILD.json", result)
print(json.dumps(result), flush=True)
raise SystemExit(result["returncode"])
