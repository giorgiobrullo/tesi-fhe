from pathlib import Path
import os,json,hashlib,subprocess,time,datetime,shutil
M=Path('/workspace/research/tmp/current-merge-profile-20261004')
runtime=M/'runtimes/profile';cache=Path('/workspace/research/tmp/current-build-timing-20261004/targets/baseline')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
save=lambda p,d:p.write_text(json.dumps(d,indent=2)+'\n')
compiler=subprocess.check_output(['/opt/homebrew/bin/rustc','-Vv'],text=True).strip()
assert compiler.startswith('rustc 1.98.1 ')
pins={str(p.relative_to(runtime)):sha(p) for p in runtime.rglob('*') if p.is_file()}
assert len(pins)==134
snapshot={'files':pins,'compiler_identity':compiler}
save(M/'SOURCE_AFTER_BINDINGS.json',snapshot)
env=os.environ.copy()
for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTFLAGS']:
 env.pop(key,None)
env.update(CARGO_TARGET_DIR=str(cache),CARGO_PROFILE_RELEASE_OPT_LEVEL='3',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',CARGO_PROFILE_RELEASE_LTO='false',RUSTC='/opt/homebrew/bin/rustc')
command=['/opt/homebrew/bin/cargo','build','--release','--locked','--offline','--manifest-path',str(runtime/'Cargo.toml')]
start=datetime.datetime.now(datetime.timezone.utc).isoformat(); t0=time.monotonic()
with (M/'logs/build.stdout').open('xb') as out,(M/'logs/build.stderr').open('xb') as err:
 p=subprocess.Popen(command,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
 save(M/'logs/build-launch.json',{'utc':start,'pid':p.pid,'command':command,'target_cache':str(cache)})
 print(json.dumps({'build_pid':p.pid,'started_utc':start}),flush=True)
 rc=p.wait()
receipt={'started_utc':start,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'returncode':rc,'elapsed_s':time.monotonic()-t0,'compiler_identity':compiler,'build_settings':{'profile':'release','opt_level':3,'codegen_units':1,'lto':False,'cargo_locked':True,'cargo_offline':True,'rustflags':None,'target':'aarch64-apple-darwin'},'source_snapshot_sha256':sha(M/'SOURCE_AFTER_BINDINGS.json')}
if rc==0:
 dest=M/'bin/merge-profile';assert not dest.exists();shutil.copy2(cache/'release/varco_demo_composite_v9',dest)
 receipt.update(binary_sha256=sha(dest),binary_path=str(dest))
save(M/'logs/build.json',receipt);print(json.dumps(receipt),flush=True)
raise SystemExit(rc)
