from pathlib import Path
import json,subprocess,time,os,hashlib,datetime
M=Path('/workspace/research/tmp/current-merge-profile-20261004');binary=M/'bin/merge-profile';keys=M/'keys/family1'
assert not keys.exists();assert json.loads((M/'logs/build.json').read_text())['returncode']==0
started=datetime.datetime.now(datetime.timezone.utc).isoformat(); t0=time.monotonic()
env=dict(os.environ,RAYON_NUM_THREADS='16');env.pop('VARCO_PROFILE_PHASES',None)
with (M/'logs/keygen.stdout').open('xb') as out,(M/'logs/keygen.stderr').open('xb') as err:
 process=subprocess.Popen([str(binary),'keygen',str(keys)],env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
 print(json.dumps({'keygen_pid':process.pid,'started_utc':started}),flush=True);rc=process.wait()
assert rc==0,rc
records=[json.loads(line) for line in (M/'logs/keygen.stdout').read_text().splitlines() if line.startswith('{')];assert len(records)==1
r=records[0];assert r['bundle_roundtrip_equal'] and r['bundle_validation_pass']
r.update(measured_preparation_wall_s=time.monotonic()-t0,origin='Fresh source-bound key for designated merge diagnostic; normal bundle roundtrip.',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),keydir=str(keys),started_utc=started,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
(M/'logs/keygen.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r),flush=True)
