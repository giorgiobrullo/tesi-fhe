from pathlib import Path
import subprocess,os,json,sys,datetime,time,hashlib
P=Path(__file__).resolve().parents[1];R=P.parents[1]
mode=sys.argv[1];assert mode in ('valid1',)
review=P/'root/SOURCE_REVIEW.md';assert review.exists() and 'PASS' in review.read_text()
correction=P/'root/HARNESS_CORRECTION_REVIEW.md';assert correction.exists() and 'PASS' in correction.read_text()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(name,value):
 with (P/'root'/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
def continuity(message):
 state=R/'RESEARCH_STATE.md';state.write_text('# Torneo DAG: processo proprio\n\n'+message+'\n\nLeggere docs/research-state/2026-10-04/CURRENT_TOURNAMENT_DAG.md e tmp/current-tournament-dag-20261004/PROTOCOL. Goalactive locale, nessun controllo su altri processi.\n\n'+state.read_text())
 with (R/'docs/research-state/2026-10-04/CURRENT_TOURNAMENT_DAG.md').open('a') as f:f.write('\n'+message+'\n')
args=['/opt/homebrew/bin/cargo']
if mode=='tests':args+=['test','--offline','--release','--manifest-path',str(P/'runtime/core/Cargo.toml'),'--lib','dag_scheduler::tests','--','--test-threads=1']
else:args+=['build','--offline','--release','--manifest-path',str(P/'probe-valid1/Cargo.toml')]
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(P/'target');env['RUSTFLAGS']='-C target-cpu=native'
start=time.monotonic();utc=now()
with (P/'root'/f'{mode.upper()}_BUILD.log').open('xb') as log:
 process=subprocess.Popen(args,cwd=P,env=env,stdout=log,stderr=subprocess.STDOUT)
 record={'started_utc':utc,'driver_pid':os.getpid(),'cargo_pid':process.pid,'args':args,'target_dir':env['CARGO_TARGET_DIR'],'rustflags':env['RUSTFLAGS'],'source_review_sha256':hashlib.sha256(review.read_bytes()).hexdigest(),'native_runs':0,'keys':0,'correction_review_sha256':hashlib.sha256(correction.read_bytes()).hexdigest()}
 save(f'{mode.upper()}_START.json',record)
 message=f'{utc}: root {mode} build started, driverPID{os.getpid()} CargoPID{process.pid}, sole owned run. Log root/{mode.upper()}_BUILD.log; source review hash {record["source_review_sha256"]}. Valid1 native/key runs0; earlier invalid campaign family1 preserved; no competing build observed by PREBUILD, no other process controlled.'
 continuity(message);print(json.dumps(record),flush=True)
 code=process.wait()
record.update({'finished_utc':now(),'exit_code':code,'wall_seconds':time.monotonic()-start,'cargo_exit_observed':True})
save(f'{mode.upper()}_EXIT.json',record)
continuity(f'{record["finished_utc"]}: root {mode} build terminal exit{code}; CargoPID{process.pid} exited, driverPID{os.getpid()} ending. Log preserved. Valid1 native/key runs0; earlier invalid campaign family1 preserved; tests/build result must be read before advancing.')
print(json.dumps(record),flush=True);sys.exit(code)
