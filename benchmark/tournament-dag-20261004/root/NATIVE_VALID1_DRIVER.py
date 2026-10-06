from pathlib import Path
import subprocess,os,json,datetime,time,hashlib,sys
P=Path(__file__).resolve().parents[1];R=P.parents[1]
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def pin(p):
 b=p.read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def save(name,value):
 with (P/'root'/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
def continuity(message):
 state=R/'RESEARCH_STATE.md';state.write_text('# Torneo DAG: campagna propria\n\n'+message+'\n\nLeggere docs/research-state/2026-10-04/CURRENT_TOURNAMENT_DAG.md e tmp/current-tournament-dag-20261004/PROTOCOL. Goalactive locale, nessun controllo su altri processi.\n\n'+state.read_text())
 with (R/'docs/research-state/2026-10-04/CURRENT_TOURNAMENT_DAG.md').open('a') as f:f.write('\n'+message+'\n')
for mode in ('TESTS','VALID1'):assert json.loads((P/'root'/f'{mode}_EXIT.json').read_text())['exit_code']==0
assert 'test result: ok. 2 passed; 0 failed' in (P/'root/TESTS_BUILD.log').read_text()
assert json.loads((P/'root/PRENATIVE_VALID1.json').read_text())['matching_build_or_project_processes']==[]
source=json.loads((P/'root/SOURCE_CANDIDATE.json').read_text())['files']
for rel,expected in source.items():assert pin(P/rel)==expected,rel
correction=P/'root/HARNESS_CORRECTION_REVIEW.md';assert correction.exists() and 'PASS' in correction.read_text()
valid=json.loads((P/'root/VALID1_SOURCE.json').read_text())['files']
for rel,expected in valid.items():assert pin(P/rel)==expected,rel
binary=P/'target/release/current_tournament_dag_probe_valid1_20261004';assert binary.exists()
start=time.monotonic();utc=now()
with (P/'root/NATIVE_VALID1.ndjson').open('xb') as log:
 process=subprocess.Popen([str(binary)],cwd=P,stdout=log,stderr=subprocess.STDOUT)
 record={'started_utc':utc,'driver_pid':os.getpid(),'native_pid':process.pid,'binary_path':str(binary),'binary':pin(binary),'preregistered_key_families':1,'frozen_envelopes_read':False,'source_review_sha256':pin(P/'root/SOURCE_REVIEW.md')['sha256'],'raw_path':str(P/'root/NATIVE_VALID1.ndjson'),'campaign':'valid1','correction_review_sha256':pin(correction)['sha256']}
 save('NATIVE_VALID1_START.json',record)
 continuity(f'{utc}: root native started, driverPID{os.getpid()} childPID{process.pid}; binarySHA256{record["binary"]["sha256"]}. Two new scheduler tests passed; helperbuildexit0. Fresh one-family RAM campaign, no frozenpayload or phases logged; raw root/NATIVE_VALID1.ndjson. Otherprocesscontrolfalse, no competing project/build in PRENATIVE.')
 print(json.dumps(record),flush=True);code=process.wait()
record.update({'finished_utc':now(),'exit_code':code,'wall_seconds':time.monotonic()-start,'native_exit_observed':True,'raw':pin(P/'root/NATIVE_VALID1.ndjson')})
save('NATIVE_VALID1_EXIT.json',record)
continuity(f'{record["finished_utc"]}: root native terminal exit{code}; childPID{process.pid} exited, driverPID{os.getpid()} ending. RawSHA256{record["raw"]["sha256"]}. No retry/rekey within this admitted campaign; earlier input-invalid campaign preserved; result/review still required before claiming correctness or speed.')
print(json.dumps(record),flush=True);sys.exit(code)
