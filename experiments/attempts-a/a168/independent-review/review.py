"""Independent read-only review of one completed A168 pilot; never launches code."""
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path

HERE=Path(__file__).resolve().parent
A168=HERE.parent
ROOT=A168.parents[1]
RUN=A168/'runs/pilot-key1'
REPORT=ROOT/'docs/research-state/2026-09-05/a168-pilot-key1-review.json'
FIGURE=ROOT/'docs/research-state/2026-09-05/fusion-pilot-figure'


def need(value,message):
    if not value:raise ValueError(message)


def eq(actual,expected,label):need(type(actual) is type(expected) and actual==expected,label)


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def read(path):return json.loads(Path(path).read_text())


def utc(text):
    value=datetime.fromisoformat(text)
    need(value.utcoffset().total_seconds()==0,'UTC timestamp')
    return value


def median(values):
    values=sorted(values)
    size=len(values)
    return values[size//2] if size%2 else (values[size//2-1]+values[size//2])/2


def main():
    report=read(REPORT)
    artifact=read(A168/'ARTIFACT_MANIFEST.json')
    eq(len(artifact),25,'25 frozen pilot artifact leaves')
    for name,h in artifact.items():eq(sha(A168/name),h,'frozen artifact '+name)
    source=read(A168/'SOURCE_MANIFEST.json')
    for name,h in source.items():eq(sha(A168/name),h,'frozen source '+name)
    source_id=hashlib.sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    eq(source_id,report['source_sha256'],'exact canonical source ID')
    eq((A168/'candidate/SOURCE_DIGEST.txt').read_text().strip(),source_id,'embedded source ID')
    origins=read(A168/'SOURCE_PINS.json')['sources']
    for path,h in origins.items():eq(sha(path),h,'pinned origin '+path)
    for name in ['src/private_argmin.rs','src/a53_scan.rs','src/a53_scan/fhe.rs','src/lib.rs','artifacts/fused_candidate_zero_body.u64le']:
        eq((A168/'candidate'/name).read_bytes(),(ROOT/'tmp/a126-refresh-schedule-gate'/name).read_bytes(),'untraced A126 source '+name)
    launcher=read(A168/'LAUNCHER_MANIFEST.json')
    for name,h in launcher['files'].items():eq(sha(A168/name),h,'corrected launcher leaf '+name)
    eq(sha(A168/'ARTIFACT_MANIFEST.json'),launcher['preserved_pilot_manifest_sha256'],'unchanged original freeze')
    eq(sha(A168/'run_pilot.py'),report['launcher_sha256'],'corrected actual launcher')
    binary=A168/'candidate/target-a168-only/release/a168_refresh_pair_pilot'
    eq(sha(binary),report['binary_sha256'],'actual current executable')
    eq(RUN.stat().st_mode&0o777,0o700,'private run directory')
    for path,h in report['runtime_files'].items():
        path=ROOT/path
        need(path.is_file() and not path.is_symlink(),'regular runtime file')
        eq(path.stat().st_mode&0o777,0o600,'private runtime file')
        eq(sha(path),h,'actual run artifact '+str(path))
    for marker in ['interrupted.json','launch-failure.json','validation-failure.json']:
        need(not (RUN/marker).exists(),'no incomplete or rejected run marker')
    prepared,child,terminal,preflight=[read(RUN/name) for name in ['prepared.json','child.json','exit.json','preflight.json']]
    for row in [prepared,child,terminal]:
        for field,value in [('run_id','pilot-key1'),('source_sha256',source_id),('binary_sha256',report['binary_sha256']),('launcher_sha256',report['launcher_sha256'])]:eq(row[field],value,'launch continuity '+field)
    eq(prepared['command'],[str(binary),'--run-pilot',str(RUN),'pilot-key1'],'fixed direct child command')
    eq(prepared['status'],'PREPARED','prepared status')
    eq(terminal['status'],'EXITED','terminal status')
    eq(terminal['exit_code'],0,'successful actual exit')
    eq(terminal['child_pid'],child['child_pid'],'child lifecycle')
    eq(child['child_pid'],report['child_pid'],'root report child')
    eq(child['started_at_utc'],report['started_at_utc'],'root start time')
    eq(terminal['exited_at_utc'],report['exited_at_utc'],'root exit time')
    need(prepared['driver_pid']!=child['child_pid'],'driver distinct from actual child')
    need(utc(prepared['prepared_at_utc'])<=utc(child['started_at_utc'])<=utc(terminal['exited_at_utc']),'UTC chronological lifecycle only')
    for key in ['binary_unchanged','source_unchanged','launcher_unchanged']:eq(terminal[key],True,'terminal '+key)
    eq(terminal['terminal_verification_errors'],{},'no terminal artifact-check errors')
    for name,field in [('records.jsonl','records_sha256'),('stdout.log','stdout_sha256'),('stderr.log','stderr_sha256')]:eq(sha(RUN/name),terminal[field],'terminal log '+name)
    eq((RUN/'stderr.log').read_bytes(),b'','empty actual stderr')
    for field,value in [('source_sha256',source_id),('binary_sha256',report['binary_sha256']),('run_id','pilot-key1'),('collector_qualified',False),('guard_status','ROOT_ASSERTION_ONLY_NOT_ALIGNED_CPU_EVIDENCE')]:eq(preflight[field],value,'declared preflight '+field)
    need(0<=(utc(prepared['prepared_at_utc'])-utc(preflight['observed_utc'])).total_seconds()<=60,'preflight freshness only')
    raw=(RUN/'records.jsonl').read_bytes();need(raw.endswith(b'\n'),'terminal raw newline')
    rows=[json.loads(line) for line in raw.decode().splitlines()]
    eq([r['record'] for r in rows],['run_start','prepared_block']+['pair_timing']*6+['pair_validation']*6+['summary'],'all15 fixed ordered records')
    start,block=rows[:2];summary=rows[-1];plan=read(A168/'PILOT.json')
    for field,value in [('pid',child['child_pid']),('source_sha256',source_id),('binary_sha256',report['binary_sha256']),('plan_sha256',sha(A168/'PILOT.json')),('core_sha256',sha(A168/'candidate/src/private_argmin.rs')),('schema','a168.pilot.v1'),('threads_requested',8),('trace_feature',False),('speedup_promotion_allowed',False),('actual_p_fail',None),('guard_status','UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR')]:eq(start[field],value,'actual start field '+field)
    eq(block['fresh_keys'],1,'one key block');eq(block['ciphertexts_pre_encrypted'],6,'six pre-encrypted inputs')
    eq(len(set(block['input_hashes'])),6,'six distinct reported encrypted inputs')
    eq(block['expected_code'],127,'expected ID');eq(block['domain'],[-1024,1962],'execution domain')
    pairs=[];previous_end=0
    for index,(row,expected,validated) in enumerate(zip(rows[2:8],plan['pairs'],rows[8:14])):
        for field,value in expected.items():eq(row[field],value,'fixed schedule '+field)
        eq(row['sequence'],index,'complete pair sequence')
        eq(row['key_id'],block['key_id'],'same reported key ID')
        eq(row['input_sha256'],block['input_hashes'][index],'same prepared input')
        eq(row['outputs_inspected'],False,'no output observer before timing complete')
        eq(row['same_key_gallery_input_source_binding'],True,'declared same source objects')
        eq(row['guard_status'],'UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR','pair unqualified guard')
        bounds={}
        for arm in ['baseline','fused']:
            begin,end,wall=[row[arm+'_'+suffix] for suffix in ['start_ns','end_ns','wall_ns']]
            need(all(type(n) is int for n in [begin,end,wall]),'integer native ns')
            need(0<=begin<end,'positive within-arm window');eq(end-begin,wall,'same-epoch wall subtraction')
            bounds[arm]=(begin,end)
        first,second=('baseline','fused') if row['order']=='AB' else ('fused','baseline')
        need(previous_end<=bounds[first][0] and bounds[first][1]<=bounds[second][0],'actual order/nonoverlap')
        previous_end=bounds[second][1]
        eq(validated['sequence'],index,'validation schedule')
        eq(validated['input_sha256'],row['input_sha256'],'retained input hash')
        eq(validated['pass'],True,'pair output/count success')
        eq([arm['arm'] for arm in validated['arms']],['A','B'],'two arm outputs')
        for arm,(label,stages,total) in zip(validated['arms'],[('A',[1651,1603,136],3390),('B',[1651,1476,136],3263)]):
            for field,value in [('arm',label),('evaluation_ok',True),('pass',True),('low',7),('high',8),('code',127),('stage_br',stages),('total_br',total)]:eq(arm[field],value,'actual output/count '+field)
            eq(sum(arm['stage_br']),arm['total_br'],'stage-total BR closure')
        if row['phase']=='measured':
            a,b=row['baseline_wall_ns'],row['fused_wall_ns'];reduction=Fraction(a-b,a)
            pairs.append(dict(sequence=index,order=row['order'],baseline_ns=a,fused_ns=b,
                paired_fractional_reduction=str(reduction),paired_reduction_percent=float(reduction)*100))
    for field,value in [('status','PILOT_COMPLETE'),('pairs',6),('warmup_pairs',2),('measured_pairs',4),('evaluations',12),('pairs_pass',6),('all_correct',True),('guard_status','UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR'),('speedup_promotion_allowed',False),('confidence_interval',None),('actual_p_fail',None)]:eq(summary[field],value,'terminal summary '+field)
    reductions=[Fraction(p['paired_fractional_reduction']) for p in pairs]
    primary=median(reductions)
    arm_medians={arm:median([Fraction(p[arm+'_ns']) for p in pairs]) for arm in ['baseline','fused']}
    validation=read(RUN/'validation.json')
    for got,wanted in zip(report['measured_pairs'],pairs):
        for key,value in wanted.items():
            if key=='paired_reduction_percent':need(math.isclose(got[key],value,rel_tol=1e-14),'display pair percent')
            else:eq(got[key],value,'root paired data '+key)
    for key,value in [('median_paired_fractional_reduction',str(primary)),('baseline_median_ns',str(arm_medians['baseline'])),('fused_median_ns',str(arm_medians['fused']))]:
        eq(report[key],value,'root arithmetic '+key);eq(validation[key],value,'frozen replay arithmetic '+key)
    need(math.isclose(report['median_paired_reduction_percent'],100*float(primary),rel_tol=1e-14),'root primary display')
    for key,value in [('speedup_promotion_allowed',False),('confidence_interval',None),('actual_p_fail',None),('guard_status','UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR')]:
        eq(report[key],value,'root scope '+key);eq(validation[key],value,'frozen replay scope '+key)
    for key in ['service_promotion','comparison_to_other_thread_or_version_results_allowed']:eq(report[key],False,'no broader root claim')
    figure=read(FIGURE/'data.json')
    eq(figure['source_review_sha256'],sha(REPORT),'figure bound safe review')
    for key in ['measured_pairs','median_paired_fractional_reduction','baseline_median_ns','fused_median_ns','guard_status','speedup_promotion_allowed','confidence_interval']:eq(figure[key],report[key],'figure data '+key)
    pin_paths=[A168/'ARTIFACT_MANIFEST.json',A168/'LAUNCHER_MANIFEST.json',A168/'SOURCE_MANIFEST.json',A168/'run_pilot.py',A168/'candidate/src/main.rs',REPORT,*[RUN/name for name in ['prepared.json','child.json','exit.json','preflight.json','records.jsonl','validation.json']],*[FIGURE/name for name in ['data.json','make_figure.py','fusion-pilot-pairs.png','fusion-pilot-pairs.svg']]]
    result=dict(status='INDEPENDENT_REVIEW_PASS_DESCRIPTIVE_PILOT_ONLY',checked_at_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=source_id,binary_sha256=report['binary_sha256'],launcher_sha256=report['launcher_sha256'],
        frozen_artifact_leaves=25,source_leaves=len(source),upstream_source_pins=len(origins),corrected_launcher_leaves=len(launcher['files']),
        ordered_records=15,pairs=6,excluded_preregistered_warmups=2,measured_pairs=pairs,evaluations=12,
        all_outputs_and_br_counts_pass=True,primary='median of four signed per-pair (A_ns-B_ns)/A_ns reductions',
        median_paired_fractional_reduction=str(primary),median_paired_reduction_percent=100*float(primary),
        baseline_median_ns=str(arm_medians['baseline']),fused_median_ns=str(arm_medians['fused']),
        baseline_median_seconds=float(arm_medians['baseline']/10**9),fused_median_seconds=float(arm_medians['fused']/10**9),
        all_measured_pairs_favor_fusion=all(value>0 for value in reductions),guard_status='UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR',
        independent_key_trials=1,statistical_independence_attested=False,os_timebase_alignment_attested=False,
        controlled_speedup_claim_allowed=False,confidence_interval=None,actual_p_fail=None,service_promotion=False,
        ratio_of_arm_medians_not_used_as_primary=True,figure_data_and_visible_labels_faithful=True,
        material_issues=[],files_sha256={str(p):sha(p) for p in pin_paths})
    with os.fdopen(os.open(HERE/'RESULT.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:json.dump(result,out,indent=2);out.write('\n')
    print(json.dumps({k:result[k] for k in ['status','median_paired_reduction_percent','baseline_median_seconds','fused_median_seconds','material_issues']}))

if __name__=='__main__':main()
