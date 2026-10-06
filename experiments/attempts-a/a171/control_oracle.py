"""A167 independent structure/envelope supplement; frozen A137 arithmetic stays trusted only as labeled."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parents[2] / "tmp/a167-a137-execution-readiness/runtime-validation"
ROOT = HERE.parents[2]
A137 = ROOT / 'tmp/a137-pfks-runtime-error-observer'
BINARY = A137 / 'target-a137-only/release/a137_pfks_runtime_error_observer'
SOURCE_ID = '4d2c1f18a7fb74c7e90a41d4a362f7f2fd5d49a01f1fd7fad250c87fa82648d8'
Q = 1 << 64
OFFSETS = [-48,48,48,-48,0,-48,48,0]
ORDERS = [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]]
SPECS = json.loads((A137/'PREREGISTRATION.json').read_text())['fixture_specs']
DIRECT_COUNTS = dict(direct_pfks=8,direct_monomial_rotations=8,
    direct_polynomial_signed_permutations=16,direct_glwe_additions=7,
    direct_control_ks=1,direct_blind_rotations=1,direct_extractions=4)
COUNTS = dict(PFKS=192,ordinary_KS=48,BR=48,sample_extractions=96)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def eq(a,b,reason):
    need(type(a) is type(b) and a == b, reason)


def integer(v,lo,hi,reason):
    need(type(v) is int and lo <= v <= hi, reason)
    return v


def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def hexhash(s):
    need(type(s) is str and re.fullmatch('[0-9a-f]{64}',s) is not None,'SHA256 syntax')
    return s


def signed(x):
    x %= Q
    return x-Q if x >= Q//2 else x


def centered_degree(x):
    x %= 4096
    return x-4096 if x > 2048 else x


def ms(x):
    return ((x+(1<<51)) >> 52) % 4096


def no_duplicates(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,'duplicate JSON key: '+key)
        result[key]=value
    return result


def reject_number(_):
    raise ValueError('float or nonfinite JSON')


def load(s):
    return json.loads(s,object_pairs_hook=no_duplicates,parse_float=reject_number,parse_constant=reject_number)


def source_check():
    eq(digest(A137/'SHA256SUMS'),SOURCE_ID,'frozen A137 source identity')
    for line in (A137/'SHA256SUMS').read_text().splitlines():
        sha,rel=line.split('  ',1)
        eq(digest(A137/rel),sha,'A137 leaf '+rel)
    for pin in json.loads((A137/'SOURCE_PINS.json').read_text())['sources']:
        eq(digest(ROOT/pin['path']),pin['sha256'],'upstream '+pin['path'])


def frozen_arithmetic(path):
    # Importing has no subprocess call; never call static_audit.audit (which invokes rustfmt).
    sys.path.insert(0,str(A137))
    try:
        spec=importlib.util.spec_from_file_location('a167_frozen_arithmetic',A137/'validate.py')
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.validate_process(path)
    finally:
        sys.path.pop(0)


def function_hash(direct):
    words=[0]*2048
    if direct:
        for z in range(-63,64): words[z%2048]=1 if z//2048%2==0 else Q-1
    else: words[0]=1
    return hashlib.sha256(b''.join(x.to_bytes(8,'little') for x in words)).hexdigest()


def weight(degree,term):
    z=(degree-(4 if term<4 else 12)*128-(term%4)*128)%4096
    if z<=63 or z>=4096-63: return 1
    if 2048-63<=z<=2048+63: return -1
    return 0


def audit_phase(a,expected,delta):
    phase=integer(a['phase'],0,Q-1,'native phase')
    error=signed(phase-expected*delta)
    calculated=dict(decoded=((phase+delta//2)%Q)//delta,signed_error=error,
        absolute_error=abs(error),half_slot_limit_exclusive=delta//2,
        half_slot_pass=abs(error)<delta//2)
    calculated['decode_pass']=calculated['decoded']==expected
    for k,v in calculated.items(): eq(a[k],v,'phase audit '+k)
    need(type(a['nontrivial']) is bool,'source mask predicate type')
    hexhash(a['sha256'])
    return calculated['decode_pass'] and calculated['half_slot_pass'] and a['nontrivial']


def classification(support,prerequisites,semantic):
    return ('support_invalid' if not support else 'inconclusive_inside_support' if not prerequisites
        else 'packed_semantic_failure_inside_support' if not semantic else 'pass')


def check_rows(rows,offset,pid):
    integer(offset,0,2,'order offset');integer(pid,1,1<<31,'Rust PID')
    need(len(rows) in (250,251),'exact raw record count')
    meta=rows[0]
    required=dict(record='meta',artifact='A137',process_id=pid,order_offset=offset,
        tfhe_version='0.11.3',pfks='24x1',params_fingerprint='b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1',
        pfpks_key_bytes_each=67141632,same_base_keys_and_inputs=True,
        functional_keys_independently_encrypted=True,comparator_present=False,tournament_present=False,
        keys_ephemeral=True,secret_key_bytes_persisted=False,contains_secret_derived_observations=True,
        ciphertext_words_persisted=False,phase_polynomial_words_persisted=False,
        support_gate='coefficientwise_modulus_switch_effective_degree')
    for k,v in required.items(): eq(meta[k],v,'meta '+k)
    for key,rel in [('main_source_sha256','src/main.rs'),('observer_source_sha256','src/observer.rs'),('lockfile_sha256','Cargo.lock'),('preregistration_sha256','PREREGISTRATION.json')]:
        eq(meta[key],digest(A137/rel),'producer source '+key)
    keys=meta['key_family_ids'];eq(set(keys),{'constant','window'},'key families')
    need(hexhash(keys['constant']) != hexhash(keys['window']),'distinct functional families')
    index=1; cases=[]; sums=dict(direct_passed=0,convolution_passed=0,scalar_passed=0,effective_support_failures=0,phase_only_support_disagreements=0)
    for f,spec in enumerate(SPECS):
        name=spec['name'];expected=spec['left'] if spec['control']==4 else spec['right']
        def take(kind,**identity):
            nonlocal index
            row=rows[index];index+=1
            eq(row['record'],kind,'record order/type');eq(row['fixture'],name,'fixture order')
            for k,v in identity.items(): eq(row[k],v,'event identity '+k)
            return row
        lanes=[take('lane',lane=j) for j in range(4)]
        arms={}
        for arm in ['direct_window','convolution_a108']:
            direct=arm=='direct_window'
            pfks=[take('pfks_witness',arm=arm,term=j) for j in range(8)]
            acc=take('accumulator_witness',arm=arm)
            noise=[take('noise_lane',arm=arm,lane=j) for j in range(4)]
            arms[arm]=(pfks,acc,noise)
            for j,p in enumerate(pfks):
                eq(p['producer'],f'{name}/{arm}/pfks/{j}','producer ID')
                eq(p['key_family'],'window' if direct else 'constant','functional key')
                eq(p['function_sha256'],function_hash(direct),'actual source function')
                for k in ['input_sha256','pfks_output_sha256','phase_polynomial_sha256','aggregate_key_error_polynomial_sha256','public_digit_words_sha256']: hexhash(p[k])
                eq(p['actual_level_order'],[1],'PFKS level order')
                eq(len(p['actual_body_row_digits']),1,'body row retained')
                integer(p['actual_body_row_digits'][0],-(1<<23),(1<<23),'body digit')
                integer(p['input_phase'],0,Q-1,'PFKS input phase')
                eq(p['primitive_row_errors_independently_measured'],False,'aggregate scope')
            for k in ['pre_br_ciphertext_sha256','pre_br_phase_polynomial_sha256','post_ks_control_sha256','input_control_sha256']: hexhash(acc[k])
            for k in ['modulus_switched_body','secret_weighted_modulus_switched_mask_sum','actual_effective_rotation_degree']: integer(acc[k],0,4095,'MS degree')
            eq(acc['actual_ks_aggregate_error'],signed(acc['post_ks_control_phase']-acc['input_control_phase']),'observed KS difference')
            eq(acc['rounded_phase_degree_diagnostic'],ms(acc['post_ks_control_phase']),'phase-only address')
            eq(acc['diagnostics_after_all_arm_timers'],True,'diagnostic timing scope')
            eq(acc['not_independent_execution_attestation'],True,'aggregate attestation scope')
            if direct: eq(acc['direct_all_ciphertext_words_equal'],True,'direct source reconstruction')
            else: eq(acc['direct_all_ciphertext_words_equal'],None,'convolution reconstruction label')
            for j,n in enumerate(noise):
                degree=acc['actual_effective_rotation_degree']+128*j
                weights=[weight(degree,t) for t in range(8)]
                for t,c in enumerate(n['term_contributions']):
                    eq(c['term'],t,'producer contribution order')
                    eq(c['message_window_weight'],weights[t],'negacyclic message weight')
                eq(n['transmitted_input_error'],signed(sum(weights[t]*pfks[t]['input_error'] for t in range(8))),'transmitted observed input errors')
                eq(n['transmitted_rounding_rho'],signed(sum(weights[t]*int(pfks[t]['rounding_rho_decimal']) for t in range(8))),'transmitted observed rho')
        p,a,_=arms['direct_window'];other,b,_=arms['convolution_a108']
        for x,y in zip(p,other):
            for k in ['input_sha256','input_phase','input_error','input_message_phase','rounding_rho_decimal','rounded_input_phase','public_digit_words_sha256','actual_body_row_digits','actual_level_order']: eq(x[k],y[k],'paired input '+k)
        for k in ['input_control_sha256','post_ks_control_sha256','input_control_phase','post_ks_control_phase','modulus_switched_body','secret_weighted_modulus_switched_mask_sum','actual_effective_rotation_degree']: eq(a[k],b[k],'paired control '+k)
        case=take('case',fixture_index=f)
        eq(case['arm_order'],ORDERS[(f+2*offset)%6],'fixed arm schedule')
        eq(case['requested_control_error'],OFFSETS[f],'requested control offset')
        direct_counter=all(type(case[k]) is int and case[k]==v for k,v in DIRECT_COUNTS.items())
        eq(case['direct_counters_pass'],direct_counter,'direct numeric counters')
        for k in ['scalar_counters_pass','convolution_counters_pass','post_ks_controls_bitwise_equal','observer_identity_pass']: need(type(case[k]) is bool,'case boolean '+k)
        eq(case['observer_identity_pass'],True,'observer closure required')
        control=case['control_phase_audit'];audit_phase(control,spec['control'],1<<59)
        eq(control['phase'],a['post_ks_control_phase'],'control phase binding')
        ingress=all(abs(signed(x['input_phase']-x['input_message_phase']))<(1<<(55 if t%4==3 else 58)) and ((x['input_phase']+(1<<(55 if t%4==3 else 58)))%Q)//(1<<(56 if t%4==3 else 59))==(spec['left']+spec['right'])[t] for t,x in enumerate(p))
        input_control=a['input_control_phase'];integer(input_control,0,Q-1,'input control phase')
        ingress=ingress and abs(signed(input_control-spec['control']*(1<<59)))<(1<<58) and ((input_control+(1<<58))%Q)//(1<<59)==spec['control']
        eq(case['ingress_ok'],ingress,'ingress predicate')
        semantic={arm:True for arm in ['direct','convolution','scalar']}
        for j,lane in enumerate(lanes):
            eq(lane['expected'],expected[j],'expected lane')
            eq(lane['delta_log'],56 if j==3 else 59,'lane scale')
            eq(lane['diagnostics_after_all_arm_timers'],True,'lane timing scope')
            for arm in semantic: semantic[arm] &= audit_phase(lane[arm],expected[j],1<<(56 if j==3 else 59))
        eq(case['scalar_ok'],semantic['scalar'],'scalar phase predicate')
        prerequisite=ingress and control['decode_pass'] and control['half_slot_pass'] and case['post_ks_controls_bitwise_equal'] and semantic['scalar'] and case['scalar_counters_pass']
        eq(case['prerequisites_ok'],prerequisite,'prerequisites')
        error=centered_degree(a['actual_effective_rotation_degree']-spec['control']*128)
        phase_degree=ms(control['phase']);phase_error=centered_degree(phase_degree-spec['control']*128)
        support=abs(error)<=63
        for k,v in [('actual_effective_rotation_error',error),('rounded_decrypted_phase_degree_diagnostic',phase_degree),('rounded_decrypted_phase_error_diagnostic',phase_error),('support_ok',support),('phase_only_support_ok_diagnostic',abs(phase_error)<=63)]: eq(case[k],v,k)
        for arm in ['direct','convolution']:
            label=classification(support,prerequisite and case[arm+'_counters_pass'],semantic[arm])
            eq(case[arm+'_class'],label,arm+' classification')
            sums[arm+'_passed']+=int(label=='pass')
        sums['scalar_passed']+=int(semantic['scalar'] and case['scalar_counters_pass'])
        sums['effective_support_failures']+=int(not support)
        sums['phase_only_support_disagreements']+=int(support != (abs(phase_error)<=63))
        cases.append({k:case[k] for k in ['fixture','direct_class','convolution_class','support_ok','scalar_ok']})
    summary=rows[index];index+=1
    passed=sums['direct_passed']==8
    for k,v in dict(record='summary',artifact='A137',process_id=pid,order_offset=offset,fixture_cases=8,observer_failures=0,fresh_keysets=1,minimum_fresh_processes=3,comparator_present=False,tournament_present=False,p_fail_proven=False,runtime_frontier_promoted=False,performance_interpretation_allowed=False,status='PASS_DIRECT_SINGLE_KEY_COMPONENT' if passed else 'FAIL_DIRECT_COMPONENT',**sums).items(): eq(summary[k],v,'summary '+k)
    if not passed:
        eq(len(rows),251,'completed failure fatal count')
        fatal=rows[index];index+=1
        for k,v in dict(record='fatal',artifact='A137',reason=f"direct arm passed {sums['direct_passed']}/8 cases",performance_interpretation_allowed=False).items(): eq(fatal[k],v,'fatal '+k)
    eq(index,len(rows),'unknown/trailing records')
    return dict(structure_pass=True,direct_component_pass=passed,convolution_component_pass=sums['convolution_passed']==8,scalar_reference_pass=sums['scalar_passed']==8,cases=cases,summary=sums,key_family_ids=keys,source_bound_counts_one_process=COUNTS)


def private_path(p,directory=False):
    p=Path(p)
    for part in [p,*p.parents]: need(not part.is_symlink(),'symlink path')
    info=p.stat();mode=info.st_mode
    eq(info.st_uid,os.getuid(),'file owner')
    need(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode),'regular private object')
    eq(stat.S_IMODE(mode),0o700 if directory else 0o600,'owner-only permissions')


def utc(s):
    need(type(s) is str,'UTC string')
    value=dt.datetime.fromisoformat(s.replace('Z','+00:00'))
    need(value.tzinfo is not None and value.utcoffset()==dt.timedelta(0),'UTC offset')
    return value


def envelope(prepared,child,terminal,run,binary,binary_hash,stdout_hash,stderr_hash):
    eq(prepared['schema'],'a167.root-prepared.v1','prepared schema')
    eq(child['schema'],'a167.root-child.v1','child schema')
    eq(terminal['schema'],'a167.root-exit.v1','exit schema')
    run_id=prepared['run_id'];need(type(run_id) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',run_id) is not None,'run id')
    offset=integer(prepared['order_offset'],0,2,'offset')
    env={'RAYON_NUM_THREADS':'1','A137_ORDER_OFFSET':str(offset),'A137_RUN_FHE':'I_ACKNOWLEDGE_A137_DIRECT_WINDOW_PFKS_FHE','A137_PREREGISTRATION_SHA256':digest(A137/'PREREGISTRATION.json')}
    for row in [prepared,child,terminal]:
        for k,v in dict(run_id=run_id,run_dir=str(run),binary=str(binary),binary_sha256=binary_hash,source_sha256=SOURCE_ID).items(): eq(row[k],v,'envelope '+k)
    eq(prepared['command'],[str(binary),'--run-authorized','--pfks','24x1'],'exact direct-child command')
    eq(prepared['cwd'],str(A137),'cwd')
    eq(prepared['required_env'],env,'required env')
    for k,v in [('stdout',str(run/'stdout.jsonl')),('stderr',str(run/'stderr.txt'))]: eq(prepared[k],v,'log path')
    pid=integer(child['pid'],1,1<<31,'child pid');eq(terminal['pid'],pid,'exit pid')
    eq(terminal['stdout_sha256'],stdout_hash,'stdout hash');eq(terminal['stderr_sha256'],stderr_hash,'stderr hash')
    need(type(terminal['exit_code']) is int and terminal['exit_code'] in (0,1),'complete semantic exit')
    need(utc(prepared['prepared_utc'])<=utc(child['started_utc'])<=utc(terminal['finished_utc']),'UTC chronology')
    return pid,offset


def verify_run(directory):
    source_check()
    run=Path(directory).absolute();private_path(run,True)
    eq(str(run),str(run.resolve()),'canonical run directory')
    for name in ['prepared.json','child.json','exit.json','stdout.jsonl','stderr.txt']: private_path(run/name)
    prepared,child,terminal=[load((run/name).read_text()) for name in ['prepared.json','child.json','exit.json']]
    need(not BINARY.is_symlink() and BINARY.is_file(),'frozen executable file')
    binary_hash=digest(BINARY)
    pid,offset=envelope(prepared,child,terminal,run,BINARY,binary_hash,digest(run/'stdout.jsonl'),digest(run/'stderr.txt'))
    lines=(run/'stdout.jsonl').read_text().splitlines()
    need(all(line.strip() for line in lines),'blank runtime record')
    rows=[load(line) for line in lines];need(all(type(r) is dict for r in rows),'record objects')
    checked=check_rows(rows,offset,pid)
    old=frozen_arithmetic(run/'stdout.jsonl')
    eq(terminal['exit_code'],0 if checked['direct_component_pass'] else 1,'semantic exit/status')
    eq(old['direct_passed'],checked['summary']['direct_passed'],'frozen arithmetic summary')
    source_check();eq(digest(BINARY),binary_hash,'executable unchanged during replay')
    return dict(schema='a167.verified-run.v1',status='PASS_COMPONENT' if checked['direct_component_pass'] else 'VALID_COMPLETED_COMPONENT_FAILURE',run_id=prepared['run_id'],run_dir=str(run),pid=pid,order_offset=offset,source_sha256=SOURCE_ID,binary_sha256=binary_hash,prepared_utc=prepared['prepared_utc'],finished_utc=terminal['finished_utc'],stdout_sha256=terminal['stdout_sha256'],stderr_sha256=terminal['stderr_sha256'],**checked,independent_ciphertext_replay=False,primitive_row_errors_independently_measured=False,key_membership_attested=False,base_key_uniqueness_attested=False,actual_p_fail=None,performance_interpretation_allowed=False)


def aggregate(reports):
    need(len(reports) in (1,3),'one smoke or complete three-process set')
    eq([r['order_offset'] for r in reports],list(range(len(reports))),'aggregate offset schedule')
    for k in ['run_id','run_dir','pid','stdout_sha256']:
        need(len({r[k] for r in reports})==len(reports),'repeated process binding '+k)
    for k in ['binary_sha256','source_sha256']:need(len({r[k] for r in reports})==1,'mixed build '+k)
    keyids=[v for r in reports for v in r['key_family_ids'].values()]
    need(len(set(keyids))==2*len(reports),'reused functional key IDs')
    for left,right in zip(reports,reports[1:]):need(utc(left['finished_utc'])<=utc(right['prepared_utc']),'overlapping/nonchronological processes')
    passed=all(r['direct_component_pass'] for r in reports)
    return dict(schema='a167.aggregate.v1',status='PASS_8_OF_8_SINGLE_KEY_SMOKE' if passed and len(reports)==1 else 'PASS_24_OF_24_DIRECT_COMPONENT' if passed else 'VALID_COMPLETED_COMPONENT_FAILURE',full_three_process_gate_complete=passed and len(reports)==3,direct_component_pass=passed,convolution_component_pass=all(r['convolution_component_pass'] for r in reports),scalar_reference_pass=all(r['scalar_reference_pass'] for r in reports),processes=reports,actual_p_fail=None,performance_interpretation_allowed=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path,nargs='+');parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=aggregate([verify_run(p) for p in args.run])
    private_path(args.output.parent,True)
    # O_EXCL via x; no overwrite of prior evidence. chmod before writing sensitive report.
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(result,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
    print(json.dumps({'status':result['status'],'output':str(args.output),'actual_p_fail':None}))
    return 0 if result['direct_component_pass'] else 1

if __name__=='__main__':
    raise SystemExit(main())
