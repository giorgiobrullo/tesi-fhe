"""Private, read-only diagnosis of terminal A165 smoke; no encrypted execution."""
import hashlib
import json
import os
from pathlib import Path

HERE=Path(__file__).resolve().parent
VALIDATOR=HERE.parents[1]
A165=VALIDATOR.parent
RUN=A165/'runs/smoke-key1'
OLD='single_full_reuse_x256'
REPAIR='single_full_direct_b1'
Q=1<<64


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    result=json.loads((VALIDATOR/'artifacts/smoke-key1-validation.json').read_text())
    assert result['status']=='PASS_RECORD_CONSISTENCY'
    assert result['launch_binding']['exit_code']==1 and not result['summary']['repair_gate_pass']
    assert sha(RUN/'stdout.jsonl')==result['launch_binding']['files_sha256']['stdout.jsonl']
    rows=[json.loads(line) for line in (RUN/'stdout.jsonl').read_text().splitlines()]
    def select(record,arm,scene,x,**more):
        return [r for r in rows if r['record']==record and r.get('arm')==arm and r.get('scene')==scene and r.get('x')==x and all(r.get(k)==v for k,v in more.items())]
    failures=[]
    for case in rows:
        if case['record']!='case' or case.get('arm') not in (OLD,REPAIR) or case['pass']:continue
        arm,scene,x=case['arm'],case['scene'],case['x']
        bad=[r for r in select('consumer_scalar_phase',arm,scene,x) if not r['pass']]
        for bit in sorted({r['bit'] for r in bad}):
            original=select('phase',arm,scene,x,stage=f'full.pbs_correction_b{bit}')[0]
            amplified=select('phase',arm,scene,x,stage=f'full.correction_x256_b{bit}')[0]
            assert int(original['phase'])*256%Q==int(amplified['phase'])
            assert int(original['signed_error'])*256==int(amplified['signed_error'])
            selected_stage=f'repair_b1.pbs_correction_b1' if arm==REPAIR and bit==1 else f'full.correction_x256_b{bit}'
            selected=select('phase',arm,scene,x,stage=selected_stage)[0]
            compare_stage='repair_b1.pbs_correction_b1' if bit==1 else f'full.correction_x256_b{bit}'
            repaired=select('phase',REPAIR,scene,x,stage=compare_stage)[0]
            repair_bad=[r for r in select('consumer_scalar_phase',REPAIR,scene,x,bit=bit) if not r['pass']]
            failures.append(dict(arm=arm,scene=scene,x=x,bit=bit,level=7-bit,
                original_raw=select('phase',arm,scene,x,stage=f'full.pbs_raw_b{bit}')[0],
                original_correction=original,amplified_correction=amplified,
                actual_retained_small_input=select('phase',arm,scene,x,stage=f'full.ks_b{bit}')[0],
                selected_weighted_phase=selected,
                margin=select('weighted_p16_margin',arm,scene,x,bit=bit)[0],
                native=select('weighted_bit',arm,scene,x,bit=bit)[0],
                failed_scalar_predicates=[r for r in bad if r['bit']==bit],
                repair_comparison=dict(selected_phase=repaired,margin=select('weighted_p16_margin',REPAIR,scene,x,bit=bit)[0],
                    native=select('weighted_bit',REPAIR,scene,x,bit=bit)[0],failed_scalar_predicates=repair_bad,
                    same_selected_ciphertext=selected['ciphertext_sha256']==repaired['ciphertext_sha256']),
                actual_downstream_pbs_executed=False))
    b1=[r for r in rows if r['record']=='consumer_scalar_phase' and r.get('arm')==REPAIR and r['bit']==1]
    pairs=[r for r in rows if r['record']=='repair_pair']
    summary=dict(schema='a165-private-smoke-diagnosis-v1',status='VALID_NEGATIVE_REPAIR_B0_CONSUMER_FAILURE',
        binding_sha256=sha(VALIDATOR/'artifacts/smoke-key1-validation.json'),
        source_files_sha256={str(p):sha(p) for p in [RUN/'stdout.jsonl',RUN/'exit.json',
            VALIDATOR/'MANIFEST.json',A165/'SOURCE_MANIFEST.json',A165/'candidate/src/diagnostic.rs']},
        actual_exit_code=1,original_summary=result['summary'],
        repaired_b1_scalar_predicates=len(b1),repaired_b1_scalar_failures=sum(not r['pass'] for r in b1),
        repair_pair_count=len(pairs),repair_pair_failures=sum(not r['pass'] for r in pairs),
        failure_details=failures,
        diagnosis='b1 direct output removes the sparse x17 b1 failure; dense x1024 b0 stays byte-identical and fails the scalar consumer.',
        x256_amplification_observed_error_identity=True,
        input_address_cause_or_output_noise_distribution_proved=False,
        actual_composed_consumer_pbs_validated=False,p_fail_proven=False,
        next_changed_premise=dict(candidate='direct b0 plus direct b1, both from retained original small inputs',
            preserve_original_full_residual_corrections=True,b0_output_delta_log=60,b0_raw_alpha_log=59,
            b1_output_delta_log=61,b1_raw_alpha_log=60,candidate_pbs=10,candidate_ks=8,
            modeled_pbs_saving_vs_11pbs_split=1,
            scope='New source/LUT/API and validation gate required. Other bits and fresh-key law remain open; no retry proposed.'))
    path=HERE/'RESULT.json'
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as handle:
        json.dump(summary,handle,indent=2);handle.write('\n')
    print(json.dumps(dict(status=summary['status'],failed_arm_cases=result['summary']['failures_baseline_shift_single_repair'],
        repaired_b1_scalar_failures=summary['repaired_b1_scalar_failures'],result_sha256=sha(path))))

if __name__=='__main__':main()
