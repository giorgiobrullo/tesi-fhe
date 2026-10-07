import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import verify as v

spec=importlib.util.spec_from_file_location('a137_test_fixture',v.A137/'tests/test_observer.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
H=lambda text:hashlib.sha256(text.encode()).hexdigest()


def synthetic(offset=0,pid=100,tag='first',convolution_bad=False,direct_bad=False):
    rows=old.make_log();meta=rows[0]
    meta.update(process_id=pid,order_offset=offset,tfhe_version='0.11.3',pfks='24x1',params_fingerprint='b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1',pfpks_key_bytes_each=67141632,same_base_keys_and_inputs=True,functional_keys_independently_encrypted=True,comparator_present=False,tournament_present=False,keys_ephemeral=True,secret_key_bytes_persisted=False,ciphertext_words_persisted=False,phase_polynomial_words_persisted=False,support_gate='coefficientwise_modulus_switch_effective_degree',key_family_ids={'constant':H(tag+'constant'),'window':H(tag+'window')})
    ordered=[meta]
    for f,s in enumerate(v.SPECS):
        name=s['name'];selected=s['left'] if s['control']==4 else s['right']
        control=s['control']*(1<<59)+v.OFFSETS[f]*(1<<52)
        degree=v.ms(control)
        relevant=[r for r in rows if r.get('fixture')==name]
        lanes=[r for r in relevant if r['record']=='lane']
        def audit(phase,expected,delta,key):
            e=v.signed(phase-expected*delta);decode=((phase+delta//2)%v.Q)//delta
            return dict(phase=phase,decoded=decode,signed_error=e,absolute_error=abs(e),half_slot_limit_exclusive=delta//2,half_slot_pass=abs(e)<delta//2,decode_pass=decode==expected,nontrivial=True,sha256=H(key))
        for j,lane in enumerate(lanes):
            delta=1<<(56 if j==3 else 59)
            lane.update(delta_log=56 if j==3 else 59,diagnostics_after_all_arm_timers=True)
            for arm in ['direct','convolution','scalar']:
                if arm=='scalar': phase=selected[j]*delta+28
                else: phase=lane[arm]['phase']
                if f==0 and j==0 and ((arm=='convolution' and convolution_bad) or (arm=='direct' and direct_bad)): phase=(phase+delta)%v.Q
                lane[arm]=audit(phase,selected[j],delta,f'{name}/{arm}/{j}')
        ordered.extend(lanes)
        for arm in ['direct_window','convolution_a108']:
            direct=arm=='direct_window'
            pfks=[r for r in relevant if r['record']=='pfks_witness' and r['arm']==arm]
            acc=next(r for r in relevant if r['record']=='accumulator_witness' and r['arm']==arm)
            noise=[r for r in relevant if r['record']=='noise_lane' and r['arm']==arm]
            for t,p in enumerate(pfks):
                p.update(producer=f'{name}/{arm}/pfks/{t}',key_family='window' if direct else 'constant',function_sha256=v.function_hash(direct),input_sha256=H(f'{name}/input/{t}'),pfks_output_sha256=H(f'{name}/{arm}/{t}'),phase_polynomial_sha256=H('phase'+arm+str(t)),aggregate_key_error_polynomial_sha256=H('error'+arm+str(t)),public_digit_words_sha256=H('digits'+str(t)),actual_level_order=[1],actual_body_row_digits=[0])
            acc.update(pre_br_ciphertext_sha256=H('prebr'+arm+name),pre_br_phase_polynomial_sha256=H('prebrphase'+arm+name),post_ks_control_sha256=H('control'+name),input_control_sha256=H('inputcontrol'+name),input_control_phase=control,post_ks_control_phase=control,actual_ks_aggregate_error=0,modulus_switched_body=degree,secret_weighted_modulus_switched_mask_sum=0,actual_effective_rotation_degree=degree,actual_effective_rotation_error=v.OFFSETS[f],rounded_phase_degree_diagnostic=degree,diagnostics_after_all_arm_timers=True,not_independent_execution_attestation=True)
            for j,n in enumerate(noise):
                oldarm='direct' if direct else 'convolution';out=lanes[j][oldarm]
                n.update(output_sha256=out['sha256'],actual_output_phase=out['phase'],semantic_error=out['signed_error'],strict_half_slot_pass=out['half_slot_pass'],margin_to_half_slot_decimal=str((1<<(55 if j==3 else 58))-out['absolute_error']),actual_pre_br_virtual_degree=degree+j*128)
                n['br_and_numeric_residual']=v.signed(n['actual_output_phase']-n['actual_pre_br_phase'])
                n['centered_terms_unwrapped_sum_decimal']=str(sum(n[k] for k in ['support_message_residual','transmitted_input_error','transmitted_rounding_rho','aggregate_pfks_key_error','aggregate_fft_phase_residual','br_and_numeric_residual']))
                for t,c in enumerate(n['term_contributions']):c['message_window_weight']=v.weight(degree+j*128,t)
            ordered.extend(pfks);ordered.append(acc);ordered.extend(noise)
        case=next(r for r in relevant if r['record']=='case')
        case.update(**v.DIRECT_COUNTS,arm_order=v.ORDERS[(f+2*offset)%6],requested_control_error=v.OFFSETS[f],actual_effective_rotation_degree=degree,actual_effective_rotation_error=v.OFFSETS[f],rounded_decrypted_phase_degree_diagnostic=degree,rounded_decrypted_phase_error_diagnostic=v.OFFSETS[f],phase_only_support_ok_diagnostic=True,ingress_ok=True,post_ks_controls_bitwise_equal=True,scalar_ok=True,convolution_counters_pass=True,convolution_class='packed_semantic_failure_inside_support' if convolution_bad and f==0 else 'pass',control_phase_audit=audit(control,s['control'],1<<59,'control'+name))
        if direct_bad and f==0:case['direct_class']='packed_semantic_failure_inside_support'
        ordered.append(case)
    summary=rows[-1]
    summary.update(process_id=pid,order_offset=offset,fixture_cases=8,fresh_keysets=1,minimum_fresh_processes=3,comparator_present=False,tournament_present=False,performance_interpretation_allowed=False,convolution_passed=7 if convolution_bad else 8,scalar_passed=8,effective_support_failures=0,phase_only_support_disagreements=0)
    if direct_bad:summary.update(direct_passed=7,status='FAIL_DIRECT_COMPONENT')
    ordered.append(summary)
    if direct_bad:ordered.append(dict(record='fatal',artifact='A137',reason='direct arm passed 7/8 cases',performance_interpretation_allowed=False))
    return ordered


def envelopes(run,binary,offset=0,pid=100,tag='first'):
    common=dict(run_id=tag,run_dir=str(run),binary=str(binary),binary_sha256=v.digest(binary),source_sha256=v.SOURCE_ID)
    prepared=dict(schema='a167.root-prepared.v1',**common,order_offset=offset,command=[str(binary),'--run-authorized','--pfks','24x1'],cwd=str(v.A137),required_env={'RAYON_NUM_THREADS':'1','A137_ORDER_OFFSET':str(offset),'A137_RUN_FHE':'I_ACKNOWLEDGE_A137_DIRECT_WINDOW_PFKS_FHE','A137_PREREGISTRATION_SHA256':v.digest(v.A137/'PREREGISTRATION.json')},stdout=str(run/'stdout.jsonl'),stderr=str(run/'stderr.txt'),prepared_utc='2026-09-05T00:00:00Z')
    child=dict(schema='a167.root-child.v1',**common,pid=pid,started_utc='2026-09-05T00:00:01Z')
    terminal=dict(schema='a167.root-exit.v1',**common,pid=pid,exit_code=0,finished_utc='2026-09-05T00:00:02Z',stdout_sha256=v.digest(run/'stdout.jsonl'),stderr_sha256=v.digest(run/'stderr.txt'))
    return prepared,child,terminal


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=v.HERE,prefix='synthetic-')
        self.root=Path(self.tmp.name);os.chmod(self.root,0o700)
        self.binary=self.root/'synthetic-not-executable';self.binary.write_bytes(b'synthetic fixture only')
    def tearDown(self):self.tmp.cleanup()
    def save_log(self,rows):
        path=self.root/'stdout.jsonl';path.write_text(''.join(json.dumps(r)+'\n' for r in rows));os.chmod(path,0o600);return path
    def check(self,rows):
        result=v.check_rows(rows,0,100)
        v.frozen_arithmetic(self.save_log(rows))
        return result
    def full_run(self,rows=None):
        self.save_log(synthetic() if rows is None else rows)
        (self.root/'stderr.txt').write_text('');os.chmod(self.root/'stderr.txt',0o600)
        triplet=envelopes(self.root,self.binary)
        if rows and len(rows)==251:triplet[2]['exit_code']=1
        for name,data in zip(['prepared.json','child.json','exit.json'],triplet):
            (self.root/name).write_text(json.dumps(data));os.chmod(self.root/name,0o600)
        with patch.object(v,'BINARY',self.binary):return v.verify_run(self.root)
    def test_good_complete_and_scope(self):
        r=self.full_run();self.assertTrue(r['direct_component_pass']);self.assertIsNone(r['actual_p_fail']);self.assertFalse(r['independent_ciphertext_replay'])
        self.assertFalse(v.aggregate([r])['full_three_process_gate_complete'])
    def test_convolution_failure_is_separate(self):
        r=self.check(synthetic(convolution_bad=True));self.assertTrue(r['direct_component_pass']);self.assertFalse(r['convolution_component_pass'])
    def test_direct_failure_is_valid_but_not_pass(self):
        r=self.full_run(synthetic(direct_bad=True));self.assertFalse(r['direct_component_pass']);self.assertEqual(r['status'],'VALID_COMPLETED_COMPONENT_FAILURE')
    def test_order_missing_duplicate_unknown_and_fatal(self):
        rows=synthetic()
        variants=[rows[:-1],rows+[{'record':'invented'}],rows[:2]+rows[3:],rows[:1]+[rows[2],rows[1]]+rows[3:],rows+[{'record':'fatal'}]]
        for x in variants:
            with self.assertRaises((ValueError,KeyError)):self.check(x)
    def test_changed_counter_cannot_hide_under_true_boolean(self):
        rows=synthetic();next(r for r in rows if r['record']=='case')['direct_pfks']=7
        with self.assertRaisesRegex(ValueError,'counter'):self.check(rows)
    def test_false_native_flags_rejected(self):
        rows=synthetic();rows[1]['direct']['phase']+=1<<59
        with self.assertRaisesRegex(ValueError,'phase audit'):self.check(rows)
    def test_changed_summary_or_offset(self):
        for field,val in [('convolution_passed',7),('scalar_passed',0),('effective_support_failures',1),('order_offset',1),('p_fail_proven',True)]:
            rows=synthetic();rows[-1][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(rows)
    def test_paired_input_function_or_body_mutation(self):
        for field,val in [('function_sha256','0'*64),('input_sha256','1'*64),('actual_body_row_digits',[]),('actual_level_order',[2])]:
            rows=synthetic();row=next(r for r in rows if r['record']=='pfks_witness' and r['arm']=='convolution_a108');row[field]=val
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(rows)
    def test_weight_and_transmitted_component_mutations(self):
        for field in ['transmitted_input_error','transmitted_rounding_rho']:
            rows=synthetic();row=next(r for r in rows if r['record']=='noise_lane');row[field]+=1
            with self.assertRaises(ValueError):self.check(rows)
        rows=synthetic();next(r for r in rows if r['record']=='noise_lane')['term_contributions'][0]['message_window_weight']=-1
        with self.assertRaises(ValueError):self.check(rows)
    def test_envelope_hash_pid_command_and_chronology(self):
        self.save_log(synthetic());(self.root/'stderr.txt').write_text('')
        base=envelopes(self.root,self.binary)
        for i,field,value in [(0,'command',[]),(1,'source_sha256','0'*64),(2,'binary_sha256','0'*64),(2,'pid',101),(1,'started_utc','2026-09-04T00:00:00Z'),(2,'stdout_sha256','0'*64),(0,'run_dir','elsewhere'),(0,'required_env',{})]:
            parts=copy.deepcopy(base);parts[i][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):v.envelope(*parts,self.root,self.binary,v.digest(self.binary),v.digest(self.root/'stdout.jsonl'),v.digest(self.root/'stderr.txt'))
    def test_read_permissions_symlink_and_raw_pid(self):
        self.full_run();os.chmod(self.root/'stdout.jsonl',0o644)
        with patch.object(v,'BINARY',self.binary),self.assertRaisesRegex(ValueError,'permissions'):v.verify_run(self.root)
        os.chmod(self.root/'stdout.jsonl',0o600)
        rows=synthetic(pid=101);self.save_log(rows)
        with patch.object(v,'BINARY',self.binary),self.assertRaises(ValueError):v.verify_run(self.root)
        (self.root/'link').symlink_to(self.root/'stdout.jsonl')
        with self.assertRaisesRegex(ValueError,'symlink'):v.private_path(self.root/'link')
    def test_json_duplicates_boolean_number_and_nonfinite(self):
        for s in ['{"x":1,"x":2}','{"x":NaN}','{"x":1.0}']:
            with self.assertRaises(ValueError):v.load(s)
        rows=synthetic();rows[0]['process_id']=True
        with self.assertRaises(ValueError):self.check(rows)
    def test_three_process_aggregate_and_reused_key(self):
        base=self.full_run();reports=[]
        for i in range(3):
            r=copy.deepcopy(base);r.update(order_offset=i,pid=100+i,run_id=f'run{i}',run_dir=f'/private/run{i}',stdout_sha256=H(str(i)),prepared_utc=f'2026-09-05T00:00:0{3*i}Z',finished_utc=f'2026-09-05T00:00:0{3*i+2}Z',key_family_ids={'constant':H('constant'+str(i)),'window':H('window'+str(i))});reports.append(r)
        self.assertTrue(v.aggregate(reports)['full_three_process_gate_complete'])
        reports[2]['key_family_ids']['constant']=reports[0]['key_family_ids']['constant']
        with self.assertRaisesRegex(ValueError,'key'):v.aggregate(reports)
    def test_frozen_source_pins(self):v.source_check()

if __name__=='__main__':unittest.main()
