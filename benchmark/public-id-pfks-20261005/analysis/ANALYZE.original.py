"""Validate only this phase's new public records; no ciphertext/fixture/model evaluation."""
from pathlib import Path
import json,statistics,collections,hashlib
phase=Path(__file__).resolve().parents[1]
receipt=json.loads((phase/'root/NATIVE_CAPTURE.json').read_text())
assert receipt['status']=='terminal' and receipt['exit_code']==0
raw=(phase/'root/NATIVE.stdout.log').read_bytes()
rows=[json.loads(line) for line in raw.splitlines()]
assert len(rows)==16 and all(r['probe']=='first-level-stock-pfks-profile.20261005.v1' for r in rows)
expected={'einstein':1,'curie':2,'turing':3}
evaluations=[r for r in rows if r['stage'] in ('correctness_profile_off','profiled_warmup','profiled_request')]
assert len(evaluations)==12
assert collections.Counter(r['stage'] for r in evaluations)=={'correctness_profile_off':3,'profiled_warmup':3,'profiled_request':6}
assert [r['stage'] for r in evaluations]==['correctness_profile_off']*3+['profiled_warmup']*3+['profiled_request']*6
assert [(r['case'],r['round']) for r in evaluations[-6:]]==[(c,n) for n in range(2) for c in expected]
assert rows[0]['stage']=='public_plan' and rows[0]['first_level_stock_pfks_calls']==244
assert (rows[0]['execution_lower'],rows[0]['execution_upper'],rows[0]['sentinel'])==(-987,2318,1261)
assert rows[-1]['stage']=='complete' and rows[-1]['pass'] and rows[-1]['decoded_id_outputs']==12
assert rows[-1]['measured_profiled_ids']==6 and rows[-1]['profiled_warmup_ids']==3
basework=evaluations[0]['counts']; terminal=evaluations[0]['terminal']; fullschedule=evaluations[0]['full_scheduling']
observations=[]
for row in evaluations:
 assert row['pass'] and row['id']==expected[row['case']]
 assert len(row['counts'])==15 and row['counts']==basework
 assert row['service_counts']=={'br':1111,'ks':1080,'pfks':509,'marginals':1709,'initial_samples':120}
 for k,v in row['service_counts'].items(): assert row['counts']['initial_score_samples' if k=='initial_samples' else k]==v
 assert row['whole_duration_ns']>=row['terminal']['duration_ns']>0
 assert row['terminal']['work']==terminal['work']
 assert row['terminal']['scheduling']==terminal['scheduling']
 assert row['full_scheduling']==fullschedule
 p=row['first_level_stock_pfks']; records=p['records']; assert p['full_work']==row['counts']
 enabled=row['stage']!='correctness_profile_off'
 assert p['enabled']==enabled and p['calls']==len(records)==(244 if enabled else 0)
 bylane=[0]*5; masks=[0]*5; sums=[0]*5
 for item in records:
  assert set(item)=={'lane','role','mask_all_zero','primitive_duration_ns'}
  lane=item['lane']; assert 0<=lane<5
  assert item['role']==('score' if lane<3 else 'id_low' if lane==3 else 'id_middle')
  assert isinstance(item['mask_all_zero'],bool) and isinstance(item['primitive_duration_ns'],int) and item['primitive_duration_ns']>0
  if lane>=3: assert item['mask_all_zero']
  bylane[lane]+=1; masks[lane]+=item['mask_all_zero']; sums[lane]+=item['primitive_duration_ns']
 assert bylane==p['by_lane'] and masks==p['mask_zero_by_lane'] and sums==p['primitive_duration_sum_ns_by_lane']
 assert bylane==([60,60,60,60,4] if enabled else [0]*5)
 assert (p['score_calls'],p['id_low_calls'],p['id_middle_calls'])==((180,60,4) if enabled else (0,0,0))
 if row['stage']=='profiled_request':
  observations.append({'case':row['case'],'round':row['round'],'whole_ms':row['whole_duration_ns']/1e6,'terminal_ms':row['terminal']['duration_ns']/1e6,'score_mask_zero_calls':sum(masks[:3]),'id_mask_zero_calls':sum(masks[3:]),'sum_score_worker_ms':sum(sums[:3])/1e6,'sum_id_worker_ms':sum(sums[3:])/1e6,'id_share_of_summed_primitive_worker_time_percent':100*sum(sums[3:])/sum(sums)})
def distribution(vals):
 vals=sorted(vals)
 return {'calls':len(vals),'min_us':vals[0]/1e3,'median_us':statistics.median(vals)/1e3,'mean_us':statistics.mean(vals)/1e3,'max_us':vals[-1]/1e3}
measured=evaluations[-6:]
classes={role:distribution([p['primitive_duration_ns'] for r in measured for p in r['first_level_stock_pfks']['records'] if p['role']==role]) for role in ('score','id_low','id_middle')}
scene={c:{'whole_ms':[r['whole_ms'] for r in observations if r['case']==c],'summed_worker_id_share_percent':[r['id_share_of_summed_primitive_worker_time_percent'] for r in observations if r['case']==c]} for c in expected}
summary={'correct_ids':12,'profiled_queries':9,'profiled_calls':2196,'measured_queries':6,'measured_calls':1464,'full_counts':basework,'terminal_work':terminal['work'],'terminal_scheduling':terminal['scheduling'],'full_scheduling':fullschedule,'class_distributions':classes,'observations':observations,'by_scene':scene,'all_selected_id_inputs_trivial':True,'measured_score_mask_zero_calls':sum(x['score_mask_zero_calls'] for x in observations),'stdout':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'scope':'One fresh family/three same-source accept queries. Per-call elapsed under real concurrent work; profiling overhead remains in whole diagnostic time. Summed worker times overlap and are not request latency, a cache benefit or e2e savings. No optimized arm/adoption/noise/security/biometric proof.'}
(phase/'root/RESULT_SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:summary[k] for k in ('correct_ids','measured_calls','class_distributions','observations')},indent=2))
