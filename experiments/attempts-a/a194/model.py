"""Exact conditional fused-output geometry; no FHE/noise-law implementation."""
from fractions import Fraction
import importlib.util
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError('A194 requires assertions enabled')
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'tmp/a185-a175-private-helper-successor/model.py'
spec=importlib.util.spec_from_file_location('a194_frozen_actual_consumer',SOURCE)
consumer=importlib.util.module_from_spec(spec);spec.loader.exec_module(consumer)
Q,U,D,N,M=1<<64,1<<52,1<<59,2048,4096
assert (consumer.Q,consumer.U,consumer.DELTA,consumer.M)==(Q,U,D,M)

def signed(x):return (x+Q//2)%Q-Q//2

def rounded(x):return ((x%Q+U//2)//U)%M

def alpha(bit):return 1<<(51+bit)

def beta(bit):
    assert 0<=bit<=6
    return 1<<(59+bit) if bit<3 else 1<<58

def raw_at(degree,correction_alpha,selection_beta=None):
    """Negacyclic extension of frozen [-alpha]*N/2 +[-beta]*N/2."""
    d=degree%M
    base=-correction_alpha if selection_beta is None or d%N<N//2 else -selection_beta
    return base if d<N else -base

def fused_at(bit,value,displacement=0,second_offset=None):
    assert 0<=bit<3 and value in (0,1)
    a,b=alpha(bit),beta(bit);d=(512+2048*value+displacement)%M
    offset=b if second_offset is None else second_offset
    correction=(raw_at(d,a,b)+a)%Q
    selected=(raw_at(d+N//2,a,b)+offset)%Q
    return dict(bit=bit,value=value,degree=d,correction=correction,selection=selected,
        expected_correction=2*a*value,expected_selection=2*b*value,
        correction_native=abs(signed(correction-2*a*value))<a,
        selection_native=abs(signed(selected-2*b*value))<b,
        exact_pair=correction==2*a*value and selected==2*b*value)

def scalar_outputs(selection,bit,value):
    multiplier=1 if bit==2 else -1
    result=[]
    for candidate in consumer.candidates(bit):
        phase=(candidate*D+multiplier*selection)%Q
        degree=consumer.rounded(phase)
        actual=consumer.target(degree);expected=int(candidate==1 and value==0)
        result.append(dict(candidate=candidate,degree=degree,actual=actual,expected=expected,passed=actual==expected))
    return result

def intervals(values):
    result=[]
    for x in sorted(values):
        if result and result[-1][1]+1==x:result[-1][1]=x
        else:result.append([x,x])
    return result

def coefficient_ms(words,secret):
    assert len(words)==len(secret)+1 and all(s in (0,1) for s in secret)
    degrees=[rounded(w) for w in words]
    residues=[signed(w-d*U) for w,d in zip(words,degrees)]
    dot=sum(w*s for w,s in zip(words[:-1],secret))%Q
    phase=(words[-1]-dot)%Q
    z=sum(r*s for r,s in zip(residues[:-1],secret))
    address=(degrees[-1]-sum(d*s for d,s in zip(degrees[:-1],secret)))%M
    assert address==rounded(phase+z)
    assert (address*U+residues[-1]-z)%Q==phase
    return dict(actual_address=address,phase_only_address=rounded(phase),phase=phase,weighted_residues=z,body_residue=residues[-1])

def chain(x,score_error=0,correction_errors=None,selection_errors=None,ks_errors=None,z=None,low_fused=True):
    """Caller-supplied joint error vector, not independent draws or a cryptographic law."""
    assert 0<=x<=4095
    corrections=correction_errors or [0]*8;selections=selection_errors or [0]*8
    ks=ks_errors or [0]*8;weighted_residues=z or [0]*8
    assert all(len(v)==8 for v in (corrections,selections,ks,weighted_residues))
    residual=(x*(1<<52)+score_error)%Q
    stages=[];bits=[]
    for bit in range(8):
        fused=bit<7 and (bit>=3 or low_fused)
        a=alpha(bit);b=beta(bit) if fused else None
        shift=11-bit
        small=(residual*(1<<shift)+ks[bit])%Q
        center=1<<61 if fused else 1<<62
        d=rounded(small+center+weighted_residues[bit])
        raw_c=raw_at(d,a,b);correction=(raw_c+a+corrections[bit])%Q
        value=(x>>bit)&1
        if fused:
            raw_w=raw_at(d+N//2,a,b)
            weighted=(raw_w+b+selections[bit])%Q
        elif bit<3:
            raw_w=None;weighted=(correction*256)%Q
        else:
            raw_w=None;weighted=correction
        expected_weight=(1<<(60+bit)) if bit<3 else D
        correct_cell=raw_c==(-a if value==0 else a)
        if fused:correct_cell &= raw_w==(-b if value==0 else b)
        stages.append(dict(bit=bit,value=value,shift=shift,small_phase=small,actual_degree=d,
            fused=fused,correction=correction,weighted=weighted,
            small_native=abs(signed(small-value*(1<<63)))<(1<<62),
            correction_native=abs(signed(correction-value*2*a))<a,
            selection_native=abs(signed(weighted-value*expected_weight))<expected_weight//2,
            raw_pair_preimage=correct_cell))
        residual=(residual-correction)%Q;bits.append(weighted)
    return dict(stages=stages,weighted=bits,top_residual=residual,expected_top=(x>>8)*(1<<60))

def witness_records():
    witnesses={}
    # Fixed +2^58 would leave a common offset bias despite native weighted decode.
    bad=fused_at(1,0,second_offset=1<<58)
    bad['consumers']=scalar_outputs(bad['selection'],1,0)
    witnesses['unchanged_boolean_offset']=bad
    witnesses['single_correct_fused_wrong_at_upper_quarter']=[]
    for value in (0,1):
        row=fused_at(2,value,512)
        d=(1024+2048*value+512)%M;a=alpha(2)
        row['single_correction']=(raw_at(d,a)+a)%Q
        row['single_correct']=row['single_correction']==value*2*a
        row['small_native']=512*U<(1<<62)
        witnesses['single_correct_fused_wrong_at_upper_quarter'].append(row)
    mask=[U//2-1]*128+[0]*731;secret=[1]*128+[0]*731
    words=mask+[(sum(mask)+448*U+(1<<61))%Q]
    ms=coefficient_ms(words,secret)
    ms.update(synthetic_secret_weight=128,small_bit_native=True,fused_phase_only_inside=True,fused_actual_inside=False,single_actual_address=(ms['actual_address']+512)%M)
    witnesses['coefficientwise_plus64']=ms
    selection=64*U
    witnesses['proper_offset_native_is_not_consumer']=dict(bit=2,value=0,correction_error=0,selection_error=selection,native_selection_pass=selection<beta(2),actual_producer_degree=512,consumers=scalar_outputs(selection,2,0))
    corrections=[alpha(0)-1]+[0]*7;ks=[0,-U]+[0]*6
    fused=chain(0,correction_errors=corrections,ks_errors=ks)
    single=chain(0,correction_errors=corrections,ks_errors=ks,low_fused=False)
    witnesses['feedback_narrows_next_gate']=dict(correction0_error=corrections[0],ks1_error=-U,first_fused_stage=fused['stages'][0],next_fused_stage=fused['stages'][1],next_single_stage=single['stages'][1])
    historical_error=1134571592613888
    witnesses['correlated_output_error_vector']=dict(correction_error=historical_error,selection_error=256*historical_error,correction_native=historical_error<alpha(2),selection_native=256*historical_error<beta(2),consumers=scalar_outputs(256*historical_error,2,0),interpretation='algebraic joint vector matching preserved A185 amplified error; not an observed fused ciphertext or reachability/probability claim')
    return witnesses

def error_interval(radius_negative,radius_positive):
    return dict(lower_inclusive=-radius_negative*U-U//2,upper_exclusive=(radius_positive+1)*U-U//2,
                lower_in_delta59=str(Fraction(-radius_negative*U-U//2,D)),upper_in_delta59=str(Fraction((radius_positive+1)*U-U//2,D)))
