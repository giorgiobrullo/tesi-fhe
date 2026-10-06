"""Clear arithmetic/source checks only; no subprocess, sampling, or encrypted execution."""
import hashlib
import unittest
import model as m

class Gate(unittest.TestCase):
    def test_exact_negacyclic_rotation_against_explicit_polynomial_permutation(self):
        for bit in range(3):
            a,b=m.alpha(bit),m.beta(bit)
            body=[-a]*(m.N//2)+[-b]*(m.N//2)
            for degree in (0,511,512,1023,1024,1536,2047,2048,2560,3071,3072,4095,4096,8191):
                rotated=[0]*m.N
                for index,value in enumerate(body):
                    cycles,target=divmod(index-degree,m.N)
                    rotated[target]=value if cycles%2==0 else -value
                self.assertEqual(rotated[0],m.raw_at(degree,a,b))
                self.assertEqual(rotated[m.N//2],m.raw_at(degree+m.N//2,a,b))
    def test_exact_both_output_degree_windows_and_edges(self):
        for bit in range(3):
            for value in (0,1):
                good=[]
                for d in range(m.M):
                    row=m.fused_at(bit,value,d-(512+2048*value))
                    if row['exact_pair']:good.append(d)
                self.assertEqual(m.intervals(good),[[2048*value,2048*value+1023]])
                for offset in (-513,512):self.assertFalse(m.fused_at(bit,value,offset)['exact_pair'])
                for offset in (-512,511):self.assertTrue(m.fused_at(bit,value,offset)['exact_pair'])
    def test_single_is_twice_as_wide(self):
        for value in (0,1):
            a=m.alpha(2)
            good=[d for d in range(m.M) if (m.raw_at(d,a)+a)%m.Q==2*a*value]
            self.assertEqual(m.intervals(good),[[2048*value,2048*value+2047]])
    def test_upward_tie_integer_lift_endpoints(self):
        for radius,positive in ((512,511),(1024,1023)):
            region=m.error_interval(radius,positive)
            for center in (512,2560):
                self.assertEqual((m.rounded(center*m.U+region['lower_inclusive'])-center)%m.M,(-radius)%m.M)
                self.assertEqual((m.rounded(center*m.U+region['upper_exclusive']-1)-center)%m.M,positive)
                self.assertEqual((m.rounded(center*m.U+region['upper_exclusive'])-center)%m.M,positive+1)
    def test_all4096_clear_score_chains_and_consumer_states(self):
        for score in range(4096):
            result=m.chain(score)
            self.assertEqual(result['top_residual'],result['expected_top'])
            self.assertTrue(all(x['raw_pair_preimage'] and x['small_native'] and x['correction_native'] and x['selection_native'] for x in result['stages']))
            for bit in range(3):self.assertTrue(all(x['passed'] for x in m.scalar_outputs(result['weighted'][bit],bit,(score>>bit)&1)))
    def test_wrong_existing_boolean_offset_can_pass_native_but_fail_consumer(self):
        row=m.witness_records()['unchanged_boolean_offset']
        self.assertTrue(row['correction_native'] and row['selection_native'])
        self.assertFalse(row['exact_pair']);self.assertFalse(all(c['passed'] for c in row['consumers']))
    def test_phase_only_misses_coefficientwise_support_departure(self):
        row=m.witness_records()['coefficientwise_plus64']
        self.assertEqual(row['phase_only_address'],960);self.assertEqual(row['actual_address'],1024)
        self.assertEqual(row['single_actual_address'],1536)
    def test_proper_offset_and_two_native_outputs_do_not_certify_consumer(self):
        row=m.witness_records()['proper_offset_native_is_not_consumer']
        self.assertTrue(row['native_selection_pass'])
        self.assertEqual(next(c for c in row['consumers'] if c['candidate']==0)['actual'],1)
    def test_feedback_native_correction_and_next_small_do_not_certify_fused_cell(self):
        row=m.witness_records()['feedback_narrows_next_gate']
        self.assertTrue(row['first_fused_stage']['correction_native'])
        self.assertTrue(row['next_fused_stage']['small_native'])
        self.assertFalse(row['next_fused_stage']['raw_pair_preimage'])
        self.assertTrue(row['next_single_stage']['raw_pair_preimage'])
    def test_correlated_output_vector_can_retain_old_failure(self):
        row=m.witness_records()['correlated_output_error_vector']
        self.assertTrue(row['correction_native'] and row['selection_native'])
        self.assertFalse(all(c['passed'] for c in row['consumers']))
    def test_paired_wrong_offset_negative_moves_whole_target_interval(self):
        # bit1=0/candidate1: same input masks, body +3Delta/2 after wrong beta offset.
        self.assertEqual((m.beta(1)-(1<<58))//m.U,192)
        for degree in range(64,192):
            self.assertEqual(m.consumer.target(degree),1)
            self.assertEqual(m.consumer.target(degree+192),0)
        for d in range(m.M):
            for residue in (-m.U//2,0,m.U//2-1):
                word=(d*m.U+residue)%m.Q
                self.assertEqual(m.rounded(word+192*m.U),(m.rounded(word)+192)%m.M)
    def test_frozen_source_geometry_and_hardcoded_offset_are_retained(self):
        p=m.ROOT/'tmp/a185-a175-private-helper-successor/candidate/src/frozen_extract.rs'
        text=p.read_text()
        for fragment in ('body[polynomial_size.0 / 2..].fill(beta.wrapping_neg())','Plaintext(1u64 << 61)','MonomialDegree(rotated.polynomial_size().0 / 2)','Plaintext(1u64 << (BOOL_DELTA_LOG - 1))'):
            self.assertIn(fragment,text)
        self.assertEqual(m.consumer.candidates(2),range(-1,2))
        self.assertEqual(len(hashlib.sha256(p.read_bytes()).hexdigest()),64)

if __name__=='__main__':unittest.main()
