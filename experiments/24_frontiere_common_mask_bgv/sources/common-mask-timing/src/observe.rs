//! Client-local witnesses, evaluated only after every server arm has returned.
use crate::crypto::{ClientKeys, Cm, Domain, Lwe, Trace};
use crate::model::Counts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;

pub fn bytes_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn words_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for x in words {
        h.update(x.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
pub fn counts(c: Counts) -> Value {
    json!({"packing":c.packing,"cm_ks":c.cm_ks,"cm_pbs":c.cm_pbs,"ordinary_ks":c.ordinary_ks,"ordinary_pbs":c.ordinary_pbs,"extraction":c.extraction})
}
pub fn lwe(client: &ClientKeys, ct: &Lwe, domain: Domain, lane: usize) -> Value {
    let sk = match domain {
        Domain::A44Small => &client.ordinary_small,
        Domain::A44Big => &client.ordinary_big,
        Domain::CmSmall => &client.cm_small[lane],
        Domain::CmBig => &client.cm_big[lane],
    };
    assert_eq!(ct.lwe_size().to_lwe_dimension(), sk.lwe_dimension());
    let phase = decrypt_lwe_ciphertext(sk, ct).0;
    let mask_dot = ct
        .get_mask()
        .as_ref()
        .iter()
        .zip(sk.as_ref())
        .fold(0u64, |a, (&x, &s)| a.wrapping_add(x.wrapping_mul(s)));
    let poly = match domain {
        Domain::A44Small => Some(2048),
        Domain::CmSmall => Some(512),
        _ => None,
    };
    let degree=poly.map(|n| {
        let weighted_sum=ct.get_mask().as_ref().iter().zip(sk.as_ref()).fold(0usize,|a,(&x,&s)|a.wrapping_add(crate::crypto::modulus_switch_word(x,n)*s as usize))%(2*n);
        let body=crate::crypto::modulus_switch_word(*ct.get_body().data,n);
        json!({"polynomial_size":n,"rounded_mask_sum_mod_2n":weighted_sum,"address":(body+2*n-weighted_sum)%(2*n)})
    });
    json!({"domain":format!("{domain:?}"),"lane":lane,"dimension":sk.lwe_dimension().0,"body":*ct.get_body().data,"mask_sha256":words_hash(ct.get_mask().as_ref()),"sha256":words_hash(ct.as_ref()),"phase":phase,"mask_dot":mask_dot,"coefficientwise":degree})
}
pub fn cm(client: &ClientKeys, ct: &Cm, big: bool) -> Value {
    json!({"mask_sha256":words_hash(&ct.as_ref()[..ct.lwe_dimension().0]),"body_values":&ct.as_ref()[ct.lwe_dimension().0..],"sha256":words_hash(ct.as_ref()),"dimension":ct.lwe_dimension().0,"bodies":4,"lanes":(0..4).map(|lane|lwe(client,&ct.extract_lwe_ciphertext(lane),if big {Domain::CmBig}else{Domain::CmSmall},lane)).collect::<Vec<_>>()})
}
pub fn traces(client: &ClientKeys, traces: &[Trace]) -> Vec<Value> {
    traces
        .iter()
        .map(|t| json!({"tag":t.tag,"ct":lwe(client,&t.ct,t.domain,t.lane)}))
        .collect()
}
pub fn canonical(client: &ClientKeys, outputs: &[Lwe]) -> Vec<u64> {
    outputs
        .iter()
        .map(|x| {
            ((decrypt_lwe_ciphertext(&client.ordinary_big, x)
                .0
                .wrapping_add(1 << 58))
                >> 59)
                & 31
        })
        .collect()
}
pub fn chain(
    client: &ClientKeys,
    result: &crate::crypto::persistent::Chain,
    arm: &str,
    key_family: &str,
) -> Value {
    json!({"type":"chain","arm":arm,"original_active_sha256":result.original_active.iter().map(|x|words_hash(x.as_ref())).collect::<Vec<_>>(),"original_bits_sha256":result.original_bits.iter().map(|r|r.iter().map(|x|words_hash(x.as_ref())).collect::<Vec<_>>()).collect::<Vec<_>>(),"key_family":key_family,"completed":result.completed,"counts":counts(result.counts),
      "checkpoints":result.checkpoints.iter().map(|c|json!({"tag":c.tag,"counts":counts(c.counts),"states":c.states.iter().map(|x|cm(client,x,true)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
      "traces":traces(client,&result.traces),"outputs":result.outputs.iter().map(|x|lwe(client,x,Domain::A44Big,0)).collect::<Vec<_>>(),
      "reductions":result.reductions.iter().map(|e|json!({"stage":e.stage,"policy":format!("{:?}",e.policy),"before":cm(client,&e.before,false),"corrected":cm(client,&e.corrected,false),
        "selected_zero":e.selected_zero.as_ref().map(|x|cm(client,x,false)),"selected_index":e.selected_index,"chooser_invocations":e.chooser_invocations,"zero_additions":e.zero_additions,
        "source_derived_zero_candidates_examined":e.source_derived_zero_candidates_examined,"assumed_normalized_input_variance":e.assumed_normalized_input_variance,"estimator_satisfied":e.estimator_satisfied,"status":e.status,"allowed":e.allowed,"pbs_executed":e.pbs_executed})).collect::<Vec<_>>(),
      "decoded":canonical(client,&result.outputs),"stock_variance_justified":false,"key_membership_attested":false})
}
