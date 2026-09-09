//! Client-local complete-chain observations; called only after both full endpoints return.
use crate::crypto::centered::integrated::{Chain, Round};
use crate::crypto::{ClientKeys, Domain, Lwe};
use crate::model::{Layout, A44_DELTA, CM_DELTA};
use crate::observe;
use crate::witness::*;
use serde_json::{json, Value};

pub fn hashes(values: &[Lwe]) -> Vec<String> {
    values
        .iter()
        .map(|x| observe::words_hash(x.as_ref()))
        .collect()
}

pub fn ordinary_vector(
    client: &ClientKeys,
    values: &[Lwe],
    messages: &[u64],
    unit: u64,
) -> Vec<Value> {
    assert_eq!(values.len(), messages.len());
    values
        .iter()
        .zip(messages)
        .map(|(ct, m)| ct_record(client, ct, Domain::A44Big, 0, m * unit, unit))
        .collect()
}

pub fn canonical(rows: &[Value]) -> bool {
    rows.iter().all(|r| r["phase_within_half_unit"] == true)
}

pub fn ingress(client: &ClientKeys, chain: &Chain, active: &[u64]) -> Value {
    let records: Vec<_> = chain
        .ingress
        .iter()
        .enumerate()
        .map(|(g, p)| {
            cm_probe_record(
                client,
                p,
                "identity",
                &active[4 * g..4 * g + 4],
                &active[4 * g..4 * g + 4],
            )
        })
        .collect();
    let scaled: Vec<_> = chain
        .ingress_inputs
        .iter()
        .enumerate()
        .map(|(g, cts)| ordinary_vector(client, cts, &active[4 * g..4 * g + 4], CM_DELTA))
        .collect();
    let nontrivial_masks = chain
        .ingress
        .iter()
        .all(|p| p.output.as_ref()[..1536].iter().any(|x| *x != 0));
    let pass = nontrivial_masks && records.iter().all(|r| r["pass"] == true);
    json!({"scaled_inputs":scaled,"probes":records,"nontrivial_masks":nontrivial_masks,"pass":pass})
}

pub fn round(
    client: &ClientKeys,
    r: &Round,
    layout: Layout,
    active: &[u64],
    values: &[u64],
) -> (Value, Vec<u64>) {
    let bits: Vec<_> = values.iter().map(|v| (v >> layout.bit) & 1).collect();
    let zeros: Vec<_> = active.iter().zip(&bits).map(|(a, b)| a * (1 - b)).collect();
    let any = u64::from(zeros.contains(&1));
    let next: Vec<_> = active
        .iter()
        .zip(&bits)
        .map(|(a, b)| u64::from(*a == 1 && (any == 0 || *b == 0)))
        .collect();
    let input: Vec<_> = r
        .input
        .iter()
        .enumerate()
        .map(|(g, c)| {
            cm_record(
                client,
                c,
                true,
                &active[4 * g..4 * g + 4]
                    .iter()
                    .map(|x| x * CM_DELTA)
                    .collect::<Vec<_>>(),
                CM_DELTA,
            )
        })
        .collect();
    let mut good = true;
    let group_records: Vec<_> = r.zeros.iter().enumerate().map(|(g,z)| {
        let aa=&active[4*g..4*g+4]; let bb=&bits[4*g..4*g+4]; let zz=&zeros[4*g..4*g+4];
        let weighted:Vec<_>=bb.iter().map(|b|b*layout.beta).collect();
        let codes:Vec<_>=aa.iter().zip(bb).map(|(a,b)|layout.alpha*a+layout.beta*b).collect();
        let zero=cm_probe_record(client,&z.zero,&format!("zero{}",layout.alpha),&codes,zz);
        good &= zero["pass"]==true;
        json!({"weighted":ordinary_vector(client,&z.weighted,&weighted,CM_DELTA),
            "bit_pack":cm_record(client,&z.bit_pack,false,&weighted.iter().map(|x|x*CM_DELTA).collect::<Vec<_>>(),CM_DELTA),
            "active_small":cm_record(client,&z.active_small,false,&aa.iter().map(|x|x*CM_DELTA).collect::<Vec<_>>(),CM_DELTA),"probe":zero})
    }).collect();
    let sums: Vec<_> = (0..4)
        .map(|j| (0..4).map(|g| zeros[4 * g + j]).sum::<u64>())
        .collect();
    let roots: Vec<_> = sums.iter().map(|s| u64::from(*s != 0)).collect();
    let reduction = cm_probe_record(client, &r.reduction, "centered", &sums, &roots);
    let bridge = ordinary_record(
        client,
        &r.any,
        "centered",
        4,
        roots.iter().sum(),
        CM_DELTA,
        any,
    );
    let broadcast = cm_record(client, &r.broadcast, false, &[any * CM_DELTA; 4], CM_DELTA);
    let broadcast_canonical = broadcast["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["phase_within_half_unit"] == true);
    good &= reduction["pass"] == true && bridge["pass"] == true && broadcast_canonical;
    let updates: Vec<_> = r
        .updates
        .iter()
        .enumerate()
        .map(|(g, u)| {
            let sums: Vec<_> = (0..4)
                .map(|j| active[4 * g + j] + zeros[4 * g + j])
                .collect();
            let codes: Vec<_> = sums.iter().map(|s| s + 1 - any).collect();
            let probe =
                cm_probe_record(client, &u.update, "update", &codes, &next[4 * g..4 * g + 4]);
            good &= probe["pass"] == true;
            let targets: Vec<_> = sums.iter().map(|s| s * CM_DELTA).collect();
            json!({"sum_big":cm_record(client,&u.sum_big,true,&targets,CM_DELTA),
            "sum_small":cm_record(client,&u.sum_small,false,&targets,CM_DELTA),"probe":probe})
        })
        .collect();
    (
        json!({"clear_input":active,"clear_bits":bits,"clear_zeros":zeros,"clear_output":next,
        "layout":{"bit":layout.bit,"weight":layout.weight,"rescale":layout.rescale,"alpha":layout.alpha,"beta":layout.beta},
        "input":input,"zeros":group_records,
        "reduction_sum":cm_record(client,&r.reduction_sum,true,&sums.iter().map(|x|x*CM_DELTA).collect::<Vec<_>>(),CM_DELTA),
        "reduction":reduction,"bridge_inputs":bridge_inputs_record(client,&r.bridge,&roots),"bridge":bridge,
        "broadcast_input":ct_record(client,&r.broadcast_input,Domain::A44Big,0,any*CM_DELTA,CM_DELTA),
        "broadcast":broadcast,"broadcast_canonical":broadcast_canonical,"updates":updates,
        "counts":observe::counts(r.counts),"pass":good}),
        next,
    )
}

pub fn egress(client: &ClientKeys, chain: &Chain, flags: &[u64]) -> Value {
    let records:Vec<_>=chain.egress.iter().enumerate().map(|(i,e)| {
        json!({"extracted":ct_record(client,&e.extracted,Domain::CmBig,i%4,flags[i]*CM_DELTA,CM_DELTA),
            "probe":ordinary_record(client,&e.output,"identity",4,flags[i],CM_DELTA,flags[i])})
    }).collect();
    let pass = records.iter().all(|r| r["probe"]["pass"] == true);
    json!({"records":records,"counts":observe::counts(chain.counts),"pass":pass})
}

pub fn digits(client: &ClientKeys, low: &Lwe, high: &Lwe, expected: u64) -> Value {
    let lo = ct_record(
        client,
        low,
        Domain::A44Big,
        0,
        (expected % 15) * A44_DELTA,
        A44_DELTA,
    );
    let hi = ct_record(
        client,
        high,
        Domain::A44Big,
        0,
        (expected / 15) * A44_DELTA,
        A44_DELTA,
    );
    let decode = |r: &Value| r["phase"].as_u64().unwrap().wrapping_add(A44_DELTA / 2) >> 59;
    let low_digit = decode(&lo);
    let high_digit = decode(&hi);
    let pass = lo["phase_within_half_unit"] == true
        && hi["phase_within_half_unit"] == true
        && low_digit == expected % 15
        && high_digit == expected / 15;
    json!({"low":lo,"high":hi,"low_digit":low_digit,"high_digit":high_digit,"code":low_digit+15*high_digit,"pass":pass})
}
