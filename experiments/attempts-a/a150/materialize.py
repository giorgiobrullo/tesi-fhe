"""Deterministic source transformation from frozen A132; no compile or execution."""

from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "a132-common-mask-round-gate"


def render_crypto():
    s = (BASE / "src/crypto.rs").read_text()
    s = s.replace(
        "use crate::model::{Counts, Layout, A44_DELTA, CM_DELTA, LANES};",
        "use crate::model::{Counts, Layout, A44_DELTA, CM_DELTA, LANES};\nuse crate::zero_pool::{apply, Policy, ReductionEvent};",
        1,
    )
    s = s.replace("type Cm =", "pub type Cm =", 1)
    s = s.replace(
        "    pub added_payload_bytes: [usize; 4],",
        "    pub added_payload_bytes: [usize; 4],\n    cm_zero_pool: CmLweCiphertextListOwned<u64>,\n    pub zero_pool_payload_bytes: usize,",
        1,
    )
    at = "    let added_payload_bytes = ["
    pool = """    // One complete shared-mask zero per pool row, with four independent lane bodies.
    let mut cm_zero_pool = CmLweCiphertextList::new(
        0u64, cm.lwe_dimension, cm.cm_dimension, cm.max_nb_zeros_n, cm.ciphertext_modulus,
    );
    let zero = PlaintextList::new(0u64, PlaintextCount(LANES));
    let zero_messages: Vec<_> = (0..cm.max_nb_zeros_n.0).map(|_| zero.clone()).collect();
    encrypt_cm_lwe_ciphertext_list(
        &cm_small, &mut cm_zero_pool, &zero_messages,
        cm.lwe_noise_distribution, &mut enc,
    );
    let zero_pool_payload_bytes = std::mem::size_of_val(cm_zero_pool.as_ref());
    assert_eq!(zero_pool_payload_bytes, 9_405_120);
"""
    assert s.count(at) == 1
    s = s.replace(at, pool + at)
    s = s.replace(
        "            added_payload_bytes,",
        "            added_payload_bytes,\n            cm_zero_pool,\n            zero_pool_payload_bytes,",
    )
    start = s.index("fn cm_pbs(")
    end = s.index("\nfn cm_ks(", start)
    s = (
        s[:start]
        + """fn cm_pbs(
    key: &EvaluationKeys,
    input: &Cm,
    lut: &CmGlweCiphertextOwned<u64>,
    counts: &mut Counts,
    policy: Policy,
    stage: &str,
    events: &mut Vec<ReductionEvent>,
) -> Option<Cm> {
    let mut event = apply(input, &key.cm_zero_pool, policy, stage);
    if !event.allowed {
        // Retain both inputs and the best candidate, without executing this PBS.
        events.push(event);
        return None;
    }
    let mut output = cm_zero(true);
    programmable_bootstrap_cm_lwe_ciphertext(&event.corrected, &mut output, lut, &key.cm_fbsk);
    counts.cm_pbs += 1;
    event.pbs_executed = true;
    events.push(event);
    Some(output)
}
"""
        + s[end:]
    )
    s = s.replace(
        "    pub counts: Counts,\n}",
        "    pub counts: Counts,\n    pub reductions: Vec<ReductionEvent>,\n    pub completed: bool,\n}",
        1,
    )
    s = s.replace(
        "    mutation: Mutation,\n) -> RoundResult {",
        "    mutation: Mutation,\n    policy: Policy,\n) -> RoundResult {",
        1,
    )
    s = s.replace(
        "    let mut traces = Vec::new();\n    let identity_cm",
        """    let mut traces = Vec::new();
    let mut reductions = Vec::new();
    // Stop before the refused BR. Preserve the partial primitive ledger and traces.
    macro_rules! accepted {
        ($call:expr) => {
            match $call {
                Some(value) => value,
                None => { return RoundResult {
                    outputs: Vec::new(), traces, counts, reductions, completed: false,
                } }
            }
        };
    }
    let identity_cm""",
        1,
    )
    calls = [
        (
            "cm_pbs(key, &a_small, &identity_cm, &mut counts)",
            "&a_small, &identity_cm",
            'format!("active_pack/{group}")',
        ),
        (
            "cm_pbs(key, &z_small, &zero_cm, &mut counts)",
            "&z_small, &zero_cm",
            'format!("z_input/{group}")',
        ),
        (
            "cm_pbs(key, &small, &nonzero_cm, &mut counts)",
            "&small, &nonzero_cm",
            'format!("reduce_input/{level}/{node}")',
        ),
        (
            "cm_pbs(key, &small, &update_cm, &mut counts)",
            "&small, &update_cm",
            'format!("update_input/{group}")',
        ),
    ]
    for old, args, tag in calls:
        assert s.count(old) == 1
        s = s.replace(
            old,
            f"accepted!(cm_pbs(key, {args}, &mut counts, policy, &{tag}, &mut reductions))",
        )
    old = "        traces,\n        counts,\n    }"
    assert s.count(old) == 1
    s = s.replace(
        old,
        "        traces,\n        counts,\n        reductions,\n        completed: true,\n    }",
    )
    s += """
/// One step of the cached stock-flow shape, using this gate's actual four-lane keys.
/// The cached concrete test uses two lanes and three steps; this is a bounded four-lane adaptation.
pub fn stock_input(client: &ClientKeys, key: &EvaluationKeys) -> (Cm, Vec<Trace>, Counts) {
    let cm = CM_PARAM_4_2_MINUS_64;
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut enc = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let messages = PlaintextList::new(0u64, PlaintextCount(LANES));
    let mut big = allocate_and_encrypt_new_cm_lwe_ciphertext(
        &client.cm_big, &messages, cm.glwe_noise_distribution, cm.ciphertext_modulus, &mut enc,
    );
    let mut traces = Vec::new();
    trace_cm(&mut traces, "stock_encrypted".into(), Domain::CmBig, &big);
    cm_lwe_ciphertext_cleartext_mul_assign(&mut big, Cleartext(cm.nu as u64));
    trace_cm(&mut traces, "stock_nu3".into(), Domain::CmBig, &big);
    let mut counts = Counts::default();
    let small = cm_ks(key, &big, &mut counts);
    trace_cm(&mut traces, "stock_input".into(), Domain::CmSmall, &small);
    (small, traces, counts)
}

pub fn stock_arm(key: &EvaluationKeys, input: &Cm, policy: Policy) -> RoundResult {
    let mut counts = Counts::default();
    let mut reductions = Vec::new();
    let mut traces = Vec::new();
    let output = cm_pbs(key, input, &cm_lut(|x| x), &mut counts, policy, "stock_input", &mut reductions);
    let completed = output.is_some();
    let outputs = if let Some(output) = output {
        trace_cm(&mut traces, "stock_output".into(), Domain::CmBig, &output);
        (0..LANES).map(|lane| output.extract_lwe_ciphertext(lane)).collect()
    } else { Vec::new() };
    RoundResult { outputs, traces, counts, reductions, completed }
}
"""
    return s


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["--write-initial"]:
        with (HERE / "src/crypto.rs").open("x") as f:
            f.write(render_crypto())
    else:
        print(
            "PLAN ONLY: materialization requires --write-initial and refuses an existing crypto.rs"
        )
