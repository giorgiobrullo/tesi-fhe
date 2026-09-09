//! Exact public CM zero-pool chooser, with status retained. No ordinary CMNR substitution.
use crate::crypto::Cm;
use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    cm_modulus_switch_noise_reduction::choose_candidate_to_improve_modulus_switch_noise_for_binary_key,
    CM_PARAM_4_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::modulus_switch_noise_reduction::{Candidate, CandidateResult};
use tfhe::core_crypto::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Plain,
    /// Catalog number supplied as an EXPLICIT UNVERIFIED stage-input variance assumption.
    SharedZerosStockAssumption,
    /// At twice that assumed variance even a perfect mask exceeds the estimator bound.
    ForcedUnmetDoubleVariance,
}

pub struct ReductionEvent {
    pub stage: String,
    pub policy: Policy,
    pub before: Cm,
    pub corrected: Cm,
    pub selected_zero: Option<Cm>,
    pub selected_index: Option<usize>,
    pub chooser_invocations: usize,
    pub zero_additions: usize,
    pub source_derived_zero_candidates_examined: usize,
    pub assumed_normalized_input_variance: Option<f64>,
    pub estimator_satisfied: Option<bool>,
    pub status: &'static str,
    pub allowed: bool,
    pub pbs_executed: bool,
}

pub fn apply(
    input: &Cm,
    pool: &CmLweCiphertextListOwned<u64>,
    policy: Policy,
    stage: &str,
) -> ReductionEvent {
    let cm = CM_PARAM_4_2_MINUS_64;
    assert_eq!(input.lwe_dimension(), cm.lwe_dimension);
    assert_eq!(input.cm_dimension(), cm.cm_dimension);
    assert_eq!(pool.lwe_dimension(), cm.lwe_dimension);
    assert_eq!(pool.cm_dimension(), cm.cm_dimension);
    assert_eq!(input.ciphertext_modulus(), cm.ciphertext_modulus);
    assert_eq!(pool.ciphertext_modulus(), cm.ciphertext_modulus);
    assert_eq!(input.ciphertext_modulus(), CiphertextModulus::new_native());
    assert_eq!(pool.cm_lwe_ciphertext_count(), cm.max_nb_zeros_n);
    let mut event = ReductionEvent {
        stage: stage.into(),
        policy,
        before: input.clone(),
        corrected: input.clone(),
        selected_zero: None,
        selected_index: None,
        chooser_invocations: 0,
        zero_additions: 0,
        source_derived_zero_candidates_examined: 0,
        assumed_normalized_input_variance: None,
        estimator_satisfied: None,
        status: "PLAIN_A132",
        allowed: true,
        pbs_executed: false,
    };
    if policy == Policy::Plain {
        return event;
    }
    let multiplier = if policy == Policy::ForcedUnmetDoubleVariance {
        2.0
    } else {
        1.0
    };
    let variance = Variance(cm.ms_input_variance_n.0 * multiplier);
    event.assumed_normalized_input_variance = Some(variance.0);
    event.chooser_invocations = 1;
    let result = choose_candidate_to_improve_modulus_switch_noise_for_binary_key(
        input,
        pool,
        cm.r_sigma_factor_n,
        cm.ms_bound_n,
        variance,
        cm.polynomial_size.to_blind_rotation_input_modulus_log(),
    );
    let (satisfied, selected) = match result {
        CandidateResult::SatisfyingBound(candidate) => (true, candidate),
        CandidateResult::BestNotSatisfyingBound(candidate) => (false, candidate),
    };
    event.estimator_satisfied = Some(satisfied);
    event.allowed = satisfied;
    event.status = if satisfied {
        "SATISFYING_ESTIMATOR_ASSUMPTION_ONLY"
    } else {
        "INCONCLUSIVE_ESTIMATOR_BOUND"
    };
    // Derived from the pinned chooser's early-return order; not a sampled cost counter.
    event.source_derived_zero_candidates_examined = if !satisfied {
        cm.max_nb_zeros_n.0
    } else {
        match selected {
            Candidate::NoAddition => 0,
            Candidate::AddEncryptionOfZero { index } => index + 1,
        }
    };
    if let Candidate::AddEncryptionOfZero { index } = selected {
        let zero = pool.get(index);
        event.selected_zero = Some(Cm::from_container(
            zero.as_ref().to_vec(),
            cm.lwe_dimension,
            cm.ciphertext_modulus,
        ));
        // ONE whole CM row: preserve one shared mask and all four own-key bodies.
        cm_lwe_ciphertext_add_assign(&mut event.corrected, &zero);
        event.selected_index = Some(index);
        event.zero_additions = 1;
    }
    event
}
