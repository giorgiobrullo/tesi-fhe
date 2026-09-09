//! Variable-N uniform thresholds -> selected Head/mean five-payload M primitives.
#![recursion_limit = "256"]

mod a53_scan;
mod a98;
mod a112;
mod wide;
mod head_witness;
mod hybrid;
mod comparator;
mod mean_center;
mod compat;
mod d1;
mod helpers;
mod h_untraced;
mod m_untraced;
mod hd1;
mod split;
mod key_envelope;
mod key_envelope_core;
mod template_permutation;
mod observer;
mod private_argmin;

use compat::{
    blind_rotate_assign, pbs_modulus_switch, ClientKey, ServerKey, ShortintBootstrappingKey,
};
use helpers::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    io::{self, Write},
};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;

const POLYNOMIAL_SIZE: usize = 2048;
const GLWE_SIZE: usize = 2;
const BOX_SIZE: usize = 128;
const STRICT_RADIUS: isize = 63;
const OUTPUTS: usize = 5;
const LEFT_CONTROL: u64 = 4;
const RIGHT_CONTROL: u64 = 12;
const SCORE_DELTA: u64 = 1 << 59;
const TORUS_PER_BLIND_ROTATION_DEGREE: u64 = 1 << 52;
const PAYLOAD_DELTAS: [u64; OUTPUTS] = [SCORE_DELTA; OUTPUTS];
const SOURCE: &str = include_str!("../../SOURCE_DIGEST.txt");
const SCHEMA: &str = "head-pfks-split32-b22-mean-center.v1";
const GROUPS: [&[usize];2]=[&[0,1,2],&[3,4]];
const OFFSETS: [&[usize];2]=[&[0,41,82],&[0,41]];
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
type Poly = PolynomialOwned<u64>;

#[derive(Clone, Copy)]
struct PfksParameters {
    base_log: usize,
    level_count: usize,
}

#[derive(Clone,Copy)]
enum Origin { Leaf(usize), Merge(usize), Sentinel }

impl Origin {
    fn nontrivial(self) -> [bool;5] {
        match self {
            Self::Leaf(_) => [true,true,true,false,false],
            Self::Merge(_) => [true;5],
            Self::Sentinel => [false;5],
        }
    }
    fn json(self) -> serde_json::Value {
        match self {
            Self::Leaf(index) => json!(["leaf",index]),
            Self::Merge(index) => json!(["merge",index]),
            Self::Sentinel => json!(["sentinel",0]),
        }
    }
}

struct Fixture {
    index: usize,
    name: String,
    left: [u64;5],
    right: [u64;5],
    expected: [u64;5],
    signs: [i64;3],
    choose_right: bool,
    combined_message_phase: u64,
    center_degree: usize,
    left_nontrivial: [bool;5],
    right_nontrivial: [bool;5],
}

impl Fixture {
    fn new(index:usize,name:String,left:[u64;5],right:[u64;5],origins:[Origin;2]) -> Self {
        let signs=std::array::from_fn(|i|(left[i] as i64-right[i] as i64).signum());
        let combined=4*signs[0]+2*signs[1]+signs[2];
        let choose_right=left[..3]>right[..3];
        Self {index,name,left,right,expected:if choose_right {right} else {left},signs,choose_right,
            combined_message_phase:((2*combined-1) as u64).wrapping_mul(SCORE_DELTA/2),
            center_degree:(128*combined-64).rem_euclid(4096) as usize,
            left_nontrivial:origins[0].nontrivial(),right_nontrivial:origins[1].nontrivial()}
    }
}

mod general;
mod service_selected;
pub mod service;

#[cfg(test)]
mod scaling_tests;

#[cfg(test)]
mod uniform_tests;
