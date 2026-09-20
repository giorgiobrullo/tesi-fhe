//! Pure circuit models run normally; expensive encrypted diagnostics stay explicitly ignored.
use super::super::test_support::negacyclic_division_sample;
use super::*;

mod counts;
mod extraction;
mod fhe;
mod luts;
