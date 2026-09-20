//! Configure one complete synchronous query at a serialized boundary.
//! Callers must not overlap queries or change these process-global controls mid-query.
use crate::{
    classic_batch, g4_query, multibit, public_digits, selector_parallel,
    shared_normalizers, smallcuts,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Reference,
    PublicParallel,
    PublicParallelG4,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::PublicParallel => "public_parallel",
            Self::PublicParallelG4 => "public_parallel_g4",
        }
    }

    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "reference" => Ok(Self::Reference),
            "public_parallel" => Ok(Self::PublicParallel),
            "public_parallel_g4" => Err("G4 is unsupported for the refreshed selector".into()),
            _ => Err(format!("unknown composite mode: {name}")),
        }
    }

    pub fn uses_g4(self) -> bool {
        self == Self::PublicParallelG4
    }
}

/// All modes use Head/shared normalizers, classic comparator parallel4, both ID cuts,
/// public threshold specialization and the existing fixed 16-thread query pool.
/// Then call EvaluationKeys::evaluate_public_thresholds(..., true).
/// G4 is rejected before any process-global control changes or key access.
pub fn begin_query(mode: Mode, diagnostic_g4: bool) {
    assert!(!mode.uses_g4(), "G4 is unsupported for the refreshed selector");
    assert!(!diagnostic_g4 || mode.uses_g4(), "G4 diagnostics require the G4 mode");
    shared_normalizers::set_mode(shared_normalizers::Mode::Both);
    classic_batch::set_mode(classic_batch::Mode::Parallel3);
    smallcuts::set_mode(smallcuts::Mode::Both);
    smallcuts::set_tail_cutoff(0);
    let digits = if mode == Mode::Reference {
        public_digits::Mode::Off
    } else {
        public_digits::Mode::Repack
    };
    public_digits::set_mode(digits);
    selector_parallel::begin_query(mode != Mode::Reference);
    multibit::begin_query(0, false);
    g4_query::begin_query(mode.uses_g4(), diagnostic_g4, diagnostic_g4);
}

#[cfg(test)]
mod repair_tests {
    use super::*;

    #[test]
    fn incompatible_g4_is_rejected_at_every_activation_boundary() {
        assert!(Mode::parse("public_parallel_g4").is_err());
        assert!(std::panic::catch_unwind(|| begin_query(Mode::PublicParallelG4, false)).is_err());
        assert!(std::panic::catch_unwind(|| g4_query::begin_query(true, false, false)).is_err());
    }
}
