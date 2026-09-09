//! Every admitted gallery uses one directly encrypted native input profile.
use crate::protocol::{LOG_LOW_MOD16_DELTA, LOG_SCORE_DELTA, MAX_GALLERY};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryProfile {
    Head51,
}

impl QueryProfile {
    pub fn for_gallery(n: usize) -> Result<Self, String> {
        if !(1..=MAX_GALLERY).contains(&n) {
            return Err(format!("gallery range must be 1..{MAX_GALLERY}"));
        }
        Ok(Self::Head51)
    }

    pub fn from_wire(value: u64) -> Result<Self, String> {
        match value {
            2 => Ok(Self::Head51),
            _ => Err("only native head51 query profile 2 is supported".into()),
        }
    }

    pub fn from_cli(value: &str) -> Result<Self, String> {
        match value {
            "head51" => Ok(Self::Head51),
            _ => Err("explicit head51 query profile required".into()),
        }
    }

    pub fn wire(self) -> u64 {
        2
    }
    pub fn name(self) -> &'static str {
        "head51"
    }
    pub fn score_delta_log(self) -> u32 {
        LOG_SCORE_DELTA
    }

    pub fn validate_scales(self, full: u64, low: u64) -> Result<(), String> {
        if full != u64::from(LOG_SCORE_DELTA) || low != u64::from(LOG_LOW_MOD16_DELTA) {
            return Err("native head51 requires full scale 51 and low scale 60".into());
        }
        Ok(())
    }

    pub fn validate_gallery(self, n: usize) -> Result<(), String> {
        Self::for_gallery(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_admitted_size_uses_the_same_native_profile() {
        for n in 1..=MAX_GALLERY {
            let profile = QueryProfile::for_gallery(n).unwrap();
            assert_eq!(profile, QueryProfile::Head51);
            assert!(profile.validate_gallery(n).is_ok());
            assert_eq!(profile.wire(), 2);
            assert_eq!(profile.score_delta_log(), 51);
        }
        for n in [0, MAX_GALLERY + 1, usize::MAX] {
            assert!(QueryProfile::for_gallery(n).is_err());
            assert!(QueryProfile::Head51.validate_gallery(n).is_err());
        }
    }

    #[test]
    fn old_profiles_and_wrong_scales_are_rejected() {
        let profile = QueryProfile::Head51;
        assert_eq!(QueryProfile::from_wire(2).unwrap(), profile);
        assert_eq!(QueryProfile::from_cli("head51").unwrap(), profile);
        assert!(profile.validate_scales(51, 60).is_ok());
        for wire in [0, 1, 3, 7, 8, u64::MAX] {
            assert!(QueryProfile::from_wire(wire).is_err());
        }
        for name in ["", "legacy52", "51", "52", "auto", "Head51"] {
            assert!(QueryProfile::from_cli(name).is_err());
        }
        for full in [0, 50, 52, 53, 59, 60, 64, u64::MAX] {
            assert!(profile.validate_scales(full, 60).is_err());
        }
        for low in [0, 51, 52, 59, 61, 64, u64::MAX] {
            assert!(profile.validate_scales(51, low).is_err());
        }
    }
}
