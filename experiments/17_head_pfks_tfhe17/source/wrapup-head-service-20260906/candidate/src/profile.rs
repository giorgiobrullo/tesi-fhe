//! Public profile choice. No ciphertext conversion and no key-dependent dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryProfile { Legacy52, Head51 }

impl QueryProfile {
    pub fn for_gallery(n:usize) -> Result<Self,String> {
        if !(1..=128).contains(&n) {return Err("gallery range must be1..128".into());}
        Ok(if n==127 {Self::Head51} else {Self::Legacy52})
    }
    pub fn from_wire(value:u64) -> Result<Self,String> {
        match value {1=>Ok(Self::Legacy52),2=>Ok(Self::Head51),_=>Err("unknown query profile".into())}
    }
    pub fn from_cli(value:&str) -> Result<Self,String> {
        match value {"legacy52"=>Ok(Self::Legacy52),"head51"=>Ok(Self::Head51),_=>Err("explicit legacy52 or head51 profile required".into())}
    }
    pub fn wire(self) -> u64 {match self {Self::Legacy52=>1,Self::Head51=>2}}
    pub fn name(self) -> &'static str {match self {Self::Legacy52=>"legacy52",Self::Head51=>"head51"}}
    pub fn score_delta_log(self) -> u32 {match self {Self::Legacy52=>52,Self::Head51=>51}}
    pub fn validate_scales(self,full:u64,low:u64) -> Result<(),String> {
        if full!=u64::from(self.score_delta_log()) || low!=60 {return Err("query profile and declared scales disagree".into());}
        Ok(())
    }
    pub fn validate_gallery(self,n:usize) -> Result<(),String> {
        if self!=Self::for_gallery(n)? {return Err("query profile does not match current public gallery size".into());}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_public_size_selects_exactly_one_profile() {
        for n in 1..=128 {
            let p=QueryProfile::for_gallery(n).unwrap();
            assert_eq!(p==QueryProfile::Head51,n==127);
            assert!(p.validate_gallery(n).is_ok());
            let wrong=if p==QueryProfile::Head51 {QueryProfile::Legacy52} else {QueryProfile::Head51};
            assert!(wrong.validate_gallery(n).is_err());
        }
        for n in [0,129,usize::MAX] {assert!(QueryProfile::for_gallery(n).is_err());}
    }
    #[test]
    fn wire_cli_and_scale_bindings_are_exact() {
        for p in [QueryProfile::Legacy52,QueryProfile::Head51] {
            assert_eq!(QueryProfile::from_wire(p.wire()).unwrap(),p);
            assert_eq!(QueryProfile::from_cli(p.name()).unwrap(),p);
            assert!(p.validate_scales(u64::from(p.score_delta_log()),60).is_ok());
            for full in [0,50,51,52,53,59,60,64,u64::MAX] {
                assert_eq!(p.validate_scales(full,60).is_ok(),full==u64::from(p.score_delta_log()));
            }
            for low in [0,51,52,59,61,64,u64::MAX] {assert!(p.validate_scales(u64::from(p.score_delta_log()),low).is_err());}
        }
        for wire in [0,3,6,7,u64::MAX] {assert!(QueryProfile::from_wire(wire).is_err());}
        for cli in ["","51","52","auto","Head51"] {assert!(QueryProfile::from_cli(cli).is_err());}
    }
}
