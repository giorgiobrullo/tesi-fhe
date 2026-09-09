//! Hash helpers; client observations remain in comparator and d1.
use super::*;

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn hash_words(words: &[u64]) -> String {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}
