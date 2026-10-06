//! Independent local row/GLWE arithmetic observations; no secret serialization.
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tfhe::core_crypto::prelude::*;
pub const U: u64 = 1u64 << 52;

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn words_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for word in words {
        h.update(word.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
pub fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0 && s.bytes().all(|x| x.is_ascii_hexdigit()));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
pub fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-')
}
// Only controlled printable ASCII enters this small JSON serializer. No dependency/lock change.
pub fn text(s: &str) -> String {
    assert!(s.bytes().all(|b| (32..127).contains(&b)));
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
pub fn object(fields: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(k, v)| format!("{}:{v}", text(k)))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}
pub fn ciphertext(words: &[u64]) -> String {
    object(&[
        (
            "words_hex",
            array(
                &words
                    .iter()
                    .map(|x| text(&format!("{x:016x}")))
                    .collect::<Vec<_>>(),
            ),
        ),
        ("sha256", text(&words_hash(words))),
    ])
}
pub fn private_directory(path: &Path) {
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}
pub fn save(directory: &Path, name: &str, content: String) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    writeln!(file, "{content}").unwrap();
    file.sync_all().unwrap();
    fs::File::open(directory).unwrap().sync_all().unwrap();
}
pub fn signed(x: u64) -> i128 {
    i128::from(x as i64)
}
pub fn dot_mod(a: &[u64], s: &[u64]) -> u64 {
    assert_eq!(a.len(), s.len());
    a.iter()
        .zip(s)
        .fold(0u64, |sum, (&a, &s)| sum.wrapping_add(a.wrapping_mul(s)))
}
pub struct Components {
    pub remainder: i128,
    pub row_noise: i128,
    pub g: u128,
    pub rows: Vec<String>,
}
pub fn measure_before_ks(
    ksk: &LweKeyswitchKeyOwned<u64>,
    input: &LweCiphertextOwned<u64>,
    large_secret: &[u64],
    small: &LweSecretKeyOwned<u64>,
) -> Components {
    let decomposer =
        SignedDecomposer::<u64>::new(DecompositionBaseLog(3), DecompositionLevelCount(5));
    let mut result = Components {
        remainder: 0,
        row_noise: 0,
        g: 1u128 << 64,
        rows: Vec::new(),
    };
    for (i, ((block, &a), &secret)) in ksk
        .iter()
        .zip(input.get_mask().as_ref())
        .zip(large_secret)
        .enumerate()
    {
        result.remainder +=
            signed(a.wrapping_sub(decomposer.closest_representable(a))) * i128::from(secret);
        let mut count = 0;
        for (storage_index, (row, term)) in block.iter().zip(decomposer.decompose(a)).enumerate() {
            let level = term.level().0;
            assert_eq!(level, 5 - storage_index);
            count += 1;
            let digit = signed(term.value());
            if digit == 0 {
                continue;
            }
            let factor = 1u128 << (digit.unsigned_abs().trailing_zeros());
            result.g = result.g.min(factor);
            // Row plaintext is S_i * 2^(64 - 3*level), with descending storage levels.
            let row_message = secret.wrapping_mul(1u64 << (64 - 3 * level));
            let row_phase = decrypt_lwe_ciphertext(small, &row).0;
            let eta = signed(row_phase.wrapping_sub(row_message));
            let contribution = -digit * eta;
            result.row_noise += contribution;
            result.rows.push(object(&[
                ("input_index", i.to_string()),
                ("level", level.to_string()),
                ("storage_index", storage_index.to_string()),
                ("digit", digit.to_string()),
                ("row_words_sha256", text(&words_hash(row.as_ref()))),
                ("eta_centered_lift", eta.to_string()),
                ("contribution_lift", contribution.to_string()),
            ]));
        }
        assert_eq!(count, 5);
    }
    result
}
