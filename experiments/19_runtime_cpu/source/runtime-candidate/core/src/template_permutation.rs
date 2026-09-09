// Source-only adapter for a separately frozen successor; no ciphertext operations.
// Query coordinates must all be one. Identity is the public 1-based gallery ID.
pub fn diversify_template(template: &mut [i64], identity: usize) {
    assert_eq!(template.len(), 512);
    assert!((1..=127).contains(&identity));
    template.rotate_right(identity - 1);
}
