//! Exact helper extraction from the passing N127 gate.
use super::*;

pub(super) fn signed_cell_mask(polynomial_size: PolynomialSize, virtual_center: usize) -> Poly {
    assert_eq!(polynomial_size.0, POLYNOMIAL_SIZE);
    let ring_size = polynomial_size.0 as isize;
    let mut coefficients = vec![0u64; polynomial_size.0];
    for error in -STRICT_RADIUS..=STRICT_RADIUS {
        let virtual_degree = virtual_center as isize + error;
        let cycles = virtual_degree.div_euclid(ring_size);
        let index = virtual_degree.rem_euclid(ring_size) as usize;
        let coefficient = if cycles.rem_euclid(2) == 0 {
            1u64
        } else {
            u64::MAX
        };
        assert!(coefficients[index] == 0 || coefficients[index] == coefficient);
        coefficients[index] = coefficient;
    }
    assert_eq!(
        coefficients.iter().filter(|&&word| word != 0).count(),
        (2 * STRICT_RADIUS + 1) as usize
    );
    Polynomial::from_container(coefficients)
}

pub(super) fn hash_lwe(ciphertext: &Lwe) -> String {
    let mut hasher = Sha256::new();
    for coefficient in ciphertext.as_ref() {
        hasher.update(coefficient.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub(super) fn modulus_switch_degree(phase: u64) -> usize {
    let two_n = 2 * POLYNOMIAL_SIZE;
    ((((phase as u128) * (two_n as u128) + (1u128 << 63)) >> 64) as usize) % two_n
}

pub(super) fn centered_degree_error(observed: usize, expected: usize) -> isize {
    let modulus = 2 * POLYNOMIAL_SIZE;
    let forward = (observed + modulus - expected) % modulus;
    if forward > modulus / 2 {
        forward as isize - modulus as isize
    } else {
        forward as isize
    }
}

pub(super) fn effective_rotation_degree(control: &Lwe, secret: &LweSecretKeyView<'_, u64>) -> usize {
    let size = PolynomialSize(POLYNOMIAL_SIZE);
    let modulus = 2 * POLYNOMIAL_SIZE;
    let body = pbs_modulus_switch(*control.get_body().data, size) % modulus;
    let mask = control
        .get_mask()
        .as_ref()
        .iter()
        .zip(secret.as_ref())
        .fold(0usize, |sum, (&a, &s)| {
            assert!(
                s <= 1,
                "effective rotation audit assumes the pinned binary secret"
            );
            (sum + pbs_modulus_switch(a, size) * s as usize) % modulus
        });
    (body + modulus - mask) % modulus
}

pub(super) fn emit(value: serde_json::Value) {
    println!("{value}");
    io::stdout().flush().expect("flush research result record");
}

pub(super) fn nontrivial(ciphertext: &Lwe) -> bool {
    ciphertext.get_mask().as_ref().iter().any(|&word| word != 0)
}
