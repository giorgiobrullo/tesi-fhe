//! A183's four-PBS two-output ingress and centered consumer refresh.
//! Server section: no secret, plaintext score, diagnostic reference or retry.
use super::*;

pub struct Output {
    pub evaluation: Evaluation,
    pub correction_low: Vec<Lwe>,
    pub correction_middle: Vec<Lwe>,
    pub refreshes: usize,
}

fn nibble(backend: &mut Backend<'_>, input: &Lwe, prefix: &str) -> (Lwe, Lwe) {
    let centered = offset(input, 1 << 59);
    let correction_msb = backend.msb(&centered, 54, format!("{prefix}.correction_msb54"));
    let consumer_msb = backend.msb(&centered, 57, format!("{prefix}.consumer_msb"));
    let remainder = sub(input, &scale(&consumer_msb, 64));
    let correction_low = backend.table(
        &remainder,
        (0..8).map(|r| r << 51).collect(),
        format!("{prefix}.correction_low3"),
    );
    let consumer_low = backend.table(
        &remainder,
        (0..8).map(|r| r << 54).collect(),
        format!("{prefix}.consumer_low3"),
    );
    (
        add(&correction_low, &correction_msb),
        add(&consumer_low, &consumer_msb),
    )
}

fn round(
    backend: &mut Backend<'_>,
    active: &[Lwe],
    digits: &[Lwe],
    prefix: &str,
    output_log: u32,
    refreshes: &mut usize,
) -> Vec<Lwe> {
    assert_eq!(active.len(), digits.len());
    assert!(!active.is_empty());
    let before = backend.calls;
    let refresh_before = *refreshes;
    let masked: Vec<_> = active
        .iter()
        .zip(digits)
        .enumerate()
        .map(|(i, (flag, digit))| {
            let signed_mask = backend.table(
                &add(&scale(digit, 32), flag),
                (0..16).map(|d| (16 - d) << 54).collect(),
                format!("{prefix}.mask/{i}"),
            );
            offset(&add(&signed_mask, digit), 16 << 54)
        })
        .collect();
    let mut layer = masked.clone();
    let mut log = 55;
    let mut depth = 0;
    while layer.len() > 1 {
        if log == 59 {
            layer = layer
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    offset(
                        &backend.table(
                            value,
                            (0u64..16)
                                .map(|m| m.wrapping_sub(8).wrapping_shl(55))
                                .collect(),
                            format!("{prefix}.refresh/{depth}/{i}"),
                        ),
                        8 << 55,
                    )
                })
                .collect();
            *refreshes += layer.len();
            log = 55;
        }
        assert!(log < 59);
        layer = layer
            .chunks(2)
            .enumerate()
            .map(|(i, pair)| {
                if pair.len() == 1 {
                    return scale(&pair[0], 2);
                }
                let absolute = backend.table(
                    &scale(&sub(&pair[0], &pair[1]), 1 << (59 - log)),
                    (0u64..16)
                        .map(|d| d.wrapping_sub(8).wrapping_shl(log))
                        .collect(),
                    format!("{prefix}.minimum/{depth}/{i}"),
                );
                offset(
                    &sub(&add(&pair[0], &pair[1]), &absolute),
                    (8u64 << log).wrapping_neg(),
                )
            })
            .collect();
        depth += 1;
        log += 1;
    }
    let minimum = scale(&layer[0], 1 << (59 - log));
    let valid = offset(
        &backend.table(&minimum, vec![1 << 62; 16], format!("{prefix}.valid")),
        1 << 62,
    );
    let half = 1u64 << (output_log - 1);
    let outputs = masked
        .iter()
        .enumerate()
        .map(|(i, q)| {
            let input = add(&sub(&scale(q, 16), &minimum), &valid);
            offset(
                &backend.table(
                    &input,
                    (0..16)
                        .map(|d| if d == 0 { half.wrapping_neg() } else { half })
                        .collect(),
                    format!("{prefix}.update/{i}"),
                ),
                half,
            )
        })
        .collect();
    assert_eq!(
        backend.calls - before,
        3 * active.len() + *refreshes - refresh_before
    );
    outputs
}

pub fn evaluate(full: &[Lwe], packed: &[Lwe], server: &ServerKey, wrong_scale: bool) -> Output {
    evaluate_with_trace(full, packed, server, wrong_scale, true)
}

pub fn evaluate_with_trace(
    full: &[Lwe],
    packed: &[Lwe],
    server: &ServerKey,
    wrong_scale: bool,
    capture_trace: bool,
) -> Output {
    assert!([4usize, 16, 127, 128].contains(&full.len())); // Explicit successor scope.
    assert_eq!(packed.len(), full.len());
    let mut backend = Backend {
        server,
        events: Vec::new(),
        capture_trace,
        calls: 0,
    };
    let (mut low, mut middle, mut top, mut c0s, mut c1s) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (i, (f, p)) in full.iter().zip(packed).enumerate() {
        let (c0, h0) = nibble(&mut backend, p, &format!("ingress/{i}/low"));
        let residual = sub(f, &scale(&c0, 2));
        let (c1, h1) = nibble(
            &mut backend,
            &scale(&residual, 16),
            &format!("ingress/{i}/middle"),
        );
        top.push(sub(&residual, &scale(&c1, 32)));
        low.push(h0);
        middle.push(h1);
        c0s.push(c0);
        c1s.push(c1);
    }
    let active = backend.initial(&top, 63);
    let factor = if wrong_scale { 2 } else { 1 };
    let mids: Vec<_> = middle.iter().map(|x| scale(x, factor)).collect();
    let lows: Vec<_> = low.iter().map(|x| scale(x, factor)).collect();
    let mut refreshes = 0;
    let active = round(
        &mut backend,
        &active,
        &mids,
        "middle_round",
        63,
        &mut refreshes,
    );
    let flags = round(
        &mut backend,
        &active,
        &lows,
        "low_round",
        59,
        &mut refreshes,
    );
    assert_eq!(backend.calls, 18 * full.len() - 1 + refreshes);
    Output {
        evaluation: Evaluation {
            low,
            middle,
            top,
            flags,
            calls: backend.calls,
            events: backend.events,
        },
        correction_low: c0s,
        correction_middle: c1s,
        refreshes,
    }
}
