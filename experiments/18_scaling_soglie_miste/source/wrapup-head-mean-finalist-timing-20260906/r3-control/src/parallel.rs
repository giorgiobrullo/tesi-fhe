//! Same arithmetic and barriers as precision.rs; only independent work is scheduled in Rayon.
use super::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct ParallelBackend<'a> {
    server: &'a ServerKey,
    calls: AtomicUsize,
}
impl<'a> ParallelBackend<'a> {
    fn primitive(&self) -> Backend<'a> {
        Backend {
            server: self.server,
            events: Vec::new(),
            capture_trace: false,
            calls: 0,
        }
    }
    fn table(&self, input: &Lwe, values: Vec<u64>, name: String) -> Lwe {
        let mut backend = self.primitive();
        let out = backend.table(input, values, name);
        assert_eq!(backend.calls, 1);
        assert!(backend.events.is_empty());
        self.calls.fetch_add(1, Ordering::Relaxed);
        out
    }
    fn msb(&self, input: &Lwe, log: u32, name: String) -> Lwe {
        let mut backend = self.primitive();
        let out = backend.msb(input, log, name);
        assert_eq!(backend.calls, 1);
        assert!(backend.events.is_empty());
        self.calls.fetch_add(1, Ordering::Relaxed);
        out
    }
    fn initial(&self, tops: &[Lwe], flag_log: u32) -> Vec<Lwe> {
        assert!([59, 63].contains(&flag_log));
        let codes: Vec<_> = tops
            .par_iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    x,
                    (0..16)
                        .map(|v| a34_top_classifier_slot_lut(v) << 59)
                        .collect(),
                    String::new(),
                )
            })
            .collect();
        let mut layer: Vec<_> = codes
            .par_iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(x, 4 << 59),
                    (0..16)
                        .map(|v| a34_canonical_category_lut(v) << 59)
                        .collect(),
                    String::new(),
                )
            })
            .collect();
        let mut depth = 0;
        while layer.len() > 1 {
            layer = layer
                .par_chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    if pair.len() == 1 {
                        pair[0].clone()
                    } else {
                        self.table(
                            &add(&pair[0], &pair[1]),
                            (0..16).map(|v| a34_pair_category_lut(v) << 59).collect(),
                            String::new(),
                        )
                    }
                })
                .collect();
            depth += 1;
        }
        codes
            .par_iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(&add(x, &layer[0]), 4 << 59),
                    (0..16)
                        .map(|v| a34_top_candidate_lut(v) << flag_log)
                        .collect(),
                    String::new(),
                )
            })
            .collect()
    }
}
fn nibble(backend: &ParallelBackend<'_>, input: &Lwe, prefix: &str) -> (Lwe, Lwe) {
    let centered = offset(input, 1 << 59);
    let correction_msb = backend.msb(&centered, 54, String::new());
    let consumer_msb = backend.msb(&centered, 57, String::new());
    let remainder = sub(input, &scale(&consumer_msb, 64));
    let correction_low =
        backend.table(&remainder, (0..8).map(|r| r << 51).collect(), String::new());
    let consumer_low = backend.table(&remainder, (0..8).map(|r| r << 54).collect(), String::new());
    (
        add(&correction_low, &correction_msb),
        add(&consumer_low, &consumer_msb),
    )
}

fn round(
    backend: &ParallelBackend<'_>,
    active: &[Lwe],
    digits: &[Lwe],
    prefix: &str,
    output_log: u32,
    refreshes: &mut usize,
) -> Vec<Lwe> {
    assert_eq!(active.len(), digits.len());
    assert!(!active.is_empty());
    let before = backend.calls.load(Ordering::Relaxed);
    let refresh_before = *refreshes;
    let masked: Vec<_> = active
        .par_iter()
        .zip(digits.par_iter())
        .enumerate()
        .map(|(i, (flag, digit))| {
            let signed_mask = backend.table(
                &add(&scale(digit, 32), flag),
                (0..16).map(|d| (16 - d) << 54).collect(),
                String::new(),
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
                .par_iter()
                .enumerate()
                .map(|(i, value)| {
                    offset(
                        &backend.table(
                            value,
                            (0u64..16)
                                .map(|m| m.wrapping_sub(8).wrapping_shl(55))
                                .collect(),
                            String::new(),
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
            .par_chunks(2)
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
                    String::new(),
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
        &backend.table(&minimum, vec![1 << 62; 16], String::new()),
        1 << 62,
    );
    let half = 1u64 << (output_log - 1);
    let outputs = masked
        .par_iter()
        .enumerate()
        .map(|(i, q)| {
            let input = add(&sub(&scale(q, 16), &minimum), &valid);
            offset(
                &backend.table(
                    &input,
                    (0..16)
                        .map(|d| if d == 0 { half.wrapping_neg() } else { half })
                        .collect(),
                    String::new(),
                ),
                half,
            )
        })
        .collect();
    assert_eq!(
        backend.calls.load(Ordering::Relaxed) - before,
        3 * active.len() + *refreshes - refresh_before
    );
    outputs
}

pub fn evaluate(
    full: &[Lwe],
    packed: &[Lwe],
    server: &ServerKey,
    wrong_scale: bool,
) -> precision::Output {
    assert!([4usize, 16, 127, 128].contains(&full.len()));
    assert_eq!(full.len(), packed.len());
    let backend = ParallelBackend {
        server,
        calls: AtomicUsize::new(0),
    };
    let rows: Vec<_> = full
        .par_iter()
        .zip(packed.par_iter())
        .map(|(f, p)| {
            let (c0, h0) = nibble(&backend, p, "");
            let residual = sub(f, &scale(&c0, 2));
            let (c1, h1) = nibble(&backend, &scale(&residual, 16), "");
            (h0, h1, sub(&residual, &scale(&c1, 32)), c0, c1)
        })
        .collect();
    let (mut low, mut middle, mut top, mut c0s, mut c1s) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (h0, h1, t, c0, c1) in rows {
        low.push(h0);
        middle.push(h1);
        top.push(t);
        c0s.push(c0);
        c1s.push(c1);
    }
    let active = backend.initial(&top, 63);
    let factor = if wrong_scale { 2 } else { 1 };
    let mids: Vec<_> = middle.par_iter().map(|x| scale(x, factor)).collect();
    let lows: Vec<_> = low.par_iter().map(|x| scale(x, factor)).collect();
    let mut refreshes = 0;
    let active = round(&backend, &active, &mids, "", 63, &mut refreshes);
    let flags = round(&backend, &active, &lows, "", 59, &mut refreshes);
    let calls = backend.calls.load(Ordering::Relaxed);
    assert_eq!(calls, 18 * full.len() - 1 + refreshes);
    precision::Output {
        evaluation: Evaluation {
            low,
            middle,
            top,
            flags,
            events: Vec::new(),
            calls,
        },
        correction_low: c0s,
        correction_middle: c1s,
        refreshes,
    }
}
