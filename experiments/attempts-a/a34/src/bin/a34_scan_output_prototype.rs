//! Micro-harness FHE isolato per il solo scan+output proposto in A34.
//!
//! Il core A33 congelato produce, tramite `private_argmin_with_trace`, i candidati finali reali
//! dopo tutti i livelli di selezione. A34 consuma direttamente quegli stessi ciphertext alla
//! scala Booleana: non esiste alcun passaggio decrypt->reencrypt. Soltanto questo binario
//! diagnostico possiede la chiave client effimera e decifra candidati/output per le asserzioni.
//!
//! Tutte le LUT aggiunte qui hanno p=16. Il selettore di ogni gruppo usa gli slot indipendenti
//! 0..7 per la prima uscita e 8..15 per la seconda; una singola KS+blind rotation viene seguita
//! da sample extraction ai gradi 0 e N/2. Gli slot logici virtuali 16..31 non sono indipendenti:
//! per la negaciclicita' dell'anello valgono esattamente `slot[s+16] = -slot[s]`. Gli ingressi
//! raggiungibili del selettore restano in 0..7, quindi non attraversano il semigiro antiperiodico.
//!
//! Limiti conservativi di fan-in/peso del rumore in un ingresso PBS: OR <=4; local-first
//! `f+2*c0+c1` <=4; selettore `local+4*prefix` <=5; riduzione cifra <=4; high digit
//! `H-P21+2*E` <=4. La somma finale contiene al massimo tre ciphertext freschi alla scala codice.

use pipeline_tfhe_rs::{
    plan_private_argmin_execution, private_argmin_with_trace, TemplateView, BOOL_DELTA_LOG,
    CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET,
    MAX_GALLERY_SIZE, PROBE_DIM, PROBE_NORM2_MAX,
};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const THRESHOLD: i64 = 4;
const EXECUTION_LOWER: i64 = THRESHOLD - 1023;
const P16: usize = 16;
const OR_RADIX: usize = 4;
const GROUP_SIZE: usize = 3;
const CODE_RADIX: u64 = 8;
const HIGH_GROUP: usize = 21;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone, Copy)]
struct CaseSpec {
    name: &'static str,
    gallery_size: usize,
    tied_ids: &'static [usize],
    all_reject: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrimitiveCounts {
    blind_rotations: u64,
    key_switches: u64,
    output_marginals: u64,
}

impl PrimitiveCounts {
    fn checked_sub(self, before: Self) -> Self {
        Self {
            blind_rotations: self
                .blind_rotations
                .checked_sub(before.blind_rotations)
                .expect("contatore BR non monotono"),
            key_switches: self
                .key_switches
                .checked_sub(before.key_switches)
                .expect("contatore KS non monotono"),
            output_marginals: self
                .output_marginals
                .checked_sub(before.output_marginals)
                .expect("contatore marginali non monotono"),
        }
    }

    fn plus(self, other: Self) -> Self {
        Self {
            blind_rotations: self.blind_rotations + other.blind_rotations,
            key_switches: self.key_switches + other.key_switches,
            output_marginals: self.output_marginals + other.output_marginals,
        }
    }
}

#[derive(Default)]
struct AtomicPrimitiveCounts {
    blind_rotations: AtomicU64,
    key_switches: AtomicU64,
    output_marginals: AtomicU64,
}

impl AtomicPrimitiveCounts {
    fn record_rotation(&self, marginals: u64) {
        self.blind_rotations.fetch_add(1, Ordering::Relaxed);
        self.key_switches.fetch_add(1, Ordering::Relaxed);
        self.output_marginals
            .fetch_add(marginals, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PrimitiveCounts {
        PrimitiveCounts {
            blind_rotations: self.blind_rotations.load(Ordering::Relaxed),
            key_switches: self.key_switches.load(Ordering::Relaxed),
            output_marginals: self.output_marginals.load(Ordering::Relaxed),
        }
    }
}

struct EvalContext<'a> {
    key_switching_key: &'a LweKeyswitchKeyOwned<u64>,
    bootstrap_key: &'a FourierLweBootstrapKeyOwned,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
    counters: &'a AtomicPrimitiveCounts,
}

impl EvalContext<'_> {
    fn apply_p16(&self, input: &Lwe, accumulator: &Glwe) -> Lwe {
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(self.key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, self.big_size, self.modulus);
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut output,
            accumulator,
            self.bootstrap_key,
        );
        self.counters.record_rotation(1);
        output
    }

    fn apply_selector_p16(
        &self,
        input: &Lwe,
        accumulator: &Glwe,
        second_sample: bool,
    ) -> SelectorSamples {
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(self.key_switching_key, input, &mut switched);
        let mut rotated = accumulator.clone();
        blind_rotate_assign(&switched, &mut rotated, self.bootstrap_key);

        let mut first = LweCiphertext::new(0u64, self.big_size, self.modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut first, MonomialDegree(0));
        let second = second_sample.then(|| {
            let mut value = LweCiphertext::new(0u64, self.big_size, self.modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &rotated,
                &mut value,
                MonomialDegree(rotated.polynomial_size().0 / 2),
            );
            value
        });
        self.counters.record_rotation(1 + u64::from(second_sample));
        SelectorSamples { first, second }
    }
}

struct SelectorSamples {
    first: Lwe,
    second: Option<Lwe>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorMode {
    DualDigits,
    N127TailClone,
    N128TailDigitAndE,
}

struct SelectorAccumulator {
    accumulator: Glwe,
    mode: SelectorMode,
}

#[derive(Debug)]
struct StageInstrumentation {
    group_flags: PrimitiveCounts,
    local_first: PrimitiveCounts,
    group_prefix: PrimitiveCounts,
    selectors: PrimitiveCounts,
    digit_reductions: PrimitiveCounts,
    high_flag: PrimitiveCounts,
    high_digit: PrimitiveCounts,
    total: PrimitiveCounts,
}

struct A34Output {
    code: Lwe,
    instrumentation: StageInstrumentation,
}

fn cases() -> Vec<CaseSpec> {
    vec![
        CaseSpec {
            name: "n1_id1",
            gallery_size: 1,
            tied_ids: &[1],
            all_reject: false,
        },
        CaseSpec {
            name: "n3_all_reject",
            gallery_size: 3,
            tied_ids: &[],
            all_reject: true,
        },
        CaseSpec {
            name: "n3_tie_id1_id3",
            gallery_size: 3,
            tied_ids: &[1, 3],
            all_reject: false,
        },
        CaseSpec {
            name: "n64_id63",
            gallery_size: 64,
            tied_ids: &[63],
            all_reject: false,
        },
        CaseSpec {
            name: "n64_id64",
            gallery_size: 64,
            tied_ids: &[64],
            all_reject: false,
        },
        CaseSpec {
            name: "n64_tie_id63_id64",
            gallery_size: 64,
            tied_ids: &[63, 64],
            all_reject: false,
        },
        CaseSpec {
            name: "n127_id127",
            gallery_size: 127,
            tied_ids: &[127],
            all_reject: false,
        },
        CaseSpec {
            name: "n128_tie_id127_id128",
            gallery_size: 128,
            tied_ids: &[127, 128],
            all_reject: false,
        },
        CaseSpec {
            name: "n128_id128",
            gallery_size: 128,
            tied_ids: &[128],
            all_reject: false,
        },
    ]
}

fn make_p16_accumulator<F>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
    delta: u64,
    function: F,
) -> Glwe
where
    F: Fn(u64) -> u64,
{
    generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        P16,
        modulus,
        delta,
        function,
    )
}

fn zero_lwe(big_size: LweSize, modulus: CiphertextModulus<u64>) -> Lwe {
    allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus)
}

fn sum_lwes(values: &[Lwe], zero: &Lwe) -> Lwe {
    let mut sum = zero.clone();
    for value in values {
        lwe_ciphertext_add_assign(&mut sum, value);
    }
    sum
}

fn compact_or<F>(mut bits: Vec<Lwe>, or_gate: &F) -> Lwe
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!bits.is_empty());
    while bits.len() > 1 {
        bits = bits.par_chunks(OR_RADIX).map(or_gate).collect();
    }
    bits.pop().expect("riduzione OR non vuota")
}

fn radix4_exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!flags.is_empty());
    if flags.len() <= OR_RADIX {
        return (0..flags.len())
            .map(|index| match index {
                0 => zero.clone(),
                1 => flags[0].clone(),
                _ => or_gate(&flags[..index]),
            })
            .collect();
    }

    let block_totals: Vec<Lwe> = flags
        .par_chunks(OR_RADIX)
        .map(|block| {
            if block.len() == 1 {
                block[0].clone()
            } else {
                or_gate(block)
            }
        })
        .collect();
    let block_prefixes = radix4_exclusive_prefix_or(&block_totals, zero, or_gate);
    (0..flags.len())
        .into_par_iter()
        .map(|index| {
            let block = index / OR_RADIX;
            let offset = index % OR_RADIX;
            if offset == 0 {
                return block_prefixes[block].clone();
            }
            let start = block * OR_RADIX;
            let mut inputs = Vec::with_capacity(offset + usize::from(block > 0));
            if block > 0 {
                inputs.push(block_prefixes[block].clone());
            }
            inputs.extend(flags[start..start + offset].iter().cloned());
            if inputs.len() == 1 {
                inputs.pop().expect("prefisso locale non vuoto")
            } else {
                or_gate(&inputs)
            }
        })
        .collect()
}

fn active_code(group: usize, group_len: usize, selector_state: usize) -> u64 {
    if !(1..=group_len).contains(&selector_state) {
        return 0;
    }
    (GROUP_SIZE * group + selector_state) as u64
}

fn selector_accumulator(
    gallery_size: usize,
    group: usize,
    group_len: usize,
    groups: usize,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
) -> SelectorAccumulator {
    let mut low = [0u64; 8];
    let mut middle = [0u64; 8];
    let mut is_id128 = [0u64; 8];
    for state in 0..8 {
        let code = active_code(group, group_len, state);
        if code != 0 {
            low[state] = code % CODE_RADIX;
            middle[state] = (code / CODE_RADIX) % CODE_RADIX;
            is_id128[state] = u64::from(code == 128);
        }
    }

    let is_last = group + 1 == groups;
    let mode = if gallery_size == 127 && is_last {
        assert_eq!(low, middle, "il tail N=127 deve avere cifre (7,7)");
        SelectorMode::N127TailClone
    } else if gallery_size == 128 && is_last {
        assert_eq!(low, middle, "il tail N=128 deve avere cifre uguali");
        SelectorMode::N128TailDigitAndE
    } else {
        SelectorMode::DualDigits
    };

    // Con un solo gruppo non esiste una riduzione successiva che converta la scala: il primo
    // semigruppo emette direttamente la cifra bassa a Delta_code e il secondo la cifra media
    // gia' pesata per 8. Per G>1 entrambe restano base-8 a Delta_bool fino alla radix-4 tree.
    let direct_code_scale = groups == 1;
    let delta = if direct_code_scale {
        1u64 << CODE_DELTA_LOG
    } else {
        1u64 << BOOL_DELTA_LOG
    };
    let second = match mode {
        SelectorMode::DualDigits if direct_code_scale => middle.map(|digit| 8 * digit),
        SelectorMode::DualDigits => middle,
        SelectorMode::N127TailClone => [0u64; 8],
        SelectorMode::N128TailDigitAndE => is_id128,
    };

    // Il generatore materializza i sedici slot indipendenti qui sotto. Nel dominio logico
    // esteso imposto dall'anello, i sedici successivi sono i loro opposti modulari; non possono
    // ospitare una terza funzione. Il sample a grado N/2 raggiunge la seconda meta' indipendente
    // (slot 8..15) della stessa rotazione; l'antiperiodicita' spiega perche' ci fermiamo a due.
    let accumulator =
        make_p16_accumulator(polynomial_size, glwe_size, modulus, delta, move |slot| {
            let slot = slot as usize;
            if slot < 8 {
                low[slot]
            } else {
                second[slot - 8]
            }
        });
    SelectorAccumulator { accumulator, mode }
}

fn reduce_digit(
    mut values: Vec<Lwe>,
    identity_accumulator: &Glwe,
    final_accumulator: &Glwe,
    context: &EvalContext<'_>,
    zero: &Lwe,
) -> Lwe {
    assert!(!values.is_empty());
    while values.len() > 1 {
        let next_len = values.len().div_ceil(OR_RADIX);
        let accumulator = if next_len == 1 {
            final_accumulator
        } else {
            identity_accumulator
        };
        values = values
            .par_chunks(OR_RADIX)
            .map(|chunk| context.apply_p16(&sum_lwes(chunk, zero), accumulator))
            .collect();
    }
    values.pop().expect("riduzione cifra non vuota")
}

fn snapshot_delta(counters: &AtomicPrimitiveCounts, before: PrimitiveCounts) -> PrimitiveCounts {
    counters.snapshot().checked_sub(before)
}

fn expected_single_output_stage(rotations: u64) -> PrimitiveCounts {
    PrimitiveCounts {
        blind_rotations: rotations,
        key_switches: rotations,
        output_marginals: rotations,
    }
}

fn a34_scan_output(candidates: &[Lwe], server_key: &ServerKey) -> A34Output {
    let gallery_size = candidates.len();
    assert!((1..=MAX_GALLERY_SIZE).contains(&gallery_size));
    let groups = gallery_size.div_ceil(GROUP_SIZE);
    let modulus = candidates[0].ciphertext_modulus();
    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("il prototipo A34 richiede una bootstrap key classica"),
    };
    let key_switching_key = &server_key.key_switching_key;
    let polynomial_size = bootstrap_key.polynomial_size();
    let glwe_size = bootstrap_key.glwe_size();
    let big_size = bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    assert_eq!(polynomial_size.0 % P16, 0);
    assert_eq!(polynomial_size.0 % 2, 0);

    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let or_accumulator =
        make_p16_accumulator(polynomial_size, glwe_size, modulus, bool_delta, |slot| {
            u64::from((1..=OR_RADIX as u64).contains(&slot))
        });
    let local_first_accumulator = make_p16_accumulator(
        polynomial_size,
        glwe_size,
        modulus,
        bool_delta,
        |slot| match slot {
            0 => 0,
            1 => 3,
            2 => 2,
            3 | 4 => 1,
            _ => 0,
        },
    );
    let digit_identity_accumulator =
        make_p16_accumulator(polynomial_size, glwe_size, modulus, bool_delta, |slot| {
            if slot < CODE_RADIX {
                slot
            } else {
                0
            }
        });
    let low_code_accumulator =
        make_p16_accumulator(polynomial_size, glwe_size, modulus, code_delta, |slot| {
            if slot < CODE_RADIX {
                slot
            } else {
                0
            }
        });
    let middle_code_accumulator =
        make_p16_accumulator(polynomial_size, glwe_size, modulus, code_delta, |slot| {
            if slot < CODE_RADIX {
                CODE_RADIX * slot
            } else {
                0
            }
        });
    let high_code_accumulator = make_p16_accumulator(
        polynomial_size,
        glwe_size,
        modulus,
        code_delta,
        |slot| match slot {
            1 => 64,
            3 => 128,
            _ => 0,
        },
    );
    let selector_accumulators: Vec<SelectorAccumulator> = (0..groups)
        .map(|group| {
            let group_len = (gallery_size - group * GROUP_SIZE).min(GROUP_SIZE);
            selector_accumulator(
                gallery_size,
                group,
                group_len,
                groups,
                polynomial_size,
                glwe_size,
                modulus,
            )
        })
        .collect();

    let counters = AtomicPrimitiveCounts::default();
    let context = EvalContext {
        key_switching_key,
        bootstrap_key,
        small_size,
        big_size,
        modulus,
        counters: &counters,
    };
    let zero = zero_lwe(big_size, modulus);
    let or_gate = |bits: &[Lwe]| -> Lwe {
        assert!(!bits.is_empty() && bits.len() <= OR_RADIX);
        context.apply_p16(&sum_lwes(bits, &zero), &or_accumulator)
    };

    let before = counters.snapshot();
    let group_flags: Vec<Lwe> = candidates
        .par_chunks(GROUP_SIZE)
        .map(|group| {
            if group.len() == 1 {
                group[0].clone()
            } else {
                or_gate(group)
            }
        })
        .collect();
    let group_flag_counts = snapshot_delta(&counters, before);

    let before = counters.snapshot();
    let local_first: Vec<Lwe> = candidates
        .par_chunks(GROUP_SIZE)
        .zip(&group_flags)
        .map(|(group, flag)| {
            if group.len() == 1 {
                return flag.clone();
            }
            let mut encoded = flag.clone();
            // f + 2*c0 + c1: L1 del rumore al massimo 4.
            lwe_ciphertext_add_assign(&mut encoded, &group[0]);
            lwe_ciphertext_add_assign(&mut encoded, &group[0]);
            lwe_ciphertext_add_assign(&mut encoded, &group[1]);
            context.apply_p16(&encoded, &local_first_accumulator)
        })
        .collect();
    let local_first_counts = snapshot_delta(&counters, before);

    let before = counters.snapshot();
    let group_prefixes = radix4_exclusive_prefix_or(&group_flags, &zero, &or_gate);
    let group_prefix_counts = snapshot_delta(&counters, before);

    let before = counters.snapshot();
    let selected: Vec<SelectorSamples> = local_first
        .par_iter()
        .zip(&group_prefixes)
        .zip(&selector_accumulators)
        .map(|((local, prefix), selector)| {
            let mut encoded = local.clone();
            // local + 4*prefix: L1 del rumore al massimo 5.
            for _ in 0..4 {
                lwe_ciphertext_add_assign(&mut encoded, prefix);
            }
            context.apply_selector_p16(
                &encoded,
                &selector.accumulator,
                selector.mode != SelectorMode::N127TailClone,
            )
        })
        .collect();
    let selector_counts = snapshot_delta(&counters, before);

    let mut low_digits = Vec::with_capacity(groups);
    let mut middle_digits = Vec::with_capacity(groups);
    let mut id128_flag = None;
    for (selector, samples) in selector_accumulators.iter().zip(selected) {
        match selector.mode {
            SelectorMode::DualDigits => {
                low_digits.push(samples.first);
                middle_digits.push(samples.second.expect("seconda cifra assente"));
            }
            SelectorMode::N127TailClone => {
                middle_digits.push(samples.first.clone());
                low_digits.push(samples.first);
                assert!(samples.second.is_none());
            }
            SelectorMode::N128TailDigitAndE => {
                low_digits.push(samples.first.clone());
                middle_digits.push(samples.first);
                id128_flag = Some(samples.second.expect("flag E assente"));
            }
        }
    }

    let before = counters.snapshot();
    let low_code = reduce_digit(
        low_digits,
        &digit_identity_accumulator,
        &low_code_accumulator,
        &context,
        &zero,
    );
    let middle_code = reduce_digit(
        middle_digits,
        &digit_identity_accumulator,
        &middle_code_accumulator,
        &context,
        &zero,
    );
    let digit_reduction_counts = snapshot_delta(&counters, before);

    let before = counters.snapshot();
    let high_any =
        (gallery_size >= 64).then(|| compact_or(group_flags[HIGH_GROUP..].to_vec(), &or_gate));
    let high_flag_counts = snapshot_delta(&counters, before);

    let before = counters.snapshot();
    let high_code = high_any.map(|any| {
        let mut encoded = any;
        lwe_ciphertext_sub_assign(&mut encoded, &group_prefixes[HIGH_GROUP]);
        if let Some(flag) = &id128_flag {
            // H - P21 + 2*E: L1 del rumore al massimo 4.
            lwe_ciphertext_add_assign(&mut encoded, flag);
            lwe_ciphertext_add_assign(&mut encoded, flag);
        }
        context.apply_p16(&encoded, &high_code_accumulator)
    });
    let high_digit_counts = snapshot_delta(&counters, before);

    let mut code = low_code;
    lwe_ciphertext_add_assign(&mut code, &middle_code);
    if let Some(high) = high_code {
        lwe_ciphertext_add_assign(&mut code, &high);
    }

    let total = counters.snapshot();
    let instrumentation = StageInstrumentation {
        group_flags: group_flag_counts,
        local_first: local_first_counts,
        group_prefix: group_prefix_counts,
        selectors: selector_counts,
        digit_reductions: digit_reduction_counts,
        high_flag: high_flag_counts,
        high_digit: high_digit_counts,
        total,
    };
    assert_instrumentation(gallery_size, &instrumentation);
    A34Output {
        code,
        instrumentation,
    }
}

fn or_reduction_count(mut items: usize) -> u64 {
    assert!(items > 0);
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(OR_RADIX);
        count += items as u64;
    }
    count
}

fn exclusive_prefix_count(items: usize) -> u64 {
    assert!(items > 0);
    if items <= 2 {
        return 0;
    }
    if items <= OR_RADIX {
        return (items - 2) as u64;
    }
    let mut totals = 0u64;
    let mut expansion = 0u64;
    let mut blocks = 0usize;
    for start in (0..items).step_by(OR_RADIX) {
        let len = (items - start).min(OR_RADIX);
        blocks += 1;
        totals += u64::from(len > 1);
        expansion += if start == 0 {
            len.saturating_sub(2) as u64
        } else {
            (len - 1) as u64
        };
    }
    totals + expansion + exclusive_prefix_count(blocks)
}

fn expected_stage_counts(gallery_size: usize) -> StageInstrumentation {
    let groups = gallery_size.div_ceil(GROUP_SIZE);
    let group_nodes = (0..gallery_size)
        .step_by(GROUP_SIZE)
        .filter(|&start| (gallery_size - start).min(GROUP_SIZE) > 1)
        .count() as u64;
    let prefix_nodes = exclusive_prefix_count(groups);
    let digit_nodes = 2 * or_reduction_count(groups);
    let high_flag_nodes = if gallery_size >= 64 {
        or_reduction_count(groups - HIGH_GROUP)
    } else {
        0
    };
    let high_digit_nodes = u64::from(gallery_size >= 64);
    let selector_marginals = 2 * groups as u64 - u64::from(gallery_size == 127);

    let group_flags = expected_single_output_stage(group_nodes);
    let local_first = expected_single_output_stage(group_nodes);
    let group_prefix = expected_single_output_stage(prefix_nodes);
    let selectors = PrimitiveCounts {
        blind_rotations: groups as u64,
        key_switches: groups as u64,
        output_marginals: selector_marginals,
    };
    let digit_reductions = expected_single_output_stage(digit_nodes);
    let high_flag = expected_single_output_stage(high_flag_nodes);
    let high_digit = expected_single_output_stage(high_digit_nodes);
    let total = group_flags
        .plus(local_first)
        .plus(group_prefix)
        .plus(selectors)
        .plus(digit_reductions)
        .plus(high_flag)
        .plus(high_digit);
    StageInstrumentation {
        group_flags,
        local_first,
        group_prefix,
        selectors,
        digit_reductions,
        high_flag,
        high_digit,
        total,
    }
}

fn assert_instrumentation(gallery_size: usize, actual: &StageInstrumentation) {
    let expected = expected_stage_counts(gallery_size);
    assert_eq!(actual.group_flags, expected.group_flags);
    assert_eq!(actual.local_first, expected.local_first);
    assert_eq!(actual.group_prefix, expected.group_prefix);
    assert_eq!(actual.selectors, expected.selectors);
    assert_eq!(actual.digit_reductions, expected.digit_reductions);
    assert_eq!(actual.high_flag, expected.high_flag);
    assert_eq!(actual.high_digit, expected.high_digit);
    assert_eq!(actual.total, expected.total);
}

fn a33_pre_scan_counts(gallery_size: usize) -> PrimitiveCounts {
    let gallery_reduction = or_reduction_count(gallery_size);
    let pairs = gallery_size.div_ceil(2);
    let pair_reduction = or_reduction_count(pairs);
    let blind_rotations =
        27 * gallery_size as u64 + 9 * gallery_reduction + pairs as u64 + pair_reduction;
    PrimitiveCounts {
        blind_rotations,
        key_switches: 24 * gallery_size as u64
            + 9 * gallery_reduction
            + pairs as u64
            + pair_reduction,
        // Cinque ManyLUT pre-scan espongono ciascuna un margine extra per template.
        output_marginals: blind_rotations + 5 * gallery_size as u64,
    }
}

fn projected_whole_counts(gallery_size: usize, scan_output: PrimitiveCounts) -> PrimitiveCounts {
    a33_pre_scan_counts(gallery_size).plus(scan_output)
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn clear_score(template: &[i64], probe: &[i64]) -> i64 {
    squared_norm(template)
        - 2 * template
            .iter()
            .zip(probe)
            .map(|(gallery, query)| gallery * query)
            .sum::<i64>()
}

fn remainder_terms(remainder: usize) -> &'static [i64] {
    match remainder {
        0 => &[],
        1 => &[-1, 1, 1],
        2 => &[-1, 1],
        3 => &[-1],
        4 => &[-1, -1, 1, 1],
        5 => &[-1, -1, 1],
        6 => &[-1, -1],
        7 => &[-2, 1],
        8 => &[-2],
        9 => &[-1, -1, -1],
        10 => &[-2, -1, 1],
        11 => &[-2, -1],
        12 => &[-1, -1, -1, -1],
        13 => &[-3, 1, 1],
        14 => &[-3, 1],
        _ => unreachable!("resto modulo 15 fuori intervallo"),
    }
}

fn template_for_score(score: i64) -> Vec<i64> {
    let mut template = vec![0i64; PROBE_DIM];
    let used = if score < 0 {
        let count = usize::try_from(-score).expect("score negativo non rappresentabile");
        template[..count].fill(1);
        count
    } else {
        let quotient = usize::try_from(score / 15).expect("quoziente non rappresentabile");
        let tail = remainder_terms((score % 15) as usize);
        template[..quotient].fill(-3);
        template[quotient..quotient + tail.len()].copy_from_slice(tail);
        quotient + tail.len()
    };
    assert!(used <= PROBE_DIM, "score non rappresentabile");
    template
}

fn translated_scores(case: CaseSpec) -> Vec<u64> {
    if case.all_reject {
        return vec![1024; case.gallery_size];
    }
    let mut scores = vec![513; case.gallery_size];
    for &id in case.tied_ids {
        assert!((1..=case.gallery_size).contains(&id));
        scores[id - 1] = 512;
    }
    scores
}

fn expected_candidates(scores: &[u64]) -> Vec<u64> {
    let minimum = *scores.iter().min().expect("score non vuoti");
    if minimum > 1023 {
        return vec![0; scores.len()];
    }
    scores
        .iter()
        .map(|&score| u64::from(score == minimum))
        .collect()
}

fn make_gallery(scores: &[u64], probe: &[i64]) -> Vec<Vec<i64>> {
    scores
        .iter()
        .map(|&translated| {
            let score = i64::try_from(translated).expect("score fuori i64") + EXECUTION_LOWER;
            let template = template_for_score(score);
            assert_eq!(clear_score(&template, probe), score);
            template
        })
        .collect()
}

fn encrypt_packed_probe(
    probe: &[i64],
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    polynomial_size: PolynomialSize,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= PROBE_NORM2_MAX);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM <= polynomial_size.0);

    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOW_MOD16_DELTA_LOG);
    }
    let mut encrypted = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
        modulus,
    );
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    encrypted
}

fn decode_symbol(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe, delta_log: u32) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (delta_log - 1))
        >> delta_log
}

fn validate_case(
    case: CaseSpec,
    server_key: &ServerKey,
    probe: &[i64],
    packed_probe: &Glwe,
    big_secret_key: &LweSecretKeyView<'_, u64>,
) {
    let scores = translated_scores(case);
    let expected_bits = expected_candidates(&scores);
    let expected_code = expected_bits
        .iter()
        .position(|&value| value == 1)
        .map_or(0, |index| (index + 1) as u64);
    let gallery = make_gallery(&scores, probe);
    let templates: Vec<TemplateView<'_>> = gallery
        .iter()
        .map(|template| TemplateView {
            template,
            norm2: squared_norm(template),
            threshold: THRESHOLD,
        })
        .collect();
    let plan = plan_private_argmin_execution(&templates).expect("planning A33 fallito");
    assert!(plan.aligned_fast_path, "{}: dispatch non A33", case.name);
    assert_eq!(plan.execution_domain.lower, EXECUTION_LOWER);

    let started = Instant::now();
    let (a33_output, trace) =
        private_argmin_with_trace(server_key, packed_probe, &templates, plan.execution_domain)
            .expect("core A33 ha rifiutato un caso valido");
    assert!(trace.aligned_fast_path);
    let candidates = trace
        .candidates_by_level
        .last()
        .expect("checkpoint dei candidati finali assente");
    assert_eq!(candidates.len(), case.gallery_size);

    // A34 riceve direttamente gli LWE prodotti dal trace A33. La decifratura diagnostica
    // sottostante avviene soltanto dopo l'intera valutazione A34 e non puo' alimentare il circuito.
    let a34 = a34_scan_output(candidates, server_key);

    let decoded_candidates: Vec<u64> = candidates
        .iter()
        .map(|candidate| decode_symbol(big_secret_key, candidate, BOOL_DELTA_LOG) & 15)
        .collect();
    assert_eq!(
        decoded_candidates, expected_bits,
        "{}: candidati A33",
        case.name
    );
    let decoded_code = decode_symbol(big_secret_key, &a34.code, CODE_DELTA_LOG) & 255;
    assert_eq!(decoded_code, expected_code, "{}: output A34", case.name);

    let old_scan_output = a33_output.metrics.scan.pbs_count + a33_output.metrics.output.pbs_count;
    let pre_scan_from_metrics = a33_output
        .metrics
        .total_pbs_count
        .checked_sub(old_scan_output)
        .expect("metriche A33 incoerenti");
    let expected_pre_scan = a33_pre_scan_counts(case.gallery_size);
    assert_eq!(pre_scan_from_metrics, expected_pre_scan.blind_rotations);
    let projected = projected_whole_counts(case.gallery_size, a34.instrumentation.total);
    if case.gallery_size == 127 {
        assert_eq!(
            a34.instrumentation.total,
            PrimitiveCounts {
                blind_rotations: 220,
                key_switches: 220,
                output_marginals: 262,
            }
        );
        assert_eq!(
            projected,
            PrimitiveCounts {
                blind_rotations: 4121,
                key_switches: 3740,
                output_marginals: 4798,
            }
        );
    }

    println!(
        "RESULT,case={},n={},code={},ties={},a33_old_scan={},a33_old_output={},a34_br={},a34_ks={},a34_marginals={},projected_br={},projected_ks={},projected_marginals={},seconds={:.6},correct=true",
        case.name,
        case.gallery_size,
        decoded_code,
        expected_bits.iter().sum::<u64>(),
        a33_output.metrics.scan.pbs_count,
        a33_output.metrics.output.pbs_count,
        a34.instrumentation.total.blind_rotations,
        a34.instrumentation.total.key_switches,
        a34.instrumentation.total.output_marginals,
        projected.blind_rotations,
        projected.key_switches,
        projected.output_marginals,
        started.elapsed().as_secs_f64(),
    );
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let all_cases = cases();
    if arguments.iter().any(|argument| argument == "--list") {
        for case in &all_cases {
            println!("CASE,name={},n={}", case.name, case.gallery_size);
        }
        return;
    }

    let n127 = expected_stage_counts(127);
    let projected_n127 = projected_whole_counts(127, n127.total);
    assert_eq!(
        n127.total,
        PrimitiveCounts {
            blind_rotations: 220,
            key_switches: 220,
            output_marginals: 262,
        }
    );
    assert_eq!(
        projected_n127,
        PrimitiveCounts {
            blind_rotations: 4121,
            key_switches: 3740,
            output_marginals: 4798,
        }
    );
    if !arguments.iter().any(|argument| argument == "--run") {
        println!(
            "usage: a34_scan_output_prototype --run [--small-only] [--case=NAME]\n\
             PLAN,cases={},source=final_A33_trace_candidates,no_decrypt_reencrypt=true,p=16,ephemeral_key=true,secret_material_persisted=false,n127_scan_output=220/220/262,n127_projected_whole=4121/3740/4798",
            all_cases.len()
        );
        return;
    }

    let selected_name = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--case="));
    let small_only = arguments.iter().any(|argument| argument == "--small-only");
    let selected: Vec<CaseSpec> = all_cases
        .into_iter()
        .filter(|case| selected_name.map_or(true, |name| case.name == name))
        .filter(|case| !small_only || case.gallery_size <= 3)
        .collect();
    assert!(!selected.is_empty(), "nessun caso selezionato");

    // Una sola chiave fresca, effimera e mai serializzata per l'intero harness.
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let probe = vec![1i64; PROBE_DIM];
    assert!(squared_norm(&probe) <= PROBE_NORM2_MAX);

    for case in selected {
        let packed_probe = encrypt_packed_probe(
            &probe,
            &glwe_secret_key,
            client_params.glwe_noise_distribution(),
            polynomial_size,
            modulus,
            &mut generator,
        );
        validate_case(case, &server_key, &probe, &packed_probe, &big_secret_key);
    }
}
