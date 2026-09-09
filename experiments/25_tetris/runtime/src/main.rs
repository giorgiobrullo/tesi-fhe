mod splitfft;
mod tetris;
use fast::service;
use rayon::prelude::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{fs, path::Path, time::Instant};
use tetris::*;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
const SCHEMA: &str = "tetris-setI-rank2-to1-exact-vs-splitfft.v1";
fn put(path: &Path, bytes: &[u8]) {
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    out.write_all(bytes).unwrap();
    out.sync_all().unwrap();
}
fn put_json(path: &Path, value: &Value) {
    put(path, &serde_json::to_vec(value).unwrap());
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    bincode::deserialize(&fs::read(path).unwrap()).unwrap()
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn emit(value: Value) {
    println!("{}", value);
}
fn audit_nibble(
    e: &NibbleEvidence,
    value: usize,
    s: &Secrets,
    big: &GlweSecretKeyOwned<u64>,
) -> Value {
    let prefix = prefix_encode(value);
    let mut failures = 0;
    let mut max_refreshed = 0;
    let mut max_traced = 0;
    let mut max_ggsw = 0;
    let input_phase = decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), &e.input).0;
    failures += usize::from(distance(input_phase, (value as u64) * D) >= D / 2);
    let small_phase = decrypt_lwe_ciphertext(&s.small, &e.small).0;
    let small_error = distance(
        small_phase,
        (value as u64).wrapping_mul(2 * D).wrapping_add(D),
    );
    failures += usize::from(small_error >= D);
    let address = (e.switched_degrees[710] as i64
        - e.switched_degrees[..710]
            .iter()
            .zip(s.small.as_ref())
            .map(|(&a, &bit)| a as i64 * bit as i64)
            .sum::<i64>())
    .rem_euclid(2048) as usize;
    failures += usize::from(address / 128 != value);
    for j in 0..4 {
        let bit = ((prefix >> (3 - j)) & 1) as u64;
        for level in 1..=2 {
            let gadget = 1u64 << (64 - 8 * level);
            let expected = bit * gadget;
            let error = distance(phase(&e.refreshed[j][level - 1], &s.refresh)[0], expected);
            max_refreshed = max_refreshed.max(error);
            failures += usize::from(error >= gadget / 2);
            let p = phase(&e.traced[j][level - 1], &s.refresh);
            for (i, &word) in p.iter().enumerate() {
                let error = distance(word, if i == 0 { expected } else { 0 });
                max_traced = max_traced.max(error);
                failures += usize::from(error >= gadget / 2);
            }
        }
        for (idx, matrix) in e.ggsws[j].iter().enumerate() {
            let gadget = 1u64 << (64 - 8 * (2 - idx));
            for (row, ct) in matrix.as_glwe_list().iter().enumerate() {
                let owned = Glwe::from_container(
                    ct.as_ref().to_vec(),
                    PolynomialSize(N),
                    CiphertextModulus::new_native(),
                );
                for (i, &word) in phase(&owned, &s.evaluation).iter().enumerate() {
                    let expected = if row == 0 {
                        s.evaluation.as_ref()[i]
                            .wrapping_mul(bit * gadget)
                            .wrapping_neg()
                    } else if i == 0 {
                        bit * gadget
                    } else {
                        0
                    };
                    let error = distance(word, expected);
                    max_ggsw = max_ggsw.max(error);
                    failures += usize::from(error >= gadget / 2);
                }
            }
        }
    }
    json!({"value":value,"prefix":prefix,"failures":failures,"small_error":small_error,"actual_br_address":address,"max_refreshed_constant_error":max_refreshed,"max_traced_coefficient_error":max_traced,"max_ggsw_row_error":max_ggsw})
}
fn save_nibble(dir: &Path, name: &str, e: &NibbleEvidence, value: usize, audit: &Value) {
    let refreshed: Vec<Vec<&[u64]>> = e
        .refreshed
        .iter()
        .map(|x| x.iter().map(|c| c.as_ref()).collect())
        .collect();
    let traced: Vec<Vec<&[u64]>> = e
        .traced
        .iter()
        .map(|x| x.iter().map(|c| c.as_ref()).collect())
        .collect();
    let ggsws: Vec<&[u64]> = e.ggsws.iter().map(|c| c.as_ref()).collect();
    put_json(
        &dir.join(format!("{name}.json")),
        &json!({"schema":SCHEMA,"kind":"nibble","value":value,"input":e.input.as_ref(),"small":e.small.as_ref(),"mean_correction":e.mean_correction,"switched_degrees":e.switched_degrees,"refreshed":refreshed,"traced":traced,"ggsws_descending_gadget_levels":ggsws,"times":e.times,"native_audit":audit}),
    );
}
#[derive(Clone, Copy, Debug)]
enum Arm {
    Exact,
    Split,
    SplitParallel,
}
impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Split => "splitfft",
            Self::SplitParallel => "splitfft_parallel6",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Exact => 0,
            Self::Split => 1,
            Self::SplitParallel => 2,
        }
    }
    fn backend(self, acceleration: &Acceleration) -> Option<&Acceleration> {
        match self {
            Self::Exact => None,
            Self::Split | Self::SplitParallel => Some(acceleration),
        }
    }
}
fn order(index: usize) -> [Arm; 2] {
    if index % 2 == 0 {
        [Arm::Exact, Arm::Split]
    } else {
        [Arm::Split, Arm::Exact]
    }
}
fn consumer_order(index: usize) -> [Arm; 3] {
    use Arm::{Exact as E, Split as S, SplitParallel as P};
    [
        [E, S, P],
        [E, P, S],
        [S, E, P],
        [S, P, E],
        [P, E, S],
        [P, S, E],
    ][index % 6]
}
fn make_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn input_json(path: &Path, pins: &mut Vec<Value>) -> Value {
    let bytes = fs::read(path).unwrap();
    pins.push(json!({"path":path,"bytes":bytes.len(),"sha256":hash(&bytes)}));
    serde_json::from_slice(&bytes).unwrap()
}
fn lwe_json(words: &Value) -> Lwe {
    let words: Vec<u64> = serde_json::from_value(words.clone()).unwrap();
    assert_eq!(words.len(), 2049);
    Lwe::from_container(words, CiphertextModulus::new_native())
}
struct Loaded {
    keys: Keys,
    secrets: Secrets,
    big: GlweSecretKeyOwned<u64>,
    acceleration: Acceleration,
    setup: Value,
}
fn load_family(private: &Path) -> Loaded {
    let prepared: Value =
        serde_json::from_slice(&fs::read(private.join("PREPARED.json")).unwrap()).unwrap();
    assert_eq!(
        prepared["schema"],
        json!("tetris-setI-rank2-to1-exact-integer-diagnostic.v1")
    );
    let names = [
        "a44-bundle.bin",
        "a44-secret.bin",
        "tetris-keys.bin",
        "tetris-secrets.bin",
        "secret-words.json",
    ];
    for name in names {
        let record = prepared["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == name)
            .unwrap();
        let bytes = fs::read(private.join(name)).unwrap();
        assert_eq!(record["bytes"], json!(bytes.len()));
        assert_eq!(record["sha256"], json!(hash(&bytes)));
    }
    let keys: Keys = read(&private.join("tetris-keys.bin"));
    let secrets: Secrets = read(&private.join("tetris-secrets.bin"));
    let big = read(&private.join("a44-secret.bin"));
    let clock = Instant::now();
    let acceleration = keys.accelerate();
    let cache_setup_s = clock.elapsed().as_secs_f64();
    let payload = acceleration.payload_bytes();
    assert_eq!(payload, 4_325_376);
    let setup = json!({"schema":SCHEMA,"cache_setup_s":cache_setup_s,"additional_fourier_payload_bytes":payload,"both_arms_resident":true,"origin_private":private,"origin_prepared_sha256":hash(&fs::read(private.join("PREPARED.json")).unwrap()),"origin_prepared":prepared,"binary_sha256":hash(&fs::read(std::env::current_exe().unwrap()).unwrap()),"split_bits":38,"planner":"fixed Dif4: N1024/base512 and N2048/base1024, before Fourier loading", "reference_comparator":"parallel3 with READY1 and native count assertion","rayon_threads":rayon::current_num_threads()});
    Loaded {
        keys,
        secrets,
        big,
        acceleration,
        setup,
    }
}
fn prerequisite(private: &Path, section: &str) {
    let record: Value =
        serde_json::from_slice(&fs::read(private.join(section).join("RESULT.json")).unwrap())
            .unwrap();
    assert_eq!(record["failures"], json!(0));
    if section == "primitive" {
        assert_eq!(record["nibbles"], json!(16));
        assert_eq!(record["digit_pairs"], json!(256));
    } else {
        assert_eq!(record["merges"], json!(9));
        assert_eq!(record["outputs"], json!(18));
    }
}
fn phase_delta(left: &NibbleEvidence, right: &NibbleEvidence, s: &Secrets) -> Value {
    assert_eq!(left.input.as_ref(), right.input.as_ref());
    assert_eq!(left.small.as_ref(), right.small.as_ref());
    assert_eq!(left.switched_degrees, right.switched_degrees);
    let mut trace_delta = 0;
    let mut ggsw_delta = 0;
    for bit in 0..4 {
        for level in 0..2 {
            assert_eq!(
                left.refreshed[bit][level].as_ref(),
                right.refreshed[bit][level].as_ref()
            );
            for (a, b) in phase(&left.traced[bit][level], &s.refresh)
                .into_iter()
                .zip(phase(&right.traced[bit][level], &s.refresh))
            {
                trace_delta = trace_delta.max(distance(a, b));
            }
        }
        for (a, b) in left.ggsws[bit]
            .as_glwe_list()
            .iter()
            .zip(right.ggsws[bit].as_glwe_list().iter())
        {
            let a = Glwe::from_container(
                a.as_ref().to_vec(),
                PolynomialSize(N),
                CiphertextModulus::new_native(),
            );
            let b = Glwe::from_container(
                b.as_ref().to_vec(),
                PolynomialSize(N),
                CiphertextModulus::new_native(),
            );
            for (a, b) in phase(&a, &s.evaluation)
                .into_iter()
                .zip(phase(&b, &s.evaluation))
            {
                ggsw_delta = ggsw_delta.max(distance(a, b));
            }
        }
    }
    json!({"input_small_and_refresh_words_equal":true,"max_traced_phase_delta":trace_delta,"max_ggsw_phase_delta":ggsw_delta})
}
fn primitive(private: &Path, out: &Path) {
    prerequisite(private, "primitive");
    make_dir(out);
    let loaded = load_family(private);
    put_json(&out.join("SETUP.json"), &loaded.setup);
    let base = out.join("primitive");
    make_dir(&base);
    for arm in [Arm::Exact, Arm::Split] {
        make_dir(&base.join(arm.name()));
    }
    let mut bits: [Vec<Bits>; 2] = [Vec::new(), Vec::new()];
    let mut total: [Times; 2] = [Times::default(), Times::default()];
    let mut differences = Vec::new();
    let mut pins = Vec::new();
    let mut failures = 0;
    for value in 0..16 {
        let original = input_json(
            &private.join(format!("primitive/nibble-{value:02}.json")),
            &mut pins,
        );
        assert_eq!(original["value"], json!(value));
        let input = lwe_json(&original["input"]);
        let mut pair: [Option<NibbleEvidence>; 2] = [None, None];
        for arm in order(value) {
            let (b, e) = loaded
                .keys
                .nibble_with_backend(&input, arm.backend(&loaded.acceleration));
            let audit = audit_nibble(&e, value, &loaded.secrets, &loaded.big);
            failures += audit["failures"].as_u64().unwrap();
            save_nibble(
                &base.join(arm.name()),
                &format!("nibble-{value:02}"),
                &e,
                value,
                &audit,
            );
            total[arm.index()].add(&e.times);
            bits[arm.index()].push(b);
            emit(
                json!({"kind":"nibble_done","value":value,"arm":arm.name(),"audit":audit,"times":e.times}),
            );
            pair[arm.index()] = Some(e);
        }
        let delta = phase_delta(
            pair[0].as_ref().unwrap(),
            pair[1].as_ref().unwrap(),
            &loaded.secrets,
        );
        differences.push(json!({"value":value,"order":order(value).map(Arm::name),"delta":delta}));
    }
    put_json(
        &out.join("NIBBLE_COMPARISON.json"),
        &json!({"schema":SCHEMA,"differences":differences,"origin_input_pins":pins,"failures":failures}),
    );
    assert_eq!(
        failures, 0,
        "all32 records retained before stopping failed gate"
    );
    let mut rows: [Vec<Value>; 2] = [Vec::new(), Vec::new()];
    let mut maximum = [0, 0];
    for a in 0..16 {
        for b in 0..16 {
            for arm in order(16 * a + b) {
                let (ct, table, t) = loaded
                    .keys
                    .digit_sign(&bits[arm.index()][a], &bits[arm.index()][b]);
                total[arm.index()].add(&t);
                let expected = ((a as i64 - b as i64).signum() as u64).wrapping_mul(D);
                let error = distance(
                    decrypt_lwe_ciphertext(&loaded.big.as_lwe_secret_key(), &ct).0,
                    expected,
                );
                let table_error = distance(phase(&table, &loaded.secrets.evaluation)[0], expected);
                maximum[arm.index()] = maximum[arm.index()].max(error);
                failures += u64::from(error >= D / 2) + u64::from(table_error >= D / 2);
                rows[arm.index()].push(json!({"a":a,"b":b,"output":ct.as_ref(),"table":table.as_ref(),"expected_phase":expected,"native_error":error,"native_table_error":table_error,"times":t}));
            }
        }
    }
    for arm in [Arm::Exact, Arm::Split] {
        let directory = base.join(arm.name());
        put_json(
            &directory.join("pairs.json"),
            &json!({"schema":SCHEMA,"kind":"digit_pairs","pairs":rows[arm.index()]}),
        );
        put_json(
            &directory.join("RESULT.json"),
            &json!({"schema":SCHEMA,"kind":"primitive_result","arm":arm.name(),"nibbles":16,"prefix_bits":64,"digit_pairs":256,"failures":failures,"max_error":maximum[arm.index()],"times":total[arm.index()]}),
        );
    }
    let result = json!({"schema":SCHEMA,"kind":"primitive_comparison","arms":["exact","splitfft"],"nibbles":32,"digit_pairs":512,"failures":failures,"times":total,"boundary":"same retained encrypted inputs and key; diagnostic stage costs, not general latency"});
    put_json(&out.join("PRIMITIVE_RESULT.json"), &result);
    emit(result);
    assert_eq!(failures, 0);
}
fn combine_signs(signs: &[Lwe]) -> Lwe {
    assert_eq!(signs.len(), 3);
    let mut control = signs[0].clone();
    for (i, word) in control.as_mut().iter_mut().enumerate() {
        *word = signs[0].as_ref()[i]
            .wrapping_mul(4)
            .wrapping_add(signs[1].as_ref()[i].wrapping_mul(2))
            .wrapping_add(signs[2].as_ref()[i]);
    }
    *control.get_mut_body().data = control.get_body().data.wrapping_sub(D / 2);
    control
}
struct Producer {
    control: Lwe,
    signs: Vec<Lwe>,
    nibble_evidence: Vec<(NibbleEvidence, NibbleEvidence)>,
    digit_evidence: Vec<(Glwe, Times)>,
    times: Times,
}
fn produce(loaded: &Loaded, arm: Arm, left: &[Lwe; 6], right: &[Lwe; 6]) -> Producer {
    let mut signs = Vec::new();
    let mut nibble_evidence = Vec::new();
    let mut digit_evidence = Vec::new();
    let mut local_times = Times::default();
    let compute_digit = |digit: usize| {
        let nibble = |input: &Lwe| {
            loaded
                .keys
                .nibble_with_backend(input, arm.backend(&loaded.acceleration))
        };
        let ((a, ae), (b, be)) = if matches!(arm, Arm::SplitParallel) {
            rayon::join(|| nibble(&left[digit]), || nibble(&right[digit]))
        } else {
            (nibble(&left[digit]), nibble(&right[digit]))
        };
        let (sign, table, time) = loaded.keys.digit_sign(&a, &b);
        (sign, ae, be, table, time)
    };
    let computations: Vec<_> = if matches!(arm, Arm::SplitParallel) {
        (0..3).into_par_iter().map(compute_digit).collect()
    } else {
        (0..3).map(compute_digit).collect()
    };
    for (sign, ae, be, table, time) in computations {
        local_times.add(&ae.times);
        local_times.add(&be.times);
        local_times.add(&time);
        nibble_evidence.push((ae, be));
        digit_evidence.push((table, time));
        signs.push(sign);
    }
    let control = combine_signs(&signs);
    Producer {
        control,
        signs,
        nibble_evidence,
        digit_evidence,
        times: local_times,
    }
}
struct FastProducer {
    control: Lwe,
    signs: Vec<Lwe>,
    times: Times,
}
fn produce_fast(loaded: &Loaded, left: &[Lwe; 6], right: &[Lwe; 6]) -> FastProducer {
    let computations: Vec<_> = (0..3)
        .into_par_iter()
        .map(|digit| {
            let ((a, at), (b, bt)) = rayon::join(
                || {
                    loaded
                        .keys
                        .nibble_without_evidence(&left[digit], &loaded.acceleration)
                },
                || {
                    loaded
                        .keys
                        .nibble_without_evidence(&right[digit], &loaded.acceleration)
                },
            );
            let (sign, _table, mut times) = loaded.keys.digit_sign(&a, &b);
            times.add(&at);
            times.add(&bt);
            (sign, times)
        })
        .collect();
    let mut times = Times::default();
    let mut signs = Vec::with_capacity(3);
    for (sign, time) in computations {
        times.add(&time);
        signs.push(sign);
    }
    let control = combine_signs(&signs);
    FastProducer {
        control,
        signs,
        times,
    }
}
struct Pilot<'a> {
    loaded: &'a Loaded,
    core: &'a service::EvaluationKeys,
    out: &'a Path,
    arm: Arm,
    records: Vec<Value>,
    times: Times,
}
impl Pilot<'_> {
    fn merge(
        &mut self,
        left: &[Lwe; 6],
        right: &[Lwe; 6],
        lc: [u64; 6],
        rc: [u64; 6],
        number: usize,
        label: &str,
    ) -> [Lwe; 6] {
        let endpoint = Instant::now();
        let fast =
            matches!(self.arm, Arm::SplitParallel).then(|| produce_fast(self.loaded, left, right));
        let retained = if fast.is_none() {
            Some(produce(self.loaded, self.arm, left, right))
        } else {
            None
        };
        let timed_control = fast
            .as_ref()
            .map(|x| &x.control)
            .unwrap_or_else(|| &retained.as_ref().unwrap().control);
        let producer_s = endpoint.elapsed().as_secs_f64();
        let clock = Instant::now();
        let actual = self.core.tetris_pilot_select(left, right, timed_control);
        let current_consumer_s = clock.elapsed().as_secs_f64();
        let endpoint_s = endpoint.elapsed().as_secs_f64();
        // The evidence-off parallel arm is matched to a separate retained replay after its endpoint.
        let diagnostic = retained.unwrap_or_else(|| produce(self.loaded, self.arm, left, right));
        if let Some(fast) = &fast {
            assert_eq!(fast.control.as_ref(), diagnostic.control.as_ref());
            for (a, b) in fast.signs.iter().zip(&diagnostic.signs) {
                assert_eq!(a.as_ref(), b.as_ref());
            }
        }
        let Producer {
            control,
            signs,
            nibble_evidence,
            digit_evidence,
            times: local_times,
        } = diagnostic;
        self.times.add(&local_times);
        let clock = Instant::now();
        let reference_control = self.core.tetris_pilot_classic_compare(left, right);
        let reference_producer_s = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        let reference = self
            .core
            .tetris_pilot_select(left, right, &reference_control);
        let reference_consumer_s = clock.elapsed().as_secs_f64();
        let mut failures = 0;
        for (digit, (ae, be)) in nibble_evidence.iter().enumerate() {
            for (side, e, value) in [("left", ae, lc[digit]), ("right", be, rc[digit])] {
                let audit = audit_nibble(e, value as usize, &self.loaded.secrets, &self.loaded.big);
                failures += audit["failures"].as_u64().unwrap();
                save_nibble(
                    self.out,
                    &format!("merge-{number}-{digit}-{side}"),
                    e,
                    value as usize,
                    &audit,
                );
            }
            let expected = ((lc[digit] as i64 - rc[digit] as i64).signum() as u64).wrapping_mul(D);
            let error = distance(
                decrypt_lwe_ciphertext(&self.loaded.big.as_lwe_secret_key(), &signs[digit]).0,
                expected,
            );
            failures += u64::from(error >= D / 2);
            put_json(
                &self.out.join(format!("merge-{number}-{digit}-sign.json")),
                &json!({"kind":"consumer_digit","digit":digit,"left_value":lc[digit],"right_value":rc[digit],"table":digit_evidence[digit].0.as_ref(),"output":signs[digit].as_ref(),"native_error":error,"times":digit_evidence[digit].1}),
            );
        }
        let wanted = if lc[..3] > rc[..3] { rc } else { lc };
        let mut max_error = 0;
        for output in [&actual, &reference] {
            for (i, ct) in output.iter().enumerate() {
                let error = distance(
                    decrypt_lwe_ciphertext(&self.loaded.big.as_lwe_secret_key(), ct).0,
                    wanted[i] * D,
                );
                max_error = max_error.max(error);
                failures += u64::from(error >= D / 2);
            }
        }
        let expected_control = (((4 * (lc[0] as i64 - rc[0] as i64).signum()
            + 2 * (lc[1] as i64 - rc[1] as i64).signum()
            + (lc[2] as i64 - rc[2] as i64).signum())
            * 2
            - 1) as u64)
            .wrapping_mul(D / 2);
        let control_error = distance(
            decrypt_lwe_ciphertext(&self.loaded.big.as_lwe_secret_key(), &control).0,
            expected_control,
        );
        failures += u64::from(control_error >= D / 2);
        let record = json!({"schema":SCHEMA,"kind":"merge","number":number,"label":label,"arm":self.arm.name(),"left_clear":lc,"right_clear":rc,"wanted":wanted,"left":left.iter().map(|x|x.as_ref()).collect::<Vec<_>>(),"right":right.iter().map(|x|x.as_ref()).collect::<Vec<_>>(),"control":control.as_ref(),"reference_control":reference_control.as_ref(),"output":actual.iter().map(|x|x.as_ref()).collect::<Vec<_>>(),"reference_output":reference.iter().map(|x|x.as_ref()).collect::<Vec<_>>(),"native_control_error":control_error,"failures":failures,"max_error":max_error,"current_consumer_s":current_consumer_s,"reference_producer_s":reference_producer_s,"reference_consumer_s":reference_consumer_s,"reference_schedule":fast::classic_batch::report(),"producer_s":producer_s,"producer_and_consumer_s":endpoint_s,"stage_times":local_times,"production_matches_retained_control_and_signs":fast.as_ref().map(|_|true),"timed_producer_control":fast.as_ref().map(|x|x.control.as_ref()),"timed_producer_signs":fast.as_ref().map(|x|x.signs.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>()),"timed_stage_times":fast.as_ref().map(|x|&x.times),"timed_diagnostic_retention":fast.is_none(),"nibble_task_schedule":if matches!(self.arm,Arm::SplitParallel){"parallel3_digits_join2_nibbles"}else{"serial6_nibbles"}});
        put_json(
            &self.out.join(format!("merge-{number}-output.json")),
            &record,
        );
        self.records.push(record);
        emit(
            json!({"kind":"merge_done","arm":self.arm.name(),"number":number,"label":label,"failures":failures,"endpoint_s":endpoint_s}),
        );
        assert_eq!(failures, 0);
        actual
    }
}
fn consumer(private: &Path, out: &Path) {
    prerequisite(private, "consumer");
    let prerequisite: Value =
        serde_json::from_slice(&fs::read(out.join("PRIMITIVE_RESULT.json")).unwrap()).unwrap();
    assert_eq!(prerequisite["failures"], json!(0));
    assert_eq!(prerequisite["digit_pairs"], json!(512));
    let loaded = load_family(private);
    put_json(&out.join("CONSUMER_SETUP.json"), &loaded.setup);
    let core = service::EvaluationKeys::from_bundle(read(&private.join("a44-bundle.bin"))).unwrap();
    let base = out.join("consumer");
    make_dir(&base);
    let directories = [
        base.join("exact"),
        base.join("splitfft"),
        base.join("splitfft_parallel6"),
    ];
    for path in &directories {
        make_dir(path);
    }
    let mut pilots = [
        Pilot {
            loaded: &loaded,
            core: &core,
            out: &directories[0],
            arm: Arm::Exact,
            records: Vec::new(),
            times: Times::default(),
        },
        Pilot {
            loaded: &loaded,
            core: &core,
            out: &directories[1],
            arm: Arm::Split,
            records: Vec::new(),
            times: Times::default(),
        },
        Pilot {
            loaded: &loaded,
            core: &core,
            out: &directories[2],
            arm: Arm::SplitParallel,
            records: Vec::new(),
            times: Times::default(),
        },
    ];
    let mut tree_children: [Vec<[Lwe; 6]>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut pins = Vec::new();
    let mut pairs = Vec::new();
    for number in 0..9 {
        let original = input_json(
            &private.join(format!("consumer/merge-{number}-output.json")),
            &mut pins,
        );
        assert_eq!(original["number"], json!(number));
        let lc: [u64; 6] = serde_json::from_value(original["left_clear"].clone()).unwrap();
        let rc: [u64; 6] = serde_json::from_value(original["right_clear"].clone()).unwrap();
        let label = original["label"].as_str().unwrap();
        let common_left: [Lwe; 6] = std::array::from_fn(|i| lwe_json(&original["left"][i]));
        let common_right: [Lwe; 6] = std::array::from_fn(|i| lwe_json(&original["right"][i]));
        for arm in consumer_order(number) {
            let index = arm.index();
            let (left, right) = if number == 8 {
                (&tree_children[index][0], &tree_children[index][1])
            } else {
                (&common_left, &common_right)
            };
            let selected = pilots[index].merge(left, right, lc, rc, number, label);
            if number == 6 || number == 7 {
                tree_children[index].push(selected);
            }
        }
        pairs.push(json!({"number":number,"label":label,"order":consumer_order(number).map(Arm::name),"shared_input_words":number<8,"exact_endpoint_s":pilots[0].records[number]["producer_and_consumer_s"],"splitfft_endpoint_s":pilots[1].records[number]["producer_and_consumer_s"],"splitfft_parallel6_endpoint_s":pilots[2].records[number]["producer_and_consumer_s"]}));
    }
    for pilot in &pilots {
        let result = json!({"schema":SCHEMA,"kind":"consumer_result","arm":pilot.arm.name(),"merges":9,"outputs":18,"failures":0,"two_level_winner":pilot.records[8]["wanted"],"stage_times":pilot.times,"records":pilot.records.iter().map(|r|json!({"number":r["number"],"label":r["label"],"current_consumer_s":r["current_consumer_s"],"reference_producer_s":r["reference_producer_s"],"reference_consumer_s":r["reference_consumer_s"],"producer_and_consumer_s":r["producer_and_consumer_s"]})).collect::<Vec<_>>()});
        put_json(&pilot.out.join("RESULT.json"), &result);
    }
    let result = json!({"schema":SCHEMA,"kind":"consumer_comparison","merges_per_arm":9,"complete_outputs":54,"failures":0,"pairs":pairs,"origin_input_pins":pins,"boundary":"one retained family, nine fixed scenes; root inputs are each arm's actual selected children; no warmup exclusion or heldout performance inference"});
    put_json(&out.join("CONSUMER_RESULT.json"), &result);
    emit(result);
}
fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}
fn timing(private: &Path, out: &Path) {
    prerequisite(private, "consumer");
    let consumer: Value =
        serde_json::from_slice(&fs::read(out.join("CONSUMER_RESULT.json")).unwrap()).unwrap();
    assert_eq!(
        (
            consumer["failures"].as_u64(),
            consumer["complete_outputs"].as_u64()
        ),
        (Some(0), Some(54))
    );
    let plan: Value = serde_json::from_str(include_str!("../prereg-timing.json")).unwrap();
    assert_eq!(plan["pairs"].as_array().unwrap().len(), 24);
    let loaded = load_family(private);
    let core = service::EvaluationKeys::from_bundle(read(&private.join("a44-bundle.bin"))).unwrap();
    let base = out.join("timing");
    make_dir(&base);
    let mut pins = Vec::new();
    let mut inputs = Vec::new();
    for number in [0, 2, 8] {
        let original = input_json(
            &private.join(format!("consumer/merge-{number}-output.json")),
            &mut pins,
        );
        assert_eq!(original["number"], json!(number));
        let left: [Lwe; 6] = std::array::from_fn(|i| lwe_json(&original["left"][i]));
        let right: [Lwe; 6] = std::array::from_fn(|i| lwe_json(&original["right"][i]));
        inputs.push((original, left, right));
    }
    put_json(
        &out.join("TIMING_SETUP.json"),
        &json!({"setup":loaded.setup,"plan":plan,"plan_sha256":hash(include_bytes!("../prereg-timing.json")),"origin_input_pins":pins}),
    );
    let mut rows = Vec::new();
    let mut failures = 0;
    for (pair, planned) in plan["pairs"].as_array().unwrap().iter().enumerate() {
        let repeat = pair / 3;
        let position = pair % 3;
        let number = [0, 2, 8][position];
        let names = if (repeat + position) % 2 == 0 {
            ["parallel3", "splitfft_parallel6"]
        } else {
            ["splitfft_parallel6", "parallel3"]
        };
        assert_eq!(
            planned,
            &json!({"pair":pair,"scene":number,"repeat":repeat,"warmup":repeat<2,"order":names})
        );
        let (original, left, right) = &inputs[position];
        let lc: [u64; 6] = serde_json::from_value(original["left_clear"].clone()).unwrap();
        let rc: [u64; 6] = serde_json::from_value(original["right_clear"].clone()).unwrap();
        let mut outputs = Vec::new();
        for name in names {
            let start_unix_ns = unix_ns();
            let start = Instant::now();
            let (control, candidate) = if name == "parallel3" {
                (core.tetris_pilot_classic_compare(left, right), None)
            } else {
                let producer = produce_fast(&loaded, left, right);
                let FastProducer {
                    control,
                    signs,
                    times,
                } = producer;
                (control, Some((signs, times)))
            };
            let elapsed = start.elapsed().as_secs_f64();
            let end_unix_ns = unix_ns();
            assert!(end_unix_ns > start_unix_ns);
            outputs.push((
                name,
                elapsed,
                start_unix_ns,
                end_unix_ns,
                control,
                candidate,
            ));
        }
        // Neither arm's decryptions, hashes, JSON serialization nor writes occur between pair timers.
        let mut pair_rows = Vec::new();
        for (name, elapsed, start_unix_ns, end_unix_ns, control, candidate) in outputs {
            let expected = (((4 * (lc[0] as i64 - rc[0] as i64).signum()
                + 2 * (lc[1] as i64 - rc[1] as i64).signum()
                + (lc[2] as i64 - rc[2] as i64).signum())
                * 2
                - 1) as u64)
                .wrapping_mul(D / 2);
            let error = distance(
                decrypt_lwe_ciphertext(&loaded.big.as_lwe_secret_key(), &control).0,
                expected,
            );
            failures += u64::from(error >= D / 2);
            let (sign_words, stage_times) =
                if let Some((candidate_signs, candidate_times)) = candidate {
                    let signs: Vec<Vec<u64>> = candidate_signs
                        .iter()
                        .map(|x| x.as_ref().to_vec())
                        .collect();
                    for (digit, sign) in candidate_signs.iter().enumerate() {
                        let expected =
                            ((lc[digit] as i64 - rc[digit] as i64).signum() as u64).wrapping_mul(D);
                        failures += u64::from(
                            distance(
                                decrypt_lwe_ciphertext(&loaded.big.as_lwe_secret_key(), sign).0,
                                expected,
                            ) >= D / 2,
                        );
                    }
                    (json!(signs), json!(candidate_times))
                } else {
                    (Value::Null, Value::Null)
                };
            let record = json!({"schema":SCHEMA,"kind":"timed_producer","pair":pair,"scene":number,"label":original["label"],"repeat":repeat,"warmup":repeat<2,"order":names,"arm":name,"elapsed_s":elapsed,"start_unix_ns":start_unix_ns,"end_unix_ns":end_unix_ns,"input_source":pins[position],"left_clear":lc,"right_clear":rc,"control":control.as_ref(),"signs":sign_words,"stage_times":stage_times,"expected_control":expected,"native_error":error,"failures":failures,"reference_schedule":if name=="parallel3"{fast::classic_batch::report()}else{Value::Null},"fresh_nibble_conversions":if name=="splitfft_parallel6"{6}else{0}});
            put_json(&base.join(format!("pair-{pair:02}-{name}.json")), &record);
            pair_rows.push(json!({"arm":name,"elapsed_s":elapsed,"start_unix_ns":start_unix_ns,"end_unix_ns":end_unix_ns}));
        }
        rows.push(json!({"pair":pair,"scene":number,"repeat":repeat,"warmup":repeat<2,"order":names,"outputs":pair_rows}));
        emit(
            json!({"kind":"timing_pair_done","pair":pair,"scene":number,"failures":failures,"outputs":pair_rows}),
        );
        assert_eq!(
            failures, 0,
            "both outputs retained before correctness failure stops this pilot"
        );
    }
    let result = json!({"schema":SCHEMA,"kind":"timing_result","pairs":24,"outputs":48,"measured_pairs":18,"warmup_pairs":6,"failures":failures,"records":rows,"boundary":"one retained key and three repeated encrypted inputs; six fresh Tetris conversions per candidate; all conversion/allocation/scheduling included; decryption, hashing, disk and PFKS excluded"});
    put_json(&out.join("TIMING_RESULT.json"), &result);
    emit(result);
}

fn install_plans() {
    // Current selected A44 plan and the explicit corresponding Tetris N1024 plan.
    for size in [512, 1024] {
        setup_custom_fft_plan(Plan::new(
            size,
            Method::UserProvided {
                base_algo: FftAlgo::Dif4,
                base_n: size,
            },
        ));
    }
}
fn main() {
    assert_eq!(
        rayon::current_num_threads(),
        16,
        "fixed pilot thread budget"
    );
    install_plans();
    let mut args = std::env::args().skip(1);
    let command = args.next().expect("primitive|consumer|timing");
    let private = args.next().expect("qualified exact private family");
    let out = args.next().expect("new comparison output directory");
    assert!(args.next().is_none());
    match command.as_str() {
        "primitive" => primitive(Path::new(&private), Path::new(&out)),
        "consumer" => consumer(Path::new(&private), Path::new(&out)),
        "timing" => timing(Path::new(&private), Path::new(&out)),
        _ => panic!("unknown command"),
    }
}
