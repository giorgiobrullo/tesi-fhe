// La banda di sfocatura della soglia leveled (varco_leveled.rs), misurata a cavallo di T.
//
// Il PBS di segno decide "s <= T" guardando in quale meta' del torus cade x = (s-T)*Delta -
// Delta/2 dopo il modulus switch a 2N. Il modulus switch aggiunge un errore (~ sqrt(n/24) * q/2N)
// che, in unita' di punteggio, e' una sfocatura intorno a T. Sui dati reali non e' mai scattata
// (nessuna coppia vicina a T, F37); qui la misuriamo apposta: per ogni d = s - T da -D a +D,
// cifriamo `PROVE` volte il valore e contiamo quante volte il bit esce 1 ("match"). Ne esce la
// curva P(match | d), da cui la deviazione della banda in unita' di punteggio, per la stessa
// Delta_s usata sulla scena reale (2^51) e per due alternative (2^50, 2^52).
//
//   cargo run --release --bin banda_soglia
use rayon::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::{generate_keys, ConfigBuilder};

const D: i64 = 48;
const PROVE: usize = 400;

fn main() {
    let (ck_hl, sk_hl) = generate_keys(ConfigBuilder::default().build());
    let (ick, _, _, _) = ck_hl.into_raw_parts();
    let sck = ick.into_raw_parts();
    let (isk, _, _, _, _) = sk_hl.into_raw_parts();
    let ssk = isk.into_raw_parts();
    let (enc_key, noise) = sck.encryption_key_and_noise();
    let ksk = &ssk.key_switching_key;
    let fbsk = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k,
        _ => panic!("attesa bootstrapping key classica"),
    };
    let modulus = CiphertextModulus::<u64>::new_native();
    let big_size = enc_key.lwe_dimension().to_lwe_size();
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        fbsk.glwe_size(),
        &PlaintextList::new((1u64 << 61).wrapping_neg(), PlaintextCount(fbsk.polynomial_size().0)),
        modulus,
    );
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!("n_piccola={} N={} -> errore teorico del modulus switch ~ sqrt(n/24)*2^(64-12) = 2^{:.1}",
             small_size.to_lwe_dimension().0, fbsk.polynomial_size().0,
             52.0 + ((small_size.to_lwe_dimension().0 as f64) / 24.0).sqrt().log2());
    for &log_delta in &[50u32, 51, 52] {
        let delta = 1u64 << log_delta;
        // cifra: PROVE cifrati per ogni d (il rumore fresco e' trascurabile rispetto al mod switch)
        let campioni: Vec<(i64, LweCiphertextOwned<u64>)> = (-D..=D)
            .flat_map(|d| {
                (0..PROVE).map(move |_| d).collect::<Vec<_>>()
            })
            .map(|d| {
                let x = (d as u64).wrapping_mul(delta).wrapping_sub(delta >> 1);
                (d, allocate_and_encrypt_new_lwe_ciphertext(&enc_key, Plaintext(x), noise, modulus, &mut enc_gen))
            })
            .collect();
        let esiti: Vec<(i64, u64)> = campioni
            .par_iter()
            .map(|(d, x)| {
                let mut ks = LweCiphertext::new(0u64, small_size, modulus);
                keyswitch_lwe_ciphertext(ksk, x, &mut ks);
                let mut out = LweCiphertext::new(0u64, big_size, modulus);
                programmable_bootstrap_lwe_ciphertext(&ks, &mut out, &acc, fbsk);
                lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(1u64 << 61));
                let dec = decrypt_lwe_ciphertext(&enc_key, &out).0;
                (*d, (dec.wrapping_add(1u64 << 61) >> 62) & 1)
            })
            .collect();
        // P(match | d): atteso 1 per d < 0 (s < T... qui d = s - T - 1 + 1: match se d <= 0)
        println!("\nDelta_s = 2^{log_delta}  (P(bit=1) per d = s - T; corretto: 1 se d <= 0, 0 se d > 0)");
        let mut sbagliati = 0usize;
        let mut prima_err = i64::MAX;
        let mut ultima_err = i64::MIN;
        let mut riga = String::new();
        for d in -D..=D {
            let uno = esiti.iter().filter(|(dd, b)| *dd == d && *b == 1).count();
            let p = uno as f64 / PROVE as f64;
            let atteso = if d <= 0 { 1.0 } else { 0.0 };
            let err = ((p - atteso).abs() * PROVE as f64).round() as usize;
            if err > 0 {
                sbagliati += err;
                prima_err = prima_err.min(d);
                ultima_err = ultima_err.max(d);
            }
            if d % 4 == 0 || (-8..=8).contains(&d) {
                riga.push_str(&format!("d={d:>3}: {p:.2}  "));
                if riga.len() > 96 { println!("  {riga}"); riga.clear(); }
            }
        }
        if !riga.is_empty() { println!("  {riga}"); }
        println!("  esiti sbagliati: {sbagliati}/{} ({:.3}%), banda con errori: d in [{}, {}]",
                 esiti.len(), 100.0 * sbagliati as f64 / esiti.len() as f64,
                 if prima_err == i64::MAX { 0 } else { prima_err }, if ultima_err == i64::MIN { 0 } else { ultima_err });
    }
}
