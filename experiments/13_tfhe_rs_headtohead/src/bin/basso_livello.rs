// "Si puo' avere ENTRAMBI?" — prodotto scalare LEVELED (senza bootstrap) a basso livello.
//
// Ad alto livello (FheInt16) il prodotto scalare costa ~51 s a N=8 (F32): l'API radix
// propaga i riporti via bootstrap a ogni somma. Qui scendiamo a `core_crypto`: la probe e'
// una manciata di cifrati LWE, e il punteggio p_i = ||g_i||^2 - 2*(g_i . a) e' una pura
// COMBINAZIONE LINEARE con coefficienti in chiaro -> operazioni LWE leveled (scalar-mul + add),
// ZERO bootstrap. Verifichiamo che decifri corretto e cronometriamo.
//
// NB parametri: dimensione/rumore scelti per far decifrare correttamente 12 bit di punteggio
// dopo l'accumulo (caveat: la validazione formale della sicurezza a 128 bit e' un passo a se';
// qui dimostriamo fattibilita' e costo, non consegniamo parametri di produzione).
//
//   cargo run --release --bin basso_livello

use std::time::Instant;
use tfhe::core_crypto::prelude::*;

const DIM: usize = 64;
const Q: i64 = 2;
const PREC: u64 = 12; // bit di messaggio per il punteggio (|p| < 2048)
const DELTA: u64 = 1u64 << (64 - PREC);

// LCG deterministico: stessi dati di main.rs.
fn lcg(s: &mut u64) -> i64 {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((*s >> 33) % (2 * Q as u64 + 1)) as i64 - Q
}

fn gallery(n: usize) -> (Vec<Vec<i64>>, Vec<i64>) {
    let mut s = 12345u64;
    let mut g = vec![vec![0i64; DIM]; n];
    let mut bsq = vec![0i64; n];
    for i in 0..n {
        for j in 0..DIM {
            let v = lcg(&mut s);
            g[i][j] = v;
            bsq[i] += v * v;
        }
    }
    (g, bsq)
}

fn encode(m: i64) -> u64 {
    (m as u64).wrapping_mul(DELTA)
}
fn decode(p: u64) -> i64 {
    // arrotonda al piu' vicino multiplo di DELTA, poi interpreta con segno su 64 bit
    let q = ((p as u128 + (DELTA as u128 >> 1)) >> (64 - PREC)) as u64 & ((1u64 << PREC) - 1);
    if q >= (1u64 << (PREC - 1)) {
        q as i64 - (1i64 << PREC)
    } else {
        q as i64
    }
}

fn main() {
    // --- parametri LWE (demo: rumore basso + dim ampia per 12 bit leveled) ---
    let lwe_dimension = LweDimension(1024);
    let std_dev = StandardDev(0.00000000000004); // ~2^-44, margine per 12 bit dopo accumulo
    let noise = DynamicDistribution::new_gaussian_from_std_dev(std_dev);
    let modulus = CiphertextModulus::new_native();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut sec_gen = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let sk = LweSecretKey::generate_new_binary(lwe_dimension, &mut sec_gen);
    let lwe_size = lwe_dimension.to_lwe_size();

    println!("Prodotto scalare LEVELED in core_crypto (LWE grezzi), DIM={DIM}\n");
    println!("{:>3} | {:>10} | {:>7} | esito", "N", "dot (tutti)", "confr.");

    let mut rng_seed = 999u64;
    for &n in &[4usize, 8, 16, 32, 64] {
        let (g, bsq) = gallery(n);
        let a: Vec<i64> = (0..DIM).map(|_| lcg(&mut rng_seed)).collect();

        // cifra la probe: DIM cifrati LWE
        let enc: Vec<LweCiphertextOwned<u64>> = a
            .iter()
            .map(|&v| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &sk,
                    Plaintext(encode(v)),
                    noise,
                    modulus,
                    &mut enc_gen,
                )
            })
            .collect();

        // --- DOT LEVELED: p_i = bsq_i + sum_j (-2*g[i][j]) * a[j]  (zero bootstrap) ---
        let t0 = Instant::now();
        let mut scores = Vec::with_capacity(n);
        for i in 0..n {
            let mut acc = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                lwe_size,
                Plaintext(encode(bsq[i])),
                modulus,
            );
            for j in 0..DIM {
                let c = (-2 * g[i][j]) as u64; // coeff in chiaro (wrapping = segno)
                if c == 0 {
                    continue;
                }
                let mut term = enc[j].clone();
                lwe_ciphertext_cleartext_mul_assign(&mut term, Cleartext(c));
                lwe_ciphertext_add_assign(&mut acc, &term);
            }
            scores.push(acc);
        }
        let dt = t0.elapsed().as_secs_f64();

        // verifica: ogni punteggio cifrato == chiaro
        let mut ok = true;
        for i in 0..n {
            let dec = decode(decrypt_lwe_ciphertext(&sk, &scores[i]).0);
            let clear = bsq[i] - 2 * (0..DIM).map(|j| g[i][j] * a[j]).sum::<i64>();
            if dec != clear {
                ok = false;
                println!("  MISMATCH i={i}: cifrato={dec} chiaro={clear}");
            }
        }
        println!(
            "{:>3} | {:>9.4}s | {:>7} | {}",
            n,
            dt,
            n,
            if ok { "OK" } else { "ERRATO" }
        );
    }

    println!("\nConfronto: ad alto livello (FheInt16) lo stesso dot e' ~51 s a N=8 (F32).");
}
