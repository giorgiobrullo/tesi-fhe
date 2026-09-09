// Il bilancio del RUMORE del varco: da dove viene la banda, e quanto vale davvero la garanzia.
//
// Fin qui la correttezza del varco era empirica ("0 discrepanze su 131.072 confronti", F43/F46) e
// la banda di sfocatura misurata per campionamento (F37: sigma ~12 unita' di punteggio). Qui
// costruiamo un modello diagnostico del rumore nelle tappe della catena e lo confrontiamo con la
// banda osservata. Non e' una derivazione del p-fail composto. Serve a rispondere alla domanda di
// un revisore severo: "i vostri
// parametri sono tarati per cifrati FRESCHI; voi ci mettete dentro un accumulo leveled di 512
// termini: la garanzia vale ancora?".
//
// La catena, per un iscritto:
//   GLWE fresco del probe (rumore sigma_0)
//     x polinomio della galleria in chiaro   -> varianza moltiplicata per ||p||^2
//     sample extract                          -> LWE grande, stesso rumore
//     + costante in chiaro                    -> nessun rumore
//     keyswitch alla chiave piccola           -> + rumore del keyswitch
//     modulus switch a 2N (dentro il PBS)     -> + rumore di arrotondamento
//     blind rotation                          -> decide il SEGNO della fase
// Nel modello centrale la decisione diventa piu' fragile quando il rumore e' grande rispetto alla
// distanza dalla soglia. La "banda" non e' un supporto duro e non esclude errori di coda.
//
//   cargo run --release --bin rumore [--params NOME] [--log-delta L] [--campioni M]
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};
use tfhe::shortint::{ClientKey, ServerKey};

fn lcg(s: &mut u64) -> i64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    ((*s >> 33) % 7) as i64 - 3 // valori a 3 bit in [-3, 3], come gli embedding quantizzati
}

/// scarto con segno rispetto al multiplo atteso, su interi a 64 bit
fn err(fase: u64, atteso: u64) -> f64 {
    fase.wrapping_sub(atteso) as i64 as f64
}

fn sigma(v: &[f64]) -> f64 {
    let m = v.iter().sum::<f64>() / v.len() as f64;
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64).sqrt()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let nome = a
        .iter()
        .position(|x| x == "--params")
        .map(|i| a[i + 1].clone())
        .unwrap_or("1_1".into());
    let log_delta: u32 = a
        .iter()
        .position(|x| x == "--log-delta")
        .map(|i| a[i + 1].parse().unwrap())
        .unwrap_or(52);
    let m: usize = a
        .iter()
        .position(|x| x == "--campioni")
        .map(|i| a[i + 1].parse().unwrap())
        .unwrap_or(400);
    let dim = 512usize;

    let params = match nome.as_str() {
        "1_1" => V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        "2_2" => V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        x => panic!("--params {x}"),
    };
    let ck = ClientKey::new(params);
    let sk = ServerKey::new(&ck);
    let (glwe_sk, lwe_sk, par) = ck.clone().into_raw_parts();
    let ksk = &sk.key_switching_key;
    let modulus = CiphertextModulus::<u64>::new_native();
    let poly = glwe_sk.polynomial_size();
    let k = glwe_sk.glwe_dimension();
    let big = LweSize(k.0 * poly.0 + 1);
    let big_key = glwe_sk.as_lwe_secret_key();
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let delta = 1u64 << log_delta;

    println!(
        "set {nome}: k={} N={} n_piccola={} | Delta = 2^{log_delta} | {m} campioni, dim {dim}\n",
        k.0,
        poly.0,
        small.to_lwe_dimension().0
    );

    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut s = 20260831u64;

    // ---- 1) rumore di un GLWE fresco (il probe appena cifrato dal client)
    let mut e_fresco = Vec::new();
    for _ in 0..m.min(60) {
        let probe: Vec<i64> = (0..dim).map(|_| lcg(&mut s)).collect();
        let mut coeff = vec![0u64; poly.0];
        for (j, &v) in probe.iter().enumerate() {
            coeff[j] = (v as u64).wrapping_mul(delta);
        }
        let mut g = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut g,
            &PlaintextList::from_container(coeff.clone()),
            par.glwe_noise_distribution(),
            &mut gen,
        );
        let mut out = PlaintextList::new(0u64, PlaintextCount(poly.0));
        decrypt_glwe_ciphertext(&glwe_sk, &g, &mut out);
        for (j, v) in out.iter().enumerate() {
            e_fresco.push(err(*v.0, coeff[j]));
        }
    }
    let s0 = sigma(&e_fresco);

    // ---- 2) rumore del PUNTEGGIO dopo il prodotto scalare leveled (poly mult + sample extract)
    let mut e_score = Vec::new();
    let mut e_ks = Vec::new();
    let mut norma2 = 0f64;
    for _ in 0..m {
        let probe: Vec<i64> = (0..dim).map(|_| lcg(&mut s)).collect();
        let gal: Vec<i64> = (0..dim).map(|_| lcg(&mut s)).collect();
        let mut coeff = vec![0u64; poly.0];
        for (j, &v) in probe.iter().enumerate() {
            coeff[j] = (v as u64).wrapping_mul(delta);
        }
        let mut g = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
        encrypt_glwe_ciphertext(
            &glwe_sk,
            &mut g,
            &PlaintextList::from_container(coeff),
            par.glwe_noise_distribution(),
            &mut gen,
        );
        // p(X) con i coefficienti in chiaro della galleria (-2 g_j), come nel varco
        let mut p = vec![0u64; poly.0];
        for j in 0..dim {
            p[dim - 1 - j] = (-2 * gal[j]) as u64;
            norma2 += (2 * gal[j] * 2 * gal[j]) as f64;
        }
        let p = Polynomial::from_container(p);
        let mut prod = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
        for (mut o, c) in prod
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(g.as_polynomial_list().iter())
        {
            polynomial_wrapping_add_mul_assign(&mut o, &c, &p);
        }
        let mut x = LweCiphertext::new(0u64, big, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&prod, &mut x, MonomialDegree(dim - 1));
        let atteso: i64 = (0..dim).map(|j| -2 * gal[j] * probe[j]).sum();
        e_score.push(err(
            decrypt_lwe_ciphertext(&big_key, &x).0,
            (atteso as u64).wrapping_mul(delta),
        ));

        // ---- 3) rumore dopo il KEYSWITCH alla chiave piccola
        let mut ks = LweCiphertext::new(0u64, small, modulus);
        keyswitch_lwe_ciphertext(ksk, &x, &mut ks);
        e_ks.push(err(
            decrypt_lwe_ciphertext(&lwe_sk, &ks).0,
            (atteso as u64).wrapping_mul(delta),
        ));
    }
    norma2 /= m as f64;
    let s1 = sigma(&e_score);
    let s2 = sigma(&e_ks);

    // ---- 4) rumore del modulus switch a 2N (stima standard: uniforme su q/4N per coefficiente)
    let n_small = small.to_lwe_dimension().0 as f64;
    let q_su_2n = 2f64.powi(64) / (2.0 * poly.0 as f64);
    let s_ms = (n_small / 12.0).sqrt() * q_su_2n / 2.0;

    let tot = (s2 * s2 + s_ms * s_ms).sqrt();
    println!(
        "{:>34} | sigma assoluto | in bit | in unita' di punteggio (/Delta)",
        "tappa"
    );
    let riga = |n: &str, v: f64| {
        println!(
            "{n:>34} | {v:>14.3e} | 2^{:<5.1} | {:.2}",
            v.log2(),
            v / delta as f64
        )
    };
    riga("GLWE fresco (probe cifrato)", s0);
    riga("dopo il prodotto scalare leveled", s1);
    riga("dopo il keyswitch", s2);
    riga("modulus switch a 2N (teorico)", s_ms);
    riga("TOTALE all'ingresso del PBS", tot);
    println!(
        "\nfattore del prodotto scalare: sigma sale x{:.1} (atteso ||p|| = sqrt({:.0}) = {:.1})",
        s1 / s0,
        norma2,
        norma2.sqrt()
    );
    println!(
        "banda prevista della decisione: sigma_totale / Delta = {:.2} unita' di punteggio",
        tot / delta as f64
    );
    println!(
        "\nlettura euristica: l'errore diventa piu' probabile vicino alla soglia; la banda non "
    );
    println!(
        "e' un supporto duro, non esclude errori di coda e non deriva il p-fail del circuito."
    );
    let per = |d: f64| {
        let z = d * delta as f64 / tot;
        0.5 * erfc(z / std::f64::consts::SQRT_2)
    };
    println!("\nstima del modello gaussiano, non bound, a distanza d dalla soglia:");
    for d in [1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0] {
        println!("   d = {d:>5.0} unita' -> {:.3e}", per(d));
    }
}

// erfc senza dipendenze (Abramowitz-Stegun 7.1.26, |errore| < 1.5e-7)
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let y = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if x >= 0.0 {
        y
    } else {
        2.0 - y
    }
}
