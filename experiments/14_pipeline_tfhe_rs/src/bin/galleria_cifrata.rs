// GALLERIA CIFRATA a costo leveled: il "Mondo 2" senza pagare cifrato x cifrato.
//
// Il limite dichiarato del nostro varco e' che la galleria sta IN CHIARO sul server (Mondo 1): il
// prodotto scalare e' cifrato x chiaro, quindi leveled e gratis. Tutta la letteratura che cifra
// anche la galleria (CKKS/BFV) paga invece moltiplicazioni cifrato x cifrato.
//
// L'idea provata qui: in TFHE esiste una terza via, il PRODOTTO ESTERNO. Se il template della
// galleria e' cifrato come GGSW e la probe come GLWE, allora
//     GGSW(P_i) (x) GLWE(A)  =  GLWE(P_i . A)
// e' un'operazione LEVELED (nessun bootstrap): e' lo stesso mattone con cui il blind rotate fa i
// suoi CMUX, e un blind rotate ne fa ~800 di fila. Quindi il prodotto scalare su galleria CIFRATA
// costerebbe ~1/800 di un PBS: praticamente lo stesso varco di prima, ma con la galleria protetta.
//
// tfhe-rs espone il prodotto esterno e la GGSW, ma sa cifrare solo messaggi COSTANTI
// (`encrypt_constant_ggsw_ciphertext`). Qui costruiamo la GGSW di un POLINOMIO seguendo la stessa
// formula di tfhe-rs (righe = GLWE(-S_i . mu . q/B^j) per i<k, GLWE(mu . q/B^j) per i=k) e ne
// verifichiamo la correttezza decifrando il risultato del prodotto esterno.
//
// La verifica giusta NON e' "ricostruisco il punteggio esatto" (servirebbe rumore << Delta/2): al varco
// serve solo il SEGNO di (s - T). Quindi si misura la banda aggiunta dal prodotto esterno e la si
// confronta con le ~22 unita' di banda che il PBS di segno ha comunque (F50), e poi si esegue il varco
// completo sulla scena reale confrontando le decisioni col chiaro.
//
//   cargo run --release --bin galleria_cifrata [--scena FILE] [--campioni M]
use dyn_stack::{GlobalPodBuffer, PodStack, StackReq};
use rayon::prelude::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::{polynomial_wrapping_add_mul_assign,
                                                           polynomial_wrapping_mul};
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{add_external_product_assign,
                                                        add_external_product_assign_scratch,
                                                        fill_with_forward_fourier_scratch,
                                                        FourierGgswCiphertext};
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::ClientKey;

const DIM: usize = 512;

fn lcg(s: &mut u64) -> i64 {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((*s >> 33) % 7) as i64 - 3 // 3 bit: [-3, 3]
}

fn sigma(v: &[f64]) -> f64 {
    let m = v.iter().sum::<f64>() / v.len() as f64;
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64).sqrt()
}

/// GGSW di un messaggio POLINOMIALE, con la stessa costruzione di `encrypt_constant_ggsw_ciphertext`
/// generalizzata: al posto del prodotto per uno scalare, il prodotto (negaciclico) per mu.
fn ggsw_polinomiale<Gen: ByteRandomGenerator>(
    sk: &GlweSecretKeyOwned<u64>,
    mu: &Polynomial<Vec<u64>>,
    base_log: DecompositionBaseLog,
    livelli: DecompositionLevelCount,
    rumore: DynamicDistribution<u64>,
    gen: &mut EncryptionRandomGenerator<Gen>,
) -> GgswCiphertextOwned<u64> {
    let (poly, k) = (sk.polynomial_size(), sk.glwe_dimension());
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut ggsw = GgswCiphertext::new(0u64, k.to_glwe_size(), poly, base_log, livelli, modulus);
    for (idx, mut livello) in ggsw.iter_mut().enumerate() {
        let l = DecompositionLevel(livelli.0 - idx);
        // fattore del gadget: (-1) * q / B^l, esattamente come lo calcola tfhe-rs
        let fattore = ggsw_encryption_multiplicative_factor(modulus, l, base_log, Cleartext(1u64));
        let ultima = livello.glwe_size().0 - 1;
        for (riga, mut glwe) in livello.as_mut_glwe_list().iter_mut().enumerate() {
            {
                let mut corpo = glwe.get_mut_body();
                if riga < ultima {
                    let chiavi = sk.as_polynomial_list();
                    let s = chiavi.get(riga);
                    let mut prod = Polynomial::new(0u64, poly);
                    polynomial_wrapping_mul(&mut prod, &s, mu);      // S_riga . mu  (mod X^N+1)
                    for (b, p) in corpo.as_mut().iter_mut().zip(prod.as_ref()) {
                        *b = p.wrapping_mul(fattore);                 // -S_riga . mu . q/B^l
                    }
                } else {
                    let f = fattore.wrapping_neg();
                    for (b, m) in corpo.as_mut().iter_mut().zip(mu.as_ref()) {
                        *b = m.wrapping_mul(f);                       // +mu . q/B^l
                    }
                }
            }
            encrypt_glwe_ciphertext_assign(sk, &mut glwe, rumore, gen);
        }
    }
    ggsw
}


struct Scena { dim: usize, g: Vec<Vec<i64>>, bsq: Vec<i64>, probe: Vec<Vec<i64>>, t: i64 }

fn carica(path: &str) -> Scena {
    let txt = std::fs::read_to_string(path).expect("manca la scena (esporta_dati.py)");
    let mut r = txt.lines();
    let h: Vec<i64> = r.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect();
    let (dim, n, np, t) = (h[0] as usize, h[1] as usize, h[2] as usize, h[3]);
    let g: Vec<Vec<i64>> = (0..n).map(|_| r.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect()).collect();
    let probe: Vec<Vec<i64>> = (0..np).map(|_| {
        let v: Vec<i64> = r.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect();
        v[1..].to_vec()
    }).collect();
    let bsq = g.iter().map(|v| v.iter().map(|x| x * x).sum()).collect();
    Scena { dim, g, bsq, probe, t }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let m: usize = a.iter().position(|x| x == "--campioni").map(|i| a[i + 1].parse().unwrap()).unwrap_or(25);
    let scena_path = a.iter().position(|x| x == "--scena").map(|i| a[i + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    let log_delta = 53u32;                     // come la scena a 3 bit (F47)
    let delta = 1u64 << log_delta;

    let ck = ClientKey::new(PARAMS);
    let sk_short = ck.clone();
    let (sk, lwe_sk, par) = ck.into_raw_parts();
    let ssk = tfhe::shortint::ServerKey::new(&sk_short);
    let ksk = &ssk.key_switching_key;
    let fbsk = match &ssk.bootstrapping_key {
        tfhe::shortint::server_key::ShortintBootstrappingKey::Classic(k) => k,
        _ => panic!(),
    };
    let _ = &lwe_sk;
    let (poly, k) = (sk.polynomial_size(), sk.glwe_dimension());
    let modulus = CiphertextModulus::<u64>::new_native();
    let big = LweSize(k.0 * poly.0 + 1);
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let big_key = sk.as_lwe_secret_key();
    let fft_owned = Fft::new(poly);
    let fft = fft_owned.as_view();

    println!("Galleria CIFRATA via prodotto esterno GGSW (x) GLWE — k={} N={} Delta=2^{log_delta}\n", k.0, poly.0);
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut s = 1234567u64;

    // ---------- A) microbenchmark: rumore e tempo del prodotto esterno, per gadget
    println!("A) il prodotto scalare su galleria cifrata (per iscritto):");
    println!("{:>8} | {:>10} | {:>11} | {:>12} | {:>22}", "gadget", "GGSW", "tempo", "banda aggiunta", "vs banda del PBS (22)");
    let mut migliore = (DecompositionBaseLog(12), DecompositionLevelCount(2), f64::MAX);
    for &(bl, lv) in &[(8usize, 2usize), (12, 2), (10, 3), (16, 1)] {
        let (base_log, livelli) = (DecompositionBaseLog(bl), DecompositionLevelCount(lv));
        let (mut err, mut tempi, mut byte) = (Vec::new(), Vec::new(), 0usize);
        for _ in 0..m {
            let probe: Vec<i64> = (0..DIM).map(|_| lcg(&mut s)).collect();
            let gal: Vec<i64> = (0..DIM).map(|_| lcg(&mut s)).collect();
            let mut coeff = vec![0u64; poly.0];
            for (j, &v) in probe.iter().enumerate() { coeff[j] = (v as u64).wrapping_mul(delta); }
            let mut glwe = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(&sk, &mut glwe, &PlaintextList::from_container(coeff), par.glwe_noise_distribution(), &mut gen);
            let mut p = vec![0u64; poly.0];
            for j in 0..DIM { p[DIM - 1 - j] = (-2 * gal[j]) as u64; }
            let ggsw = ggsw_polinomiale(&sk, &Polynomial::from_container(p), base_log, livelli, par.glwe_noise_distribution(), &mut gen);
            byte = ggsw.as_ref().len() * 8;
            let mut req = GlobalPodBuffer::new(StackReq::try_any_of([
                fill_with_forward_fourier_scratch(fft).unwrap(),
                add_external_product_assign_scratch::<u64>(k.to_glwe_size(), poly, fft).unwrap()]).unwrap());
            let stack = PodStack::new(&mut req);
            let mut fggsw = FourierGgswCiphertext::new(k.to_glwe_size(), poly, base_log, livelli);
            fggsw.as_mut_view().fill_with_forward_fourier(ggsw.as_view(), fft, stack);
            let mut out = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
            let t0 = Instant::now();
            add_external_product_assign(out.as_mut_view(), fggsw.as_view(), glwe.as_view(), fft, stack);
            tempi.push(t0.elapsed().as_secs_f64() * 1e3);
            let mut x = LweCiphertext::new(0u64, big, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&out, &mut x, MonomialDegree(DIM - 1));
            let atteso: i64 = (0..DIM).map(|j| -2 * gal[j] * probe[j]).sum();
            err.push(decrypt_lwe_ciphertext(&big_key, &x).0.wrapping_sub((atteso as u64).wrapping_mul(delta)) as i64 as f64);
        }
        let banda = sigma(&err) / delta as f64;
        if banda < migliore.2 { migliore = (base_log, livelli, banda); }
        println!("{:>8} | {:>7} KB | {:>8.3} ms | {:>9.2} unita | {:>22}", format!("2^{bl}x{lv}"), byte / 1024,
                 tempi.iter().sum::<f64>() / m as f64, banda,
                 if banda < 2.0 { "trascurabile" } else if banda < 22.0 { "confrontabile" } else { "domina" });
    }
    let (base_log, livelli, banda_ext) = migliore;
    println!("\n  gadget scelto: 2^{}x{} (banda {:.2} unita)", base_log.0, livelli.0, banda_ext);

    // ---------- B) il varco COMPLETO con galleria cifrata, sulla scena reale
    let sc = carica(&scena_path);
    println!("\nB) varco completo su scena reale (dim {}, T {}): galleria CIFRATA vs IN CHIARO", sc.dim, sc.t);
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        fbsk.glwe_size(), &PlaintextList::new((1u64 << 55).wrapping_neg(), PlaintextCount(fbsk.polynomial_size().0)), modulus);
    println!("{:>5} | {:>12} | {:>12} | {:>10} | {:>12} | decisioni vs chiaro", "N", "dot cifrato", "PBS", "totale", "galleria");
    for &n in &[8usize, 32, 128] {
        if n > sc.g.len() { continue; }
        // iscrizione: ogni template diventa una GGSW in dominio di Fourier (una volta sola)
        let mut req = GlobalPodBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
        let stack = PodStack::new(&mut req);
        let mut galleria = Vec::with_capacity(n);
        let mut byte_gal = 0usize;
        for i in 0..n {
            let mut p = vec![0u64; poly.0];
            for j in 0..sc.dim { p[sc.dim - 1 - j] = (-2 * sc.g[i][j]) as u64; }
            let g = ggsw_polinomiale(&sk, &Polynomial::from_container(p), base_log, livelli, par.glwe_noise_distribution(), &mut gen);
            let mut fg = FourierGgswCiphertext::new(k.to_glwe_size(), poly, base_log, livelli);
            fg.as_mut_view().fill_with_forward_fourier(g.as_view(), fft, stack);
            byte_gal += fg.as_view().data().len() * 16;
            galleria.push(fg);
        }
        // ||g_i||^2 - T: in Mondo 2 il server non lo conosce -> arriva cifrato dal client (una volta)
        let costanti: Vec<LweCiphertextOwned<u64>> = (0..n).map(|i| {
            let v = ((sc.bsq[i] - sc.t) as u64).wrapping_mul(delta).wrapping_sub(delta >> 1);
            allocate_and_encrypt_new_lwe_ciphertext(&big_key, Plaintext(v), par.glwe_noise_distribution(), modulus, &mut gen)
        }).collect();

        let (mut t_dot, mut t_pbs, mut ok, mut tot) = (0f64, 0f64, 0usize, 0usize);
        for p in sc.probe.iter().take(16) {
            let mut coeff = vec![0u64; poly.0];
            for (j, &v) in p.iter().enumerate() { coeff[j] = (v as u64).wrapping_mul(delta); }
            let mut glwe = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(&sk, &mut glwe, &PlaintextList::from_container(coeff), par.glwe_noise_distribution(), &mut gen);

            let t0 = Instant::now();
            let xs: Vec<LweCiphertextOwned<u64>> = (0..n).into_par_iter().map(|i| {
                let mut req = GlobalPodBuffer::new(add_external_product_assign_scratch::<u64>(k.to_glwe_size(), poly, fft).unwrap());
                let stack = PodStack::new(&mut req);
                let mut out = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
                add_external_product_assign(out.as_mut_view(), galleria[i].as_view(), glwe.as_view(), fft, stack);
                let mut x = LweCiphertext::new(0u64, big, modulus);
                extract_lwe_sample_from_glwe_ciphertext(&out, &mut x, MonomialDegree(sc.dim - 1));
                lwe_ciphertext_add_assign(&mut x, &costanti[i]);   // + (||g||^2 - T) cifrato
                x
            }).collect();
            t_dot += t0.elapsed().as_secs_f64();

            let t0 = Instant::now();
            let bits: Vec<u64> = xs.par_iter().map(|x| {
                let mut ks = LweCiphertext::new(0u64, small, modulus);
                keyswitch_lwe_ciphertext(ksk, x, &mut ks);
                let mut o = LweCiphertext::new(0u64, big, modulus);
                programmable_bootstrap_lwe_ciphertext(&ks, &mut o, &acc, fbsk);
                lwe_ciphertext_plaintext_add_assign(&mut o, Plaintext(1u64 << 55));
                (decrypt_lwe_ciphertext(&big_key, &o).0.wrapping_add(1u64 << 55) >> 56) & 1
            }).collect();
            t_pbs += t0.elapsed().as_secs_f64();

            for i in 0..n {
                let s_i: i64 = sc.bsq[i] - 2 * (0..sc.dim).map(|j| sc.g[i][j] * p[j]).sum::<i64>();
                tot += 1;
                if bits[i] == (s_i <= sc.t) as u64 { ok += 1; }
            }
        }
        let np = sc.probe.len().min(16) as f64;
        println!("{:>5} | {:>9.4} s | {:>9.4} s | {:>7.3} s | {:>9} MB | {}/{} corrette",
                 n, t_dot / np, t_pbs / np, (t_dot + t_pbs) / np, byte_gal / (1 << 20), ok, tot);
    }
    println!("\nConfronto: in Mondo 1 (galleria in chiaro) lo stesso varco fa 0,12 s a N=128 (F46/F47).");
}
