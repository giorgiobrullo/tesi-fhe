// L'ARGMIN ESATTO sul server, a torneo, con il CIRCUIT BOOTSTRAPPING: il design originale
// dell'incontro reso praticabile.
//
// F45 aveva misurato l'argmin esatto con la matrice di tutti i confronti a coppie: corretto ma
// QUADRATICO (3,7 s a N=64, 14,4 s a N=128, 10.816 PBS). Il motivo per cui non si poteva fare un
// torneo era che il bit di confronto esce come LWE, mentre per SELEZIONARE (il CMUX di TFHE) serve
// una GGSW. Il ponte fra i due e' il *circuit bootstrapping* (LWE -> GGSW), che tfhe-rs espone
// (`circuit_bootstrap_boolean`). Con quello il torneo diventa possibile: N-1 confronti invece di
// N(N-1)/2, e profondita' log N.
//
// Il candidato di ogni nodo e' UN GLWE che porta con se' due cose:
//   coefficiente dim-1 : il punteggio s_i (esce li' dal prodotto scalare polinomiale)
//   coefficiente N-1   : l'indice i (aggiunto in chiaro: e' gratis). NON il coefficiente 0: il
//                        prodotto P_i . A ha supporto [0, 2*dim-2], quindi i coefficienti oltre
//                        2*dim-2 sono esattamente ZERO ed e' li' che l'indice si puo' scrivere pulito.
// Un solo CMUX seleziona entrambi. Per ogni confronto:
//   estrai i due punteggi (sample extract, gratis) -> differenza (gratis) -> keyswitch ->
//   PBS di SEGNO che produce il bit PULITO in cima al toro (0 oppure 2^63) -> keyswitch ->
//   circuit bootstrap (LWE -> GGSW) -> CMUX.
// Il PBS di segno non e' opzionale: `circuit_bootstrap_boolean` con DeltaLog(63) pretende un LWE che
// contenga SOLO il bit in cima (moltiplica per 1 e tratta tutto il resto come rumore), mentre la
// differenza dei punteggi ha i bit bassi pieni di dati.
// Alla fine si estraggono indice e punteggio del vincitore e si confronta il punteggio con la soglia.
//
//   cargo run --release --bin argmin_torneo [--scena FILE] [--probe M]
use dyn_stack::{GlobalPodBuffer, PodStack, StackReq};
use rayon::prelude::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{cmux, cmux_scratch, FourierGgswCiphertext};
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{circuit_bootstrap_boolean,
                                                          circuit_bootstrap_boolean_scratch};
use tfhe::core_crypto::prelude::*;

// parametri LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS di tfhe-rs (128 bit), gli unici del set
// pensati per il circuit bootstrapping: N=2048, k=1, PBS a 2 livelli, CBS 2^5 x 3, PFKS 2^15 x 2.
const N_POLY: usize = 2048;
const K: usize = 1;
const N_LWE: usize = 769;
const STD_LWE: f64 = 0.0000043131554647504185;
const STD_GLWE: f64 = 0.00000000000000029403601535432533;

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
    let scena_path = a.iter().position(|x| x == "--scena").map(|i| a[i + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    let n_probe: usize = a.iter().position(|x| x == "--probe").map(|i| a[i + 1].parse().unwrap()).unwrap_or(8);
    let sc = carica(&scena_path);

    // il punteggio sta al coefficiente dim-1, l'indice al coefficiente 0: due Delta indipendenti
    let log_ds = 52u32;                 // punteggio (range ~2^11 a 3 bit): margine per il rumore dei CMUX
    let ds = 1u64 << log_ds;
    let log_di = 56u32;                 // indice (<= 1023)
    let di = 1u64 << log_di;

    let modulus = CiphertextModulus::<u64>::new_native();
    let poly = PolynomialSize(N_POLY);
    let glwe_dim = GlweDimension(K);
    let glwe_size = glwe_dim.to_glwe_size();
    let noise_lwe = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(STD_LWE));
    let noise_glwe = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(STD_GLWE));

    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut sec = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!("Argmin ESATTO a torneo con circuit bootstrapping — N_poly={N_POLY} k={K} n={N_LWE}");
    let t0 = Instant::now();
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(glwe_dim, poly, &mut sec);
    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(LweDimension(N_LWE), &mut sec);
    let big_sk = glwe_sk.as_lwe_secret_key();
    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk, &glwe_sk, DecompositionBaseLog(15), DecompositionLevelCount(2), noise_glwe, modulus, &mut gen);
    let mut fbsk = FourierLweBootstrapKey::new(bsk.input_lwe_dimension(), bsk.glwe_size(),
                                               bsk.polynomial_size(), bsk.decomposition_base_log(),
                                               bsk.decomposition_level_count());
    let fft_owned = Fft::new(poly);
    let fft = fft_owned.as_view();
    fbsk.as_mut_view().par_fill_with_forward_fourier(bsk.as_view(), fft);
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_sk, &lwe_sk, DecompositionBaseLog(6), DecompositionLevelCount(2), noise_lwe, modulus, &mut gen);
    let pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &big_sk, &glwe_sk, DecompositionBaseLog(15), DecompositionLevelCount(2), noise_glwe, modulus, &mut gen);
    println!("chiavi generate in {:.1}s (bsk + ksk + pfpksk del circuit bootstrap)\n", t0.elapsed().as_secs_f64());

    let (cbs_bl, cbs_lv) = (DecompositionBaseLog(5), DecompositionLevelCount(3));
    // accumulatore costante -2^62: il PBS lo restituisce con segno opposto a seconda della meta' del
    // toro in cui cade la fase, quindi +2^62 dopo la somma di 2^62 -> bit 1 in cima
    let acc_segno = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size, &PlaintextList::new((1u64 << 62).wrapping_neg(), PlaintextCount(N_POLY)), modulus);
    let big_size = LweSize(K * N_POLY + 1);
    let small_size = LweSize(N_LWE + 1);

    println!("{:>5} | {:>10} | {:>10} | {:>10} | {:>7} | indice | rumore sul   | vs matrice", "N", "dot", "torneo", "totale", "confr.");
    println!("{:>5} | {:>10} | {:>10} | {:>10} | {:>7} | esatto | punteggio    | F45 (N^2)", "", "", "", "", "");
    for &n in &[8usize, 16, 32, 64, 128] {
        if n > sc.g.len() { continue; }
        let (mut t_dot, mut t_tor, mut ok, mut ok_s) = (0f64, 0f64, 0usize, 0usize);
        let mut rumore: Vec<f64> = Vec::new();
        for p in sc.probe.iter().take(n_probe) {
            // ---- client: probe come GLWE (encoding polinomiale)
            let mut coeff = vec![0u64; N_POLY];
            for (j, &v) in p.iter().enumerate() { coeff[j] = (v as u64).wrapping_mul(ds); }
            let mut glwe = GlweCiphertext::new(0u64, glwe_size, poly, modulus);
            encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &PlaintextList::from_container(coeff), noise_glwe, &mut gen);

            // ---- server: N candidati, ognuno un GLWE con punteggio (coeff dim-1) e indice (coeff 0)
            let t0 = Instant::now();
            let mut cand: Vec<GlweCiphertextOwned<u64>> = (0..n).into_par_iter().map(|i| {
                let mut pol = vec![0u64; N_POLY];
                for j in 0..sc.dim { pol[sc.dim - 1 - j] = (-2 * sc.g[i][j]) as u64; }
                let pol = Polynomial::from_container(pol);
                let mut out = GlweCiphertext::new(0u64, glwe_size, poly, modulus);
                for (mut o, c) in out.as_mut_polynomial_list().iter_mut().zip(glwe.as_polynomial_list().iter()) {
                    polynomial_wrapping_add_mul_assign(&mut o, &c, &pol);
                }
                // costante in chiaro: ||g_i||^2 sul coefficiente del punteggio, indice sul coefficiente 0
                let mut corpo = out.get_mut_body();
                let b = corpo.as_mut();
                b[sc.dim - 1] = b[sc.dim - 1].wrapping_add((sc.bsq[i] as u64).wrapping_mul(ds));
                b[N_POLY - 1] = b[N_POLY - 1].wrapping_add((i as u64).wrapping_mul(di));
                out
            }).collect();
            t_dot += t0.elapsed().as_secs_f64();

            // ---- torneo: log2(N) livelli, i confronti di ogni livello in parallelo
            let t0 = Instant::now();
            let mut conf = 0usize;
            while cand.len() > 1 {
                let nuovi: Vec<GlweCiphertextOwned<u64>> = cand.par_chunks(2).map(|ch| {
                    if ch.len() < 2 { return ch[0].clone(); }
                    let (ca, cb) = (&ch[0], &ch[1]);
                    // differenza dei punteggi: il segno sta in cima al toro
                    let mut xa = LweCiphertext::new(0u64, big_size, modulus);
                    let mut xb = LweCiphertext::new(0u64, big_size, modulus);
                    extract_lwe_sample_from_glwe_ciphertext(ca, &mut xa, MonomialDegree(sc.dim - 1));
                    extract_lwe_sample_from_glwe_ciphertext(cb, &mut xb, MonomialDegree(sc.dim - 1));
                    lwe_ciphertext_sub_assign(&mut xa, &xb);            // s_a - s_b
                    lwe_ciphertext_plaintext_sub_assign(&mut xa, Plaintext(ds >> 1));  // pareggio -> vince il primo
                    let mut ks = LweCiphertext::new(0u64, small_size, modulus);
                    keyswitch_lwe_ciphertext(&ksk, &xa, &mut ks);

                    let mut req = GlobalPodBuffer::new(StackReq::try_any_of([
                        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(glwe_size, poly, fft).unwrap(),
                        circuit_bootstrap_boolean_scratch::<u64>(small_size, big_size, glwe_size, poly, fft).unwrap(),
                        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch(fft).unwrap(),
                        cmux_scratch::<u64>(glwe_size, poly, fft).unwrap()]).unwrap());
                    let stack = PodStack::new(&mut req);

                    // PBS di segno -> bit PULITO in cima al toro: 0 se s_a >= s_b, 2^63 se s_a < s_b
                    let mut bit = LweCiphertext::new(0u64, big_size, modulus);
                    programmable_bootstrap_lwe_ciphertext(&ks, &mut bit, &acc_segno, &fbsk);
                    lwe_ciphertext_plaintext_add_assign(&mut bit, Plaintext(1u64 << 62));
                    let mut bit_ks = LweCiphertext::new(0u64, small_size, modulus);
                    keyswitch_lwe_ciphertext(&ksk, &bit, &mut bit_ks);

                    // circuit bootstrap: LWE(bit) -> GGSW(bit), il ponte che rende possibile il CMUX
                    let mut ggsw = GgswCiphertext::new(0u64, glwe_size, poly, cbs_bl, cbs_lv, modulus);
                    circuit_bootstrap_boolean(fbsk.as_view(), bit_ks.as_view(), ggsw.as_mut_view(),
                                              DeltaLog(63), pfpksk.as_view(), fft, stack);
                    let mut fggsw = FourierGgswCiphertext::new(glwe_size, poly, cbs_bl, cbs_lv);
                    fggsw.as_mut_view().fill_with_forward_fourier(ggsw.as_view(), fft, stack);

                    // CMUX: b=0 -> tiene b (s_a >= s_b), b=1 -> prende a
                    let mut c0 = cb.clone();
                    let mut c1 = ca.clone();
                    cmux(c0.as_mut_view(), c1.as_mut_view(), fggsw.as_view(), fft, stack);
                    c0
                }).collect();
                conf += cand.len() / 2;
                cand = nuovi;
            }
            t_tor += t0.elapsed().as_secs_f64();

            // ---- esito: indice del vincitore (coeff 0) e punteggio (coeff dim-1)
            let vinc = &cand[0];
            let mut xi = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(vinc, &mut xi, MonomialDegree(N_POLY - 1));
            let idx = (decrypt_lwe_ciphertext(&big_sk, &xi).0.wrapping_add(di >> 1) >> log_di) as usize;
            let mut xs = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(vinc, &mut xs, MonomialDegree(sc.dim - 1));

            // atteso in chiaro (primo minimo)
            let s: Vec<i64> = (0..n).map(|i| sc.bsq[i] - 2 * (0..sc.dim).map(|j| sc.g[i][j] * p[j]).sum::<i64>()).collect();
            let mut best = 0usize;
            for i in 1..n { if s[i] < s[best] { best = i; } }
            if idx == best { ok += 1; }
            // quanto rumore ha accumulato il punteggio del vincitore attraverso i log N CMUX?
            let e = decrypt_lwe_ciphertext(&big_sk, &xs).0
                .wrapping_sub((s[best] as u64).wrapping_mul(ds)) as i64 as f64 / ds as f64;
            rumore.push(e.abs());
            if e.abs() < 0.5 { ok_s += 1; }
            let _ = conf;
        }
        let np = sc.probe.len().min(n_probe) as f64;
        let f45 = match n { 8 => "0,09 s", 16 => "0,29 s", 32 => "0,97 s", 64 => "3,66 s", 128 => "14,4 s", _ => "-" };
        println!("{:>5} | {:>8.3} s | {:>8.3} s | {:>8.3} s | {:>7} | {:>2}/{:<2} | {:>5.2} unita | {}",
                 n, t_dot / np, t_tor / np, (t_dot + t_tor) / np, n - 1, ok, np as usize,
                 rumore.iter().sum::<f64>() / rumore.len() as f64, f45);
        let _ = ok_s;
    }
    println!("\n(l'ultima colonna e' l'argmin esatto a matrice di F45, quadratico, sulla stessa scena)");
}
