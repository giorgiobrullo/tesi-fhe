// Il varco senza ponte: prodotto scalare LEVELED + una soglia parallela per iscritto.
//
// L'idea. Il punteggio s_i = ||g_i||^2 - 2 g_i.a e' una combinazione lineare a coefficienti in
// chiaro del probe cifrato: si calcola su LWE grezzi senza bootstrap (F34). Per decidere
// "s_i <= T ?" non serve estrarre le cifre del punteggio (il ponte verso la forma radix, che con i
// parametri standard a N=2048 non e' affidabile su 13-14 bit): basta il SEGNO di (s_i - T),
// cioe' un solo PBS negaciclico per iscritto, con accumulatore costante. Gli N confronti sono
// indipendenti -> profondita' 1, tutti in parallelo. Uscita: N bit (one-hot se un solo iscritto e'
// sotto soglia), come proposto da Carnemolla e accettato dal prof per la privacy.
//
// Il prezzo: il PBS lavora sul torus intero dopo il modulus switch, quindi la decisione e'
// "sfocata" in una banda intorno a T dell'ordine del rumore (misurata qui: discrepanze cifrato vs
// chiaro e la loro distanza |s_i - T|).
//
// Chiavi e parametri: quelli standard di tfhe-rs (PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
// 128 bit), presi dalle chiavi dell'API ad alto livello via into_raw_parts. Il probe e' cifrato
// sotto la chiave "grande" (n = 2048, rumore GLWE) con encoding Delta_s scelto sul range reale
// dei punteggi; keyswitch alla chiave piccola, PBS, decifra con la grande.
//
// Dati: scena reale esportata da esporta_dati.py (ResNet100, VGGFace2, 4 bit, N=128).
//
//   cargo run --release --bin varco_leveled            (tutti i core)
//   RAYON_NUM_THREADS=1 cargo run --release --bin varco_leveled
use rayon::prelude::*;
use std::fs;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::parameters::V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use tfhe::{generate_keys, ConfigBuilder};


struct Scena {
    dim: usize,
    g: Vec<Vec<i64>>,
    bsq: Vec<i64>,
    probe: Vec<Vec<i64>>,
    label: Vec<i64>,
    t: i64,
}

fn carica(path: &str) -> Scena {
    let txt = fs::read_to_string(path).expect("manca results/scena_reale.txt: lancia esporta_dati.py");
    let mut righe = txt.lines();
    let h: Vec<i64> = righe.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect();
    let (dim, n, np, t) = (h[0] as usize, h[1] as usize, h[2] as usize, h[3]);
    let mut g = Vec::with_capacity(n);
    for _ in 0..n {
        g.push(righe.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect::<Vec<i64>>());
    }
    let (mut probe, mut label) = (Vec::with_capacity(np), Vec::with_capacity(np));
    for _ in 0..np {
        let r: Vec<i64> = righe.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect();
        label.push(r[0]);
        probe.push(r[1..].to_vec());
    }
    let bsq = g.iter().map(|v| v.iter().map(|x| x * x).sum()).collect();
    Scena { dim, g, bsq, probe, label, t }
}

fn main() {
    // argv[1]: scena (default results/scena_reale.txt); argv[2]: N minimo (default 8); le N raddoppiano fino alla galleria
    let args: Vec<String> = std::env::args().collect();
    let default_scena = concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale.txt").to_string();
    let scena = carica(args.get(1).unwrap_or(&default_scena));
    let n_min: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let mut ns: Vec<usize> = Vec::new();
    let mut n = n_min;
    while n <= scena.g.len() { ns.push(n); n *= 2; }
    let threads = rayon::current_num_threads();
    // --multibit: parametri multi-bit (group 3) e PBS multi-bit; --mb-threads K forza i thread interni del PBS
    let multibit = args.iter().any(|a| a == "--multibit");
    let mb_threads: Option<usize> = args.iter().position(|a| a == "--mb-threads").map(|i| args[i + 1].parse().unwrap());

    // --- chiavi standard dall'API ad alto livello, poi le parti grezze ---
    let cfg = if multibit {
        ConfigBuilder::with_custom_parameters(V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64).build()
    } else {
        ConfigBuilder::default().build()
    };
    let (ck_hl, sk_hl) = generate_keys(cfg);
    let (ick, _, _, _) = ck_hl.into_raw_parts();
    let sck = ick.into_raw_parts();
    let (isk, _, _, _, _) = sk_hl.into_raw_parts();
    let ssk = isk.into_raw_parts();
    let (enc_key, noise) = sck.encryption_key_and_noise();
    let ksk = &ssk.key_switching_key;
    let modulus = CiphertextModulus::<u64>::new_native();
    let big_size = enc_key.lwe_dimension().to_lwe_size();
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let poly = ssk.bootstrapping_key.polynomial_size();
    let glwe_size = ssk.bootstrapping_key.glwe_size();
    let variante = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(_) => "PBS classico, TUniform, default tfhe-rs".to_string(),
        ShortintBootstrappingKey::MultiBit { thread_count, .. } =>
            format!("PBS multi-bit group 3, thread interni {}", mb_threads.unwrap_or(thread_count.0)),
    };

    // --- encoding del punteggio: Delta_s massimo tale che |s - T| * Delta_s < 2^63 ---
    let mut max_abs = 0i64;
    for p in &scena.probe {
        for i in 0..scena.g.len() {
            let s: i64 = scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>();
            max_abs = max_abs.max((s - scena.t).abs() + 1);
        }
    }
    let w = 64 - (max_abs as u64).leading_zeros(); // bit necessari per |d|
    let log_delta = 63 - w; // Delta_s = 2^log_delta
    let delta: u64 = 1u64 << log_delta;
    println!("scena: DIM={} N={} probe={} T={}  |s-T| max {} -> {} bit, Delta_s = 2^{}, thread {}",
             scena.dim, scena.g.len(), scena.probe.len(), scena.t, max_abs, w, log_delta, threads);
    println!("parametri: n_grande={} n_piccola={} N_poly={} (128 bit, {variante})\n",
             big_size.to_lwe_dimension().0, small_size.to_lwe_dimension().0, poly.0);

    // accumulatore costante -2^55: dopo il PBS vale -2^55 se x in [0, 2^63) (s > T), +2^55 se
    // x in [2^63, 2^64) (s <= T); sommando 2^55 si ottiene 0 oppure 2^56 = il bit "match", con
    // 8 bit di spazio sopra per le somme dell'uscita compatta (indice = sum i*b_i, conteggio =
    // sum b_i, entrambe leveled sui bit freschi del PBS).
    const LOG_DO: u32 = 56;
    let c: u64 = (1u64 << (LOG_DO - 1)).wrapping_neg();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size, &PlaintextList::new(c, PlaintextCount(poly.0)), modulus);
    let pbs = |ks: &LweCiphertextOwned<u64>, out: &mut LweCiphertextOwned<u64>| match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => programmable_bootstrap_lwe_ciphertext(ks, out, &acc, k),
        ShortintBootstrappingKey::MultiBit { fourier_bsk, thread_count, deterministic_execution } =>
            multi_bit_programmable_bootstrap_lwe_ciphertext(ks, out, &acc, fourier_bsk,
                                                            ThreadCount(mb_threads.unwrap_or(thread_count.0)), *deterministic_execution),
    };

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!("{:>3} | {:>8} | {:>9} | {:>9} | {:>10} | discrepanze (|s-T| delle sbagliate)",
             "N", "dot", "KS+PBS", "totale", "PBS/thread");
    let mut banda: Vec<i64> = Vec::new();
    for &n in &ns {
        let mut tot_dot = 0f64;
        let mut tot_pbs = 0f64;
        let mut tot_compatta = 0f64;
        let (mut compatta_ok, mut compatta_tot) = (0usize, 0usize);
        let mut errori = 0usize;
        let mut confronti = 0usize;
        let mut err_dist: Vec<i64> = Vec::new();
        let (mut gen_ok, mut gen_tot, mut imp_acc, mut imp_tot) = (0, 0, 0, 0);
        for (p, &lab) in scena.probe.iter().zip(&scena.label) {
            // client: cifra il probe, DIM LWE sotto la chiave grande
            let enc: Vec<LweCiphertextOwned<u64>> = p
                .iter()
                .map(|&v| allocate_and_encrypt_new_lwe_ciphertext(
                    &enc_key, Plaintext((v as u64).wrapping_mul(delta)), noise, modulus, &mut enc_gen))
                .collect();

            // server, tappa 1: N punteggi leveled, x_i = (s_i - T) * Delta - Delta/2 (0 PBS)
            let t0 = Instant::now();
            let xs: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let cost = ((scena.bsq[i] - scena.t) as u64).wrapping_mul(delta).wrapping_sub(delta >> 1);
                    let mut a = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(cost), modulus);
                    for j in 0..scena.dim {
                        let coef = (-2 * scena.g[i][j]) as u64;
                        if coef == 0 { continue; }
                        let mut term = enc[j].clone();
                        lwe_ciphertext_cleartext_mul_assign(&mut term, Cleartext(coef));
                        lwe_ciphertext_add_assign(&mut a, &term);
                    }
                    a
                })
                .collect();
            tot_dot += t0.elapsed().as_secs_f64();

            // server, tappa 2: N bit di soglia, un keyswitch + un PBS ciascuno, in parallelo
            let t0 = Instant::now();
            let bits: Vec<LweCiphertextOwned<u64>> = xs
                .par_iter()
                .map(|x| {
                    let mut ks = LweCiphertext::new(0u64, small_size, modulus);
                    keyswitch_lwe_ciphertext(ksk, x, &mut ks);
                    let mut out = LweCiphertext::new(0u64, big_size, modulus);
                    pbs(&ks, &mut out);
                    lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(1u64 << (LOG_DO - 1)));
                    out
                })
                .collect();
            tot_pbs += t0.elapsed().as_secs_f64();

            // server, tappa 3 (opzionale): uscita compatta = per ogni BLOCCO di 64 iscritti il conteggio
            // sum b_i e l'indice in binario (bit k = sum dei b_i con il bit k di i acceso). Coefficienti
            // 0/1 e al piu' 64 addendi: il rumore del PBS (~2^48) resta sotto 2^51 contro un margine di
            // 2^55 (con somme su tutti gli N, a N=1024 arrivava a ~2^53 e sbagliava 8 probe su 128).
            // Il client somma i blocchi in chiaro: conteggio totale, e indice = blocco*64 + indice locale.
            const BLOCCO: usize = 64;
            let t0 = Instant::now();
            let nbit = (usize::BITS - (BLOCCO - 1).leading_zeros()) as usize;
            let nblocchi = (n + BLOCCO - 1) / BLOCCO;
            let mut cnt_ct: Vec<LweCiphertextOwned<u64>> = Vec::with_capacity(nblocchi);
            let mut idx_ct: Vec<Vec<LweCiphertextOwned<u64>>> = Vec::with_capacity(nblocchi);
            for b in 0..nblocchi {
                let mut cnt = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
                let mut idx: Vec<LweCiphertextOwned<u64>> = (0..nbit)
                    .map(|_| allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus))
                    .collect();
                for i in b * BLOCCO..((b + 1) * BLOCCO).min(n) {
                    lwe_ciphertext_add_assign(&mut cnt, &bits[i]);
                    let loc = i - b * BLOCCO;
                    for k in 0..nbit {
                        if (loc >> k) & 1 == 1 {
                            lwe_ciphertext_add_assign(&mut idx[k], &bits[i]);
                        }
                    }
                }
                cnt_ct.push(cnt); idx_ct.push(idx);
            }
            tot_compatta += t0.elapsed().as_secs_f64();
            let dec8 = |ct: &LweCiphertextOwned<u64>| {
                (decrypt_lwe_ciphertext(&enc_key, ct).0.wrapping_add(1u64 << (LOG_DO - 1)) >> LOG_DO) & 0xFF
            };
            let (mut cnt_dec, mut idx_dec) = (0usize, 0usize);
            for b in 0..nblocchi {
                let c = dec8(&cnt_ct[b]) as usize;
                cnt_dec += c;
                if c == 1 {
                    idx_dec = b * BLOCCO + (0..nbit).map(|k| (dec8(&idx_ct[b][k]) as usize) << k).sum::<usize>();
                }
            }

            // client: decifra gli N bit, confronto col chiaro
            let mut sotto: Vec<usize> = Vec::new();
            for i in 0..n {
                let dec = decrypt_lwe_ciphertext(&enc_key, &bits[i]).0;
                let bit = ((dec.wrapping_add(1u64 << (LOG_DO - 1))) >> LOG_DO) & 1; // arrotonda al multiplo di 2^56
                let s: i64 = scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>();
                let atteso = (s <= scena.t) as u64;
                confronti += 1;
                if bit != atteso {
                    errori += 1;
                    err_dist.push((s - scena.t).abs());
                }
                if bit == 1 { sotto.push(i); }
            }
            // uscita compatta: il conteggio deve coincidere, e con un solo match l'indice
            let ok_c = cnt_dec == sotto.len() && (sotto.len() != 1 || idx_dec == sotto[0]);
            compatta_tot += 1;
            if ok_c { compatta_ok += 1; }
            if lab >= 0 {
                gen_tot += 1;
                if sotto.len() == 1 && sotto[0] as i64 == lab { gen_ok += 1; }
            } else {
                imp_tot += 1;
                if !sotto.is_empty() { imp_acc += 1; }
            }
        }
        let np = scena.probe.len() as f64;
        err_dist.sort();
        println!(
            "{:>3} | {:>7.3}s | {:>8.3}s | {:>8.3}s | {:>9.1}ms | {}/{} {:?}",
            n, tot_dot / np, tot_pbs / np, (tot_dot + tot_pbs) / np,
            tot_pbs / np / n as f64 * 1000.0 * threads as f64,
            errori, confronti, &err_dist[..err_dist.len().min(12)]
        );
        println!("      esito per probe: genuini riconosciuti (one-hot giusto) {}/{}, impostori accettati {}/{}; \
                  uscita compatta (indice, conteggio) corretta {}/{} in {:.1} ms",
                 gen_ok, gen_tot, imp_acc, imp_tot, compatta_ok, compatta_tot, tot_compatta / np * 1000.0);
        banda.extend(err_dist);
    }
    banda.sort();
    if !banda.is_empty() {
        println!("\nbanda di sfocatura: {} discrepanze, |s-T| mediana {} max {} (punteggio in unita' intere, 13-14 bit)",
                 banda.len(), banda[banda.len() / 2], banda[banda.len() - 1]);
    } else {
        println!("\nnessuna discrepanza cifrato/chiaro.");
    }
}
