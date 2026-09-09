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
use tfhe::shortint::parameters::{
    V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
};
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey as ShortintClientKey, ServerKey as ShortintServerKey};

struct Scena {
    dim: usize,
    g: Vec<Vec<i64>>,
    bsq: Vec<i64>,
    probe: Vec<Vec<i64>>,
    label: Vec<i64>,
    t: i64,
}

fn carica(path: &str) -> Scena {
    let txt =
        fs::read_to_string(path).expect("manca results/scena_reale.txt: lancia esporta_dati.py");
    let mut righe = txt.lines();
    let h: Vec<i64> = righe
        .next()
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let (dim, n, np, t) = (h[0] as usize, h[1] as usize, h[2] as usize, h[3]);
    let mut g = Vec::with_capacity(n);
    for _ in 0..n {
        g.push(
            righe
                .next()
                .unwrap()
                .split_whitespace()
                .map(|x| x.parse().unwrap())
                .collect::<Vec<i64>>(),
        );
    }
    let (mut probe, mut label) = (Vec::with_capacity(np), Vec::with_capacity(np));
    for _ in 0..np {
        let r: Vec<i64> = righe
            .next()
            .unwrap()
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        label.push(r[0]);
        probe.push(r[1..].to_vec());
    }
    let bsq = g.iter().map(|v| v.iter().map(|x| x * x).sum()).collect();
    Scena {
        dim,
        g,
        bsq,
        probe,
        label,
        t,
    }
}

fn main() {
    // argv[1]: scena (default results/scena_reale.txt); argv[2]: N minimo (default 8); le N raddoppiano fino alla galleria
    let args: Vec<String> = std::env::args().collect();
    let default_scena = concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale.txt").to_string();
    let scena = carica(args.get(1).unwrap_or(&default_scena));
    let n_min: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let mut ns: Vec<usize> = Vec::new();
    let mut n = n_min;
    while n <= scena.g.len() {
        ns.push(n);
        n *= 2;
    }
    let threads = rayon::current_num_threads();
    // --params NOME: set di parametri (128 bit) per il PBS di segno. Al varco serve solo un segno, quindi
    // i set "piccoli" (LUT a 1-2 bit, N=256-1024) sono candidati: PBS piu' economico, banda piu' larga.
    // --multibit equivale a --params multibit; --mb-threads K forza i thread interni del PBS multi-bit.
    let multibit = args.iter().any(|a| a == "--multibit");
    let mb_threads: Option<usize> = args
        .iter()
        .position(|a| a == "--mb-threads")
        .map(|i| args[i + 1].parse().unwrap());
    let nome_params = args
        .iter()
        .position(|a| a == "--params")
        .map(|i| args[i + 1].clone())
        .unwrap_or_else(|| {
            if multibit {
                "multibit".to_string()
            } else {
                "default".to_string()
            }
        });
    let sck = match nome_params.as_str() {
        "default" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
        "multibit" => ShortintClientKey::new(
            V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        ),
        "1_0" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64),
        "1_1" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64),
        "2_0" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64),
        "2_1" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64),
        altro => panic!("--params sconosciuto: {altro} (default|multibit|1_0|1_1|2_0|2_1)"),
    };
    let ssk = ShortintServerKey::new(&sck);
    let (enc_key, noise) = sck.encryption_key_and_noise();
    let ksk = &ssk.key_switching_key;
    let modulus = CiphertextModulus::<u64>::new_native();
    let big_size = enc_key.lwe_dimension().to_lwe_size();
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let poly = ssk.bootstrapping_key.polynomial_size();
    let glwe_size = ssk.bootstrapping_key.glwe_size();
    let variante = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(_) => format!(
            "set {nome_params}, PBS classico, k={}",
            glwe_size.to_glwe_dimension().0
        ),
        ShortintBootstrappingKey::MultiBit { thread_count, .. } => format!(
            "set {nome_params}, PBS multi-bit group 3, thread interni {}",
            mb_threads.unwrap_or(thread_count.0)
        ),
    };

    // --- encoding del punteggio: Delta_s massimo tale che |s - T| * Delta_s < 2^63 ---
    let mut max_abs = 0i64;
    for p in &scena.probe {
        for i in 0..scena.g.len() {
            let s: i64 =
                scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>();
            max_abs = max_abs.max((s - scena.t).abs() + 1);
        }
    }
    let w = 64 - (max_abs as u64).leading_zeros(); // bit necessari per |d|
                                                   // --log-delta L forza Delta (per studiare l'overflow: vedi F56); --delta-onesto usa il bound
                                                   // indipendente dai dati 2*dim*q^2 + max||g||^2 + |T|, l'unico difendibile contro un client malicious
                                                   // Bound indipendente dal PROBE (ma non dalla galleria, che il server conosce in Mondo 1):
                                                   //   |s - T| <= 2*q * max_i ||g_i||_1 + max_i ||g_i||^2 + |T|
                                                   // e' 4x piu' stretto del caso peggiore 2*dim*q^2, perche' i template quantizzati sono sparsi.
                                                   // q dichiarato del PROBE: e' il range che il client si impegna a rispettare, ed e' quello che
                                                   // entra nel bound (l'avversario sceglie il probe, non la galleria). Prenderlo dalla galleria
                                                   // sarebbe un errore: se la galleria fosse piu' stretta del dominio dichiarato, il bound
                                                   // risulterebbe troppo piccolo e il wrap tornerebbe possibile. --q-probe K lo forza.
    let q_gal = scena
        .g
        .iter()
        .flat_map(|v| v.iter())
        .map(|x| x.abs())
        .max()
        .unwrap_or(3);
    let q_pro = scena
        .probe
        .iter()
        .flat_map(|v| v.iter())
        .map(|x| x.abs())
        .max()
        .unwrap_or(3);
    let q_max = args
        .iter()
        .position(|x| x == "--q-probe")
        .map(|i| args[i + 1].parse::<i64>().unwrap())
        .unwrap_or_else(|| q_gal.max(q_pro));
    let l1_max = scena
        .g
        .iter()
        .map(|v| v.iter().map(|x| x.abs()).sum::<i64>())
        .max()
        .unwrap_or(0);
    let bound_onesto =
        2 * q_max * l1_max + scena.bsq.iter().cloned().max().unwrap_or(0) + scena.t.abs();
    let log_delta = if args.iter().any(|x| x == "--delta-onesto") {
        63 - (64 - (bound_onesto as u64).leading_zeros())
    } else if let Some(i) = args.iter().position(|x| x == "--log-delta") {
        args[i + 1].parse().unwrap()
    } else {
        63 - w
    };
    let delta: u64 = 1u64 << log_delta;
    println!("scena: DIM={} N={} probe={} T={} | |s-T| max sui probe {} ({} bit) | bound onesto {} | Delta_s = 2^{} -> precipizio di wrap {} | thread {}",
             scena.dim, scena.g.len(), scena.probe.len(), scena.t, max_abs, w, bound_onesto, log_delta, 1u64 << (63 - log_delta), threads);
    // --log-do L  e  --blocco B: il bit d'esito vale 2^L e l'uscita compatta somma B bit per blocco.
    // Servono log2(B)+1 bit di franco sopra L, quindi L <= 64 - log2(B) - 1. Piu' L e' alto, piu'
    // margine ha la DECODIFICA del bit contro il rumore in uscita del PBS (vedi la revisione di F47).
    let blocco: usize = args
        .iter()
        .position(|x| x == "--blocco")
        .map(|i| args[i + 1].parse().unwrap())
        .unwrap_or(64);
    let log_do: u32 = args
        .iter()
        .position(|x| x == "--log-do")
        .map(|i| args[i + 1].parse().unwrap())
        .unwrap_or(56);
    assert!(
        log_do as usize + (usize::BITS - (blocco - 1).leading_zeros()) as usize + 1 <= 64,
        "log-do troppo alto per il blocco"
    );
    let LOG_DO: u32 = log_do;
    println!("parametri: n_grande={} n_piccola={} N_poly={} (128 bit, {variante}) | bit d'esito 2^{log_do}, blocco {blocco}\n",
             big_size.to_lwe_dimension().0, small_size.to_lwe_dimension().0, poly.0);

    // accumulatore costante -2^55: dopo il PBS vale -2^55 se x in [0, 2^63) (s > T), +2^55 se
    // x in [2^63, 2^64) (s <= T); sommando 2^55 si ottiene 0 oppure 2^56 = il bit "match", con
    // 8 bit di spazio sopra per le somme dell'uscita compatta (indice = sum i*b_i, conteggio =
    // sum b_i, entrambe leveled sui bit freschi del PBS).
    let c: u64 = (1u64 << (LOG_DO - 1)).wrapping_neg();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(c, PlaintextCount(poly.0)),
        modulus,
    );
    let pbs = |ks: &LweCiphertextOwned<u64>, out: &mut LweCiphertextOwned<u64>| match &ssk
        .bootstrapping_key
    {
        ShortintBootstrappingKey::Classic(k) => {
            programmable_bootstrap_lwe_ciphertext(ks, out, &acc, k)
        }
        ShortintBootstrappingKey::MultiBit {
            fourier_bsk,
            thread_count,
            deterministic_execution,
        } => multi_bit_programmable_bootstrap_lwe_ciphertext(
            ks,
            out,
            &acc,
            fourier_bsk,
            ThreadCount(mb_threads.unwrap_or(thread_count.0)),
            *deterministic_execution,
        ),
    };

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!(
        "{:>3} | {:>8} | {:>9} | {:>9} | {:>10} | discrepanze (|s-T| delle sbagliate)",
        "N", "dot", "KS+PBS", "totale", "PBS/thread"
    );
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
                .map(|&v| {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &enc_key,
                        Plaintext((v as u64).wrapping_mul(delta)),
                        noise,
                        modulus,
                        &mut enc_gen,
                    )
                })
                .collect();

            // server, tappa 1: N punteggi leveled, x_i = (s_i - T) * Delta - Delta/2 (0 PBS)
            let t0 = Instant::now();
            let xs: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let cost = ((scena.bsq[i] - scena.t) as u64)
                        .wrapping_mul(delta)
                        .wrapping_sub(delta >> 1);
                    let mut a = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big_size,
                        Plaintext(cost),
                        modulus,
                    );
                    for j in 0..scena.dim {
                        let coef = (-2 * scena.g[i][j]) as u64;
                        if coef == 0 {
                            continue;
                        }
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
            let blocco_i = blocco;
            let t0 = Instant::now();
            let nbit = (usize::BITS - (blocco_i - 1).leading_zeros()) as usize;
            let nblocchi = (n + blocco_i - 1) / blocco_i;
            let mut cnt_ct: Vec<LweCiphertextOwned<u64>> = Vec::with_capacity(nblocchi);
            let mut idx_ct: Vec<Vec<LweCiphertextOwned<u64>>> = Vec::with_capacity(nblocchi);
            for b in 0..nblocchi {
                let mut cnt = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    big_size,
                    Plaintext(0u64),
                    modulus,
                );
                let mut idx: Vec<LweCiphertextOwned<u64>> = (0..nbit)
                    .map(|_| {
                        allocate_and_trivially_encrypt_new_lwe_ciphertext(
                            big_size,
                            Plaintext(0u64),
                            modulus,
                        )
                    })
                    .collect();
                for i in b * blocco_i..((b + 1) * blocco_i).min(n) {
                    lwe_ciphertext_add_assign(&mut cnt, &bits[i]);
                    let loc = i - b * blocco_i;
                    for k in 0..nbit {
                        if (loc >> k) & 1 == 1 {
                            lwe_ciphertext_add_assign(&mut idx[k], &bits[i]);
                        }
                    }
                }
                cnt_ct.push(cnt);
                idx_ct.push(idx);
            }
            tot_compatta += t0.elapsed().as_secs_f64();
            let dec8 = |ct: &LweCiphertextOwned<u64>| {
                (decrypt_lwe_ciphertext(&enc_key, ct)
                    .0
                    .wrapping_add(1u64 << (LOG_DO - 1))
                    >> LOG_DO)
                    & 0xFF
            };
            let (mut cnt_dec, mut idx_dec) = (0usize, 0usize);
            for b in 0..nblocchi {
                let c = dec8(&cnt_ct[b]) as usize;
                cnt_dec += c;
                if c == 1 {
                    idx_dec = b * blocco_i
                        + (0..nbit)
                            .map(|k| (dec8(&idx_ct[b][k]) as usize) << k)
                            .sum::<usize>();
                }
            }

            // client: decifra gli N bit, confronto col chiaro
            let mut sotto: Vec<usize> = Vec::new();
            for i in 0..n {
                let dec = decrypt_lwe_ciphertext(&enc_key, &bits[i]).0;
                let bit = ((dec.wrapping_add(1u64 << (LOG_DO - 1))) >> LOG_DO) & 1; // arrotonda al multiplo di 2^56
                let s: i64 =
                    scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>();
                let atteso = (s <= scena.t) as u64;
                confronti += 1;
                if bit != atteso {
                    errori += 1;
                    err_dist.push((s - scena.t).abs());
                }
                if bit == 1 {
                    sotto.push(i);
                }
            }
            // uscita compatta: il conteggio deve coincidere, e con un solo match l'indice
            let ok_c = cnt_dec == sotto.len() && (sotto.len() != 1 || idx_dec == sotto[0]);
            compatta_tot += 1;
            if ok_c {
                compatta_ok += 1;
            }
            if lab >= 0 {
                gen_tot += 1;
                if sotto.len() == 1 && sotto[0] as i64 == lab {
                    gen_ok += 1;
                }
            } else {
                imp_tot += 1;
                if !sotto.is_empty() {
                    imp_acc += 1;
                }
            }
        }
        let np = scena.probe.len() as f64;
        err_dist.sort();
        println!(
            "{:>3} | {:>7.3}s | {:>8.3}s | {:>8.3}s | {:>9.1}ms | {}/{} {:?}",
            n,
            tot_dot / np,
            tot_pbs / np,
            (tot_dot + tot_pbs) / np,
            tot_pbs / np / n as f64 * 1000.0 * threads as f64,
            errori,
            confronti,
            &err_dist[..err_dist.len().min(12)]
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
