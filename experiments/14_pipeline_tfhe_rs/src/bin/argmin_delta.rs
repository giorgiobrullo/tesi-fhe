// L'argmin ESATTO sul server senza il ponte: la matrice dei confronti a coppie (Zuber-Sirdey)
// coi nostri PBS economici.
//
// Il confronto tra due punteggi larghi e' un segno, come la soglia: s_i <= s_j  <=>  (s_i - s_j)
// negativo, un PBS negaciclico ad accumulatore costante, nessuna cifra da estrarre. Con tutte le
// N(N-1)/2 coppie si ottiene la matrice a_ij = [s_i <= s_j] (i<j); la riga del vincitore (il primo
// minimo: s_i < s_j per j<i, s_i <= s_j per j>i) e' tutta a uno. "Tutti a uno" si verifica a
// blocchi di 8 con una LUT a 4 bit (somma di 8 bit -> "== 8"), ricorsivamente: ~19 PBS per riga a
// N=128. Poi la soglia SOLO sul vincitore: match = sum_i AND(w_i, t_i) con t_i = [s_i <= T].
// Uscita: w (one-hot esatto, pareggi risolti come in chiaro), indice in binario, bit di match.
// E' il design dell'incontro (argmin, poi soglia sul vincitore), quadratico in N.
//
//   cargo run --release --bin argmin_delta -- [scena] [N_min] [probe_max]
use rayon::prelude::*;
use std::fs;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::{generate_keys, ConfigBuilder};

const LOG_DB: u32 = 59; // bit a 0 / 2^59: sommabili a 8 senza uscire dal padding, LUT a 4 bit

struct Scena {
    dim: usize,
    g: Vec<Vec<i64>>,
    bsq: Vec<i64>,
    probe: Vec<Vec<i64>>,
    label: Vec<i64>,
    t: i64,
}

fn carica(path: &str) -> Scena {
    let txt = fs::read_to_string(path).expect("manca la scena: lancia esporta_dati.py");
    let mut righe = txt.lines();
    let h: Vec<i64> = righe
        .next()
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let (dim, n, np, t) = (h[0] as usize, h[1] as usize, h[2] as usize, h[3]);
    let g: Vec<Vec<i64>> = (0..n)
        .map(|_| {
            righe
                .next()
                .unwrap()
                .split_whitespace()
                .map(|x| x.parse().unwrap())
                .collect()
        })
        .collect();
    let (mut probe, mut label) = (Vec::new(), Vec::new());
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
    let args: Vec<String> = std::env::args().collect();
    let default_scena = concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale.txt").to_string();
    let scena = carica(args.get(1).unwrap_or(&default_scena));
    let n_min: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(8);
    let probe_max: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(32);
    let mut ns = Vec::new();
    let mut n = n_min;
    while n <= scena.g.len() {
        ns.push(n);
        n *= 2;
    }

    let (ck_hl, sk_hl) = generate_keys(ConfigBuilder::default().build());
    let (ick, _, _, _) = ck_hl.into_raw_parts();
    let sck = ick.into_raw_parts();
    let (isk, _, _, _, _) = sk_hl.into_raw_parts();
    let ssk = isk.into_raw_parts();
    let (enc_key, noise) = sck.encryption_key_and_noise();
    let ksk = &ssk.key_switching_key;
    let fbsk = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k,
        _ => panic!(),
    };
    let modulus = CiphertextModulus::<u64>::new_native();
    let big_size = enc_key.lwe_dimension().to_lwe_size();
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let (poly, glwe_size) = (fbsk.polynomial_size(), fbsk.glwe_size());

    // encoding: Delta per le differenze (range doppio) e per la soglia
    let (mut max_d, mut max_t) = (0i64, 0i64);
    for p in &scena.probe {
        let s: Vec<i64> = (0..scena.g.len())
            .map(|i| scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>())
            .collect();
        let (lo, hi) = (*s.iter().min().unwrap(), *s.iter().max().unwrap());
        max_d = max_d.max(hi - lo + 1);
        max_t = max_t.max((hi - scena.t).abs().max((lo - scena.t).abs()) + 1);
    }
    let log_dd = 63 - (64 - (max_d as u64).leading_zeros());
    let dd = 1u64 << log_dd;
    let log_dt = 63 - (64 - (max_t as u64).leading_zeros());
    let dt = 1u64 << log_dt;
    println!("scena: N={} probe={} T={} | Delta confronti 2^{} (|s_i-s_j| < {}), Delta soglia 2^{} | thread {}",
             scena.g.len(), scena.probe.len(), scena.t, log_dd, max_d, log_dt, rayon::current_num_threads());

    // accumulatori: segno (costante -2^58 -> bit a 2^59 dopo +2^58) e LUT "== c" a 4 bit su valori a 2^59
    let acc_segno = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (1u64 << (LOG_DB - 1)).wrapping_neg(),
            PlaintextCount(poly.0),
        ),
        modulus,
    );
    let acc_eq: Vec<GlweCiphertextOwned<u64>> = (0..=8u64)
        .map(|c| {
            generate_programmable_bootstrap_glwe_lut(
                poly,
                glwe_size,
                16,
                modulus,
                1u64 << LOG_DB,
                |v| if v == c { 1 } else { 0 },
            )
        })
        .collect();
    let pbs = |x: &LweCiphertextOwned<u64>, acc: &GlweCiphertextOwned<u64>| {
        let mut ks = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(ksk, x, &mut ks);
        let mut out = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(&ks, &mut out, acc, fbsk);
        out
    };
    let segno = |x: &LweCiphertextOwned<u64>| {
        // bit = [x nella meta' negativa]
        let mut o = pbs(x, &acc_segno);
        lwe_ciphertext_plaintext_add_assign(&mut o, Plaintext(1u64 << (LOG_DB - 1)));
        o
    };
    // "tutti a uno" su una lista di bit a 2^59: blocchi di 8, somma leveled, LUT "== len", ricorsivo
    let tutti_uno =
        |bits: Vec<LweCiphertextOwned<u64>>, contatore: &mut usize| -> LweCiphertextOwned<u64> {
            let mut cur = bits;
            while cur.len() > 1 {
                let mut next = Vec::with_capacity((cur.len() + 7) / 8);
                for ch in cur.chunks(8) {
                    let mut s = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big_size,
                        Plaintext(0u64),
                        modulus,
                    );
                    for b in ch {
                        lwe_ciphertext_add_assign(&mut s, b);
                    }
                    next.push(pbs(&s, &acc_eq[ch.len()]));
                    *contatore += 1;
                }
                cur = next;
            }
            cur.pop().unwrap()
        };
    let dec_bit = |ct: &LweCiphertextOwned<u64>| {
        (decrypt_lwe_ciphertext(&enc_key, ct)
            .0
            .wrapping_add(1u64 << (LOG_DB - 1))
            >> LOG_DB)
            & 0xF
    };

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut enc_gen =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!(
        "{:>4} | {:>7} | {:>8} | {:>8} | {:>8} | {:>8} | {:>6} | esatto (indice, match)",
        "N", "dot", "coppie", "vincit.", "soglia", "totale", "PBS"
    );
    for &n in &ns {
        let np = scena.probe.len().min(probe_max);
        let (mut tt, mut ok_idx, mut ok_match, mut ok_onehot) = ([0f64; 4], 0usize, 0usize, 0usize);
        let mut n_pbs = 0usize;
        for (p, _lab) in scena.probe.iter().zip(&scena.label).take(np) {
            let enc: Vec<LweCiphertextOwned<u64>> = p
                .iter()
                .map(|&v| {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &enc_key,
                        Plaintext((v as u64).wrapping_mul(dd)),
                        noise,
                        modulus,
                        &mut enc_gen,
                    )
                })
                .collect();
            let enc_t: Vec<LweCiphertextOwned<u64>> = p
                .iter()
                .map(|&v| {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &enc_key,
                        Plaintext((v as u64).wrapping_mul(dt)),
                        noise,
                        modulus,
                        &mut enc_gen,
                    )
                })
                .collect();
            let leveled = |enc: &Vec<LweCiphertextOwned<u64>>, delta: u64, cost: i64, i: usize| {
                let mut a = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    big_size,
                    Plaintext((cost as u64).wrapping_mul(delta)),
                    modulus,
                );
                for j in 0..scena.dim {
                    let c = (-2 * scena.g[i][j]) as u64;
                    if c == 0 {
                        continue;
                    }
                    let mut term = enc[j].clone();
                    lwe_ciphertext_cleartext_mul_assign(&mut term, Cleartext(c));
                    lwe_ciphertext_add_assign(&mut a, &term);
                }
                a
            };
            // tappa 1: punteggi leveled per i confronti (x) e per la soglia (y), 0 PBS
            let t0 = Instant::now();
            let xs: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| leveled(&enc, dd, scena.bsq[i], i))
                .collect();
            let ys: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let mut y = leveled(&enc_t, dt, scena.bsq[i] - scena.t, i);
                    lwe_ciphertext_plaintext_sub_assign(&mut y, Plaintext(dt >> 1));
                    y
                })
                .collect();
            tt[0] += t0.elapsed().as_secs_f64();
            // tappa 2: a_ij = [s_i <= s_j] per i<j: (x_i - x_j) - Delta/2 nella meta' negativa
            let t0 = Instant::now();
            let coppie: Vec<(usize, usize)> = (0..n)
                .flat_map(|i| ((i + 1)..n).map(move |j| (i, j)))
                .collect();
            let a_ij: Vec<LweCiphertextOwned<u64>> = coppie
                .par_iter()
                .map(|&(i, j)| {
                    let mut d = xs[i].clone();
                    lwe_ciphertext_sub_assign(&mut d, &xs[j]);
                    lwe_ciphertext_plaintext_sub_assign(&mut d, Plaintext(dd >> 1));
                    segno(&d)
                })
                .collect();
            n_pbs += coppie.len();
            tt[1] += t0.elapsed().as_secs_f64();
            // tappa 3: riga i tutta a uno -> w_i (primo minimo: per j<i serve s_i < s_j = NOT a_ji)
            let t0 = Instant::now();
            let idx_of = |i: usize, j: usize| -> usize {
                // posizione della coppia (i<j) nella lista
                i * n - i * (i + 1) / 2 + (j - i - 1)
            };
            let ws: Vec<(LweCiphertextOwned<u64>, usize)> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let mut bits = Vec::with_capacity(n - 1);
                    for j in 0..n {
                        if j == i {
                            continue;
                        }
                        if j > i {
                            bits.push(a_ij[idx_of(i, j)].clone());
                        } else {
                            let mut b = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                                big_size,
                                Plaintext(1u64 << LOG_DB),
                                modulus,
                            );
                            lwe_ciphertext_sub_assign(&mut b, &a_ij[idx_of(j, i)]);
                            bits.push(b);
                        }
                    }
                    let mut c = 0usize;
                    let w = tutti_uno(bits, &mut c);
                    (w, c)
                })
                .collect();
            n_pbs += ws.iter().map(|w| w.1).sum::<usize>();
            let ws: Vec<LweCiphertextOwned<u64>> = ws.into_iter().map(|w| w.0).collect();
            tt[2] += t0.elapsed().as_secs_f64();
            // tappa 4: t_i = [s_i <= T], match = sum_i AND(w_i, t_i) (una LUT "== 2" per i), indice = sum i*w_i in binario
            let t0 = Instant::now();
            let ands: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let ti = segno(&ys[i]);
                    let mut s = ws[i].clone();
                    lwe_ciphertext_add_assign(&mut s, &ti);
                    pbs(&s, &acc_eq[2])
                })
                .collect();
            n_pbs += 2 * n;
            let mut m = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                big_size,
                Plaintext(0u64),
                modulus,
            );
            for a in &ands {
                lwe_ciphertext_add_assign(&mut m, a);
            }
            let nbit = (usize::BITS - (n - 1).leading_zeros()) as usize;
            let mut idx: Vec<LweCiphertextOwned<u64>> = (0..nbit)
                .map(|_| {
                    allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big_size,
                        Plaintext(0u64),
                        modulus,
                    )
                })
                .collect();
            for i in 0..n {
                for k in 0..nbit {
                    if (i >> k) & 1 == 1 {
                        lwe_ciphertext_add_assign(&mut idx[k], &ws[i]);
                    }
                }
            }
            tt[3] += t0.elapsed().as_secs_f64();
            // verifica contro il chiaro
            let s: Vec<i64> = (0..n)
                .map(|i| {
                    scena.bsq[i] - 2 * (0..scena.dim).map(|j| scena.g[i][j] * p[j]).sum::<i64>()
                })
                .collect();
            let mut best = 0;
            for i in 1..n {
                if s[i] < s[best] {
                    best = i;
                }
            }
            let w_dec: Vec<u64> = ws.iter().map(|w| dec_bit(w)).collect();
            let onehot_ok = w_dec.iter().sum::<u64>() == 1 && w_dec[best] == 1;
            let idx_dec: usize = (0..nbit).map(|k| (dec_bit(&idx[k]) as usize) << k).sum();
            let m_dec = dec_bit(&m);
            ok_onehot += onehot_ok as usize;
            ok_idx += (idx_dec == best) as usize;
            ok_match += (m_dec == (s[best] <= scena.t) as u64) as usize;
        }
        let f = np as f64;
        println!("{:>4} | {:>6.3}s | {:>7.2}s | {:>7.2}s | {:>7.2}s | {:>7.2}s | {:>6} | one-hot {}/{}, indice {}/{}, match {}/{}",
                 n, tt[0] / f, tt[1] / f, tt[2] / f, tt[3] / f, tt.iter().sum::<f64>() / f, n_pbs / np, ok_onehot, np, ok_idx, np, ok_match, np);
    }
}
