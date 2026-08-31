// L'uscita del varco in UNA GLWE: il packing keyswitch al posto dell'uscita compatta a blocchi.
//
// Il problema. Il varco produce N bit cifrati, uno per iscritto, ciascuno un LWE sotto la chiave
// grande (2049 u64 = 16,4 KB). Mandarli tutti costa 67 MB a N=4096. L'uscita compatta di F43 li
// somma a blocchi (conteggio + indice locale in binario) e scende a 7,3 MB con blocchi da 64, ma
// paga due prezzi: le somme accumulano il rumore in uscita dal PBS (e' la trappola di F55, che
// costringe a blocchi piccoli e quindi a piu' cifrati), e il blocco piccolo rimanda su la
// dimensione. I due vincoli tirano in direzioni opposte.
//
// L'idea. Un LWE si puo' spostare dentro il COEFFICIENTE di una GLWE con un packing keyswitch:
// 2048 bit entrano in una sola GLWE (2 * 2048 u64 = 32 KB). Niente somme, quindi niente accumulo
// di rumore e nessun vincolo su LOG_DO; e la dimensione dell'uscita diventa ~N/2048 GLWE, cioe'
// 32 KB fino a N=2048 e 64 KB a N=4096. Il client decifra la GLWE e legge gli N bit direttamente:
// conteggio, indice, e anche QUALI iscritti hanno aperto (informazione che e' sua, non del server).
//
//   cargo run --release --bin uscita_impacchettata -- [--scena F] [--pks BASE LIVELLI] [--probe M]
use rayon::prelude::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// tempo-thread cumulato di keyswitch e blind rotate, per sapere quanto pesa davvero il KS
static T_KS: AtomicU64 = AtomicU64::new(0);
static T_BR: AtomicU64 = AtomicU64::new(0);
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey as ShortintClientKey, ServerKey as ShortintServerKey};

struct Scena { dim: usize, g: Vec<Vec<i64>>, bsq: Vec<i64>, probe: Vec<Vec<i64>>, t: i64 }

fn carica(path: &str) -> Scena {
    let txt = fs::read_to_string(path).expect("scena mancante");
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
    let def = concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_4096_q3.txt").to_string();
    let sc = carica(a.iter().position(|x| x == "--scena").map(|i| a[i + 1].clone()).unwrap_or(def).as_str());
    let n_probe: usize = a.iter().position(|x| x == "--probe").map(|i| a[i + 1].parse().unwrap()).unwrap_or(4);
    let pks_b: usize = a.iter().position(|x| x == "--pks").map(|i| a[i + 1].parse().unwrap()).unwrap_or(15);
    let pks_l: usize = a.iter().position(|x| x == "--pks").map(|i| a[i + 2].parse().unwrap()).unwrap_or(3);
    const LOG_DO: u32 = 62; // niente somme -> il bit puo' stare in alto quanto si vuole

    // --params: col packing non c'e' nessuna somma, quindi LOG_DO puo' stare a 62 e i set piccoli
    // (che F46/F47 davano per rotti, e F66 spiega: erano annegati nel rumore a LOG_DO=56) tornano
    // in gioco. Vale nello scenario honest-but-curious (varco fisico, F61), non contro un client
    // malicious, dove il Delta onesto di F56 li esclude comunque.
    let nome = a.iter().position(|x| x == "--params").map(|i| a[i + 1].clone())
        .unwrap_or_else(|| "default".to_string());
    let sck = match nome.as_str() {
        "default" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
        "1_0" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64),
        "1_1" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64),
        "2_0" => ShortintClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64),
        altro => panic!("--params sconosciuto: {altro}"),
    };
    println!("set di parametri: {nome}");
    let ssk = ShortintServerKey::new(&sck);
    let (enc_key, noise) = sck.encryption_key_and_noise();
    let ksk = &ssk.key_switching_key;
    let modulus = CiphertextModulus::<u64>::new_native();
    let big = enc_key.lwe_dimension().to_lwe_size();
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let poly = ssk.bootstrapping_key.polynomial_size();
    let glwe_size = ssk.bootstrapping_key.glwe_size();
    let fbsk = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k, _ => panic!("serve il PBS classico") };

    // la chiave grande E' la chiave GLWE appiattita: la rileggo come GlweSecretKey per il packing
    let glwe_sk = GlweSecretKey::from_container(enc_key.as_ref().to_vec(), poly);
    let mut bs = new_seeder();
    let sd = bs.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(sd.seed(), sd);
    let t0 = Instant::now();
    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &enc_key, &glwe_sk, DecompositionBaseLog(pks_b), DecompositionLevelCount(pks_l),
        noise, modulus, &mut gen);
    let t_pksk = t0.elapsed().as_secs_f64();
    let byte_pksk = pksk.as_ref().len() * 8;

    // Delta onesto (F56/F58): bound indipendente dal probe
    let q = sc.g.iter().flat_map(|v| v.iter()).map(|x| x.abs()).max().unwrap()
        .max(sc.probe.iter().flat_map(|v| v.iter()).map(|x| x.abs()).max().unwrap());
    let l1 = sc.g.iter().map(|v| v.iter().map(|x| x.abs()).sum::<i64>()).max().unwrap();
    let bound = 2 * q * l1 + sc.bsq.iter().cloned().max().unwrap() + sc.t.abs();
    let log_delta = 63 - (64 - (bound as u64).leading_zeros());
    let delta = 1u64 << log_delta;
    println!("packing keyswitch: base 2^{pks_b} x {pks_l} livelli | chiave {:.1} MB in {t_pksk:.1}s | \
              bound onesto {bound} -> Delta 2^{log_delta} | bit d'esito 2^{LOG_DO}\n", byte_pksk as f64 / 1e6);

    let c: u64 = (1u64 << (LOG_DO - 1)).wrapping_neg();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size, &PlaintextList::new(c, PlaintextCount(poly.0)), modulus);

    println!("{:>5} | {:>9} | {:>9} | {:>8} | {:>11} | {:>26} | {}",
             "N", "KS+PBS", "packing", "GLWE", "uscita", "confronto blocchi 64", "bit sbagliati");
    let mut n = 128;
    while n <= sc.g.len() {
        let (mut t_pbs, mut t_pack, mut sbagliati, mut tot) = (0f64, 0f64, 0usize, 0usize);
        let mut dist: Vec<i64> = Vec::new();
        for p in sc.probe.iter().take(n_probe) {
            let enc: Vec<LweCiphertextOwned<u64>> = p.iter().map(|&v|
                allocate_and_encrypt_new_lwe_ciphertext(&enc_key,
                    Plaintext((v as u64).wrapping_mul(delta)), noise, modulus, &mut gen)).collect();
            let t = Instant::now();
            let bits: Vec<LweCiphertextOwned<u64>> = (0..n).into_par_iter().map(|i| {
                let cost = ((sc.bsq[i] - sc.t) as u64).wrapping_mul(delta).wrapping_sub(delta >> 1);
                let mut x = allocate_and_trivially_encrypt_new_lwe_ciphertext(big, Plaintext(cost), modulus);
                for j in 0..sc.dim {
                    let co = (-2 * sc.g[i][j]) as u64;
                    if co == 0 { continue; }
                    let mut term = enc[j].clone();
                    lwe_ciphertext_cleartext_mul_assign(&mut term, Cleartext(co));
                    lwe_ciphertext_add_assign(&mut x, &term);
                }
                let mut ks = LweCiphertext::new(0u64, small, modulus);
                let tk = Instant::now();
                keyswitch_lwe_ciphertext(ksk, &x, &mut ks);
                let dks = tk.elapsed().as_secs_f64();
                let mut o = LweCiphertext::new(0u64, big, modulus);
                let tb = Instant::now();
                programmable_bootstrap_lwe_ciphertext(&ks, &mut o, &acc, fbsk);
                T_KS.fetch_add((dks * 1e9) as u64, Ordering::Relaxed);
                T_BR.fetch_add((tb.elapsed().as_secs_f64() * 1e9) as u64, Ordering::Relaxed);
                lwe_ciphertext_plaintext_add_assign(&mut o, Plaintext(1u64 << (LOG_DO - 1)));
                o
            }).collect();
            t_pbs += t.elapsed().as_secs_f64();

            // impacchetta: ceil(n / poly) GLWE, ognuna con fino a poly bit nei suoi coefficienti
            let t = Instant::now();
            let nglwe = (n + poly.0 - 1) / poly.0;
            let mut pacchi: Vec<GlweCiphertextOwned<u64>> = Vec::with_capacity(nglwe);
            for b in 0..nglwe {
                let da = b * poly.0;
                let quanti = (n - da).min(poly.0);
                let mut lista = LweCiphertextList::new(0u64, big, LweCiphertextCount(quanti), modulus);
                for (mut dst, src) in lista.iter_mut().zip(bits[da..da + quanti].iter()) {
                    dst.as_mut().copy_from_slice(src.as_ref());
                }
                let mut out = GlweCiphertext::new(0u64, glwe_size, poly, modulus);
                par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&pksk, &lista, &mut out);
                pacchi.push(out);
            }
            t_pack += t.elapsed().as_secs_f64();

            // client: decifra e rilegge gli N bit
            let mut letti = vec![0u64; n];
            for (b, pac) in pacchi.iter().enumerate() {
                let mut pl = PlaintextList::new(0u64, PlaintextCount(poly.0));
                decrypt_glwe_ciphertext(&glwe_sk, pac, &mut pl);
                for (j, v) in pl.iter().enumerate() {
                    let idx = b * poly.0 + j;
                    if idx < n {
                        letti[idx] = (v.0.wrapping_add(1u64 << (LOG_DO - 1)) >> LOG_DO) & 1;
                    }
                }
            }
            for i in 0..n {
                let s: i64 = sc.bsq[i] - 2 * (0..sc.dim).map(|j| sc.g[i][j] * p[j]).sum::<i64>();
                let atteso = if s <= sc.t { 1u64 } else { 0u64 };
                if letti[i] != atteso { sbagliati += 1; dist.push(s - sc.t); }
                tot += 1;
            }
        }
        let (aks, abr) = (T_KS.swap(0, Ordering::Relaxed) as f64 / 1e6, T_BR.swap(0, Ordering::Relaxed) as f64 / 1e6);
        println!("      tempo-thread: keyswitch {:.1} ms ({:.1}%), blind rotate {:.1} ms ({:.1}%)",
                 aks, 100.0 * aks / (aks + abr), abr, 100.0 * abr / (aks + abr));
        let byte_pack = ((n + poly.0 - 1) / poly.0) * glwe_size.0 * poly.0 * 8;
        let byte_blocchi = ((n + 63) / 64) * 7 * big.0 * 8;
        println!("{n:>5} | {:>8.3}s | {:>8.3}s | {:>7} | {:>8.2} MB | {:>18.2} MB ({:>4.0}x) | {sbagliati}/{tot} {dist:?}",
                 t_pbs / n_probe as f64, t_pack / n_probe as f64,
                 (n + poly.0 - 1) / poly.0, byte_pack as f64 / 1e6,
                 byte_blocchi as f64 / 1e6, byte_blocchi as f64 / byte_pack as f64);
        n *= 2;
    }
}
