// Il varco end-to-end: la CLI con i tre ruoli (client, server, client), file su disco al posto
// della rete. E' il varco leveled di F37 in forma "consegnabile":
//
//   varco keygen  <dir>                                  client: chiavi (client.key, server.key)
//   varco encrypt <dir> <probe.txt> <probe.ct>           client: probe -> UN GLWE (32 KB)
//   varco server  <dir> <galleria.txt> <probe.ct> <esito.ct>   server: N soglie, uscita compatta
//   varco decrypt <dir> <esito.ct>                       client: {conteggio, indice}
//
// Encoding polinomiale del probe (Zuber-Sirdey): A(X) = sum_j a_j X^j cifrato come GLWE (k=1,
// N=2048) sotto la chiave grande. Il server, per l'iscritto i, moltiplica per il polinomio in
// chiaro P_i(X) = sum_j (-2 g_ij) X^(511-j): il coefficiente 511 del prodotto e' -2 g_i.a, e
// l'estrazione di quel campione da' un LWE sotto la chiave grande, come in varco_leveled.rs.
// Poi la costante (||g_i||^2 - T) Delta - Delta/2, keyswitch, PBS di segno, uscita compatta
// (conteggio + indice in binario). Tutto coi parametri standard a 128 bit di tfhe-rs.
//
// Formati: galleria.txt = "DIM N T LOG_DELTA" + N righe di DIM interi; probe.txt = DIM interi;
// i cifrati sono u64 little-endian grezzi con una piccola intestazione.
use rayon::prelude::*;
use std::fs;
use std::io::Write;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::{generate_keys, ClientKey, ConfigBuilder, ServerKey};

const LOG_DO: u32 = 56; // encoding del bit di esito: 0 oppure 2^56, 8 bit di spazio per le somme

fn leggi_interi(path: &str) -> Vec<Vec<i64>> {
    fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("manca {path}"))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split_whitespace().map(|x| x.parse().unwrap()).collect())
        .collect()
}

fn scrivi_u64(path: &str, header: &[u64], dati: &[&[u64]]) {
    let mut f = fs::File::create(path).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(header.len() as u64).to_le_bytes());
    for h in header {
        buf.extend_from_slice(&h.to_le_bytes());
    }
    for d in dati {
        for x in *d {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    f.write_all(&buf).unwrap();
}

fn leggi_u64(path: &str) -> (Vec<u64>, Vec<u64>) {
    let b = fs::read(path).unwrap_or_else(|_| panic!("manca {path}"));
    let w: Vec<u64> = b
        .chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let nh = w[0] as usize;
    (w[1..1 + nh].to_vec(), w[1 + nh..].to_vec())
}

fn chiavi(dir: &str) -> (ClientKey, ServerKey) {
    let ck: ClientKey =
        bincode::deserialize(&fs::read(format!("{dir}/client.key")).expect("manca client.key"))
            .unwrap();
    let sk: ServerKey =
        bincode::deserialize(&fs::read(format!("{dir}/server.key")).expect("manca server.key"))
            .unwrap();
    (ck, sk)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let modulus = CiphertextModulus::<u64>::new_native();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let dir = &args[2];
            fs::create_dir_all(dir).unwrap();
            let t0 = Instant::now();
            let (ck, sk) = generate_keys(ConfigBuilder::default().build());
            fs::write(format!("{dir}/client.key"), bincode::serialize(&ck).unwrap()).unwrap();
            fs::write(format!("{dir}/server.key"), bincode::serialize(&sk).unwrap()).unwrap();
            println!("{{\"keygen_s\": {:.3}}}", t0.elapsed().as_secs_f64());
        }
        Some("encrypt") => {
            let (dir, probe_path, out) = (&args[2], &args[3], &args[4]);
            let (ck, _) = chiavi(dir);
            let (ick, _, _, _) = ck.into_raw_parts();
            let (glwe_sk, _, params) = ick.into_raw_parts().into_raw_parts();
            let poly = glwe_sk.polynomial_size();
            let probe = &leggi_interi(probe_path)[0];
            let log_delta: u32 = args.get(5).map(|s| s.parse().unwrap()).unwrap_or(50);
            let delta = 1u64 << log_delta;
            let t0 = Instant::now();
            let mut coeff = vec![0u64; poly.0];
            for (j, &a) in probe.iter().enumerate() {
                coeff[j] = (a as u64).wrapping_mul(delta);
            }
            let mut boxed_seeder = new_seeder();
            let seeder = boxed_seeder.as_mut();
            let mut enc_gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let mut glwe = GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &PlaintextList::from_container(coeff),
                                    params.glwe_noise_distribution(), &mut enc_gen);
            scrivi_u64(out, &[poly.0 as u64, glwe_sk.glwe_dimension().0 as u64, log_delta as u64], &[glwe.as_ref()]);
            println!("{{\"encrypt_s\": {:.4}, \"probe_ct_bytes\": {}}}", t0.elapsed().as_secs_f64(),
                     fs::metadata(out).unwrap().len());
        }
        Some("server") => {
            let (dir, gal_path, ct_path, out) = (&args[2], &args[3], &args[4], &args[5]);
            let (_, sk) = chiavi(dir);
            let (isk, _, _, _, _) = sk.into_raw_parts();
            let ssk = isk.into_raw_parts();
            let ksk = &ssk.key_switching_key;
            let fbsk = match &ssk.bootstrapping_key {
                ShortintBootstrappingKey::Classic(k) => k,
                _ => panic!("attesa bootstrapping key classica"),
            };
            let righe = leggi_interi(gal_path);
            let (dim, n, t, log_delta) = (righe[0][0] as usize, righe[0][1] as usize, righe[0][2], righe[0][3] as u32);
            let g: Vec<Vec<i64>> = righe[1..1 + n].to_vec();
            let bsq: Vec<i64> = g.iter().map(|v| v.iter().map(|x| x * x).sum()).collect();
            let (hdr, dati) = leggi_u64(ct_path);
            let (poly, k) = (PolynomialSize(hdr[0] as usize), GlweDimension(hdr[1] as usize));
            assert_eq!(hdr[2] as u32, log_delta, "Delta del probe diverso da quello della galleria");
            let delta = 1u64 << log_delta;
            let glwe = GlweCiphertext::from_container(dati, poly, modulus);
            let big_size = LweSize(k.0 * poly.0 + 1);
            let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
            let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                fbsk.glwe_size(), &PlaintextList::new((1u64 << (LOG_DO - 1)).wrapping_neg(), PlaintextCount(fbsk.polynomial_size().0)), modulus);

            // tappa 1: N punteggi leveled, ognuno un prodotto polinomiale + un'estrazione (0 PBS)
            let t0 = Instant::now();
            let xs: Vec<LweCiphertextOwned<u64>> = (0..n)
                .into_par_iter()
                .map(|i| {
                    let mut p = vec![0u64; poly.0];
                    for j in 0..dim {
                        p[dim - 1 - j] = (-2 * g[i][j]) as u64;
                    }
                    let p = Polynomial::from_container(p);
                    let mut prod = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
                    for (mut o, c) in prod.as_mut_polynomial_list().iter_mut().zip(glwe.as_polynomial_list().iter()) {
                        polynomial_wrapping_add_mul_assign(&mut o, &c, &p);
                    }
                    let mut x = LweCiphertext::new(0u64, big_size, modulus);
                    extract_lwe_sample_from_glwe_ciphertext(&prod, &mut x, MonomialDegree(dim - 1));
                    let cost = ((bsq[i] - t) as u64).wrapping_mul(delta).wrapping_sub(delta >> 1);
                    lwe_ciphertext_plaintext_add_assign(&mut x, Plaintext(cost));
                    x
                })
                .collect();
            let t_dot = t0.elapsed().as_secs_f64();

            // tappa 2: N bit di soglia, keyswitch + PBS di segno, in parallelo
            let t0 = Instant::now();
            let bits: Vec<LweCiphertextOwned<u64>> = xs
                .par_iter()
                .map(|x| {
                    let mut ks = LweCiphertext::new(0u64, small_size, modulus);
                    keyswitch_lwe_ciphertext(ksk, x, &mut ks);
                    let mut o = LweCiphertext::new(0u64, big_size, modulus);
                    programmable_bootstrap_lwe_ciphertext(&ks, &mut o, &acc, fbsk);
                    lwe_ciphertext_plaintext_add_assign(&mut o, Plaintext(1u64 << (LOG_DO - 1)));
                    o
                })
                .collect();
            let t_pbs = t0.elapsed().as_secs_f64();

            // tappa 3: uscita compatta a blocchi di 64 (conteggio + indice locale in binario, leveled);
            // somme corte per tenere il rumore del PBS (~2^48 x sqrt(addendi)) lontano dal margine 2^55
            let t0 = Instant::now();
            const BLOCCO: usize = 64;
            let nbit = (usize::BITS - (BLOCCO - 1).leading_zeros()) as usize;
            let nblocchi = (n + BLOCCO - 1) / BLOCCO;
            let mut cts: Vec<LweCiphertextOwned<u64>> = Vec::with_capacity(nblocchi * (1 + nbit));
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
                cts.push(cnt); cts.extend(idx);
            }
            let t_comp = t0.elapsed().as_secs_f64();
            let dati: Vec<&[u64]> = cts.iter().map(|c| c.as_ref()).collect();
            scrivi_u64(out, &[n as u64, nbit as u64, big_size.0 as u64, BLOCCO as u64], &dati);
            println!("{{\"n\": {n}, \"t_dot_s\": {t_dot:.4}, \"t_pbs_s\": {t_pbs:.4}, \"t_compatta_s\": {t_comp:.5}, \
                      \"threads\": {}, \"esito_ct_bytes\": {}}}", rayon::current_num_threads(), fs::metadata(out).unwrap().len());
        }
        Some("decrypt") => {
            let (dir, ct_path) = (&args[2], &args[3]);
            let (ck, _) = chiavi(dir);
            let (ick, _, _, _) = ck.into_raw_parts();
            let sck = ick.into_raw_parts();
            let (enc_key, _) = sck.encryption_key_and_noise();
            let (hdr, dati) = leggi_u64(ct_path);
            let (n, nbit, size, blocco) = (hdr[0] as usize, hdr[1] as usize, hdr[2] as usize, hdr[3] as usize);
            let t0 = Instant::now();
            let dec8 = |sl: &[u64]| {
                let ct = LweCiphertext::from_container(sl.to_vec(), modulus);
                (decrypt_lwe_ciphertext(&enc_key, &ct).0.wrapping_add(1u64 << (LOG_DO - 1)) >> LOG_DO) & 0xFF
            };
            let nblocchi = (n + blocco - 1) / blocco;
            let (mut cnt, mut idx) = (0usize, 0usize);
            for b in 0..nblocchi {
                let base = b * (1 + nbit) * size;
                let c = dec8(&dati[base..base + size]) as usize;
                cnt += c;
                if c == 1 {
                    idx = b * blocco + (0..nbit).map(|k| (dec8(&dati[base + (k + 1) * size..base + (k + 2) * size]) as usize) << k).sum::<usize>();
                }
            }
            println!("{{\"n\": {n}, \"conteggio\": {cnt}, \"indice\": {}, \"decrypt_s\": {:.5}}}",
                     if cnt == 1 { idx as i64 } else { -1 }, t0.elapsed().as_secs_f64());
        }
        _ => eprintln!("uso: varco keygen <dir> | encrypt <dir> <probe.txt> <probe.ct> [log_delta] | server <dir> <galleria.txt> <probe.ct> <esito.ct> | decrypt <dir> <esito.ct>"),
    }
}
