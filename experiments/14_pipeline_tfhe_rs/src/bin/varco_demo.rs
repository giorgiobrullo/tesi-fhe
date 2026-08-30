// Il varco come SERVIZIO: i due ruoli separati, che parlano solo byte cifrati.
//
// E' il varco di F37/F41/F46/F47 (prodotto scalare leveled + un PBS di segno per iscritto, uscita
// compatta a blocchi, parametri MESSAGE_1_CARRY_1, embedding quantizzato a 3 bit) impacchettato
// nei due processi del modello di minaccia dell'incontro:
//
//   client (terminale fidato)   keygen, encrypt, decrypt: ha la chiave segreta, non la manda mai
//   server (macchina remota)    serve: ha la galleria IN CHIARO e la chiave di valutazione,
//                               calcola sul cifrato, non puo' decifrare nulla
//
// Sottocomandi:
//   varco_demo keygen  <dir>                    -> <dir>/client.key (segreta), <dir>/server.key (valutazione)
//   varco_demo encrypt <dir> <probe.txt> <out>  -> probe cifrato: UN GLWE (encoding polinomiale)
//   varco_demo decrypt <dir> <esito.ct>         -> {"conteggio": k, "indice": i}
//   varco_demo serve   <porta> <dim> <T> <log_delta>
//
// Il server espone un HTTP minimale (solo std::net, nessuna dipendenza):
//   POST /chiave    corpo = server.key                      (una volta, all'avvio del client)
//   POST /iscrivi   corpo = "nome\nv1 v2 ... vdim"          (template IN CHIARO: e' la galleria del server)
//   POST /varco     corpo = probe cifrato                   -> esito cifrato (+ header X-Tempo-Ms, X-Pbs)
//   GET  /stato     -> JSON con iscritti, chiave presente, parametri
//   POST /reset     svuota la galleria
use rayon::prelude::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const LOG_DO: u32 = 56; // bit d'esito: 0 oppure 2^56
const BLOCCO: usize = 64; // addendi per blocco nell'uscita compatta (F43)

// ---------------------------------------------------------------- utilita' di formato
fn scrivi_u64(path: &str, header: &[u64], dati: &[&[u64]]) {
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
    std::fs::write(path, buf).unwrap();
}

fn bytes_to_u64(b: &[u8]) -> (Vec<u64>, Vec<u64>) {
    let w: Vec<u64> = b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    let nh = w[0] as usize;
    (w[1..1 + nh].to_vec(), w[1 + nh..].to_vec())
}

fn u64_to_bytes(header: &[u64], dati: &[&[u64]]) -> Vec<u8> {
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
    buf
}

// ---------------------------------------------------------------- stato del server
struct Galleria {
    dim: usize,
    t: i64,
    delta: u64,
    iscritti: Vec<(String, Vec<i64>, i64)>, // nome, template quantizzato, ||g||^2
    chiave: Option<ServerKey>,
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let modulus = CiphertextModulus::<u64>::new_native();
    match a.get(1).map(String::as_str) {
        // ------------------------------------------------ client: chiavi
        Some("keygen") => {
            let dir = &a[2];
            std::fs::create_dir_all(dir).unwrap();
            let t0 = Instant::now();
            let ck = ClientKey::new(PARAMS);
            let sk = ServerKey::new(&ck);
            std::fs::write(format!("{dir}/client.key"), bincode::serialize(&ck).unwrap()).unwrap();
            std::fs::write(format!("{dir}/server.key"), bincode::serialize(&sk).unwrap()).unwrap();
            println!("{{\"keygen_s\": {:.2}, \"client_key_b\": {}, \"server_key_b\": {}}}",
                     t0.elapsed().as_secs_f64(),
                     std::fs::metadata(format!("{dir}/client.key")).unwrap().len(),
                     std::fs::metadata(format!("{dir}/server.key")).unwrap().len());
        }
        // ------------------------------------------------ client: cifra il probe (un GLWE)
        Some("encrypt") => {
            let (dir, probe_path, out) = (&a[2], &a[3], &a[4]);
            let log_delta: u32 = a.get(5).map(|s| s.parse().unwrap()).unwrap_or(53);
            let ck: ClientKey = bincode::deserialize(&std::fs::read(format!("{dir}/client.key")).unwrap()).unwrap();
            let (glwe_sk, _, params) = ck.into_raw_parts();
            let poly = glwe_sk.polynomial_size();
            let probe: Vec<i64> = std::fs::read_to_string(probe_path).unwrap()
                .split_whitespace().map(|x| x.parse().unwrap()).collect();
            assert!(probe.len() <= poly.0, "probe piu' lungo del polinomio ({} > {})", probe.len(), poly.0);
            let delta = 1u64 << log_delta;
            let t0 = Instant::now();
            let mut coeff = vec![0u64; poly.0];
            for (j, &v) in probe.iter().enumerate() {
                coeff[j] = (v as u64).wrapping_mul(delta);
            }
            let mut boxed = new_seeder();
            let seeder = boxed.as_mut();
            let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let mut glwe = GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &PlaintextList::from_container(coeff),
                                    params.glwe_noise_distribution(), &mut gen);
            scrivi_u64(out, &[poly.0 as u64, glwe_sk.glwe_dimension().0 as u64, log_delta as u64], &[glwe.as_ref()]);
            println!("{{\"encrypt_ms\": {:.2}, \"probe_ct_b\": {}}}",
                     t0.elapsed().as_secs_f64() * 1000.0, std::fs::metadata(out).unwrap().len());
        }
        // ------------------------------------------------ client: decifra l'esito
        Some("decrypt") => {
            let (dir, ct_path) = (&a[2], &a[3]);
            let ck: ClientKey = bincode::deserialize(&std::fs::read(format!("{dir}/client.key")).unwrap()).unwrap();
            let (enc_key, _) = ck.encryption_key_and_noise();
            let (hdr, dati) = bytes_to_u64(&std::fs::read(ct_path).unwrap());
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
            println!("{{\"conteggio\": {cnt}, \"indice\": {}, \"decrypt_ms\": {:.2}}}",
                     if cnt == 1 { idx as i64 } else { -1 }, t0.elapsed().as_secs_f64() * 1000.0);
        }
        // ------------------------------------------------ server: il servizio
        Some("serve") => {
            let porta: u16 = a[2].parse().unwrap();
            let dim: usize = a.get(3).map(|s| s.parse().unwrap()).unwrap_or(512);
            let t: i64 = a.get(4).map(|s| s.parse().unwrap()).unwrap_or(0);
            let log_delta: u32 = a.get(5).map(|s| s.parse().unwrap()).unwrap_or(53);
            let stato = Mutex::new(Galleria { dim, t, delta: 1u64 << log_delta, iscritti: Vec::new(), chiave: None });
            let l = TcpListener::bind(("0.0.0.0", porta)).unwrap();
            println!("varco in ascolto su :{porta} | dim={dim} T={t} Delta=2^{log_delta} | parametri {:?}, 128 bit",
                     PARAMS.message_modulus);
            println!("il server NON ha la chiave segreta: riceve byte cifrati e ne restituisce altri.");
            for s in l.incoming() {
                if let Ok(s) = s {
                    gestisci(s, &stato, modulus);
                }
            }
        }
        _ => eprintln!("uso: varco_demo keygen <dir> | encrypt <dir> <probe.txt> <out> [log_delta] | \
                        decrypt <dir> <esito.ct> | serve <porta> <dim> <T> <log_delta>"),
    }
}

// ---------------------------------------------------------------- HTTP minimale (solo std)
fn gestisci(mut s: TcpStream, stato: &Mutex<Galleria>, modulus: CiphertextModulus<u64>) {
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut riga = String::new();
    if r.read_line(&mut riga).is_err() || riga.is_empty() {
        return;
    }
    let parti: Vec<&str> = riga.split_whitespace().collect();
    if parti.len() < 2 {
        return;
    }
    let (metodo, path) = (parti[0].to_string(), parti[1].to_string());
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        let hl = h.to_ascii_lowercase();
        if let Some(v) = hl.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut corpo = vec![0u8; len];
    if len > 0 && r.read_exact(&mut corpo).is_err() {
        return;
    }

    let (codice, tipo, extra, body): (u16, &str, String, Vec<u8>) = match (metodo.as_str(), path.as_str()) {
        ("POST", "/chiave") => {
            match bincode::deserialize::<tfhe::shortint::ServerKey>(&corpo) {
                Ok(k) => {
                    stato.lock().unwrap().chiave = Some(k);
                    (200, "application/json", String::new(), b"{\"ok\":true}".to_vec())
                }
                Err(e) => (400, "application/json", String::new(), format!("{{\"errore\":\"chiave non valida: {e}\"}}").into_bytes()),
            }
        }
        ("POST", "/iscrivi") => {
            let testo = String::from_utf8_lossy(&corpo);
            let mut righe = testo.splitn(2, '\n');
            let nome = righe.next().unwrap_or("?").trim().to_string();
            let v: Vec<i64> = righe.next().unwrap_or("").split_whitespace().filter_map(|x| x.parse().ok()).collect();
            let mut g = stato.lock().unwrap();
            if v.len() != g.dim {
                (400, "application/json", String::new(),
                 format!("{{\"errore\":\"attesi {} valori, ricevuti {}\"}}", g.dim, v.len()).into_bytes())
            } else {
                let bsq = v.iter().map(|x| x * x).sum();
                g.iscritti.push((nome.clone(), v, bsq));
                let n = g.iscritti.len();
                (200, "application/json", String::new(), format!("{{\"ok\":true,\"indice\":{},\"iscritti\":{n}}}", n - 1).into_bytes())
            }
        }
        ("POST", "/varco") => {
            let g = stato.lock().unwrap();
            if g.chiave.is_none() {
                (400, "application/json", String::new(), b"{\"errore\":\"chiave di valutazione mancante\"}".to_vec())
            } else if g.iscritti.is_empty() {
                (400, "application/json", String::new(), b"{\"errore\":\"galleria vuota\"}".to_vec())
            } else {
                let t0 = Instant::now();
                let (out, n_pbs) = varco(&g, &corpo, modulus);
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                (200, "application/octet-stream", format!("X-Tempo-Ms: {ms:.1}\r\nX-Pbs: {n_pbs}\r\n"), out)
            }
        }
        ("GET", "/stato") => {
            let g = stato.lock().unwrap();
            let nomi: Vec<String> = g.iscritti.iter().map(|x| format!("\"{}\"", x.0)).collect();
            (200, "application/json", String::new(),
             format!("{{\"iscritti\":{},\"nomi\":[{}],\"chiave\":{},\"dim\":{},\"soglia\":{}}}",
                     g.iscritti.len(), nomi.join(","), g.chiave.is_some(), g.dim, g.t).into_bytes())
        }
        ("POST", "/reset") => {
            stato.lock().unwrap().iscritti.clear();
            (200, "application/json", String::new(), b"{\"ok\":true}".to_vec())
        }
        _ => (404, "application/json", String::new(), b"{\"errore\":\"non trovato\"}".to_vec()),
    };

    let testa = format!("HTTP/1.1 {codice} OK\r\nContent-Type: {tipo}\r\nContent-Length: {}\r\n\
                         Access-Control-Allow-Origin: *\r\n{extra}\r\n", body.len());
    let _ = s.write_all(testa.as_bytes());
    let _ = s.write_all(&body);
    let _ = s.flush();
}

// ---------------------------------------------------------------- il varco (F37/F41/F43)
fn varco(g: &Galleria, probe_ct: &[u8], modulus: CiphertextModulus<u64>) -> (Vec<u8>, usize) {
    let ssk = g.chiave.as_ref().unwrap();
    let ksk = &ssk.key_switching_key;
    let fbsk = match &ssk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k,
        _ => panic!("attesa bootstrapping key classica"),
    };
    let (hdr, dati) = bytes_to_u64(probe_ct);
    let (poly, k) = (PolynomialSize(hdr[0] as usize), GlweDimension(hdr[1] as usize));
    let glwe = GlweCiphertext::from_container(dati, poly, modulus);
    let big = LweSize(k.0 * poly.0 + 1);
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let n = g.iscritti.len();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        fbsk.glwe_size(),
        &PlaintextList::new((1u64 << (LOG_DO - 1)).wrapping_neg(), PlaintextCount(fbsk.polynomial_size().0)),
        modulus,
    );

    // 1) N punteggi leveled: un prodotto di polinomi + un'estrazione, zero bootstrap
    // 2) N bit di soglia: un keyswitch + un PBS di segno ciascuno, tutti indipendenti
    let bits: Vec<LweCiphertextOwned<u64>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let (_, gal, bsq) = &g.iscritti[i];
            let mut p = vec![0u64; poly.0];
            for j in 0..g.dim {
                p[g.dim - 1 - j] = (-2 * gal[j]) as u64;
            }
            let p = Polynomial::from_container(p);
            let mut prod = GlweCiphertext::new(0u64, k.to_glwe_size(), poly, modulus);
            for (mut o, c) in prod.as_mut_polynomial_list().iter_mut().zip(glwe.as_polynomial_list().iter()) {
                polynomial_wrapping_add_mul_assign(&mut o, &c, &p);
            }
            let mut x = LweCiphertext::new(0u64, big, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&prod, &mut x, MonomialDegree(g.dim - 1));
            let cost = ((bsq - g.t) as u64).wrapping_mul(g.delta).wrapping_sub(g.delta >> 1);
            lwe_ciphertext_plaintext_add_assign(&mut x, Plaintext(cost));
            let mut ks = LweCiphertext::new(0u64, small, modulus);
            keyswitch_lwe_ciphertext(ksk, &x, &mut ks);
            let mut o = LweCiphertext::new(0u64, big, modulus);
            programmable_bootstrap_lwe_ciphertext(&ks, &mut o, &acc, fbsk);
            lwe_ciphertext_plaintext_add_assign(&mut o, Plaintext(1u64 << (LOG_DO - 1)));
            o
        })
        .collect();

    // 3) uscita compatta: per blocchi di 64, conteggio + indice locale in binario (leveled)
    let nbit = (usize::BITS - (BLOCCO - 1).leading_zeros()) as usize;
    let nblocchi = (n + BLOCCO - 1) / BLOCCO;
    let mut cts: Vec<LweCiphertextOwned<u64>> = Vec::with_capacity(nblocchi * (1 + nbit));
    for b in 0..nblocchi {
        let mut cnt = allocate_and_trivially_encrypt_new_lwe_ciphertext(big, Plaintext(0u64), modulus);
        let mut idx: Vec<LweCiphertextOwned<u64>> = (0..nbit)
            .map(|_| allocate_and_trivially_encrypt_new_lwe_ciphertext(big, Plaintext(0u64), modulus))
            .collect();
        for i in b * BLOCCO..((b + 1) * BLOCCO).min(n) {
            lwe_ciphertext_add_assign(&mut cnt, &bits[i]);
            let loc = i - b * BLOCCO;
            for j in 0..nbit {
                if (loc >> j) & 1 == 1 {
                    lwe_ciphertext_add_assign(&mut idx[j], &bits[i]);
                }
            }
        }
        cts.push(cnt);
        cts.extend(idx);
    }
    let dati: Vec<&[u64]> = cts.iter().map(|c| c.as_ref()).collect();
    (u64_to_bytes(&[n as u64, nbit as u64, big.0 as u64, BLOCCO as u64], &dati), n)
}
