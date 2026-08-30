// Microbenchmark della SELEZIONE cifrata in tfhe-rs (radix, API ad alto livello).
//
// Cosa misura: il costo dell'argmin + soglia sul vincitore quando i punteggi sono gia' in forma
// radix (FheUint8 = 4 blocchi da 2 bit, bastano 8 bit per il ranking, F36; FheUint16 = 8 blocchi,
// la larghezza intera del punteggio). Vettori casuali della precisione reale, come nel metodo
// dei microbenchmark dell'incontro: la correttezza (verificata) non conta, la complessita' si'.
//
// Le varianti, nell'ordine del "percorso" per la tesi:
//   seq-F32   catena di N-1 confronti come nell'head-to-head (lt + min + select dell'indice)
//   seq       stessa catena senza il `min` ridondante (il select basta: 1 confronto, 2 select)
//   torneo    albero a eliminazione, profondita' log2 N, confronti di ogni livello in parallelo
//             (rayon; ogni thread ha la sua copia della server key)
//   +soglia   il confronto in piu' sul vincitore (esito match/no-match, mai la distanza)
// e due set di parametri (128 bit): il default (KS-PBS, TUniform) e il multi-bit (group 3),
// il PBS pensato da Zama per il multicore. Il numero di thread lo decide RAYON_NUM_THREADS.
//
//   cargo run --release --bin selezione            (tutti i core)
//   RAYON_NUM_THREADS=1 cargo run --release --bin selezione
use rayon::prelude::*;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16, FheUint8};

const NS: [usize; 5] = [8, 16, 32, 64, 128];

fn lcg(s: &mut u64) -> u64 {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *s >> 33
}

fn argmin_clear(p: &[u64]) -> usize {
    let mut b = 0;
    for i in 1..p.len() {
        if p[i] < p[b] {
            b = i;
        }
    }
    b
}

macro_rules! bench_tipo {
    ($t:ty, $sc:ty, $nome:expr, $bits:expr, $ck:expr, $etichetta:expr) => {{
        let mut s = 20260830u64;
        for &n in &NS {
            let vals: Vec<u64> = (0..n).map(|_| lcg(&mut s) % (1u64 << $bits)).collect();
            let enc: Vec<$t> = vals.iter().map(|&v| <$t>::try_encrypt(v, $ck).unwrap()).collect();
            let triv = |i: usize| <$t>::try_encrypt_trivial(i as u64).unwrap();
            let atteso = argmin_clear(&vals);
            let soglia = (vals[atteso] + (1u64 << ($bits - 3))) as $sc; // sotto soglia: match

            // --- seq-F32: lt + min + select (come experiments/13, F32) ---
            let t0 = Instant::now();
            let mut minv = enc[0].clone();
            let mut mini = triv(0);
            for i in 1..n {
                let c: FheBool = enc[i].lt(&minv);
                mini = c.if_then_else(&triv(i), &mini);
                minv = enc[i].min(&minv);
            }
            let t_seq_f32 = t0.elapsed().as_secs_f64();
            let d: u64 = mini.decrypt($ck); let ok1 = d as usize == atteso;

            // --- seq: lt + select del valore + select dell'indice ---
            let t0 = Instant::now();
            let mut minv = enc[0].clone();
            let mut mini = triv(0);
            for i in 1..n {
                let c: FheBool = enc[i].lt(&minv);
                minv = c.if_then_else(&enc[i], &minv);
                mini = c.if_then_else(&triv(i), &mini);
            }
            let t_seq = t0.elapsed().as_secs_f64();
            let d: u64 = mini.decrypt($ck); let ok2 = d as usize == atteso;

            // --- torneo: livelli in parallelo ---
            let t0 = Instant::now();
            let mut lvl: Vec<($t, $t)> = enc.iter().enumerate().map(|(i, v)| (v.clone(), triv(i))).collect();
            while lvl.len() > 1 {
                lvl = lvl
                    .par_chunks(2)
                    .map(|ch| {
                        if ch.len() == 2 {
                            let (v0, i0) = &ch[0];
                            let (v1, i1) = &ch[1];
                            let c: FheBool = v1.lt(v0); // strict: a parita' vince il primo (indice minore)
                            (c.if_then_else(v1, v0), c.if_then_else(i1, i0))
                        } else {
                            ch[0].clone()
                        }
                    })
                    .collect();
            }
            let t_tor = t0.elapsed().as_secs_f64();
            let (win_v, win_i) = lvl.pop().unwrap();
            let d: u64 = win_i.decrypt($ck); let ok3 = d as usize == atteso;

            // --- soglia sul vincitore: un confronto scalare in piu' ---
            let t0 = Instant::now();
            let m: FheBool = win_v.le(soglia);
            let t_sog = t0.elapsed().as_secs_f64();
            let ok4 = m.decrypt($ck) == (vals[atteso] <= soglia as u64);

            println!(
                "{:>9} | {:>3} | {:>9.2}s | {:>8.2}s | {:>8.2}s | {:>7.3}s | {}",
                $etichetta, n, t_seq_f32, t_seq, t_tor, t_sog,
                if ok1 && ok2 && ok3 && ok4 { "OK" } else { "ERRATO" }
            );
        }
        let _ = $nome;
    }};
}

fn main() {
    let threads = rayon::current_num_threads();
    println!("thread rayon: {threads}\n");
    println!("{:>9} | {:>3} | {:>10} | {:>9} | {:>9} | {:>8} | esito", "param", "N", "seq-F32", "seq", "torneo", "+soglia");

    // 1) parametri di default (KS-PBS, TUniform, 128 bit)
    let (ck, sk) = generate_keys(ConfigBuilder::default().build());
    set_server_key(sk.clone());
    rayon::broadcast(|_| set_server_key(sk.clone()));
    bench_tipo!(FheUint8, u8, "FheUint8", 8, &ck, "def/u8");
    bench_tipo!(FheUint16, u16, "FheUint16", 14, &ck, "def/u16");

    // 2) parametri multi-bit (group 3), il PBS per il multicore
    let cfg = ConfigBuilder::with_custom_parameters(V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64).build();
    let (ck, sk) = generate_keys(cfg);
    set_server_key(sk.clone());
    rayon::broadcast(|_| set_server_key(sk.clone()));
    bench_tipo!(FheUint8, u8, "FheUint8", 8, &ck, "mb3/u8");
    bench_tipo!(FheUint16, u16, "FheUint16", 14, &ck, "mb3/u16");
}
