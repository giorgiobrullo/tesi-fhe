// Head-to-head del 100x: lo STESSO match 1:N cifrato (prodotto scalare + argmin) in tfhe-rs
// (TFHE nativo, Rust) e in Concrete-python, sulla stessa macchina (M4 Max). Replica il circuito
// `seq_fn` di experiments/10_argmin_struttura/bench_struttura.py: DIM=64, valori in [-Q,Q],
// punteggio p_i = ||g_i||^2 - 2 (g_i . a) (enc x plaintext, niente PBS), poi argmin sequenziale
// (catena di N-1 confronti con min + select dell'indice). Punteggi signed a ~10 bit: uso
// FheInt16, che ha PIU' bit dei ~9-10 di Concrete, quindi semmai e' conservativo verso tfhe-rs.
// Stampa il tempo del prodotto scalare, dell'argmin, e verifica l'indice contro il chiaro.
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};

const DIM: usize = 64;
const Q: i64 = 2;

// LCG deterministico (no Date/rand): stessi dati a ogni run.
fn lcg(s: &mut u64) -> i64 {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((*s >> 33) % (2 * Q as u64 + 1)) as i64 - Q
}

fn gallery(n: usize) -> (Vec<Vec<i64>>, Vec<i64>) {
    let mut s = 12345u64;
    let mut g = vec![vec![0i64; DIM]; n];
    let mut bsq = vec![0i64; n];
    for i in 0..n {
        for j in 0..DIM {
            let v = lcg(&mut s);
            g[i][j] = v;
            bsq[i] += v * v;
        }
    }
    (g, bsq)
}

fn argmin_clear(g: &[Vec<i64>], bsq: &[i64], a: &[i64]) -> usize {
    let mut best = 0usize;
    let mut bestv = i64::MAX;
    for i in 0..g.len() {
        let dot: i64 = (0..DIM).map(|j| g[i][j] * a[j]).sum();
        let p = bsq[i] - 2 * dot;
        if p < bestv {
            bestv = p;
            best = i;
        }
    }
    best
}

fn main() {
    let config = ConfigBuilder::default().build();
    let t0 = Instant::now();
    let (ck, sk) = generate_keys(config);
    println!("keygen {:.1}s\n", t0.elapsed().as_secs_f64());
    set_server_key(sk);

    let mut s = 999u64;
    let a: Vec<i64> = (0..DIM).map(|_| lcg(&mut s)).collect();
    let enc: Vec<FheInt16> = a.iter().map(|&v| FheInt16::encrypt(v as i16, &ck)).collect();

    println!("{:>3} | {:>12} | {:>10} | {:>7} | esito", "N", "dot+argmin", "argmin", "confr.");
    for &n in &[4usize, 8, 16, 32, 64] {
        let (g, bsq) = gallery(n);

        // --- prodotto scalare cifrato: p_i = bsq_i - 2*(g_i . a), enc x plaintext ---
        let t_s = Instant::now();
        let mut p: Vec<FheInt16> = Vec::with_capacity(n);
        for i in 0..n {
            let mut acc = &enc[0] * (g[i][0] as i16);
            for j in 1..DIM {
                acc += &enc[j] * (g[i][j] as i16);
            }
            p.push(acc * (-2i16) + (bsq[i] as i16));
        }
        let dt_score = t_s.elapsed().as_secs_f64();

        // --- argmin sequenziale: N-1 confronti, min(valore) + select(indice) ---
        let t_a = Instant::now();
        let mut minv = p[0].clone();
        let mut mini = FheInt16::try_encrypt_trivial(0i16).unwrap();
        for i in 1..n {
            let cond: FheBool = p[i].lt(&minv);
            let ie = FheInt16::try_encrypt_trivial(i as i16).unwrap();
            mini = cond.if_then_else(&ie, &mini);
            minv = p[i].min(&minv);
        }
        let dt_arg = t_a.elapsed().as_secs_f64();

        let idx: i16 = mini.decrypt(&ck);
        let exp = argmin_clear(&g, &bsq, &a);
        let ok = idx as usize == exp;
        println!(
            "{:>3} | {:>11.2}s | {:>9.2}s | {:>7} | {}",
            n,
            dt_score + dt_arg,
            dt_arg,
            n - 1,
            if ok { "OK" } else { "ERRATO" }
        );
    }
}
