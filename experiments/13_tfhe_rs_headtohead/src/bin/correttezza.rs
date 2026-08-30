// Test di correttezza dell'argmin cifrato in tfhe-rs.
//
// Il dubbio a cui risponde: "il 100x di tfhe-rs e' reale, o e' veloce perche' l'argmin e'
// implementato male e per certi valori sbaglia?". TFHE e' aritmetica ESATTA (a differenza di
// CKKS, che approssima): l'unico modo di sbagliare e' l'overflow del bit-width. Qui lo
// escludiamo empiricamente: verifichiamo che l'indice del minimo calcolato SOTTO CIFRATURA
// coincida con quello in chiaro, su molti vettori casuali e su casi avversari.
//
// Isola l'argmin (la primitiva non lineare in discussione): i punteggi sono cifrati
// direttamente, senza passare dal prodotto scalare (enc x plaintext, leveled, gia' verificato
// dall'head-to-head in main.rs). Stessa catena dell'head-to-head: lt + if_then_else + min,
// FheInt16. Tie-break: vince il primo minimo (strict <), identico in chiaro e cifrato.
//
// Esecuzione:  cargo run --release --bin correttezza

use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};

// argmin in chiaro con la STESSA semantica della catena cifrata: strict <, vince il primo.
fn argmin_clear(p: &[i64]) -> usize {
    let mut best = 0usize;
    let mut bestv = p[0];
    for i in 1..p.len() {
        if p[i] < bestv {
            bestv = p[i];
            best = i;
        }
    }
    best
}

// argmin cifrato: identico a main.rs (lt + if_then_else + min).
fn argmin_enc(p: &[FheInt16]) -> FheInt16 {
    let mut minv = p[0].clone();
    let mut mini = FheInt16::try_encrypt_trivial(0i16).unwrap();
    for i in 1..p.len() {
        let cond: FheBool = p[i].lt(&minv);
        let ie = FheInt16::try_encrypt_trivial(i as i16).unwrap();
        mini = cond.if_then_else(&ie, &mini);
        minv = p[i].min(&minv);
    }
    mini
}

// LCG deterministico (no rand/Date): riproducibile a ogni run.
fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 33
}

// costruisce i casi avversari per una data N.
fn avversari(n: usize) -> Vec<(Vec<i64>, &'static str)> {
    let mut v = Vec::new();
    v.push((vec![7i64; n], "tutti uguali"));
    {
        let mut p = vec![100i64; n];
        p[0] = -5;
        p[n / 2] = -5; // pareggio al minimo -> deve vincere il primo (idx 0)
        v.push((p, "pareggio al minimo"));
    }
    v.push(((0..n as i64).collect(), "crescente"));
    v.push(((0..n as i64).rev().collect(), "decrescente"));
    {
        let mut p = vec![50i64; n];
        p[n - 1] = -1000; // min in coda
        v.push((p, "min in coda"));
    }
    {
        let mut p = vec![50i64; n];
        p[0] = -1000; // min in testa
        v.push((p, "min in testa"));
    }
    v.push((
        (0..n).map(|i| if i % 2 == 0 { -1 } else { 1 }).collect(),
        "alternato",
    ));
    v
}

fn main() {
    let (ck, sk) = generate_keys(ConfigBuilder::default().build());
    set_server_key(sk);

    // range dei punteggi: quello reale alla config del head-to-head (~10-12 bit signed),
    // uno largo, e uno agli estremi di FheInt16 per escludere ogni overflow.
    let ranges: [(i64, i64, &str); 3] = [
        (-2048, 2047, "12-bit"),
        (-16000, 16000, "largo"),
        (i16::MIN as i64 + 1, i16::MAX as i64, "estremo"),
    ];
    let sizes = [4usize, 8, 16, 32];
    let per_config = 15usize; // probe casuali per (N, range)

    let mut tot = 0usize;
    let mut ko = 0usize;
    let mut s = 20260722u64;
    let t0 = Instant::now();

    for &n in &sizes {
        // --- casuali, su tutti i range ---
        for &(lo, hi, rname) in &ranges {
            let span = (hi - lo + 1) as u64;
            for _ in 0..per_config {
                let p: Vec<i64> = (0..n).map(|_| lo + (lcg(&mut s) % span) as i64).collect();
                let enc: Vec<FheInt16> =
                    p.iter().map(|&x| FheInt16::encrypt(x as i16, &ck)).collect();
                let idx: i16 = argmin_enc(&enc).decrypt(&ck);
                let exp = argmin_clear(&p);
                tot += 1;
                if idx as usize != exp {
                    ko += 1;
                    println!("  ERRATO  N={n} range={rname}  atteso={exp} avuto={idx}  p={p:?}");
                }
            }
        }
        // --- avversari ---
        for (p, nome) in avversari(n) {
            let enc: Vec<FheInt16> = p.iter().map(|&x| FheInt16::encrypt(x as i16, &ck)).collect();
            let idx: i16 = argmin_enc(&enc).decrypt(&ck);
            let exp = argmin_clear(&p);
            tot += 1;
            if idx as usize != exp {
                ko += 1;
                println!("  ERRATO(avv: {nome})  N={n}  atteso={exp} avuto={idx}  p={p:?}");
            }
        }
        println!(
            "N={n:>2}: {tot} test cumulati, {ko} errati   [{:.0}s]",
            t0.elapsed().as_secs_f64()
        );
    }

    println!("\n=== {tot} test totali | {} corretti | {ko} errati ===", tot - ko);
    if ko == 0 {
        println!("OK: l'argmin cifrato tfhe-rs coincide col chiaro su TUTTI i casi (nessun overflow, nessun errore).");
    } else {
        println!("ATTENZIONE: {ko} discrepanze, vedi sopra.");
    }
}
