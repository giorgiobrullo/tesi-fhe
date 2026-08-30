// Quanto costa un PBS "largo"? Il costo unitario del ponte leveled -> radix.
//
// Il ponte dovrebbe leggere le cifre di un punteggio a 13-14 bit: serve un PBS la cui LUT risolva
// tutti quei bit. tfhe-rs offre set validati a 128 bit fino a 8 bit di precisione (message 8,
// carry 0: N=32768, 2 livelli); oltre non ci sono parametri validati, e Concrete a 13-14 bit paga
// 1,5-4 s a PBS (F33). Qui misuriamo, sulla stessa macchina, il PBS a 2+2 bit (il nostro, N=2048)
// e quello a 8 bit (N=32768), con una LUT identita' verificata su tutti i valori del dominio.
//
//   cargo run --release --bin pbs_largo
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
                                 V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                                 V0_11_PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64, ClassicPBSParameters};
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

fn misura(nome: &str, p: ClassicPBSParameters) {
    let t0 = Instant::now();
    let cks = ClientKey::new(p);
    let sks = ServerKey::new(&cks);
    let t_key = t0.elapsed().as_secs_f64();
    let (enc_key, noise) = cks.encryption_key_and_noise();
    let ksk = &sks.key_switching_key;
    let fbsk = match &sks.bootstrapping_key { ShortintBootstrappingKey::Classic(k) => k, _ => panic!() };
    let modulus = CiphertextModulus::<u64>::new_native();
    let big = enc_key.lwe_dimension().to_lwe_size();
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let (poly, glwe) = (fbsk.polynomial_size(), fbsk.glwe_size());
    let bits = (p.message_modulus.0 * p.carry_modulus.0).trailing_zeros();
    let delta = 1u64 << (63 - bits);                                   // padding + 'bits' bit di messaggio
    let acc = generate_programmable_bootstrap_glwe_lut(poly, glwe, 1usize << bits, modulus, delta, |v| v);
    let mut boxed = new_seeder(); let seeder = boxed.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut ok = 0usize; let mut tot = 0f64; let n_val = 1usize << bits;
    for v in 0..n_val as u64 {
        let ct = allocate_and_encrypt_new_lwe_ciphertext(&enc_key, Plaintext(v * delta), noise, modulus, &mut gen);
        let t0 = Instant::now();
        let mut ks = LweCiphertext::new(0u64, small, modulus);
        keyswitch_lwe_ciphertext(ksk, &ct, &mut ks);
        let mut out = LweCiphertext::new(0u64, big, modulus);
        programmable_bootstrap_lwe_ciphertext(&ks, &mut out, &acc, fbsk);
        tot += t0.elapsed().as_secs_f64();
        let dec = (decrypt_lwe_ciphertext(&enc_key, &out).0.wrapping_add(delta >> 1)) >> (63 - bits);
        ok += (dec == v) as usize;
    }
    let bsk_mb = sks.bootstrapping_key_size_bytes() / (1 << 20);
    println!("{:>22} | {:>2} bit | N={:>5} n={:>4} l={} | keygen {:>5.1}s | KS+PBS {:>7.1} ms | chiave bootstrap {:>5} MB | LUT identita' esatta {}/{}",
             nome, bits, poly.0, small.to_lwe_dimension().0, p.pbs_level.0, t_key, 1000.0 * tot / n_val as f64, bsk_mb, ok, n_val);
}

fn main() {
    println!("un thread per PBS (single-thread), M4 Max\n");
    misura("MESSAGE_2_CARRY_2 (nostro)", V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    misura("MESSAGE_8_CARRY_0", V0_11_PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64);
    misura("MESSAGE_4_CARRY_4", V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64);
    println!("\nIl ponte vorrebbe 13-14 bit: nessun set validato in tfhe-rs; Concrete li paga 1,5-4 s a PBS (F33).");
}
