# Helper FCMA: sorgente pronta, non compilata

4 ottobre 2026. Due wrapper a nome conservato, `neon_update` e `fcma_update`, accettano rispettivamente il token Neon/NeonFcma e usano `Simd::vectorize` con lo stesso `WithSimd`. Non costruiscono token unchecked. Prima della vectorize controllano output/lhs2048 complessi e rhs1024; due chunk da1024, un complesso per elemento SIMD. Il booleano First resta dinamico.

I loop sono il boundary letterale di TFHE-rs1.8.1 `src/core_crypto/fft_impl/fft64/crypto/ggsw.rs:650–674`: First sovrascrive con `mul_c64s`, MAC aggiorna con `mul_add_c64s`. Qui `zip` è sufficiente perché i controlli fissano le tre lunghezze e la lane count1. Nessuna coda è ignorata. Nessun FFT/KS/key/GLWE o nuova interpretazione di digit è incluso.

Pulp0.22.3 primario: `src/aarch64.rs:1024–1039,1099–1114` per Neon, `:2069–2073,2102–2103` e helper inline-asm `:6–53` per FCMA. `:1394–1407,2346–2359` lega i rispettivi token al WithSimd. I grafi First/MAC e l'ordine di arrotondamento restano diversi: questo caller non promette equivalenza bit per bit o correttezza di una pipeline cifrata.

Cargo richiede pulp `=0.22.3` con default/std, release opt3/cgu1/ltofalse. Il lockfile è di proprietà del root: l'autore non lo crea o modifica; risoluzione/cache/build restano compiti del root. Nessuna compilation, rustfmt, test o esecuzione svolta dall'autore.

`main` ammette soltanto `--capabilities`, conserva gli indirizzi dei wrapper attraverso black_box e stampa un JSON con feature Rust e risultati delle factory checked. Non chiama i wrapper, non alloca array di operandi, non misura tempi. Factory entrambe disponibili→exit0; unsupported→exit1 dopo JSON; argomenti errati→exit2 senza JSON. Compilazione limitata a aarch64.

I due simboli possono contenere thunk verso specializzazioni prodotte da vectorize: il successivo audit codegen deve seguire soltanto destinazioni univocamente legate al wrapper, senza contare il thunk come corpo aritmetico. Non confrontare naïvely i conteggi di questo caller fisso con ogni ramo del servizio generic-dispatch. Presenza di FCMLA o meno istruzioni statiche non è una misura della latenza; l'inline asm può cambiare scheduling/register allocation.

Fonti direttamente lette/hashate (registry locale `/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`): pulp0.22.3 `src/aarch64.rs` SHA256 `428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29`; `src/lib.rs` `847f58ab06d89dc93684116b67c19c1f486acab56726ef5a3566bae01bfb0145`; `Cargo.toml` `b9d9fe17a5a2188b06a704d5810b4b68b82474816d238f2442501495abb1e4df`. TFHE1.8.1 ggsw source `d2cf985c055b55627ce1e9714e404862a71e6aec7c8b459293c9bcbb67a1d956`, boundary già letto nella fase V e riletto per questo helper. Nessun vecchio modello C3–C34/A77, payload o runtime mantenuto modificato.
