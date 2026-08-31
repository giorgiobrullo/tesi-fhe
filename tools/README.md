# tools/ldfix — far girare Concrete su macOS

Concrete-python invoca `ld` con `-L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib`,
percorso che su questa macchina non esiste: l'SDK sta dentro `Xcode.app`. Il link fallisce con
`ld: library 'System' not found` e **qualunque** compilazione FHE va in errore. Per mesi abbiamo
creduto che Concrete non fosse utilizzabile sul Mac (vedi F25/F32) e i benchmark Concrete sono
stati fatti sull'home server Linux — che è anche il motivo per cui i confronti Concrete/tfhe-rs
NON erano a parità di macchina.

Non è un limite di Concrete: è un percorso sbagliato. Il wrapper qui sotto sostituisce quel `-L`
con l'SDK vero (`xcrun --show-sdk-path`) e chiama il linker di sistema. Niente modifiche a
`/Library`, niente sudo, reversibile: basta togliere la directory dal PATH.

    PATH=$(pwd)/tools/ldfix:$PATH uv run python benchmark/breakdown_query.py

Verifica rapida che funzioni:

    PATH=$(pwd)/tools/ldfix:$PATH uv run python -c "
    from concrete import fhe; import numpy as np
    @fhe.compiler({'x':'encrypted'})
    def f(x): return x + 1
    print(f.compile([np.int64(i) for i in range(-8,8)]).encrypt_run_decrypt(3))"   # -> 4
