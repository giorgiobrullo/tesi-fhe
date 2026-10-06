# Modulus switch: operazione distinta, contratto ancora mancante

4 ottobre 2026. Solo audit della sorgente TFHE-rs **1.8.1** e dell'adattatore mantenuto; nessun run, chiave o parametro nuovo. Il probe encoding55 respinto resta distinto dalla baseline59 funzionante.

**Esiste un'operazione diversa dal semplice centraggio:** `DriftTechniqueNoiseReduction`. `CenteredMeanNoiseReduction` applica una correzione pubblica del body calcolata dagli errori di arrotondamento della mask, inclusa la correzione half-case; non cerca mask alternative (core `modulus_switch.rs`, 35–101). Non è qui verificata l'identità bit per bit con il nostro mean-only.

Il drift prova invece l'input invariato e l'input sommato, separatamente, a ciascuna cifratura di zero della chiave ausiliaria. Sceglie il primo candidato che soddisfa il criterio, oppure il migliore trovato. Poi applica il modulus switch ordinario (core `modulus_switch_noise_reduction.rs`, 99–195, 229–239; shortint omonimo, 102–117). È calcolo pubblico CPU su ciphertext, senza BR aggiuntiva nella routine stessa; non è rumore nullo o costo nullo.

Il criterio sorgente è `abs(mu) + r_sigma * sqrt(V + input_variance_modular)` (core, 44–85): `mu` è errore arrotondato del body meno metà della somma degli errori della mask; `V` è un quarto della loro somma dei quadrati. Gli errori e il bound sono nelle unità del modulo nativo, non direttamente in gradi. Le premesse configurabili sono numero di zeri, `ms_bound`, `ms_r_sigma_factor`, `ms_input_variance` (shortint parameters/mod.rs, 785–800). **Non misura l'errore effettivo sotto il segreto fissato.** Inoltre il wrapper accetta anche `BestNotSatisfyingBound`: l'assert del raggiungimento del bound esiste solo sotto `cfg(test)` (core, 223–231).

Servono nuove cifrature di zero sotto **lo stesso piccolo segreto binario 859**, con lo stesso modulo nativo e una distribuzione di rumore dichiarata; il costruttore le genera normalmente (shortint, 167–205). La routine impone stessa dimensione/modulo e almeno uno zero (core, 112–136). Restituisce il medesimo tipo di input switched per BR: non impone un nuovo ring o una diversa Classic BSK. Ma `W/runtime/core/src/compat.rs` 54–60 respinge configurazioni non-Standard, e 86–95 forza Standard: conservarne/applicarne il drift richiederebbe un'integrazione esplicita.

**Esito:** operazione distinta e interfaccia dimensionalmente possibile; nessun contratto parametrizzato qui disponibile che garantisca **±3** per la combinazione55 dopo KS. Occorre giustificare input variance, rumore degli zeri, fattore statistico, bound nelle unità corrette e comportamento senza candidato valido. La conformance confronta campi/dimensione/conteggio, non prova quelle premesse (shortint, 47–78). Nessun trasferimento automatico del p-fail di catalogo o proposta di nuova campagna segue dall'API. Audit terminato a questo confine.

## Fonti effettivamente lette e SHA256

T=`/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.8.1`; W=`/workspace/maintained`. Hash dei file completi; letture delle routine citate.

| File | SHA256 |
| --- | --- |
| T/src/shortint/server_key/modulus_switch_noise_reduction.rs | `d5e5ed7c23f5a09033854b3492d81db3245fb3795f1a52c0219be6301efe81e7` |
| T/src/core_crypto/algorithms/modulus_switch_noise_reduction.rs | `97e8a9d0e7e785b6efc62cefb202b45cdca9ed796792a41109818c04750f9a2a` |
| T/src/core_crypto/algorithms/modulus_switch.rs | `d6db1e94476fb89fea9c823242ef6be12f3908be426903e5ff05a6aa48aa1345` |
| T/src/shortint/parameters/mod.rs | `1c5014cc027c73f0aeefcecd2496e364a13e5378d2317bea00c7c9a646623049` |
| W/runtime/core/src/compat.rs | `d6565c7b69a9774a92505ffe6c2303b284e8ba810b91fb6cf6a7d84690fbb633` |
