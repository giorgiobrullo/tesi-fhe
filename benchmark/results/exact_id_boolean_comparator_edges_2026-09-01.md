# Regressione storica degli estremi exact-ID con comparatore Booleano

> **Storico: revisione a 5.166/5.196 PBS, precedente all'hardening finale.** I quattro smoke e i
> conteggi qui sotto restano misure valide del circuito eseguito, ma questa revisione conservava il
> selettore accoppiato e alcuni riscalamenti poi rimossi. Non e' il riferimento del core corrente.
> La regressione mirata del core post-fix e' in
> `fhe_digiface_exact_noise_bounded_targeted_2026-09-01.md`; lo stato canonico e' in
> `../../README.md` e `../../status.md`, e la cronologia tecnica in
> `exact_id_noise_hardening_2026-09-01.md`.

Data: 1 settembre 2026. Host: Apple M4 Max, 16 thread Rayon. Libreria: tfhe-rs 0.11.3,
parameter set `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Circuito provato

La revisione misurata applicava i primi tre hardening senza cambiare il contratto applicativo:

1. ricostruzione bitwise del codice `indice+1`, con al massimo otto componenti finali;
2. selezione dei 12 bit della soglia del vincitore e dei due sentinel mediante masked OR reduction
   con refresh;
3. confronto `min<=threshold` come macchina Booleana MSB-first, con PBS su somme non pesate di al
   massimo tre bit al posto dello stato ternario pesato.

Il server restituiva un solo LWE: `0=rifiuto`, `i+1=identita' accettata`.

Comando:

```sh
RAYON_NUM_THREADS=16 target/release/argmin_bucket_bits_periodic \
  --run --keys 1 --sizes 127,128 --cases edges --real-probes 1 --allow-slow
```

`--allow-slow` disabilita soltanto il gate storico sotto 10 secondi; non modifica circuito,
oracolo o controllo di correttezza.

## Risultati

| N | caso | codice atteso | codice osservato | PBS attesi/osservati | tempo core | sotto 10 s |
|---:|---|---:|---:|---:|---:|---|
| 127 | soglia strict del vincitore, altri permissivi | 0 | 0 | 5.166 / 5.166 | 15,216195 s | no |
| 127 | vincitore spostato nell'ultimo template | 127 | 127 | 5.166 / 5.166 | 14,262328 s | no |
| 128 | soglia strict del vincitore, altri permissivi | 0 | 0 | 5.196 / 5.196 | 12,675771 s | no |
| 128 | vincitore spostato nell'ultimo template | 128 | 128 | 5.196 / 5.196 | 11,975856 s | no |

Tutti i quattro risultati coincidono con l'oracolo clear (`all_correct=true`). Nessuno dei quattro
resta sotto il gate storico di latenza (`all_under_10s=false`). I tempi sono osservazioni del run,
non un bound e non un benchmark controllato in isolamento dal carico della macchina.

## Fingerprint dello stato misurato

I fingerprint seguenti sono stati rilevati nel workspace immediatamente dopo il run:

| artefatto | SHA-256 |
|---|---|
| `src/private_argmin.rs` | `91d3470dc089f277000d4f78047a9a96d29351c0ed0025c9c177c2684b9e5862` |
| `src/bin/argmin_bucket_bits_periodic.rs` | `6013701391a3a98109e253cc911f82b9079df57b9cadc5f4683c053b782583f8` |
| binario release | `784c9a403916e344113277a187fe975cf2d893935ddb00cb0fb209c6c8764892` |
| `Cargo.toml` | `bdd7e63b67fbcd7a6326248bed09daf33e30f95a7873b44fff37b591261a634a` |
| `Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` e Cargo 1.97.1.

## Limite

Il run verificava i sentinel di rifiuto, tutti i sette bit del codice 127, l'ottavo bit del codice
128 e la capacita' massima di quella revisione. Restavano fuori da un bound composto i fan-in
custom, i riscalamenti della selezione, la sottrazione non rinfrescata dei winner e la somma finale
a `Delta=2^55`; gli hardening successivi hanno rimosso questi percorsi, ma richiedono evidenza di
validazione separata.
