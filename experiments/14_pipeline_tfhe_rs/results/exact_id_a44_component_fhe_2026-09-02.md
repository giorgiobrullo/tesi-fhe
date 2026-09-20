# A44 max-15 two-LWE exact ID: component FHE validation (2026-09-02)

## Result

A44 is now component-FHE-validated on macOS arm64 with the pinned TFHE-rs 0.11.3 preset
`V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`. It combines two previously separate
repairs without changing the exact-identification contract:

- the A41 terminal representation returns two p16 LWEs and reconstructs
  `code = low + 16*high`;
- the A44 parameter retune raises the nominal `max_noise_level` from 5 to 15, so the modeled raw
  peak 10 no longer exceeds the advertised numeric ceiling;
- `0` remains rejection and `i+1` remains the first nearest accepted identity.

The executed parameter binding was:

```text
params_id=tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64
fingerprint_sha256=b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1
message_modulus=2, carry_modulus=8, max_noise_level=15, log2_p_fail=-64.088
```

## Executed validation

The source passed 9/9 Python geometry/noise tests, standalone Rust formatting, 19/19 active
release library tests, release harness compilation, a locked/offline build, and the exact dry-plan
binding. The compiled binary was then executed in three independently recorded suites:

| suite | key blocks | FHE evaluations | result |
|---|---:|---:|---|
| small | 1 | 21 | 21/21 pass |
| focused N=127/128 | 3 | 12 | 12/12 pass |
| complete | 3 | 87 | 87/87 pass |
| total | **7** | **120** | **120/120 pass** |

Every invocation generated fresh in-memory keys and declared that no secret material was
persisted. The log can attest that declaration and the repeated parameter binding; it cannot prove
memory erasure.

The A63 read-only gate independently parsed every record and failed closed on unknown fields,
wrong fixture order, parameter drift, incomplete key blocks, wrong counts, reconstruction errors,
or failure markers. Its required-full result is `PASS`.

## Exact-ID boundary coverage

The complete suite ran the same 29 fixtures on three independent keys. It covered all p16 high
categories, accepted/rejected threshold boundaries, rejection, first and last identity, and
interior/tail ties. Every one of the 87 results satisfied `code=low+16*high`.

| gallery | blind rotations | key switches | conservative output marginals |
|---:|---:|---:|---:|
| 127 | 3,655 | 3,274 | 4,206 |
| 128 | 3,682 | 3,298 | 4,237 |

Selected full-suite timing diagnostics across the three keys were:

| fixture | median | range |
|---|---:|---:|
| N=64, last identity | 4.057869 s | 3.136109--4.497486 s |
| N=127, last identity | 7.712354 s | 6.585761--8.018827 s |
| N=128, last identity | 6.758987 s | 6.588368--8.242917 s |
| N=127, first identity | 6.562034 s | 6.242795--9.968762 s |
| N=127, interior tie at 64 | 6.282661 s | 6.055405--8.833253 s |
| N=128, tail tie at 127 | 6.696113 s | 6.200539--8.145606 s |

The host was under high unrelated load and these are component fixtures, not a paired service
benchmark. They demonstrate execution and order of magnitude only; they do not establish an
A41/A44 speed difference.

## Data

[Machine-readable component result](exact_id_a44_component_gate_2026-09-02.json).
The standalone prototype and full validation program are not included.

## Implementation results and remaining limits

A44 closes the two concrete local defects identified for A38 at the implementation level:

1. there is no final `Delta=2^56` ciphertext sum; and
2. the largest modeled raw L1 value, 10, is below the selected preset's maximum 15 without margin
   rescaling.

It still does **not** provide a nontrivial end-to-end cryptographic failure bound. A60 establishes
that the current raw `core_crypto` path does not carry the `NoiseLevel` provenance enforced by the
checked shortint/integer APIs. Therefore

```text
4206 * 2^-64.088 = 2^-52.049766865268
```

is conditional arithmetic, not an unconditional query bound. The only presently defensible
unconditional statement for the raw graph is `p_fail <= 1`. A Gaussian tail for the initial score,
the raw-LUT transfer, correlated extraction accounting, and an authenticated serialized parameter
envelope remain open.

A44 is consequently a validated fast candidate and a stronger engineering repair than A38/A41,
but it is not promoted. A claim-safe reference path using genuine checked integer/shortint
ciphertexts is the next formal control; service serialization, primary DigiFace, Docker, and a
scene-paired performance gate are also still required.
