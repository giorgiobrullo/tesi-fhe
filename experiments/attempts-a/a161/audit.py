"""Light pinned-source assertions and symbolic call counts; no linked TFHE calls."""

import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    text = {}
    for name, pin in pins.items():
        raw = Path(pin["path"]).read_bytes()
        need(
            hashlib.sha256(raw).hexdigest() == pin["sha256"], "source changed: " + name
        )
        text[name] = raw.decode()
    return text


def check():
    s = sources()
    need("let (s1, _) = <(f64, f64)>::generate_one" in s["gaussian"], "scalar discard")
    need("fn fill_slice" not in s["gaussian"], "Gaussian specialization changed")
    dynamic = s["dispatch"].split("RandomGenerable<DynamicDistribution<T>> for T", 1)[1]
    need("fn fill_slice" not in dynamic, "dynamic scalar fill specialization changed")
    need(
        "*s = Self::generate_one(generator, distribution);" in s["dispatch"],
        "default scalar loop",
    )
    need(
        "Scalar::fill_slice(self, distribution, output);" in s["random_generator"],
        "generic fill",
    )
    need(
        "output.chunks_mut(2).for_each" in s["random_generator"], "separate paired API"
    )
    need(
        "for a in uniform_rand_bytes_u.iter_mut()" in s["gaussian"],
        "first candidate word",
    )
    need(
        "for a in uniform_rand_bytes_v.iter_mut()" in s["gaussian"],
        "second candidate word",
    )
    need(
        "implement_gaussian!(f64, i64);" in s["gaussian"], "16-byte candidate geometry"
    )
    need(
        "self.0.next_byte().unwrap()" in s["random_generator"],
        "exhaustion remains failure",
    )
    need(
        "fill_slice_with_random_noise_from_distribution_custom_mod"
        in s["glwe_encryption"],
        "GLWE generic route",
    )
    need(
        "random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus)"
        in s["lwe_encryption"],
        "LWE scalar route",
    )
    need(
        ".try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))"
        in s["lwe_encryption"],
        "bounded per-row fork",
    )
    need("EncryptionNoiseSampleCount(1)" in s["lwe_entity"], "one row noise sample")
    need(
        ".rev()" in s["ksk_generation"]
        and "encrypt_lwe_ciphertext_list(" in s["ksk_generation"],
        "descending-level row list",
    )
    pattern = s["standard_pattern"]
    need(
        pattern.index("engine.new_bootstrapping_key")
        < pattern.index("allocate_and_generate_new_lwe_keyswitch_key("),
        "BSK precedes KSK",
    )
    need(
        "let noise_iter = self" in s["encryption_generator"]
        and ".zip(noise_iter)" in s["encryption_generator"],
        "separate mask/noise fork",
    )
    need(
        "self.block_cipher.clone()" in s["aes_ctr"]
        and "self.state = new_parent_state;" in s["aes_ctr"],
        "fork reuses cipher and advances parent",
    )
    need("Seed(u128::generate_one" in s["deterministic_seeder"], "derived seed width")
    need(
        "SecretRandomGenerator::new(deterministic_seeder.seed())" in s["engine"],
        "engine secret seed",
    )
    need(
        "NoiseRandomGenerator::new(seeder)" in s["encryption_generator"],
        "separate noise seed draw",
    )
    harness = s["u10_harness"]
    need(
        "noise: DynamicDistribution<u64>" in harness, "actual generic distribution type"
    )
    need("encrypt_glwe_ciphertext(" in harness, "actual packed query function")
    need(
        "EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder)"
        in harness,
        "fresh query generator",
    )
    need(
        "PER_SAMPLE_TARGET_FAILURE_PROBABILITY_LOG2: f64 = -128."
        in s["encryption_generator"],
        "allocation target constant",
    )
    # Source-form arithmetic transcription only: not an accepted finite-law failure bound.
    attempts = math.ceil(-128.0 / math.log2(1.0 - math.pi / 4.0))
    need(attempts == 58, "source-form reservation transcription changed")
    return dict(
        status="PINNED_SOURCE_CALLGRAPH_AND_SYNTHETIC_MODEL_ONLY",
        source_files=len(s),
        actual_generic_query_route="one accepted pair per scalar; second discarded",
        actual_generic_ksk_route="one accepted pair per LWE row; second discarded",
        query_coefficients_per_encryption=2048,
        query_accepted_pairs_per_encryption=2048,
        query_mask_bytes_per_encryption=2048 * 8,
        query_minimum_noise_bytes_per_encryption=2048 * 16,
        ksk_rows=2048 * 5,
        ksk_levels_stored=[5, 4, 3, 2, 1],
        ksk_mask_bytes_reserved_per_row=859 * 8,
        source_formula_attempt_allowance_per_row=attempts,
        source_formula_noise_bytes_reserved_per_row=attempts * 16,
        library_formula_uses_success_probability="pi/4; allocation model, not verified finite-sampler law",
        linked_rust_reservation_value_observed=False,
        actual_sampler_executed=False,
        compiled_float_enclosure_established=False,
        finite_csprng_statistical_independence_established=False,
        actual_pipeline_p_fail=None,
    )


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
