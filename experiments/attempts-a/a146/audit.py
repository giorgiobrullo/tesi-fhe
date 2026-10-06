"""Read pinned cached sources and emit a bounded exact/source-only report."""

import argparse
import hashlib
import json
from pathlib import Path

import model

HERE = Path(__file__).resolve().parent


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    sources = {}
    for pin in pins:
        path = Path(pin["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != pin["sha256"]:
            raise ValueError("frozen source changed: " + str(path))
        sources[path.name] = path.read_text()
    cm = sources["cm_modulus_switch_noise_reduction.rs"]
    assert cm.count("Scalar::ZERO,") == 2  # base/candidate measures ignore lane bodies.
    assert (
        "mask_sum," in cm
        and "cm_lwe_ciphertext_add_assign(lwe, &encryption_of_zero);" in cm
    )
    assert (
        "#[cfg(test)]" in cm
        and "CandidateResult::BestNotSatisfyingBound(candidate) => candidate" in cm
    )
    assert "CenteredMeanNoiseReduction" not in cm
    core = sources["modulus_switch_noise_reduction.rs"]
    assert "let expectancy = body_error - sum_mask_errors / 2_f64;" in core
    assert "let variance = sum_square_mask_errors / 4_f64;" in core
    assert "let std_dev = (variance + input_variance.value).sqrt();" in core
    encryption = sources["cm_lwe_encryption.rs"]
    assert "slice_wrapping_dot_product(output_mask.as_ref(), sk.as_ref())" in encryption
    assert ".zip_eq(output_bodies.iter_mut())" in encryption
    assert ".wrapping_add(noise)" in encryption
    kernel = sources["cm_bootstrap.rs"]
    assert "modulus_switch((*body.data).cast_into(), log_modulus)" in kernel
    assert "modulus_switch((*lwe_mask_element).cast_into(), log_modulus)" in kernel
    a132 = sources["crypto.rs"]
    assert (
        "Plain public wrapper, with NO implicit CM noise-reduction key/application."
        in a132
    )
    assert (
        "programmable_bootstrap_cm_lwe_ciphertext(input, &mut output, lut, &key.cm_fbsk);"
        in a132
    )
    assert "improve_lwe_ciphertext_modulus_switch_noise_for_binary_key_cm(" not in a132
    assert "cm_lwe_ciphertext_count" not in a132
    profile = (
        sources["cm_params.rs"]
        .split("pub const CM_PARAM_4_2_MINUS_64:")[1]
        .split("\n};")[0]
    )
    for text in [
        "CmDimension(4)",
        "LweDimension(772)",
        "PolynomialSize(512)",
        "CmLweCiphertextCount(1515)",
        "Variance(3.11402591442555e-5)",
        "RSigmaFactor(9.16364588440807)",
        "NoiseEstimationMeasureBound(1152921504606846976.0)",
    ]:
        assert text in profile
    return len(pins)


def report():
    return dict(
        status="SOURCE_AND_EXACT_ALGEBRA_ONLY",
        source_pins=verify_sources(),
        scheme="shared zero-candidate selection/addition, NOT CenteredMeanNoiseReduction",
        viable_representation_adapter=True,
        estimator_budget_for_a132_established=False,
        examples=model.examples(),
        next_gate="New A132 execution successor: source/typecheck in a clear window, stock fresh-zero API smoke, then paired no-CMNR/CM-zero-reduction one-key N4 C1 with every corrected BR input observed",
        cargo=False,
        typecheck=False,
        library_execution=False,
        fhe_execution=False,
        sampled_noisy_counterexample=False,
        catalog_probability_transferred=False,
        performance_claim=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = report()
    if args.output:
        with args.output.open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
    print(json.dumps(result, indent=2))


if not __debug__:
    raise RuntimeError("A146 requires assertions enabled")
if __name__ == "__main__":
    main()
