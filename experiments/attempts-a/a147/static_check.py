"""Pinned-source and exact synthetic evidence only; never runs Rust or processes."""

import hashlib
import inspect
import json
from pathlib import Path
import model as m

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    pins = json.loads((ROOT / "SOURCE_PINS.json").read_text())
    for pin in pins:
        path = Path(pin["path"])
        assert sha(path) == pin["sha256"], path
        lines = path.read_text().splitlines()
        for fragment in pin["fragments"]:
            assert fragment["text"] in lines[fragment["line"] - 1]
    source = (ROOT / "src/lib.rs").read_text()
    production, tests = source.split("#[cfg(test)]", 1)
    measure = production.split("pub fn measure_key_rows(", 1)[1].split(
        ") -> ClientRowSamples", 1
    )[0]
    assert "payload" not in measure and "output:" not in measure
    predict = production.split("pub fn predict(", 1)[1].split(") -> Prediction", 1)[0]
    assert "actual_pfks_output" not in predict
    assert (
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext("
        not in production
    )
    assert "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(" in tests
    assert "let level = levels - level_index;" in production
    assert "decomposer.decompose(rounded)" in production
    assert "row_index + 1 == rows" in production and "u64::MAX" in production
    assert "fn phase(&self, ciphertext: &[u64], target: isize)" in production
    assert "Serialize" not in production.replace("Debug/Serialize", "")
    assert "payload" not in inspect.signature(m.measure).parameters
    assert "output" not in inspect.signature(m.measure).parameters
    secret, out_secret = [1, 0], [[1, 0, 1, 1, 0, 0, 1, 0]]
    poly = [1, 1, 0, 0, 0, 0, 0, -1]
    kernel = [1, 0, 0, 0, 0, 0, 0, 0]
    rows, eta = m.synthetic_key(secret, out_secret, 1, poly, 8, 2)
    samples = m.measure(rows, secret, out_secret, 1, poly, kernel, [0], 8, 2)
    ct = [(3 << 56) + (5 << 48), (11 << 56) + (13 << 48), (7 << 56) + (17 << 48)]
    output = m.pfks_ciphertext(rows, ct, 8, 2)
    predicted = m.contract(samples, [ct], [0])
    observed = m.observed_aggregate(output, ct, secret, out_secret, samples, 0)
    assert predicted["modular"] == observed
    corrupt = output.copy()
    corrupt[-8] ^= 1
    mutated = m.observed_aggregate(corrupt, ct, secret, out_secret, samples, 0)
    assert observed != mutated
    wrong = m.measure(rows, secret, out_secret, -1, poly, kernel, [0], 8, 2)
    wrong_predicted = m.contract(wrong, [ct], [0])["modular"]
    wrong_observed = m.observed_aggregate(output, ct, secret, out_secret, wrong, 0)
    assert wrong_predicted == wrong_observed
    assert wrong.errors[0, 1, 0] != eta[0, 1][0] & m.MASK
    result = {
        "status": "SOURCE_AND_EXACT_SYNTHETIC_ONLY",
        "source_pins": len(pins),
        "synthetic_row_contraction": {
            k: v for k, v in predicted.items() if k != "coefficients"
        },
        "synthetic_observed_aggregate": observed,
        "mutated_output_aggregate": mutated,
        "coherent_wrong_function_counterexample": {
            "prediction_equals_residual": wrong_predicted == wrong_observed,
            "true_row_eta": eta[0, 1][0],
            "mislabeled_row_eta_centered": m.centered(wrong.errors[0, 1, 0]),
            "conclusion": "closure does not authenticate functional-key plaintext or noise calibration",
        },
        "a137_first_gate_cost_model": {
            "row_levels": 2049,
            "one_target_scalar_products_per_key_row": 4096,
            "one_target_total_scalar_products": 2049 * 4096,
            "not_measured_seconds_or_peak_memory": True,
        },
        "client_row_data": "synthetic values only saved here; actual samples stay client memory",
        "linked_rust_test": "NOT_RUN",
        "fresh_key_measurements": "NOT_RUN",
        "tails": "OPEN",
        "covariance": "NOT_ASSUMED",
        "source_sha256": sha(ROOT / "src/lib.rs"),
    }
    (ROOT / "artifacts/result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run()
