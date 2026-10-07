"""Correlation-aware ledger and source-port arithmetic. No FHE or tail estimate."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q = 1 << 64
DELTA = 1 << 59
U = 1 << 52


def signed(word):
    word %= Q
    return word - Q if word >= Q // 2 else word


def load_source(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for item in pins:
        if (
            hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest()
            != item["sha256"]
        ):
            raise ValueError("source drift: " + item["path"])
    binding = json.loads((HERE / "SOURCE_BINDING.json").read_text())
    for key, filename in [
        ("main_sha256", "src/main.rs"),
        ("source_pins_sha256", "SOURCE_PINS.json"),
        ("lockfile_sha256", "Cargo.lock"),
    ]:
        if hashlib.sha256((HERE / filename).read_bytes()).hexdigest() != binding[key]:
            raise ValueError("harness binding drift: " + filename)
    return len(pins)


@dataclass(frozen=True)
class Expression:
    terms: dict[str, int]
    offset: int = 0

    @staticmethod
    def atom(identity):
        return Expression({identity: 1})

    def scale(self, coefficient):
        if type(coefficient) is not int:
            raise TypeError("exact integer scale required")
        return Expression(
            {
                atom: coefficient * value
                for atom, value in self.terms.items()
                if coefficient * value
            },
            coefficient * self.offset,
        )

    def add(self, other):
        terms = dict(self.terms)
        for atom, value in other.terms.items():
            terms[atom] = terms.get(atom, 0) + value
            if terms[atom] == 0:
                del terms[atom]
        return Expression(terms, self.offset + other.offset)

    def observe(self, values):
        # Missing primitive-row values remain missing rather than being inferred individually.
        return signed(
            self.offset
            + sum(
                coefficient * values[atom] for atom, coefficient in self.terms.items()
            )
        )

    def summary(self):
        serialized = json.dumps(
            {"terms": self.terms, "offset": str(self.offset)},
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "atoms": len(self.terms),
            "l1": sum(map(abs, self.terms.values())),
            "squared_l2": sum(c * c for c in self.terms.values()),
            "offset_torus": str(self.offset),
            "expression_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
            "first_atoms": sorted(self.terms.items())[:8],
        }


def psd(matrix):
    """Exact rational Schur complements; zero diagonal needs a zero row."""
    matrix = [row[:] for row in matrix]
    while matrix:
        if matrix[0][0] < 0:
            return False
        if matrix[0][0] == 0:
            if any(matrix[0][1:]):
                return False
            matrix = [row[1:] for row in matrix[1:]]
            continue
        pivot = matrix[0][0]
        matrix = [
            [
                matrix[i][j] - matrix[i][0] * matrix[0][j] / pivot
                for j in range(1, len(matrix))
            ]
            for i in range(1, len(matrix))
        ]
    return True


def variance(expression, covariance):
    """No missing covariance is replaced by zero; offsets do not supply a mean law."""
    atoms = sorted(expression.terms)
    if not atoms:
        return {
            "status": "EXACT_ALGEBRAIC_VARIANCE",
            "variance": "0",
            "mean_torus": str(expression.offset),
        }
    missing = [a for a in atoms if (a, a) not in covariance]
    if missing:
        return {
            "status": "OPEN",
            "missing_marginal_variances": len(missing),
            "covariance_not_assumed_zero": True,
            "mean_or_bias_certified": False,
        }
    matrix = []
    for a in atoms:
        row = []
        for b in atoms:
            if (a, b) not in covariance:
                return {
                    "status": "OPEN",
                    "missing_covariance": [a, b],
                    "covariance_not_assumed_zero": True,
                    "mean_or_bias_certified": False,
                }
            value = Fraction(covariance[(a, b)])
            if (b, a) in covariance and value != Fraction(covariance[(b, a)]):
                raise ValueError("asymmetric covariance")
            row.append(value)
        matrix.append(row)
    if not psd(matrix):
        raise ValueError("covariance matrix is not positive semidefinite")
    weights = [expression.terms[a] for a in atoms]
    result = sum(
        weights[i] * weights[j] * matrix[i][j]
        for i in range(len(atoms))
        for j in range(len(atoms))
    )
    return {
        "status": "CONDITIONAL_ON_SUPPLIED_COVARIANCE",
        "variance": str(result),
        "mean_or_bias_certified": False,
        "tail_certified": False,
    }


def rms_bound(expression, radii):
    """Minkowski on externally justified RMS bounds, not library variances."""
    if any(atom not in radii for atom in expression.terms):
        return {"status": "OPEN", "reason": "missing externally justified RMS bound"}
    bounds = {atom: Fraction(value) for atom, value in radii.items()}
    if any(value < 0 for value in bounds.values()):
        raise ValueError("negative RMS bound")
    result = abs(expression.offset) + sum(
        abs(c) * bounds[a] for a, c in expression.terms.items()
    )
    return {
        "status": "CONDITIONAL_RMS_BOUND",
        "rms_torus_bound": str(result),
        "tail_certified": False,
    }


def ks_rows(words, key_id, decompose):
    # Original big-LWE body is copied by KS, not decomposed into a KSK body row.
    terms = {}
    for row, word in enumerate(words[:-1]):
        for level, digit in decompose(word):
            if digit:
                terms[f"KSK/{key_id}/row/{row}/level/{level}"] = -digit
    return Expression(terms)


def formulas():
    """Direct source port of cached generated formulas; not execution of the library."""
    q = float(Q)
    n, big, base, levels = 859.0, 2048.0, 8.0, 5.0

    def minimum(dim):
        return 2 ** (4.0 - 2.88539008177793 * math.log(q)) + 2 ** (
            5.31469187675068 - 0.0497829131652661 * dim
        )

    ks = levels * big * minimum(n) * (base**2 / 12.0 + 0.166666666666667) + big * (
        0.0208333333333333 * q**-2 + 0.0416666666666667 * base ** (-2 * levels)
    )
    ks += -(q**-2) / 12.0 + q**-2 / 12.0
    address = 4096.0
    ms = (
        n * (0.0208333333333333 * q**-2 + 0.0416666666666667 * address**-2)
        - q**-2 / 12.0
        + address**-2 / 12.0
    )
    base, levels, k, size, mantissa = float(1 << 23), 1.0, 1.0, 2048.0, 53.0
    exponent = (
        2 * max(0.0, -mantissa + math.log2(math.e) * math.log(q))
        + 2.88539008177793 * math.log(base)
        - 2.88539008177793 * math.log(q)
    )
    fft = (
        0.00705
        * 2**exponent
        * levels**1.01827
        * k**1.22003
        * size**2.22003
        * (k + 1) ** 1.01827
    )
    key = (
        levels
        * size
        * minimum(k * size)
        * (base**2 / 12.0 + 0.166666666666667)
        * (k + 1)
    )
    rounding = (
        -(q**-2) / 24.0
        + 0.5
        * k
        * size
        * (0.0208333333333333 * q**-2 + 0.0416666666666667 * base ** (-2 * levels))
        + base ** (-2 * levels) / 24.0
    )
    pbs = n * (fft + key + rounding)
    return {
        "scope": "Python port of source formulas; Rust library harness NOT_RUN",
        "variance_unit": "normalized original torus",
        "ks_additive_variance": ks,
        "ms_additive_variance": ms,
        "ms_total_variance": ks + ms,
        "pbs_marginal_model_variance": pbs,
        "minimal_small_key_calibration_variance": minimum(n),
        "minimal_glwe_key_calibration_variance": minimum(k * size),
        "a44_small_sigma_squared": 2.3088161607134664e-6**2,
        "a44_glwe_sigma_squared": 2.845267479601915e-15**2,
        "132_bits_meaning": "security/noise calibration, not a p_fail exponent",
        "raw_a133_bound": "OPEN",
        "p_fail_claimed": False,
    }


def a133_tools():
    validator = load_source(
        ROOT / "tmp/a133-a126-runtime-noise-witness/validate.py", "_a141_a133_validator"
    )
    pins = validator.sources()
    geometry = validator.a131()
    body = struct.unpack(
        "<2048Q",
        (
            ROOT
            / "tmp/a133-a126-runtime-noise-witness/artifacts/fused_candidate_zero_body.u64le"
        ).read_bytes(),
    )
    return validator, pins, geometry, body


def adapt_event(event, tools=None):
    validator, pins, geometry, body = tools or a133_tools()
    checks = validator.validate_event(event, pins, body, geometry)
    cts = event["ciphertexts"]
    registry = {}
    values = {}

    def semantic(name, expected, producer):
        ct = cts[name]
        identity = "CT/" + ct["domain"] + "/" + ct["ciphertext_id"]
        phase = int(ct["client_observed_phase_torus"])
        expected %= Q
        if identity not in registry:
            registry[identity] = {
                "reference_expected_torus": expected,
                "phase": phase,
                "producers": [producer],
            }
            values[identity] = signed(phase - expected)
        else:
            if registry[identity]["phase"] != phase:
                raise ValueError(
                    "one ciphertext ID has contradictory phase observations"
                )
            registry[identity]["producers"].append(producer)
        # Reference centers are fixed oracle plaintexts, not random actual-address LUT values.
        offset = signed(registry[identity]["reference_expected_torus"] - expected)
        return Expression({identity: 1}, offset)

    previous = semantic(
        "previous_candidate", event["state"] * DELTA, "previous candidate aggregate"
    )
    bit = semantic("positive_b3", event["positive_b3"] * DELTA, "positive b3")
    input_error = previous.add(bit.scale(6))
    if input_error.observe(values) != int(event["input"]["signed_error_torus"]):
        raise ValueError("input adapter identity")
    samples = event["raw_samples"]
    sample0 = semantic(
        "raw_sample0",
        int(samples[0]["expected_torus"]),
        event["producer_id"] + "/sample/0",
    )
    sample768 = semantic(
        "raw_sample768",
        int(samples[1]["expected_torus"]),
        event["producer_id"] + "/sample/768",
    )
    any_error = semantic(
        "any_zero_level4",
        event["immediate_update"]["expected_any_zero"] * DELTA,
        "level4 OR root",
    )
    update = sample0.add(sample768).add(any_error.scale(-1))
    if update.observe(values) != int(event["immediate_update"]["signed_error_torus"]):
        raise ValueError("update adapter identity")
    words = [int(x, 16) for x in cts["input"]["words_u64le_hex"]]
    rows = ks_rows(words, event["key_id"], geometry.decomposition)
    # These corrections are known for this observation, but random/correlated across draws.
    # Do not turn them into unconditional deterministic offsets or independent fresh noise.
    ks_remainder_id = (
        "KS-rounding/" + event["key_id"] + "/" + cts["input"]["ciphertext_id"] + "/3x5"
    )
    ms_rounding_id = (
        "MS-rounding/"
        + cts["post_ks_consumed_by_br"]["domain"]
        + "/"
        + cts["post_ks_consumed_by_br"]["ciphertext_id"]
    )
    small_error = input_error.add(Expression.atom(ks_remainder_id)).add(rows)
    address_numerator = small_error.add(Expression.atom(ms_rounding_id))
    values[ks_remainder_id] = int(event["ks"]["decomposition_remainder_lift_torus"])
    values[ms_rounding_id] = int(
        event["modulus_switch"]["rounding_correction_lift_torus"]
    )
    return {
        "event_id": event["event_id"],
        "source": "validated A133 client diagnostic; execution attestation OPEN",
        "observed_checks": checks,
        "input_expression": input_error.summary(),
        "update_expression": update.summary(),
        "input_variance": variance(input_error, {}),
        "update_variance": variance(update, {}),
        "ks_row_expression": rows.summary(),
        "small_error_expression": small_error.summary(),
        "address_numerator_expression": address_numerator.summary(),
        "ks_row_aggregate_constraint": {
            "observed_value_torus": event["ks"][
                "inferred_aggregate_row_contribution_torus"
            ],
            "primitive_row_values_available": False,
            "shared_key_id": event["key_id"],
        },
        "rounding_observations_torus": {
            ks_remainder_id: str(values[ks_remainder_id]),
            ms_rounding_id: str(values[ms_rounding_id]),
        },
        "rounding_is_not_assumed_independent": True,
        "atoms_with_shared_ciphertext": {
            identity: {
                "reference_expected_torus": str(item["reference_expected_torus"]),
                "client_observed_phase_torus": str(item["phase"]),
                "producers": item["producers"],
            }
            for identity, item in registry.items()
        },
        "raw_pair": {
            "producer_id": event["producer_id"],
            "degrees": [s["degree"] for s in samples],
            "covariance": "OPEN",
            "identical_errors_assumed": False,
            "independence_assumed": False,
            "actual_ideal_errors_torus": [
                s["signed_error_to_actual_ideal_torus"] for s in samples
            ],
            "semantic_errors_torus": [
                s["signed_error_to_expected_torus"] for s in samples
            ],
        },
        "observed_input_error_torus": str(input_error.observe(values)),
        "observed_update_error_torus": str(update.observe(values)),
        "library_pbs_variance_attached_to_actual_atoms": False,
        "missing_prior_candidate_expansion": "A133 records previous candidate aggregate, not all pre-fusion update marginals",
        "bias_or_tail_certified": False,
        "p_fail_claimed": False,
    }
