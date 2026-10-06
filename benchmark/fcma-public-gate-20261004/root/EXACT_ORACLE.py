#!/usr/bin/env python3
"""Fresh exact oracle for public Neon/FCMA graphs; no float evaluation."""
import argparse
import hashlib
import json
import re
from fractions import Fraction
from pathlib import Path

SOURCE_SHA = "428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29"
SOURCE = Path("/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pulp-0.22.3/src/aarch64.rs")
FIELDS = ("a0", "a1", "b0", "b1", "neon_first", "neon_final", "fcma_first", "fcma_final")
FPCR_MASK = (3 << 22) | (1 << 24) | 3
FRACTION_MASK = (1 << 52) - 1

def require(condition, message):
    if not condition:
        raise ValueError(message)

def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field: " + name)
        result[name] = value
    return result

def power_two(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)

def from_bits(bits):
    exponent, fraction = (bits >> 52) & 2047, bits & FRACTION_MASK
    require(exponent != 2047, "nonfinite binary64")
    mantissa = fraction if exponent == 0 else (1 << 52) + fraction
    value = mantissa * power_two(-1074 if exponent == 0 else exponent - 1075)
    return -value if bits >> 63 else value

def nearest_even(value):
    quotient, remainder = divmod(value.numerator, value.denominator)
    twice = 2 * remainder
    return quotient + int(twice > value.denominator or
                          (twice == value.denominator and quotient & 1))

def to_bits(value):
    if value == 0:
        return 0  # Only numerical zero equivalence is claimed.
    sign = (1 << 63) if value < 0 else 0
    magnitude = abs(value)
    exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
    if magnitude < power_two(exponent):
        exponent -= 1
    if exponent < -1022:
        significand = nearest_even(magnitude * power_two(1074))
        return sign | significand  # 2^52 encodes the minimum normal.
    significand = nearest_even(magnitude * power_two(52 - exponent))
    if significand == 1 << 53:
        significand >>= 1
        exponent += 1
    require(exponent <= 1023, "exact graph rounds to overflow")
    return sign | ((exponent + 1023) << 52) | (significand - (1 << 52))

def rounded(value):
    return from_bits(to_bits(value))

def fma(a, b, c):
    return rounded(a * b + c)

def first(backend, a, b):
    if backend == "neon":
        return (fma(a[0], b[0], rounded(-a[1] * b[1])),
                fma(a[0], b[1], rounded(a[1] * b[0])))
    return (fma(a[1], -b[1], fma(a[0], b[0], Fraction(0))),
            fma(a[1], b[0], fma(a[0], b[1], Fraction(0))))

def mac(backend, a, b, c):
    if backend == "neon":
        return (fma(a[0], b[0], fma(-a[1], b[1], c[0])),
                fma(a[0], b[1], fma(a[1], b[0], c[1])))
    return (fma(a[1], -b[1], fma(a[0], b[0], c[0])),
            fma(a[1], b[0], fma(a[0], b[1], c[1])))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source", type=Path, default=SOURCE)
    args = parser.parse_args()
    data = args.input.read_bytes()
    errors, seen = [], set()
    counts = {"rows_checked": 0, "finite_values_checked": 0,
              "component_checks": 0, "comparison_failures": 0,
              "zero_sign_equivalences": 0, "error_count": 0}
    def record(error):
        counts["error_count"] += 1
        if len(errors) < 8:
            errors.append(error)
    source_sha, fpcr, fpcr_final = None, None, None
    try:
        source_sha = hashlib.sha256(args.source.read_bytes()).hexdigest()
        require(source_sha == SOURCE_SHA, "primary source hash mismatch")
        lines = data.decode("utf-8").splitlines()
        require(len(lines) == 8194, "expected header plus 8192 rows plus completion")
        header = json.loads(lines[0], object_pairs_hook=unique_object)
        require(isinstance(header, dict), "header must be an object")
        require(header.get("kind") == "header" and
                header.get("schema") == "fcma_public_validate_v1", "header schema mismatch")
        fpcr = header.get("fpcr")
        require(type(fpcr) is int and 0 <= fpcr < 1 << 64, "invalid FPCR integer")
        require(fpcr & FPCR_MASK == 0, "FPCR violates RN/gradual/FZ/AH/FIZ premises")
        require(header.get("pulp_source_sha256") == SOURCE_SHA, "header primary hash mismatch")
        require(header.get("cases") == 4 and header.get("elements_per_case") == 2048,
                "header geometry mismatch")
        require(header.get("neon_available") is True and
                header.get("fcma_available") is True, "unsupported or unrecorded factory")
        complete = json.loads(lines[-1], object_pairs_hook=unique_object)
        require(isinstance(complete, dict) and complete.get("kind") == "complete" and
                complete.get("status") == "VALIDATION_DUMP_COMPLETE" and
                complete.get("cases") == 4 and complete.get("rows") == 8192,
                "invalid or missing completion")
        fpcr_final = complete.get("fpcr")
        require(type(fpcr_final) is int and fpcr_final == fpcr, "final FPCR mismatch")
        for line_number, line in enumerate(lines[1:-1], 2):
            try:
                row = json.loads(line, object_pairs_hook=unique_object)
                require(isinstance(row, dict), "sample must be an object")
                case, index = row["case"], row["index"]
                require(type(case) is int and type(index) is int and
                        0 <= case < 4 and 0 <= index < 2048, "invalid case/index")
                require((case, index) not in seen, "duplicate case/index")
                require((case, index) == divmod(line_number - 2, 2048), "sample order mismatch")
                if "kind" in row:
                    require(row["kind"] == "sample", "unexpected sample kind")
                actual, values = {}, {}
                for field in FIELDS:
                    words = row[field]
                    require(type(words) is list and len(words) == 2, "invalid pair: " + field)
                    require(all(type(word) is str and re.fullmatch("[0-9a-f]{16}", word)
                                for word in words), "invalid hex16: " + field)
                    actual[field] = [int(word, 16) for word in words]
                    values[field] = [from_bits(word) for word in actual[field]]
                    counts["finite_values_checked"] += 2
                seen.add((case, index))
                for backend in ("neon", "fcma"):
                    expected = {"first": first(backend, values["a0"], values["b0"]),
                                "final": mac(backend, values["a1"], values["b1"],
                                             values[backend + "_first"])}
                    for stage in ("first", "final"):
                        for component in range(2):
                            observed = actual[backend + "_" + stage][component]
                            predicted = to_bits(expected[stage][component])
                            counts["component_checks"] += 1
                            if observed != predicted:
                                if from_bits(observed) == 0 and from_bits(predicted) == 0:
                                    counts["zero_sign_equivalences"] += 1
                                else:
                                    counts["comparison_failures"] += 1
                                    record({"line": line_number, "case": case, "index": index,
                                            "backend": backend, "stage": stage,
                                            "component": component, "actual": f"{observed:016x}",
                                            "expected": f"{predicted:016x}"})
                counts["rows_checked"] += 1
            except (ValueError, KeyError, TypeError, OverflowError) as error:
                record({"line": line_number, "error": str(error)})
        require(len(seen) == 8192 and counts["rows_checked"] == 8192, "incomplete coverage")
        require(counts["finite_values_checked"] == 131072 and
                counts["component_checks"] == 65536, "incomplete primitive checks")
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, OverflowError) as error:
        record({"error": str(error)})
    receipt = {"schema": "fcma_exact_oracle_v1",
               "status": "PASS" if counts["error_count"] == 0 else "FAIL",
               "input_sha256": hashlib.sha256(data).hexdigest(), **counts,
               "unique_rows": len(seen), "fpcr": fpcr, "fpcr_final": fpcr_final,
               "fpcr_rejected_mask": FPCR_MASK, "primary_source_sha256": source_sha,
               "errors": errors, "errors_limit": 8, "actual_first_used_for_final": True,
               "zero_semantics": "+0/-0 numerically equivalent; no zero-sign bit claim",
               "scope": "public same-operand graph only; no FFT/FHE/full-BR/performance claim"}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    return 0 if receipt["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
