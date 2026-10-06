"""Exact scalar bit-2 consumer regions; no ciphertext or process execution."""

import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODEL = ROOT / "tmp/a169-low-correction-b0-b1-repair/model.py"
spec = importlib.util.spec_from_file_location("a169_model", MODEL)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
Q = 1 << 64
U = 1 << 52
CANDIDATES = (-1, 0, 1)


def signed_lut(degree):
    degree %= 4096
    selected = int(64 <= degree % 2048 < 192)
    return selected if degree < 2048 else -selected


def runs(values):
    result = []
    for value in values:
        if result and result[-1][1] + 1 == value:
            result[-1][1] = value
        else:
            result.append([value, value])
    return result


def derive(value):
    accepted = []
    for degree in range(4096):
        expected = [int(candidate == 1 and value == 0) for candidate in CANDIDATES]
        predicted = [signed_lut(degree + 128 * candidate) for candidate in CANDIDATES]
        actual = [model.scalar_consumer(degree * U, 2, candidate) for candidate in CANDIDATES]
        if predicted != actual:
            raise ValueError("Independent degree lookup differs from frozen scalar model")
        if predicted == expected:
            accepted.append(degree)
        # Check the exact first/last integer torus word of each rounding cell.
        for phase in ((degree * U - U // 2) % Q, (degree * U + U // 2 - 1) % Q):
            observed = [model.scalar_consumer(phase, 2, candidate) for candidate in CANDIDATES]
            if observed != predicted:
                raise ValueError("Scalar rounding-cell endpoint differs")
    return runs(accepted)


regions = {str(value): derive(value) for value in (0, 1)}
if regions != {"0": [[0, 63], [4032, 4095]], "1": [[320, 1983], [2368, 4031]]}:
    raise ValueError(f"Unexpected exact regions: {regions}")
result = dict(
    status="STATIC_EXACT_SCALAR_REGION_PASS",
    candidates=list(CANDIDATES),
    bit=2,
    level=5,
    source_multiplier=1,
    delta59=1 << 59,
    rounding_unit=U,
    nominal_degrees_by_bit_value=[0, 1024],
    accepted_degree_intervals_inclusive=regions,
    zero_bit_connected_error_torus_interval={"lower_inclusive": -64 * U - U // 2, "upper_exclusive": 64 * U - U // 2},
    set_bit_connected_error_torus_interval={"lower_inclusive": -704 * U - U // 2, "upper_exclusive": 960 * U - U // 2},
    zero_bit_error_interval_in_delta59=["-129/256", "127/256"],
    set_bit_error_interval_in_delta59=["-1409/256", "1919/256"],
    set_bit_native_delta62_error_interval_in_delta59=["-4", "4"],
    set_bit_native_interval_strictly_inside_scalar_region=True,
    checked_degree_centers=8192,
    checked_rounding_cell_endpoints=16384,
    native_set_bit_does_not_guarantee_zero_bit_consumer=True,
    ideal_candidate_and_keyswitch=True,
    coefficientwise_modulus_switch_error_assumed_zero=True,
    actual_composed_pbs=False,
    formal_probability=None,
    source_pins={str(MODEL.relative_to(ROOT)): hashlib.sha256(MODEL.read_bytes()).hexdigest()},
)
with (HERE / "RESULT.json").open("x") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
print(json.dumps({"status": result["status"], "degree_intervals": regions, "actual_composed_pbs": False}))
