"""Bounded independent public arithmetic/source audit; no frozen model import."""
from pathlib import Path
import hashlib
import itertools
import json

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
EXPECTED_MANIFEST = "2713035029dc76cf06625c5fe252de6de612d04e392af4a2a2fb99e23e264c97"
Q, U, DELTA = 1 << 64, 1 << 52, 1 << 59


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def degree(word):
    quotient, remainder = divmod(word % Q, U)
    return (quotient + (remainder >= U // 2)) % 4096


def ternary(deg):
    deg %= 4096
    if 64 <= deg <= 1983:
        return 1
    if 2112 <= deg <= 4031:
        return -1
    return 0


def control(deg):
    return 12 if deg % 4096 < 2048 else 4


def check():
    assert sha(BASE / "MANIFEST.json") == EXPECTED_MANIFEST
    files = json.loads((BASE / "MANIFEST.json").read_text())["files"]
    for name, expected in files.items():
        assert sha(BASE / name) == expected, name
    pins = json.loads((BASE / "SOURCE_PINS.json").read_text())["files"]
    for name, expected in pins.items():
        assert sha(Path(name)) == expected, name
    for d in range(-15, 16):
        assert ternary(degree(d * DELTA)) == (d > 0) - (d < 0)
    for signs in itertools.product((-1, 0, 1), repeat=3):
        weighted = 4 * signs[0] + 2 * signs[1] + signs[2]
        first = next((x for x in signs if x), 0)
        assert ((weighted > 0) - (weighted < 0)) == first
        assert control(degree(weighted * DELTA - DELTA // 2)) == (12 if first > 0 else 4)
    assert control(degree(0)) == 12  # Missing half-offset loses tie-left.
    witnesses = []
    mask_sum = 128 * (U // 2 - 1)
    for phase in (0, -DELTA // 2, 12 * DELTA):
        body = (phase + mask_sum) % Q
        actual_phase = (body - mask_sum) % Q
        address = degree(body)  # Every nonzero mask word rounds to zero.
        assert actual_phase == phase % Q
        assert (address - degree(actual_phase)) % 4096 == 64
        witnesses.append([degree(actual_phase), address])
    assert witnesses == [[0, 64], [4032, 0], [1536, 1600]]
    assert ternary(witnesses[0][1]) == 1
    assert control(witnesses[1][1]) == 12
    # Each right-window center is 1536+128*lane, support radius63.
    # At +64 every lane falls in an empty midpoint, including the final ID lane.
    for lane in range(4):
        point = 1600 + 128 * lane
        assert all(abs(point - (1536 + 128 * center)) >= 64 for center in range(4))
    ledger = {"comparator": [0, 4, 4, 4], "D1": [4, 1, 1, 4], "direct_D2": [8, 1, 1, 4], "scalar_D2": [8, 4, 4, 4]}
    assert [sum(row[i] for row in ledger.values()) for i in range(4)] == [20, 10, 10, 16]
    return dict(
        status="PASS_BOUNDED_INDEPENDENT_A186_MATH_INTERFACE_REVIEW",
        frozen_manifest_sha256=EXPECTED_MANIFEST,
        frozen_leaves_verified=len(files),
        source_and_metadata_pins_verified=len(pins),
        independent_public_checks=dict(ternary_difference_centers=31, ternary_patterns=27, coefficient_MS_witnesses=3, right_window_hole_lanes=4),
        primitive_order=["PFKS", "ordinary_KS", "BR", "sample_extractions"],
        independent_ledger=ledger,
        total=[20, 10, 10, 16],
        id_delta_log=56,
        actual_upstream_bridge=False,
        actual_comparator_executed=False,
        actual_raw_logs_or_binary_read=False,
        full_test_suite_rerun=False,
        frozen_files_modified=False,
        remainder_notation="R_j=sum_i s_i(a_i-a_hat_i); native same-modulus body copied unchanged; K_j=-sum d_i,l eta_i,l",
        blocking_math_issue=False,
        conditional_scope_preserved=True,
    )


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
