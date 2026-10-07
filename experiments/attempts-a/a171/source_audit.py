"""Read-only source/pin checks. No child process, Cargo, FHE or runtime log reads."""

import hashlib
import json
from pathlib import Path
import replay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ORIGIN = ROOT / "tmp/a137-pfks-runtime-error-observer"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit():
    replay.source_check()
    before = (ORIGIN / "src/main.rs").read_text()
    after = (HERE / "candidate/src/main.rs").read_text()
    preserved = {}
    for first, last in [
        ("fn signed_cell_mask(", "fn packed_selector_masks("),
        ("fn packed_selector_masks(", "fn a30_scalar_selector_masks("),
        ("fn a30_scalar_selector_masks(", "fn polynomial_fft_wrapping_mul"),
        ("fn polynomial_fft_wrapping_mul", "fn scalar_d2_select_tuple("),
        ("fn scalar_d2_select_tuple(", "fn packed_d2_select("),
        ("fn packed_d2_select(", "fn hash_lwe("),
        ("fn direct_window_d2_select(", "/// Exact effective phase"),
        ("fn effective_rotation_degree(", "fn emit("),
    ]:
        old = before[before.index(first) : before.index(last)]
        new = after[after.index(first) : after.index(last)]
        replay.eq(new, old, "frozen helper bytes " + first)
        preserved[first] = hashlib.sha256(old.encode()).hexdigest()
    replay.eq(
        (HERE / "candidate/src/observer.rs").read_bytes(),
        (ORIGIN / "src/observer.rs").read_bytes(),
        "whole original observer",
    )
    for name in ["Cargo.toml", "Cargo.lock"]:
        original = (
            (ORIGIN / name)
            .read_text()
            .replace("a137_pfks_runtime_error_observer", "a171_pfks_d1_component")
        )
        replay.eq(
            (HERE / "candidate" / name).read_text(),
            original,
            "root package-name-only " + name,
        )
    d1 = (HERE / "candidate/src/d1.rs").read_text()
    select = d1[
        d1.index("pub(super) fn select(") : d1.index("pub(super) fn arm_order(")
    ]
    observer = d1[d1.index("pub(super) fn observe(") :]
    for call in [
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(",
        "keyswitch_lwe_ciphertext(",
        "blind_rotate_assign(",
        "extract_lwe_sample_from_glwe_ciphertext(",
    ]:
        replay.eq(
            select.count(call), 1, "single source callsite with fixed loop " + call
        )
        replay.eq(observer.count(call), 0, "observer has no server crypto " + call)
    replay.need(
        "word.wrapping_sub(l)" in select and "word.wrapping_add(l)" in select,
        "actual ring subtraction/addback",
    )
    replay.need(
        "(RIGHT_CONTROL as usize + lane) * BOX_SIZE" in select, "right-window rotation"
    )
    replay.need(
        "mod observer;" in after and "mod d1;" in after, "distinct observer modules"
    )
    return dict(
        schema="a171.source-readiness.v1",
        status="PASS_STATIC_SOURCE_ONLY",
        preserved_source_regions=preserved,
        original_observer_byte_identical=True,
        tfhe="0.11.3",
        offline_lockfile_resolution_run=False,
        compiled=False,
        real_fhe_run=False,
        count_per_fixture=dict(PFKS=28, KS=7, BR=7, samples=16),
        count_per_first_process=dict(PFKS=224, KS=56, BR=56, samples=128),
        count_per_full_three_processes=dict(PFKS=672, KS=168, BR=168, samples=384),
        raw_records_per_first_process=322,
        distinct_functional_key_families=2,
        functional_key_rows_each=2049,
        functional_key_levels=1,
        functional_key_bytes_each=67141632,
        original_five_rust_tests_retained_but_not_run=True,
        new_python_tests="13 synthetic checks; all 4064 fixture/lane/interior-address combinations",
        independent_runtime_envelope_ready=False,
        actual_p_fail=None,
        paired_performance_claim=False,
    )


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
