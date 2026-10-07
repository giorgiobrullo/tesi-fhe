"""Authorized read-only replay of exact terminal A187 identities; no execution."""

import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
A187 = HERE.parents[1]
SOURCE = "24aa2671670b7f7f2896ae4f062be0dded177b002f8c9cf2507be59281c67f3b"
ARTIFACT = "2552f2512a26df7ae704f1a5667cf57ed4576bf07185bbb864d81ace2b9fe42f"
BINARY = "2ce1593394263bf4ae1e612c610a1bef8391a0f79c7bca0b550ad9ada1ade7ac"
RAW = "a0e1ce76b2c7e038bb00111fde909da8ad3645db1ede5590d74645da1c7db432"
ROOT_REPORT = "0ab5a372db160fdd23d472676c9918e94aac16c23b2cdaede5f1d2c4b9a93966"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def preimport_check():
    manifest_bytes = (A187 / "MANIFEST.json").read_bytes()
    need(sha(manifest_bytes) == ARTIFACT, "root-pinned frozen artifact")
    manifest = json.loads(manifest_bytes)
    need(manifest["source_id"] == SOURCE, "root-pinned actual source")
    for name, expected in manifest["files"].items():
        need(sha((A187 / name).read_bytes()) == expected, "pre-import source " + name)
    need(sha((A187 / "SOURCE_MANIFEST.json").read_bytes()) == SOURCE, "source manifest")
    return len(manifest["files"])


def save(name, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    fd = os.open(
        HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(HERE, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(data)


def main():
    leaves = preimport_check()
    sys.path.insert(0, str(A187))
    import run_gate as b
    import verify as frozen
    import replay as r

    b.private(HERE, True)
    root_path = A187 / "artifacts/first-precision-validation.json"
    b.private(root_path)
    root_bytes = root_path.read_bytes()
    r.eq(sha(root_bytes), ROOT_REPORT, "captured saved root report")
    root = r.parse(root_bytes)
    # This is the unmodified body of frozen verify.verify, retaining the same
    # captured record objects for additional summaries without rereading raw.
    records, binding = frozen.envelope(b.RUN)
    for field, expected in dict(
        child_pid=14819,
        driver_pid=14818,
        binary_sha256=BINARY,
        exit_code=0,
        source_id=SOURCE,
        artifact_sha256=ARTIFACT,
        started_at_utc="2026-09-05T09:00:30.580604+00:00",
        exited_at_utc="2026-09-05T09:00:34.243148+00:00",
    ).items():
        r.eq(binding[field], expected, "independent expected " + field)
    r.eq(binding["files_sha256"]["stdout.jsonl"], RAW, "exact expected raw bytes")
    fresh = r.replay(records, binding["binary_sha256"], binding["exit_code"])
    fresh["launch_binding"] = binding
    fresh["local_direct_child_record_binding"] = True
    fresh_hash = save("fresh-validation.json", fresh)
    r.eq(fresh, root, "saved root report matches fresh independent replay")
    r.eq(fresh_hash, ROOT_REPORT, "byte-identical canonical report")
    cursor = 2
    event_details = []
    for arm, count in enumerate((63, 71, 71)):
        events = records[cursor : cursor + count]
        cursor += count + 1
        bad = [
            dict(
                stage=e["stage"],
                address=e["actual_ms_address"],
                expected_lut_word=e["expected_lut_word"],
                actual_lut_word=e["lut_word_at_actual_address"],
            )
            for e in events
            if not e["exact_preimage_pass"]
        ]
        event_details.append(
            dict(
                arm=r.ARMS[arm],
                events=count,
                preimage_failures=len(bad),
                first_failed_preimage=bad[0] if bad else None,
                stock_degree_formula_failures=sum(
                    not e["stock_degree_formula_match"] for e in events
                ),
                coefficient_closure_failures=sum(
                    not r.coefficients.verify_event(e)["coefficient_closure_pass"]
                    for e in events
                ),
            )
        )
    r.eq(cursor, 210, "complete fixed event/case partition")
    result = dict(
        schema="a187-independent-terminal-first-review-v1",
        status="INDEPENDENT_VALID_A187_FIRST_PASS",
        gate_pass=fresh["gate_pass"],
        frozen_artifact_leaves_verified=leaves,
        source_manifest_sha256=SOURCE,
        artifact_manifest_sha256=ARTIFACT,
        binary_sha256=BINARY,
        raw_sha256=RAW,
        root_saved_validation_sha256=ROOT_REPORT,
        fresh_validation_sha256=fresh_hash,
        exact_saved_report_matches=True,
        direct_child=binding,
        fixture_index=2,
        scores=[255, 256, 254, 4095],
        keysets=1,
        records=211,
        events=205,
        reports=fresh["reports"],
        event_details=event_details,
        ledger=dict(
            BR=205,
            KS=205,
            sample_extractions=213,
            input_glwe_encryptions=1,
            public_glwe_products=4,
            input_samples=8,
            pbs_output_samples=205,
            arm_BR_KS_counts=[63, 71, 71],
            refreshes=0,
            extra_crypto_MS=0,
        ),
        all_server_arms_before_observations_is_source_bound=True,
        independent_actual_internal_BR_degree_receipt=False,
        degree_evidence="Recomputed from actual retained post-KS words and client aggregates, checked against stock formula; source binds that ciphertext to BR.",
        independent_secret_membership_attestation=False,
        root_source_to_binary_build_attestation_required=True,
        old_diagnostic_allowed_to_fail=True,
        wrong_scale_preimages_are_relative_to_its_changed_nominal_graph=True,
        one_fixture_does_not_validate_n127_refresh=True,
        head_start_6_to_4_globally_validated=False,
        full_exact_id=False,
        actual_p_fail=None,
        timing_claim=False,
        automatic_retry_or_expansion_authorized=False,
    )
    need(result["gate_pass"] is True, "registered first precision gate")
    save("review.json", result)
    print(
        json.dumps({k: result[k] for k in ("status", "gate_pass", "records", "events")})
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        save(
            "invalid-review.json",
            dict(
                status="INDEPENDENT_INVALID_OR_INCOMPLETE_A187",
                gate_pass=False,
                error_type=type(error).__name__,
                error=str(error),
                retry_or_expansion_authorized=False,
            ),
        )
        raise
