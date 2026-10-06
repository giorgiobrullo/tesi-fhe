"""Independent invocation of frozen A182/A175 replay; no launch, probe or wait."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
A182 = HERE.parents[1]
sys.path.insert(0, str(A182))
import binding as b  # noqa:E402
import verify as frozen  # noqa:E402

A182_MANIFEST = "ce9a4fd11c914265eb2cbb08c2d6c68d3402debccb02213622867d8b7860c18d"


def self_check(expected):
    b.eq(
        b.digest(HERE / "MANIFEST.json"),
        b.hexhash(expected),
        "acknowledged prewritten review manifest",
    )
    own = b.load(HERE / "MANIFEST.json")
    for name, want in own["files"].items():
        path = b.no_symlinks(HERE / name)
        b.need(path.is_relative_to(HERE), "review source containment")
        b.eq(b.digest(path), want, "review source " + name)
    b.eq(
        b.digest(A182 / "MANIFEST.json"), A182_MANIFEST, "original frozen A182 envelope"
    )
    return b.source_check(A182_MANIFEST)


def compact(fresh, root_hash, fresh_hash):
    arith = fresh["arithmetic"]
    env = fresh["launch_binding"]
    b.eq(fresh["records"], 17703, "complete original firstkey")
    b.eq(
        arith["ledger"],
        dict(
            BR=5124,
            KS=3360,
            samples=6020,
            client_lwe_encryptions=784,
            client_glwe_encryptions=28,
        ),
        "fixed ledger",
    )
    summary = arith["producer_projection"]["summary"]
    return dict(
        schema="a182-independent-first-key-review-v1",
        status="INDEPENDENT_BOUND_FIRST_KEY_PASS"
        if fresh["complete_gate_pass"]
        else "INDEPENDENT_BOUND_COMPLETE_NEGATIVE",
        complete_gate_pass=fresh["complete_gate_pass"],
        root_saved_validation_matches_fresh_replay=True,
        root_validation_sha256=root_hash,
        fresh_validation_sha256=fresh_hash,
        source_sha256=b.SOURCE_ID,
        binary_sha256=env["binary_sha256"],
        child_pid=env["child_pid"],
        actual_exit_code=env["exit_code"],
        started_at_utc=env["started_at_utc"],
        exited_at_utc=env["exited_at_utc"],
        raw_sha256=env["files_sha256"]["stdout.jsonl"],
        records=17703,
        scores=28,
        consumers=1568,
        producer_gate_pass=fresh["producer_gate_pass"],
        actual_consumer_gate_pass=fresh["actual_consumer_gate_pass"],
        original_six_arm_summary=summary,
        consumer_arm_order=["baseline_dual", "single_full_direct_b0_b1"],
        consumer_gate_order=[
            "candidate_native",
            "actual_address",
            "output_at_actual_address",
            "semantic_output",
            "stock_equivalence",
            "observer_closure",
        ],
        consumer_failure_counts=arith["consumer_failure_counts"],
        consumer_case_failures=arith["consumer_case_failures"],
        failed_consumers=arith["failed_consumers"],
        ledger=arith["ledger"],
        stock_equivalence_failures=[row[4] for row in arith["consumer_failure_counts"]],
        independently_attested_key_membership=False,
        root_source_to_binary_build_attestation_required=True,
        candidate_from_prior_selector_round=False,
        full_exact_id_validated=False,
        actual_p_fail=None,
        timing_claim_allowed=False,
        retry_or_expansion_authorized=False,
    )


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--review", action="store_true")
    p.add_argument("--binary-sha256")
    p.add_argument("--root-validation-sha256")
    p.add_argument("--review-manifest-sha256")
    args = p.parse_args(argv)
    if not args.review:
        b.need(
            all(value is None for key, value in vars(args).items() if key != "review"),
            "noargs plan or complete review",
        )
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_RUNTIME_READ",
                    a182_manifest_sha256=A182_MANIFEST,
                    expected_records=17703,
                    process_probes=False,
                    launch=False,
                )
            )
        )
        return 0
    b.need(
        all(value is not None for key, value in vars(args).items() if key != "review"),
        "explicit actual binary/root report/reviewer source hashes",
    )
    b.private(HERE, directory=True)
    for name in ("review.json", "fresh-validation.json"):
        b.no_symlinks(HERE / name)
        b.need(not (HERE / name).exists(), "exclusive independent result")
    try:
        self_check(args.review_manifest_sha256)
        root_path = A182 / "artifacts/first-key1-validation.json"
        b.private(root_path.parent, directory=True)
        b.private(root_path)
        root_bytes = root_path.read_bytes()
        root_hash = hashlib.sha256(root_bytes).hexdigest()
        b.eq(
            root_hash,
            b.hexhash(args.root_validation_sha256),
            "captured saved root validation",
        )
        saved = b.parse(root_bytes)
        fresh = frozen.verify(b.hexhash(args.binary_sha256), A182_MANIFEST)
        b.save(HERE / "fresh-validation.json", fresh)
        b.eq(saved, fresh, "saved root report equals independent full frozen replay")
        result = compact(fresh, root_hash, b.digest(HERE / "fresh-validation.json"))
        code = 0 if result["complete_gate_pass"] else 1
    except Exception as error:
        result = dict(
            schema="a182-independent-first-key-review-v1",
            status="INDEPENDENT_REVIEW_INVALID_OR_INCOMPLETE",
            complete_gate_pass=False,
            completed_negative_established=False,
            error_type=type(error).__name__,
            error=str(error),
            retry_or_expansion_authorized=False,
            actual_p_fail=None,
        )
        code = 2
    b.save(HERE / "review.json", result)
    print(
        json.dumps({key: result[key] for key in ("status", "complete_gate_pass")}),
        flush=True,
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
