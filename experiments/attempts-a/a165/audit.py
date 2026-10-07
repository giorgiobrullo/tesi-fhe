"""Pinned source/static checks only; no compiler, FHE or process commands."""

import hashlib
import json
from pathlib import Path
import re

import model

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def function(source, name):
    match = re.search(r"\bfn " + name + r"\s*\(", source)
    require(match is not None, "missing Rust function " + name)
    start = source.index("{", match.end())
    depth, cursor = 1, start + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[match.start() : cursor]


def verify_origins():
    origin = json.loads((HERE / "ORIGIN.json").read_text())
    parent = Path(origin["parent"])
    require(
        sha(parent / "artifacts/candidate_hashes.json")
        == origin["parent_candidate_manifest_sha256"],
        "parent manifest drift",
    )
    for name, expected in origin["parent_candidate_files"].items():
        require(sha(parent / name) == expected, "frozen parent drift: " + name)
        if name not in (
            "candidate/.cargo/config.toml",
            "candidate/README.md",
            "candidate/src/main.rs",
            "candidate/src/diagnostic.rs",
        ):
            require(
                sha(HERE / name) == expected, "unchanged candidate file drift: " + name
            )
    require(
        sha(parent / "runs/smoke-key1/stdout.jsonl")
        == origin["failed_smoke_stdout_sha256"],
        "preserved failed smoke drift",
    )
    require(
        sha(parent / "runtime-validation/artifacts/smoke-key1-validation.json")
        == origin["failed_smoke_replay_sha256"],
        "preserved failed replay drift",
    )
    return parent


def verify_source_text(source=None):
    parent = verify_origins()
    old = (parent / "candidate/src/diagnostic.rs").read_text()
    new = (
        source
        if source is not None
        else (HERE / "candidate/src/diagnostic.rs").read_text()
    )
    unchanged = [
        "snapshot",
        "scaled",
        "snapshot_raw_correction",
        "accumulator",
        "traced_extract",
        "same_lwe",
        "same_capture",
        "split_arm",
        "single_arm",
        "boundary_targets",
        "digest",
        "decode",
        "a50_target_one_from_scalar_phase",
    ]
    for name in unchanged:
        require(
            function(old, name) == function(new, name),
            "original cryptographic/observer function drift: " + name,
        )
    repair = function(new, "repaired_b1_arm")
    compact = re.sub(r"\s+", "", repair)
    require(
        "letmutarm=single_arm(full,sk,false);" in compact,
        "repair must retain full old arm",
    )
    require(
        'point.stage=="full.ks_b1"' in compact
        and "assert!(retained.small_key)" in compact,
        "retained actual small b1",
    )
    require("letsmall=retained.ciphertext.clone();" in compact, "same input clone")
    require(
        "&small,&accumulator(bsk,61,false),bsk,full.lwe_size(),1u64<<60,&extra_pbs,"
        in compact,
        "direct Delta61 Single PBS",
    )
    require(repair.count("correction_from_small_bit(") == 1, "exactly one new PBS")
    require(
        "keyswitch_lwe_ciphertext" not in repair and "encrypt_" not in repair,
        "no added KS/encryption",
    )
    require(
        compact.count("arm.weighted_bits[") == 1
        and "arm.weighted_bits[1]=direct.correction;" in compact,
        "only weighted b1 replaced",
    )
    require("arm.top_residual" not in repair, "residual must remain unchanged")
    require(
        '"repair_b1.pbs_correction_b1"' in compact and '"repair_b1",1,61,' in compact,
        "actual direct output traced",
    )
    run = re.sub(r"\s+", "", function(new, "run"))
    for expected in [
        'stage!="smoke"||keysets!=1',
        "ifarm_index<4",
        "single_arm(&full,&server,false),repaired_b1_arm(&full,&server),single_arm(&full,&server,true)",
        "letrepair_gate_pass=controls_valid&&repair_pair_failures==0&&failures[3]==0;",
        "native_decode_failures[1..3]",
        "consumer_phase_failures[1..3]",
        "if!repair_gate_pass",
        '"repair_pair"',
        '"direct_output_consumed"',
        '"pbs_per_score":[11,11,8,9,8]',
        '"ks_per_score":[8,8,8,8,8]',
    ]:
        require(expected in run, "fixed gate/schema condition missing: " + expected)
    require(
        new.count("keyswitch_lwe_ciphertext(")
        == old.count("keyswitch_lwe_ciphertext("),
        "unchanged total KS call sites",
    )
    require(
        model.SCHEMA in new
        and 'insert("schema".into(),json!(A165_SCHEMA))'
        in re.sub(r"\s+", "", function(new, "emit")),
        "version on every raw row",
    )
    return dict(
        unchanged_functions=len(unchanged),
        original_single_arm_byte_identical=True,
        frozen_helpers_byte_identical=True,
        retained_actual_small_input=True,
        added_pbs=1,
        added_ks=0,
        only_weighted_bit_replaced=1,
    )


def verify_source():
    verify_source_text()
    manifest = json.loads((HERE / "SOURCE_MANIFEST.json").read_text())
    for name, expected in manifest["files"].items():
        require(sha(HERE / name) == expected, "A165 source drift: " + name)
    digest = sha(HERE / "SOURCE_MANIFEST.json")
    require(
        (HERE / "candidate/SOURCE_DIGEST.txt").read_text().strip() == digest,
        "source digest binding",
    )
    return digest
