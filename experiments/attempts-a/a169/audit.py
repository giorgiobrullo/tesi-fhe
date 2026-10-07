"""Pinned source checks only. No compiler, FHE, process or runtime dispatch."""

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
    depth = 1
    cursor = start + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[match.start() : cursor]


def verify_origins():
    origin = json.loads((HERE / "ORIGIN.json").read_text())
    parent = Path(origin["parent"])
    for name, key in [
        ("SOURCE_MANIFEST.json", "parent_source_manifest_sha256"),
        ("ARTIFACT_MANIFEST.json", "parent_artifact_manifest_sha256"),
    ]:
        require(
            sha(parent / name) == origin[key], "frozen parent manifest drift " + name
        )
    for name, expected in origin["parent_source_files"].items():
        require(sha(parent / name) == expected, "frozen A165 source drift " + name)
        if name.startswith("candidate/") and name not in (
            "candidate/.cargo/config.toml",
            "candidate/README.md",
            "candidate/src/main.rs",
            "candidate/src/diagnostic.rs",
        ):
            require(
                sha(HERE / name) == expected,
                "unchanged inherited candidate file " + name,
            )
    for name, expected in origin["preserved_evidence_sha256"].items():
        require(
            sha(parent / name) == expected, "preserved A165 negative evidence " + name
        )
    return parent


def segment(text, start, end):
    return text[text.index(start) : text.index(end, text.index(start))]


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
        "repaired_b1_arm",
        "boundary_targets",
        "digest",
        "decode",
        "a50_target_one_from_scalar_phase",
    ]
    for name in unchanged:
        require(
            function(old, name) == function(new, name),
            "frozen crypto/observer function " + name,
        )
    require(
        segment(old, "for keyset in 0..keysets {", "let arms = [")
        == segment(new, "for keyset in 0..keysets {", "let arms = ["),
        "same key/packed product/nonzero scenes/score construction",
    )
    require(
        segment(
            old, "for (arm_index, arm) in arms.iter().enumerate() {", "let bad_phase ="
        )
        == segment(
            new, "for (arm_index, arm) in arms.iter().enumerate() {", "let bad_phase ="
        ).replace("arm_index < 5", "arm_index < 4"),
        "unchanged full client/native/margin/scalar observation loop",
    )
    require(
        segment(
            old, "let original = &arms[2];", "// The client now inspects every arm."
        ).strip()
        == segment(
            new, "let original = &arms[2];", "// A second comparison retains"
        ).strip(),
        "original b1 pair comparison unchanged",
    )
    repair = function(new, "repaired_b0_b1_arm")
    compact = re.sub(r"\s+", "", repair)
    for expected in [
        "letmutarm=repaired_b1_arm(full,sk);",
        'point.stage=="full.ks_b0"',
        "assert!(retained.small_key)",
        "letsmall=retained.ciphertext.clone();",
        "&small,&accumulator(bsk,60,false),bsk,full.lwe_size(),1u64<<59,&extra_pbs,",
        '"repair_b0",0,60,',
        '"repair_b0.pbs_correction_b0"',
        "arm.weighted_bits[0]=direct.correction;",
        "assert_eq!((arm.pbs,arm.ks),(10,8));",
        'arm.name="single_full_direct_b0_b1";',
    ]:
        require(expected in compact, "actual b0 extension condition " + expected)
    require(repair.count("correction_from_small_bit(") == 1, "one new b0 PBS")
    require(compact.count("arm.weighted_bits[") == 1, "only new b0 replacement")
    require(
        "keyswitch_lwe_ciphertext" not in repair
        and "encrypt_" not in repair
        and "arm.top_residual" not in repair,
        "no new KS/encryption/residual mutation",
    )
    run = re.sub(r"\s+", "", function(new, "run"))
    for expected in [
        'stage!="smoke"||keysets!=1',
        "ifarm_index<5",
        "single_arm(&full,&server,false),repaired_b1_arm(&full,&server),repaired_b0_b1_arm(&full,&server),single_arm(&full,&server,true)",
        "letrepair_gate_pass=controls_valid&&repair_pair_failures==0&&failures[3]==0;",
        "letrepair_b0_b1_gate_pass=controls_valid&&repair_pair_failures==0&&repair_b0_pair_failures==0&&failures[4]==0;",
        "if!repair_b0_b1_gate_pass",
        '"pbs_per_score":[11,11,8,9,10,8]',
        '"ks_per_score":[8,8,8,8,8,8]',
        '"repair_pair_records_per_score":2',
        '"record":"repair_pair"',
        '"record":"repair_pair_b0"',
        "repair_b0_b1.trace.len()==original_b1.trace.len()+2",
        "letb0_pair_pass=old_b1_trace_identical&&b0_top_identical&&b0_other_weighted_identical&&b0_direct_consumed",
        "original_b1.pbs==9&&repair_b0_b1.pbs==10&&original_b1.ks==8&&repair_b0_b1.ks==8",
        "(1..8).all(|bit|{same_lwe(&original_b1.weighted_bits[bit],&repair_b0_b1.weighted_bits[bit],)})",
        '"original_top_sha256"',
        '"repair_top_sha256"',
        '"retained_b1_small_input_sha256"',
        '"original_direct_b1_sha256"',
        '"preserved_direct_b1_sha256"',
    ]:
        require(expected in run, "fixed pair/gate/ledger condition " + expected)
    require(
        new.count("keyswitch_lwe_ciphertext(")
        == old.count("keyswitch_lwe_ciphertext("),
        "same KS call sites",
    )
    require(
        model.SCHEMA in new
        and 'insert("schema".into(),json!(A169_SCHEMA))'
        in re.sub(r"\s+", "", function(new, "emit")),
        "version every row",
    )
    return dict(
        unchanged_functions=len(unchanged),
        original_b1_repair_byte_identical=True,
        packed_score_and_observer_loop_unchanged=True,
        new_b0_pbs=1,
        new_ks=0,
        candidate_pbs=10,
        candidate_ks=8,
    )


def verify_source():
    verify_source_text()
    manifest = json.loads((HERE / "SOURCE_MANIFEST.json").read_text())
    for name, expected in manifest["files"].items():
        require(sha(HERE / name) == expected, "A169 source drift " + name)
    digest = sha(HERE / "SOURCE_MANIFEST.json")
    require(
        (HERE / "candidate/SOURCE_DIGEST.txt").read_text().strip() == digest,
        "full source digest binding",
    )
    return digest
