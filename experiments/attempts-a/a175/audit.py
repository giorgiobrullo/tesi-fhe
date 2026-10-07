"""Source/interface checks only; no compiler, native probe or cryptography."""

from pathlib import Path
import hashlib
import re

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "a169-low-correction-b0-b1-repair"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def function(text, name):
    match = re.search(r"\bfn " + name + r"\s*\(", text)
    need(match is not None, "missing function " + name)
    start = text.index("{", match.end())
    depth, cursor = 1, start + 1
    while depth:
        depth += (text[cursor] == "{") - (text[cursor] == "}")
        cursor += 1
    return text[match.start() : cursor]


def segment(text, begin, end):
    start = text.index(begin)
    return text[start : text.index(end, start)]


def verify_source():
    old = (OLD / "candidate/src/diagnostic.rs").read_text()
    new = (HERE / "candidate/src/diagnostic.rs").read_text()
    preserved = [
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
        "repaired_b0_b1_arm",
        "boundary_targets",
        "digest",
        "decode",
        "a50_target_one_from_scalar_phase",
        "emit",
    ]
    hashes = {}
    for name in preserved:
        before, after = function(old, name), function(new, name)
        need(before == after, "unchanged original function " + name)
        hashes[name] = hashlib.sha256(after.encode()).hexdigest()
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "src/frozen_extract.rs",
        "LICENSE.tfhe-rs-BSD-3-Clause-Clear",
    ):
        need(
            (OLD / "candidate" / name).read_bytes()
            == (HERE / "candidate" / name).read_bytes(),
            "frozen candidate leaf " + name,
        )
    old_key = segment(old, "for keyset in 0..keysets {", "let arms = [")
    new_key = segment(new, "for keyset in 0..keysets {", "let arms = [")
    need(
        new_key.replace("        a175_key_record(&server, keyset);\n", "") == old_key,
        "same normal key setup, nonzero GLWE/product/score expressions",
    )
    for begin, end in [
        ("let original = &arms[2];", "// The client now inspects every arm."),
        ("for (arm_index, arm) in arms.iter().enumerate() {", "let bad_phase ="),
    ]:
        need(
            segment(old, begin, end) == segment(new, begin, end),
            "preserved producer client/pair block",
        )
    old_summary = segment(
        old, "let controls_valid =", "    if !repair_b0_b1_gate_pass {"
    )
    new_summary = segment(
        new, "let controls_valid =", "    let actual_consumer_gate_pass ="
    )
    need(old_summary == new_summary, "preserved complete producer summary")
    need(
        new.index("let mut actual_consumers")
        < new.index("let original = &arms[2];")
        < new.index("// The client now inspects"),
        "server work before all client phase inspection",
    )
    consume = function(
        (HERE / "candidate/src/actual_consumer.rs").read_text(), "a175_consume"
    )
    for call, count in [
        ("keyswitch_lwe_ciphertext(", 1),
        ("a175_retained_blind_rotate(", 1),
        ("blind_rotate_assign(", 1),
        ("extract_lwe_sample_from_glwe_ciphertext(", 2),
    ]:
        need(consume.count(call) == count, "exact new consumer call ledger " + call)
    need(
        "decrypt_" not in consume and "secret" not in consume,
        "consumer server has no secret/decryption",
    )
    retained = (HERE / "candidate/src/retained_br.rs").read_text()
    compact = re.sub(r"\s+", "", retained)
    for expression in [
        "letnonzero=*word!=0;",
        "ifnonzero{",
        "receipt.masks.push(degree);",
        "receipt.masks.push(0);",
        "polynomial_wrapping_monic_monomial_div(",
        "polynomial_wrapping_monic_monomial_mul_and_subtract(",
        "add_external_product_assign(",
    ]:
        need(expression in compact, "stock native branch/order primitive " + expression)
    need(
        compact.count("pbs_modulus_switch(") == 2,
        "body plus nonzero-mask modulus-switch sites",
    )
    need(
        "body[64..192].fill(1u64<<59)"
        in re.sub(r"\s+", "", (HERE / "candidate/src/actual_consumer.rs").read_text()),
        "exact frozen target-one body",
    )
    return dict(
        preserved_function_hashes=hashes,
        preserved_function_count=len(hashes),
        original_glwe_product_score_expressions_preserved=True,
        original_six_arm_observation_and_summary_preserved=True,
        normal_matched_key_setup_preserved=True,
        consumer_KS=1,
        consumer_BR=2,
        consumer_samples=2,
        source_only=True,
        compiled=False,
        cryptography_executed=False,
    )
