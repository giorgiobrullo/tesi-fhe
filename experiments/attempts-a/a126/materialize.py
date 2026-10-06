#!/usr/bin/env python3
"""Build the isolated A126 source tree from pinned A66 text, without compilation."""

from __future__ import annotations

import difflib
import hashlib
import json
import subprocess
from pathlib import Path

import gate

HERE = Path(__file__).resolve().parent
BASE = gate.ROOT / "tmp/a66-a62-latency-ready-prototype"


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(
            f"expected one replacement site, found {source.count(old)}: {old[:70]}"
        )
    return source.replace(old, new)


def materialize() -> None:
    gate.source_texts()
    original = (BASE / "src/private_argmin.rs").read_text()
    source = original
    # Existing entry points pass false; the new entry points select the new graph explicitly.
    for variant in ("TwoP16Digits", "A53Radix15TwoP16Digits", "SingleCode"):
        old = f"AlignedWireFormat::{variant},\n        "
        indentation = "    " if variant == "SingleCode" else ""
        old += indentation + "trace,"
        new = f"AlignedWireFormat::{variant},\n        {indentation}false,\n        {indentation}trace,"
        source = replace_once(source, old, new)
    source = replace_once(
        source,
        "    wire_format: AlignedWireFormat,\n    mut trace:",
        "    wire_format: AlignedWireFormat,\n    fuse_refresh: bool,\n    mut trace:",
    )

    endpoint_start = source.index("pub fn private_argmin_a62(\n")
    endpoint_end = source.index("\n/// Esegue lo stesso core", endpoint_start)
    endpoint = source[endpoint_start:endpoint_end].replace(
        "private_argmin_a62", "private_argmin_a126"
    )
    trace_start = source.index("pub fn private_argmin_a62_with_trace(\n")
    trace_end = source.index("\nfn private_argmin_two_lwe_impl", trace_start)
    traced_endpoint = source[trace_start:trace_end].replace(
        "private_argmin_a62", "private_argmin_a126"
    )
    impl_start = source.index("fn private_argmin_a62_impl(\n")
    impl_end = source.index("\nfn private_argmin_impl", impl_start)
    implementation = source[impl_start:impl_end].replace(
        "private_argmin_a62", "private_argmin_a126"
    )
    implementation = implementation.replace(
        "        false,\n        trace,", "        true,\n        trace,"
    )
    new_endpoints = (
        "\n/// A126: fuse the level3 refresh and level4 zero test; raw noise tails remain open.\n"
        + endpoint
        + '\n#[doc(hidden)]\n#[cfg(feature = "diagnostic-trace")]\n'
        + traced_endpoint
        + "\n"
        + implementation
        + "\n"
    )
    source = replace_once(
        source,
        "\nfn private_argmin_two_lwe_impl(\n",
        new_endpoints + "\nfn private_argmin_two_lwe_impl(\n",
    )

    source = replace_once(
        source,
        "    pub candidates_by_level: Vec<Vec<Lwe>>,",
        """    pub candidates_by_level: Vec<Vec<Lwe>>,
    /// A126 diagnostic-only encrypted checkpoints. Scale is 2^59 throughout.
    pub a126_fusion_inputs: Vec<Lwe>,
    pub a126_fresh_candidates: Vec<Lwe>,
    pub a126_zero_candidates: Vec<Lwe>,""",
    )

    counts = """
/// Structural A126 counts: N fewer BR/KS; the same two output marginals replace two PBS.
pub fn a126_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let mut counts = a62_aligned_operation_counts(gallery_size)?;
    counts.blind_rotations = counts.blind_rotations.checked_sub(gallery_size as u64)?;
    counts.key_switches = counts.key_switches.checked_sub(gallery_size as u64)?;
    Some(counts)
}

"""
    source = replace_once(
        source,
        "pub fn expected_pbs_count(gallery_size: usize)",
        counts + "pub fn expected_pbs_count(gallery_size: usize)",
    )
    setup = """
    assert!(!fuse_refresh || wire_format == AlignedWireFormat::A53Radix15TwoP16Digits);
    let a126_fusion_accumulator = fuse_refresh.then(|| {
        let bytes = include_bytes!("../artifacts/fused_candidate_zero_body.u64le");
        assert_eq!(bytes.len(), polynomial_size.0 * 8);
        let body = bytes.chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        raw_accumulator(body)
    });
"""
    source = replace_once(
        source,
        "    let a50_radix15_or_accumulator = raw_accumulator(a50_radix15_or_body);",
        "    let a50_radix15_or_accumulator = raw_accumulator(a50_radix15_or_body);\n"
        + setup,
    )
    helper = """
    let apply_a126_fusion = |input: &Lwe| -> (Lwe, Lwe) {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = a126_fusion_accumulator.as_ref().expect("A126 accumulator").clone();
        blind_rotate_assign(&switched, &mut rotated, fourier_bootstrap_key);
        let mut candidate = LweCiphertext::new(0u64, big_size, modulus);
        let mut zero_candidate = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut candidate, MonomialDegree(0));
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut zero_candidate, MonomialDegree(768));
        pbs_count.fetch_add(1, Ordering::Relaxed);
        (candidate, zero_candidate)
    };
"""
    # Restrict this insertion to the aligned implementation's existing selector helper.
    aligned_start = source.index("fn private_argmin_aligned_a38_impl(\n")
    prefix, aligned = source[:aligned_start], source[aligned_start:]
    aligned = replace_once(
        aligned,
        "    let apply_selector_pbs = |input: &Lwe, accumulator: &Glwe|",
        helper + "    let apply_selector_pbs = |input: &Lwe, accumulator: &Glwe|",
    )
    old_start = aligned.index("        let weighted_bits: Vec<Lwe> = bits\n")
    old_end = aligned.index(
        "        if let Some(trace) = trace.as_deref_mut() {\n            trace.zero_candidates_by_level",
        old_start,
    )
    original_zero = aligned[old_start:old_end]
    old_branch = original_zero.replace(
        "        let zero_candidates: Vec<Lwe> = candidates", "        candidates"
    ).rstrip()
    old_branch = old_branch.removesuffix(";")
    new_zero = (
        """        let zero_candidates: Vec<Lwe> = if fuse_refresh && level == 4 {
            // bits is the positive canonical b3; weighted_bits would already negate it.
            let inputs: Vec<Lwe> = candidates.par_iter().zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    let six_bits = scale_lwe_signed(&bit.ciphertext, 6);
                    lwe_ciphertext_add_assign(&mut encoded, &six_bits);
                    encoded
                }).collect();
            let pairs: Vec<(Lwe, Lwe)> = inputs.par_iter().map(apply_a126_fusion).collect();
            if let Some(trace) = trace.as_deref_mut() {
                trace.a126_fusion_inputs = inputs;
                trace.a126_fresh_candidates = pairs.iter().map(|(candidate, _)| candidate.clone()).collect();
                trace.a126_zero_candidates = pairs.iter().map(|(_, zero)| zero.clone()).collect();
            }
            candidates = pairs.iter().map(|(candidate, _)| candidate.clone()).collect();
            pairs.into_iter().map(|(_, zero)| zero).collect()
        } else {
"""
        + old_branch
        + "\n        };\n"
    )
    aligned = aligned[:old_start] + new_zero + aligned[old_end:]
    aligned = replace_once(
        aligned,
        "if use_a50_selection && A38_CHUNK_END_LEVELS.contains(&level) {",
        "if use_a50_selection && A38_CHUNK_END_LEVELS.contains(&level) && !(fuse_refresh && level == 3) {",
    )
    aligned = replace_once(
        aligned,
        "} else if level == A38_CHUNK_END_LEVELS[0] {",
        "} else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[0] {",
    )
    aligned = replace_once(
        aligned,
        "} else if level == A38_CHUNK_END_LEVELS[1] {",
        "} else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[1] {",
    )
    aligned = replace_once(
        aligned,
        "        a62_aligned_operation_counts(n).unwrap().blind_rotations",
        "        if fuse_refresh { a126_aligned_operation_counts(n).unwrap().blind_rotations }\n        else { a62_aligned_operation_counts(n).unwrap().blind_rotations }",
    )
    source = prefix + aligned

    for relative in ("src/a53_scan.rs", "src/a53_scan/fhe.rs", "Cargo.lock"):
        destination = HERE / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((BASE / relative).read_bytes())
    (HERE / "src/private_argmin.rs").write_text(source)
    library = (BASE / "src/lib.rs").read_text()
    library += "\npub use private_argmin::{a126_aligned_operation_counts, private_argmin_a126};\n"
    library += '#[cfg(feature = "diagnostic-trace")]\npub use private_argmin::private_argmin_a126_with_trace;\n'
    (HERE / "src/lib.rs").write_text(library)
    manifest = (
        (BASE / "Cargo.toml")
        .read_text()
        .replace("a66_a62_latency_ready_prototype", "a126_refresh_schedule_gate")
    )
    (HERE / "Cargo.toml").write_text(manifest)
    lock = (
        (HERE / "Cargo.lock")
        .read_text()
        .replace(
            'name = "a66_a62_latency_ready_prototype"',
            'name = "a126_refresh_schedule_gate"',
        )
    )
    (HERE / "Cargo.lock").write_text(lock)
    (HERE / ".cargo").mkdir(exist_ok=True)
    (HERE / ".cargo/config.toml").write_text(
        '[build]\ntarget-dir = "target-a126-only"\nrustflags = ["-C", "target-cpu=native"]\n'
    )
    subprocess.run(
        [
            "rustfmt",
            "--edition",
            "2021",
            str(HERE / "src/private_argmin.rs"),
            str(HERE / "src/lib.rs"),
        ],
        check=True,
    )
    source = (HERE / "src/private_argmin.rs").read_text()
    patch = "".join(
        difflib.unified_diff(
            original.splitlines(True),
            source.splitlines(True),
            fromfile="frozen-a66/src/private_argmin.rs",
            tofile="a126/src/private_argmin.rs",
        )
    )
    (HERE / "artifacts/a126_core.patch").write_text(patch)
    print(
        json.dumps(
            {
                "status": "MATERIALIZED_SOURCE_ONLY_NOT_COMPILED",
                "core_sha256": hashlib.sha256(source.encode()).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    materialize()
