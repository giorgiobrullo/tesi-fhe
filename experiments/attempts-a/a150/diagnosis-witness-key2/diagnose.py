"""Read preserved A150 records; emit aggregates only. No crypto or subprocesses."""
from pathlib import Path
import hashlib
import json
import os

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
Q = 1 << 64
DELTA = 1 << 61


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_write(name, data):
    fd = os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(data)


def identity_lut(degree):
    # Cached helper: four512-entry boxes, negate first256, rotate left256.
    coeff = [i // 512 for i in range(2048)]
    coeff[:256] = [-v for v in coeff[:256]]
    coeff = coeff[256:] + coeff[:256]
    degree %= 4096
    return coeff[degree] if degree < 2048 else -coeff[degree - 2048]


def main():
    rows = [json.loads(line) for line in (ROOT / "runs/witness-key2/stdout.jsonl").read_text().splitlines()]
    phases = {(r["case"], r["stage"], r["lane"]): r for r in rows if r["type"] == "phase"}
    summaries = {r["case"]: r for r in rows if r["type"] == "case_summary"}
    plain, wrong = "n4_plain", "n4_negative_WrongLaneKsk"
    result = next(r for r in rows if r["type"] == "summary")
    assert not result["bounded_diagnostic_gate_pass"] and not result["graph_negatives_pass"]
    assert summaries[plain]["passed"] and summaries["n4_shared_zero"]["passed"]
    assert summaries[wrong]["stage_mismatches"] == summaries[wrong]["output_mismatches"] == 0
    by_stage = {}
    for prefix in ["next/", "egress_small/", "output/"]:
        keys = [(stage, lane) for (case, stage, lane) in phases if case == plain and stage.startswith(prefix)]
        a = [phases[(plain,) + key] for key in keys]
        b = [phases[(wrong,) + key] for key in keys]
        by_stage[prefix] = {"count": len(keys), "changed_phases": sum(x["phase_u64"] != y["phase_u64"] for x, y in zip(a, b)),
                           "baseline_max_abs_error_delta": max(abs(int(x["signed_error_i64"])) / int(x["delta_u64"]) for x in a),
                           "wrong_map_max_abs_error_delta": max(abs(int(x["signed_error_i64"])) / int(x["delta_u64"]) for x in b)}
    assert by_stage["next/"]["changed_phases"] == 0
    assert by_stage["egress_small/"]["changed_phases"] == by_stage["output/"]["changed_phases"] == 4
    egress = {case: [phases[case, f"egress_small/{i}", 0] for i in range(4)] for case in [plain, wrong]}
    cyclic_zero = (sum(int(r["phase_u64"]) for r in egress[wrong]) - sum(int(r["phase_u64"]) for r in egress[plain])) % Q == 0
    assert cyclic_zero
    for i in range(4):
        assert identity_lut(i * 512) == i
    predictions = []
    for offset in [-128, 128]:
        entry = {"body_offset_torus": str(offset * (1 << 52)), "degree_offset": offset, "scope": "CLEAR_REPLAY_EXISTING_COEFFICIENTWISE_ADDRESSES_ONLY"}
        for case in [plain, wrong]:
            rr = egress[case]
            expected = [r["expected"] for r in rr]
            values = [identity_lut(r["br_geometry"]["coefficientwise_degree"] + offset) for r in rr]
            entry[case] = {"predicted_lut_outputs_signed": values, "mismatch_count": sum(x != y for x, y in zip(values, expected)),
                           "original_center_displacements": [r["br_geometry"]["center_displacement"] for r in rr]}
        assert entry[plain]["mismatch_count"] == 0
        predictions.append(entry)
    assert [x[wrong]["mismatch_count"] for x in predictions] == [1, 2]
    cached = Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0/src/core_crypto"
    source_paths = [ROOT / "src/crypto.rs", ROOT / "src/main.rs", ROOT / "src/model.rs", ROOT.parent / "a132-common-mask-round-gate/src/crypto.rs",
                    cached / "algorithms/lwe_keyswitch.rs", cached / "algorithms/lwe_programmable_bootstrapping/mod.rs",
                    cached / "experimental/entities/common_mask_entities/cm_lwe_ciphertext.rs"]
    source_paths += [ROOT / "runs/witness-key2" / name for name in ["stdout.jsonl", "stderr.log", "prepared.json", "started.json", "exit.json", "replay.json"]]
    out = {"schema": "a150-witness-key2-diagnosis-v1", "status": "FAILED_GATE_PRESERVED_NEGATIVE_NONDISCRIMINATING", "private_client_diagnostic": True,
           "gate_summary_unchanged": result, "source_and_record_pins": {str(p): digest(p) for p in source_paths},
           "phase_change_summary": by_stage, "cyclic_sum_phase_difference_zero_mod_2_64": cyclic_zero,
           "next_finite_margin_control_clear_replay": predictions,
           "not_demonstrated": ["new FHE result", "universal wrong-key discriminator", "independent lane-error trials", "noise improvement", "composed failure bound"],
           "runtime_actions": 0, "source_edits": 0}
    private_write("RESULT.json", json.dumps(out, indent=2) + "\n")
    print("Diagnosis replay PASS; original gate remains FAILED. Two finite clear margin predictions discriminate1 and2 lanes. No raw phases emitted.")


if __name__ == "__main__":
    main()
