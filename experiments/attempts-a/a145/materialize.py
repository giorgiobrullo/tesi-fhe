"""Materialize an isolated A138 successor; never execute Cargo or FHE."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"frozen source shape changed: {old[:80]}")
    return source.replace(old, new, 1)


def main():
    sources = [
        "tmp/a138-nibble-ingress-gate/src/main.rs",
        "tmp/a138-nibble-ingress-gate/src/a34_tables.rs",
        "tmp/a138-nibble-ingress-gate/Cargo.toml",
        "tmp/a138-nibble-ingress-gate/Cargo.lock",
        "tmp/a142-nibble-joint-noise-domain/graph.py",
        "tmp/a142-nibble-joint-noise-domain/regions.py",
        "tmp/a142-nibble-joint-noise-domain/a138_model.py",
        "tmp/a142-nibble-joint-noise-domain/a135_model.py",
    ]
    pins = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
    frozen = HERE / "SOURCE_PINS.json"
    if frozen.exists():
        if json.loads(frozen.read_text()) != pins:
            raise ValueError("frozen input drift")
    else:
        frozen.write_text(json.dumps(pins, indent=2) + "\n")
    (HERE / "src").mkdir(exist_ok=True)
    for name in ["regions.py", "a138_model.py", "a135_model.py"]:
        (HERE / name).write_bytes(
            (ROOT / "tmp/a142-nibble-joint-noise-domain" / name).read_bytes()
        )
    (HERE / "src/a34_tables.rs").write_bytes((ROOT / sources[1]).read_bytes())
    for name in ["Cargo.toml", "Cargo.lock"]:
        original = (ROOT / "tmp/a138-nibble-ingress-gate" / name).read_text()
        (HERE / name).write_text(
            replace_once(
                original,
                'name = "a138_nibble_ingress_gate"',
                'name = "a145_padding_flag_ingress_gate"',
            )
        )
    rust = (ROOT / sources[0]).read_text()
    rust = rust.replace("A138", "A145").replace("a138", "a145")
    rust = replace_once(
        rust,
        "struct Evaluation {",
        """#[derive(Clone, Copy)]
struct Arm {
    name: &'static str,
    independent: bool,
    padding: bool,
    wrong_final: bool,
    wrong_scale: bool,
}
const ARMS: [Arm; 6] = [
    Arm { name: "canonical_shared", independent: false, padding: false, wrong_final: false, wrong_scale: false },
    Arm { name: "canonical_separate", independent: true, padding: false, wrong_final: false, wrong_scale: false },
    Arm { name: "padding_shared", independent: false, padding: true, wrong_final: false, wrong_scale: false },
    Arm { name: "padding_separate", independent: true, padding: true, wrong_final: false, wrong_scale: false },
    Arm { name: "negative_final_delta63", independent: false, padding: true, wrong_final: true, wrong_scale: false },
    Arm { name: "negative_digit_scale", independent: false, padding: true, wrong_final: false, wrong_scale: true },
];

struct Evaluation {""",
    )
    rust = replace_once(
        rust,
        "fn initial(&mut self, tops: &[Lwe]) -> Vec<Lwe> {",
        "fn initial(&mut self, tops: &[Lwe], flag_log: u32) -> Vec<Lwe> {\n        assert!([59, 63].contains(&flag_log));",
    )
    rust = replace_once(
        rust, "a34_top_candidate_lut(v) << 59", "a34_top_candidate_lut(v) << flag_log"
    )
    rust = replace_once(
        rust,
        "fn round(&mut self, active: &[Lwe], digits: &[Lwe], name: &str) -> Vec<Lwe> {",
        "fn round(&mut self, active: &[Lwe], digits: &[Lwe], name: &str, active_log: u32, valid_log: u32, output_log: u32) -> Vec<Lwe> {\n        assert!([active_log, valid_log, output_log].iter().all(|x| [59, 63].contains(x)));\n        let valid_half = 1u64 << (valid_log - 1);\n        let output_half = 1u64 << (output_log - 1);",
    )
    rust = replace_once(rust, "&scale(a, 16)", "&scale(a, 1u64 << (63 - active_log))")
    rust = replace_once(
        rust,
        'vec![1 << 58; 16], format!("{name}.valid")',
        'vec![valid_half; 16], format!("{name}.valid")',
    )
    rust = replace_once(
        rust, "offset(&signed_valid, 1 << 58)", "offset(&signed_valid, valid_half)"
    )
    rust = replace_once(
        rust, "&scale(&valid, 16)", "&scale(&valid, 1u64 << (63 - valid_log))"
    )
    rust = replace_once(
        rust, "(1u64 << 58).wrapping_neg()", "output_half.wrapping_neg()"
    )
    rust = replace_once(
        rust,
        "                            1 << 58\n",
        "                            output_half\n",
    )
    rust = replace_once(
        rust, "offset(&signed, 1 << 58)", "offset(&signed, output_half)"
    )
    rust = replace_once(
        rust,
        "    independent: bool,\n    wrong_scale: bool,\n) -> Evaluation {",
        "    arm: Arm,\n) -> Evaluation {\n    let independent = arm.independent;\n    let wrong_scale = arm.wrong_scale;\n    let flag_log = if arm.padding { 63 } else { 59 };\n    let final_log = if arm.wrong_final { 63 } else { 59 };",
    )
    rust = replace_once(
        rust, "backend.initial(&top)", "backend.initial(&top, flag_log)"
    )
    rust = replace_once(
        rust,
        'backend.round(&active, &middle_for_consumer, "middle_round")',
        'backend.round(&active, &middle_for_consumer, "middle_round", flag_log, flag_log, flag_log)',
    )
    rust = replace_once(
        rust,
        'backend.round(&active, &low_for_consumer, "low_round")',
        'backend.round(&active, &low_for_consumer, "low_round", flag_log, flag_log, final_log)',
    )
    rust = replace_once(
        rust,
        '    let execute = args.iter().any(|x| x == "--run");',
        '    let execute = args.iter().any(|x| x == "--run");\n    let full_suite = args.iter().any(|x| x == "--full");',
    )
    rust = replace_once(
        rust, '        if a != "--run"', '        if a != "--run" && a != "--full"'
    )
    rust = replace_once(
        rust,
        '    println!(\n        "{}",\n        json!({"record":"plan"',
        '    let selected_indices: Vec<usize> = if full_suite { (0..fixtures.len()).collect() } else { vec![2] };\n    println!(\n        "{}",\n        json!({"record":"plan"',
    )
    rust = replace_once(
        rust,
        '"stage":"first_composed_n4","fixtures":fixtures',
        '"stage":"padding_flags_n4","suite":if full_suite {"full8"} else {"single2"},"selected_fixture_indices":selected_indices,"fixtures":fixtures',
    )
    rust = replace_once(
        rust,
        '"arms":["shared512","independent_scale","negative_wrong_consumer_scale"],"br_ks_per_fixture":[55,63,55]',
        '"arms":ARMS.iter().map(|a| a.name).collect::<Vec<_>>(),"br_ks_per_fixture":[55,63,55,63,55,55]',
    )
    rust = replace_once(
        rust, "let mut failures = [0usize; 2];", "let mut failures = [0usize; 4];"
    )
    rust = replace_once(
        rust,
        "let mut negatives_by_key = vec![0usize; keysets];",
        "let mut negatives_by_key = vec![[0usize; 2]; keysets];",
    )
    rust = replace_once(
        rust,
        "        for (case, scores) in fixtures.iter().enumerate() {",
        "        for &case in &selected_indices {\n            let scores = &fixtures[case];",
    )
    rust = replace_once(
        rust,
        """            let evaluations = [
                evaluate(&full, &low, &server, false, false),
                evaluate(&full, &low, &server, true, false),
                evaluate(&full, &low, &server, false, true),
            ];""",
        """            let evaluations: Vec<_> = ARMS.iter()
                .map(|arm| evaluate(&full, &low, &server, *arm)).collect();""",
    )
    rust = replace_once(rust, "if arm < 2 {", "if arm < 4 {")
    rust = replace_once(
        rust,
        "negatives_by_key[keyset] += usize::from(!consumer);",
        "negatives_by_key[keyset][arm - 4] += usize::from(!consumer);",
    )
    rust = replace_once(
        rust,
        '"record":"case","keyset":keyset,"case":case,"arm":arm,',
        '"record":"case","keyset":keyset,"case":case,"arm":arm,"arm_name":ARMS[arm].name,"padding_flags":ARMS[arm].padding,"actual_final_output_log":if ARMS[arm].wrong_final {63} else {59},"required_final_output_log":59,"flag_phase_words":evaluation.flags.iter().map(|x| decrypt_lwe_ciphertext(&big_secret,x).0.to_string()).collect::<Vec<_>>(),',
    )
    rust = replace_once(
        rust,
        "failures == [0, 0]\n        && negatives_by_key.iter().all(|count| *count > 0)\n        && cases == 8 * keysets",
        "failures == [0, 0, 0, 0]\n        && negatives_by_key.iter().all(|counts| counts.iter().all(|count| *count > 0))\n        && cases == selected_indices.len() * keysets",
    )
    rust = replace_once(
        rust, '"BOUNDED_COMPOSED_GATE_PASS"', '"BOUNDED_PADDING_COMPOSED_GATE_PASS"'
    )
    rust = replace_once(
        rust,
        '"wrong_scale_negatives_detected_by_key":negatives_by_key',
        '"negative_arm_failures_detected_by_key":negatives_by_key,"selected_fixture_indices":selected_indices',
    )
    (HERE / "src/main.rs").write_text(rust)

    graph = (ROOT / sources[4]).read_text()
    graph = replace_once(
        graph,
        "def __init__(self, events=None, perturbations=None):",
        "def __init__(self, events=None, perturbations=None, padding=False, wrong_final=False):\n        self.padding = padding\n        self.wrong_final = wrong_final",
    )
    graph = replace_once(
        graph,
        "candidate = [int(i in (3, 14)) << 59 for i in range(16)]",
        "candidate = [int(i in (3, 14)) << (63 if self.padding else 59) for i in range(16)]",
    )
    graph = replace_once(
        graph,
        "    def round(self, active, digits, prefix):\n        masked = []",
        "    def round(self, active, digits, prefix):\n        flag_log = 63 if self.padding else 59\n        output_log = (63 if self.wrong_final else 59) if prefix == 'low_round' else flag_log\n        flag_factor = 1 << (63 - flag_log)\n        masked = []",
    )
    graph = replace_once(
        graph, "d.scale(256).add(a.scale(16))", "d.scale(256).add(a.scale(flag_factor))"
    )
    graph = replace_once(
        graph,
        'minimum, frozen.consumer.valid_words(), f"{prefix}.valid"\n        ).offset(1 << 58)',
        'minimum, frozen.consumer.valid_words(flag_log), f"{prefix}.valid"\n        ).offset(1 << (flag_log - 1))',
    )
    graph = replace_once(
        graph,
        "q.scale(128).sub(minimum).add(valid.scale(16))",
        "q.scale(128).sub(minimum).add(valid.scale(flag_factor))",
    )
    graph = replace_once(
        graph,
        'frozen.consumer.update_words(),\n                f"{prefix}.update/{i}",\n            ).offset(1 << 58)',
        'frozen.consumer.update_words(output_log),\n                f"{prefix}.update/{i}",\n            ).offset(1 << (output_log - 1))',
    )
    (HERE / "graph.py").write_text(graph)
    print("Materialized A145 source; original inputs unchanged; no compiler or FHE")


if __name__ == "__main__":
    main()
