"""Validate saved A137 aggregate identities, with local client phase observations trusted.

No ciphertext/phase-polynomial words are persisted. Their hashes identify retained
observations but do not let this replay independently prove decryption or spreading.
"""

from pathlib import Path
import json
from static_audit import HERE, sha256

Q = 1 << 64
MASK = Q - 1


def signed(word):
    word &= MASK
    return word - Q if word >= Q // 2 else word


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_noise_lane(row):
    terms = [
        row[k]
        for k in [
            "support_message_residual",
            "transmitted_input_error",
            "transmitted_rounding_rho",
            "aggregate_pfks_key_error",
            "aggregate_fft_phase_residual",
            "br_and_numeric_residual",
        ]
    ]
    require(
        all(-Q // 2 <= value < Q // 2 for value in terms), "non-centered error term"
    )
    require(signed(sum(terms)) == row["semantic_error"], "noise additive closure")
    require(
        str(sum(terms)) == row["centered_terms_unwrapped_sum_decimal"], "unwrapped sum"
    )
    ideal = row["ideal_body_at_actual_degree"]
    exact = row["exact_pre_br_phase_reconstructed"]
    actual = row["actual_pre_br_phase"]
    output = row["actual_output_phase"]
    expected = row["expected_phase"]
    require((ideal + sum(terms[1:4])) & MASK == exact, "PFKS decomposition")
    require(signed(ideal - expected) == terms[0], "support message residual")
    require(signed(actual - exact) == terms[4], "FFT residual")
    require(signed(output - actual) == terms[5], "BR residual")
    require(signed(output - expected) == row["semantic_error"], "semantic residual")
    require(row["delta"] == 1 << (56 if row["lane"] == 3 else 59), "mixed lane scale")
    magnitude = abs(row["semantic_error"])
    require(
        row["strict_half_slot_pass"] == (magnitude < row["delta"] // 2),
        "strict half slot",
    )
    require(
        row["margin_to_half_slot_decimal"] == str(row["delta"] // 2 - magnitude),
        "margin",
    )
    require(row["sample_degree"] == row["lane"] * 128, "sample orientation")
    require(row["closure_pass"] is True, "reported closure failure")
    if row["arm"] == "direct_window":
        require(terms[4] == 0, "direct has no FFT residual")
    require(
        row["p_fail_proven"] is False
        and row["performance_interpretation_allowed"] is False,
        "claim widening",
    )
    contributions = row["term_contributions"]
    require(sorted(t["term"] for t in contributions) == list(range(8)), "term schedule")
    require(
        signed(sum(t["aggregate_key_error_contribution"] for t in contributions))
        == terms[3],
        "PFKS contribution sum",
    )
    require(
        sum(t["exact_pfks_phase_contribution"] for t in contributions) & MASK == exact,
        "exact PFKS sum",
    )


def validate_rows(rows):
    meta = [r for r in rows if r.get("record") == "meta"]
    require(
        len(meta) == 1 and meta[0]["artifact"] == "A137", "meta cardinality/artifact"
    )
    for key, file in [
        ("main_source_sha256", "src/main.rs"),
        ("observer_source_sha256", "src/observer.rs"),
        ("lockfile_sha256", "Cargo.lock"),
    ]:
        require(
            meta[0][key] == sha256(HERE / file),
            "source/binary producer metadata mismatch: " + key,
        )
    require(
        meta[0]["preregistration_sha256"] == sha256(HERE / "PREREGISTRATION.json"),
        "preregistration",
    )
    require(
        meta[0]["contains_secret_derived_observations"] is True,
        "observation privacy label",
    )
    by_type = {
        kind: [r for r in rows if r.get("record") == kind]
        for kind in [
            "case",
            "lane",
            "pfks_witness",
            "accumulator_witness",
            "noise_lane",
            "summary",
        ]
    }
    for kind, count in [
        ("case", 8),
        ("lane", 32),
        ("pfks_witness", 128),
        ("accumulator_witness", 16),
        ("noise_lane", 64),
        ("summary", 1),
    ]:
        require(len(by_type[kind]) == count, kind + " cardinality")
    specs = json.loads((HERE / "PREREGISTRATION.json").read_text())["fixture_specs"]
    cases = by_type["case"]
    require(sorted(c["fixture_index"] for c in cases) == list(range(8)), "case indices")
    require(len({c["fixture"] for c in cases}) == 8, "fixture names")
    for case in cases:
        name = case["fixture"]
        spec = specs[case["fixture_index"]]
        require(name == spec["name"], "frozen fixture identity")
        expected_values = spec["left"] if spec["control"] == 4 else spec["right"]
        lanes = [r for r in by_type["lane"] if r["fixture"] == name]
        require(sorted(r["lane"] for r in lanes) == list(range(4)), "output lanes")
        for arm in ["direct_window", "convolution_a108"]:
            pfks = [
                r
                for r in by_type["pfks_witness"]
                if r["fixture"] == name and r["arm"] == arm
            ]
            acc = [
                r
                for r in by_type["accumulator_witness"]
                if r["fixture"] == name and r["arm"] == arm
            ]
            noise = [
                r
                for r in by_type["noise_lane"]
                if r["fixture"] == name and r["arm"] == arm
            ]
            require(
                sorted(r["term"] for r in pfks) == list(range(8)),
                "PFKS term cardinality",
            )
            require(
                len(acc) == 1 and sorted(r["lane"] for r in noise) == list(range(4)),
                "accumulator/noise cardinality",
            )
            acc = acc[0]
            require(
                acc["post_ks_control_sha256"] == case["control_phase_audit"]["sha256"],
                "actual post-KS control identity",
            )
            degree = (
                acc["modulus_switched_body"]
                - acc["secret_weighted_modulus_switched_mask_sum"]
            ) % 4096
            require(
                degree
                == acc["actual_effective_rotation_degree"]
                == case["actual_effective_rotation_degree"],
                "actual MS address",
            )
            difference = (degree - spec["control"] * 128) % 4096
            expected_error = difference - 4096 if difference > 2048 else difference
            require(
                case["actual_effective_rotation_error"] == expected_error,
                "control displacement",
            )
            require(
                acc["support_ok"]
                == case["support_ok"]
                == (abs(case["actual_effective_rotation_error"]) <= 63),
                "support classification",
            )
            for term in pfks:
                expected_input = (spec["left"] + spec["right"])[term["term"]] * (
                    1 << (56 if term["term"] % 4 == 3 else 59)
                )
                require(
                    term["input_message_phase"] == expected_input,
                    "frozen input message",
                )
                require(
                    (term["input_phase"] + int(term["rounding_rho_decimal"])) & MASK
                    == term["rounded_input_phase"],
                    "PFKS rounding phase",
                )
                require(
                    signed(term["input_phase"] - term["input_message_phase"])
                    == term["input_error"],
                    "input phase error",
                )
                require(
                    term["primitive_row_errors_independently_measured"] is False,
                    "aggregate is not primitive row evidence",
                )
            for row in noise:
                validate_noise_lane(row)
                require(
                    row["actual_pre_br_virtual_degree"] == degree + row["lane"] * 128,
                    "BR orientation",
                )
                require(
                    row["support_ok"] == case["support_ok"],
                    "lane support classification",
                )
                old = next(r for r in lanes if r["lane"] == row["lane"])[
                    "direct" if arm == "direct_window" else "convolution"
                ]
                require(
                    row["expected_phase"]
                    == expected_values[row["lane"]] * row["delta"],
                    "frozen expected output",
                )
                if row["support_ok"]:
                    require(
                        row["support_message_residual"] == 0,
                        "supported window message identity",
                    )
                require(
                    row["output_sha256"] == old["sha256"]
                    and row["actual_output_phase"] == old["phase"],
                    "output identity",
                )
                require(
                    row["semantic_error"] == old["signed_error"],
                    "output error identity",
                )
            if arm == "direct_window":
                require(
                    acc["direct_all_ciphertext_words_equal"] is True,
                    "direct accumulator mismatch",
                )
        require(case["observer_identity_pass"] is True, "observer identity failure")
        if case["direct_class"] == "pass":
            require(
                all(
                    case[k]
                    for k in [
                        "support_ok",
                        "prerequisites_ok",
                        "direct_counters_pass",
                        "scalar_counters_pass",
                    ]
                ),
                "PASS prerequisite mismatch",
            )
            for lane in lanes:
                for arm in ["direct", "scalar"]:
                    require(
                        all(
                            lane[arm][k]
                            for k in ["decode_pass", "half_slot_pass", "nontrivial"]
                        ),
                        "PASS output mismatch",
                    )
                    require(
                        lane[arm]["decoded"]
                        == lane["expected"]
                        == expected_values[lane["lane"]],
                        "PASS expected decode",
                    )
    summary = by_type["summary"][0]
    passed = sum(c["direct_class"] == "pass" for c in cases)
    require(
        summary["direct_passed"] == passed and summary["observer_failures"] == 0,
        "summary mismatch",
    )
    require(
        summary["p_fail_proven"] is False
        and summary["runtime_frontier_promoted"] is False,
        "summary claim widening",
    )
    require(
        summary["status"]
        == (
            "PASS_DIRECT_SINGLE_KEY_COMPONENT"
            if passed == 8
            else "FAIL_DIRECT_COMPONENT"
        ),
        "summary status",
    )
    return summary

