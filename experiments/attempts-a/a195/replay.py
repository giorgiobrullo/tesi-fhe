"""A195 fixed staged expansion, exact prefix replay; no executable launches."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError("A195 requires Python assertions enabled")
import component as c  # noqa: E402 -- disable bytecode and enforce assertions first

HERE = Path(__file__).resolve().parent
need, eq, parse, sha, sha_bytes = c.need, c.eq, c.parse, c.sha, c.sha_bytes
STAGES = {"n4-smoke": 2, "n4-full": 16}


def fixtures():
    rows = parse((HERE / "FIXTURES.json").read_bytes())["fixtures"]
    eq([r["id"] for r in rows], list(range(16)))
    for row in rows:
        need(type(row["scores"]) is list and len(row["scores"]) == 4, "N4 fixture")
        need(
            all(type(x) is int and 0 <= x < 4096 for x in row["scores"]), "12-bit score"
        )
    return rows


def reference():
    return dict(
        schema="a195.nominal_schedule.v1",
        fixtures=[c.nominal_reference(r["scores"]) for r in fixtures()],
    )


def source_check():
    import origin

    origin.verify()
    for manifest in ("SOURCE_ORIGINS.json", "SOURCE_PINS.json"):
        for path, expected in parse((HERE / manifest).read_bytes())["files"].items():
            eq(sha(path), expected, "upstream pin " + path)
    for path in parse((HERE / "SOURCE_ORIGINS.json").read_bytes())["unchanged"]:
        eq(
            (HERE / path).read_bytes(),
            (HERE.parent / "a187-padding-precision-runtime-gate" / path).read_bytes(),
            "unchanged datapath " + path,
        )
    anchor = parse((HERE / "PASSING_FIRST.json").read_bytes())
    eq(anchor["status"], "INDEPENDENT_VALID_A187_FIRST_PASS")
    eq(anchor["gate_pass"], True)
    source = parse((HERE / "SOURCE_MANIFEST.json").read_bytes())
    for name, expected in source["files"].items():
        eq(sha(HERE / name), expected, "source " + name)
    identity = sha(HERE / "SOURCE_MANIFEST.json")
    eq((HERE / "SOURCE_DIGEST.txt").read_text(), identity + "\n")
    artifact = parse((HERE / "MANIFEST.json").read_bytes())
    eq(artifact["source_id"], identity)
    for name, expected in artifact["files"].items():
        eq(sha(HERE / name), expected, "artifact " + name)
    eq(
        parse((HERE / "REFERENCE.json").read_bytes()),
        reference(),
        "independent LUT bytes and affine offsets",
    )
    return identity


def plan(stage, execute=True):
    n = STAGES[stage]
    total = 3 * n
    return dict(
        record="stage_plan",
        schema="a195.precision_expansion.v1",
        execution_requested=execute,
        stage=stage,
        keysets=3,
        fixture_indices=list(range(n)),
        planned_components=total,
        component_records=211,
        raw_records_if_pass=2 + 211 * total,
        pbs_if_pass=205 * total,
        ks_if_pass=205 * total,
        input_encryptions_if_pass=total,
        total_extractions_if_pass=213 * total,
        stop_first_component_negative=True,
        fresh_stage_keys=True,
        timing_allowed=False,
        automatic_expansion=False,
    )


def summary(stage, completed, gate):
    n = STAGES[stage]
    return dict(
        record="stage_summary",
        schema="a195.precision_expansion.v1",
        stage=stage,
        gate_pass=gate,
        status="A195_STAGE_PASS" if gate else "A195_PREFIX_NEGATIVE",
        completed_components=completed,
        planned_components=3 * n,
        generated_keysets=(completed + n - 1) // n,
        pbs=205 * completed,
        ks=205 * completed,
        input_glwe_encryptions=completed,
        public_glwe_products=4 * completed,
        input_sample_extractions=8 * completed,
        pbs_output_sample_extractions=205 * completed,
        total_sample_extractions=213 * completed,
        actual_coefficient_degree_replays=205 * completed,
        extra_crypto_ms_calls=0,
        refresh_calls=0,
        raw_records=2 + 211 * completed,
        full_id=False,
        formal_tail=False,
        timing_claim=False,
    )


def replay(
    records, binary_hash, exit_code, stage, verify_source=True, forbidden_keys=()
):
    need(stage in STAGES, "fixed stage")
    need(type(exit_code) is int and exit_code in (0, 1), "complete terminal exit")
    source = source_check() if verify_source else "SYNTHETIC_SOURCE"
    need(
        type(records) is list and len(records) >= 213 and (len(records) - 2) % 211 == 0,
        "complete component prefix",
    )
    eq(records[0], plan(stage))
    n = STAGES[stage]
    count = (len(records) - 2) // 211
    need(1 <= count <= 3 * n, "registered prefix bound")
    schedule = [(key, fixture) for key in range(3) for fixture in range(n)]
    reports = []
    keys = {}
    child = None
    hash_phases = {}
    for index, (key, fixture) in enumerate(schedule[:count]):
        block = records[1 + 211 * index : 1 + 211 * (index + 1)]
        component_gate = block[-1]["gate_pass"]
        need(type(component_gate) is bool, "component gate boolean")
        need(
            component_gate or index == count - 1, "no continuation after first negative"
        )
        result = c.replay(
            block,
            binary_hash,
            0 if component_gate else 1,
            fixtures()[fixture]["scores"],
            key,
            fixture,
            source,
        )
        provenance = block[1]
        pair = [provenance["big_key_sha256"], provenance["small_key_sha256"]]
        if key in keys:
            eq(keys[key], pair, "one fixed keypair per keyset")
        else:
            need(
                not set(pair).intersection(forbidden_keys),
                "fresh stage keys differ from predecessor",
            )
            need(
                len(set(pair)) == 2
                and not set(pair).intersection(h for ps in keys.values() for h in ps),
                "distinct new key hashes",
            )
            keys[key] = pair
        if child is None:
            child = result["child_pid"]
        eq(result["child_pid"], child, "one direct child")
        for event in block:
            if event["record"] != "event":
                continue
            for domain, hfield, pfield in (
                (0, "input_sha256", "big_phase_word"),
                (1, "small_sha256", "small_phase_word"),
                (0, "output_sha256", "output_phase_word"),
            ):
                identity = (pair[domain], event[hfield])
                phase = event[pfield]
                if identity in hash_phases:
                    eq(
                        hash_phases[identity],
                        phase,
                        "cross-component same-key ciphertext identity",
                    )
                hash_phases[identity] = phase
        reports.append(dict(keyset=key, fixture_index=fixture, **result))
    gate = count == 3 * n and all(x["gate_pass"] for x in reports)
    if not gate:
        eq(
            reports[-1]["gate_pass"],
            False,
            "complete final negative required, not truncated passing prefix",
        )
    eq(records[-1], summary(stage, count, gate))
    eq(exit_code, 0 if gate else 1, "stage outcome/exit")
    return dict(
        schema="a195.stage_replay.v1",
        status="VALID_A195_STAGE_PASS" if gate else "VALID_A195_PREFIX_NEGATIVE",
        stage=stage,
        gate_pass=gate,
        records=len(records),
        completed_components=count,
        planned_components=3 * n,
        generated_keysets=len(keys),
        key_hashes=list(keys.values()),
        events=205 * count,
        pbs=205 * count,
        ks=205 * count,
        total_extractions=213 * count,
        child_pid=child,
        source_id=source,
        binary_sha256=binary_hash,
        reports=reports,
        actual_secret_membership_attested=False,
        full_id=False,
        formal_tail=False,
        timing_claim=False,
    )
