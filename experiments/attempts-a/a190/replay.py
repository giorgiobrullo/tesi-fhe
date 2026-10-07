"""Strict source-bound complete first-N4 record consistency and semantic replay.
No secret membership, primitive execution attestation, variance, speed or full-ID proof.
"""

import hashlib
import json
import sys
import oracle as o

sys.dont_write_bytecode = True
Q = o.Q


def need(x, why):
    if not x:
        raise ValueError(why)


def same(a, b, why="strict mismatch"):
    need(type(a) is type(b), why + " type")
    if type(b) is dict:
        need(a.keys() == b.keys(), why + " fields")
        for k in b:
            same(a[k], b[k], why + "/" + str(k))
    elif type(b) in (list, tuple):
        need(len(a) == len(b), why + " length")
        for x, y in zip(a, b):
            same(x, y, why)
    else:
        need(a == b, why)


def integer(x, limit=Q):
    need(type(x) is int and 0 <= x < limit, "canonical integer")
    return x


def pairs(items):
    d = {}
    for k, v in items:
        need(k not in d, "duplicate JSON")
        d[k] = v
    return d


def parse(raw):
    need(type(raw) is bytes and raw.endswith(b"\n"), "complete captured JSONL")
    return [
        json.loads(
            x,
            object_pairs_hook=pairs,
            parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
        for x in raw.splitlines()
    ]


def hash_words(words):
    return hashlib.sha256(
        b"".join(integer(x).to_bytes(8, "little") for x in words)
    ).hexdigest()


def ms(word, n):
    return ((word + (1 << (64 - (2 * n).bit_length()))) % Q) >> (
        65 - (2 * n).bit_length()
    )


def linear(*terms):
    need(bool(terms), "terms")
    n = len(terms[0][1])
    need(all(len(w) == n for _, w in terms), "word geometry")
    return [sum(c * w[i] for c, w in terms) % Q for i in range(n)]


def phase_affine(output, *terms, constant=0):
    same(
        output["phase"],
        (constant + sum(coeff * x["phase"] for coeff, x in terms)) % Q,
        "same-key affine phase closure",
    )


def raw_lut(kind, address):
    n = 2048
    x = address % n
    v = int((64 <= x < (192 if kind == "target" else 1984)))
    return v if address < n else -v


class Checker:
    def __init__(self):
        self.aliases = {}
        self.semantic = []
        self.support = []

    def ct(self, x, domain, lane=0, expected=None, delta=o.D):
        same(
            set(x),
            {
                "domain",
                "lane",
                "dimension",
                "words",
                "sha256",
                "phase",
                "mask_dot",
                "coefficientwise",
            },
        )
        dim = {"A44Big": 2048, "A44Small": 859, "CmBig": 1536, "CmSmall": 772}[domain]
        same((x["domain"], x["lane"], x["dimension"]), (domain, lane, dim))
        same(len(x["words"]), dim + 1)
        same(x["sha256"], hash_words(x["words"]))
        integer(x["phase"])
        integer(x["mask_dot"])
        same((x["words"][-1] - x["mask_dot"]) % Q, x["phase"], "phase closure")
        key = (domain, lane, x["sha256"])
        if key in self.aliases:
            same(x, self.aliases[key], "shared ciphertext witness")
        else:
            self.aliases[key] = x
        poly = {"A44Small": 2048, "CmSmall": 512}.get(domain)
        if poly:
            d = x["coefficientwise"]
            same(set(d), {"polynomial_size", "rounded_mask_sum_mod_2n", "address"})
            same(d["polynomial_size"], poly)
            integer(d["rounded_mask_sum_mod_2n"], 2 * poly)
            integer(d["address"], 2 * poly)
            same(
                d["address"],
                (ms(x["words"][-1], poly) - d["rounded_mask_sum_mod_2n"]) % (2 * poly),
                "coefficientwise address",
            )
        else:
            same(x["coefficientwise"], None)
        if expected is not None:
            err = (x["phase"] - expected * delta + Q // 2) % Q - Q // 2
            self.semantic.append(-delta // 2 <= err < delta // 2)
        return x["words"]

    def center(self, x, value, delta):
        n = x["coefficientwise"]["polynomial_size"]
        address = x["coefficientwise"]["address"]
        center = (value * delta // (Q // (2 * n))) % (2 * n)
        half = delta // (Q // (2 * n)) // 2
        displacement = (address - center + n) % (2 * n) - n
        self.support.append(-half <= displacement < half)

    def cm(self, x, big, expected=None):
        same(set(x), {"words", "sha256", "dimension", "bodies", "lanes"})
        dim = 1536 if big else 772
        same(x["dimension"], dim)
        same(x["bodies"], 4)
        same(len(x["words"]), dim + 4)
        same(len(x["lanes"]), 4)
        same(x["sha256"], hash_words(x["words"]))
        for lane, ct in enumerate(x["lanes"]):
            words = self.ct(
                ct,
                "CmBig" if big else "CmSmall",
                lane,
                None if expected is None else expected[lane],
                o.C,
            )
            same(
                words,
                x["words"][:dim] + [x["words"][dim + lane]],
                "whole CM mask/bodies",
            )
        return x["words"]


def original_inputs(record, prep):
    same(record["original_active_sha256"], [x["sha256"] for x in prep["active"]])
    same(
        record["original_bits_sha256"], [[x["sha256"] for x in r] for r in prep["bits"]]
    )


def ordinary(c, r, prep, family):
    same(
        set(r),
        {
            "type",
            "arm",
            "key_family",
            "original_active_sha256",
            "original_bits_sha256",
            "ordinary_ks",
            "ordinary_pbs",
            "states",
            "events",
            "decoded",
        },
    )
    same(r["type"], "ordinary")
    same(r["arm"], "ordinary_u8")
    same(r["key_family"], family)
    original_inputs(r, prep)
    same(r["ordinary_ks"], 48)
    same(r["ordinary_pbs"], 48)
    expected, events = o.ordinary()
    same([x["tag"] for x in r["states"]], list(expected))
    same([x["tag"] for x in r["events"]], list(events))
    states = {x["tag"]: x["values"] for x in r["states"]}
    actual = {x["tag"]: x for x in r["events"]}
    for tag, vals in states.items():
        same(len(vals), len(expected[tag]))
        for x, v in zip(vals, expected[tag]):
            c.ct(x, "A44Big", expected=v)
    same(states["initial"], prep["active"])
    for tag, e in actual.items():
        same(set(e), {"tag", "input", "small", "output", "lut_words", "lut_sha256"})
        ip, op, kind = events[tag]
        c.ct(e["input"], "A44Big", expected=ip)
        c.ct(e["small"], "A44Small", expected=ip)
        c.ct(e["output"], "A44Big", expected=op)
        body = [0] * 2048 + [
            o.D if 64 <= i < (192 if kind == "target" else 1984) else 0
            for i in range(2048)
        ]
        same(e["lut_words"], body, "actual U8 raw body")
        same(e["lut_sha256"], hash_words(body))
        c.support.append(raw_lut(kind, e["small"]["coefficientwise"]["address"]) == op)
    for level, layout in enumerate(o.LAYOUTS):
        p = f"round/{level}/"
        prior = states["initial" if not level else f"round/{level - 1}/output"]
        weighted = states[p + "weighted"]
        z = states[p + "zero"]
        anyz = states[p + "any"][0]
        lin = states[p + "linear"]
        out = states[p + "output"]
        for i in range(4):
            same(
                weighted[i]["words"],
                linear((1 if level == 5 else -1, prep["bits"][level][i]["words"])),
                "signed source multiplier",
            )
            phase_affine(weighted[i], (1 if level == 5 else -1, prep["bits"][level][i]))
            e = actual[p + f"zero/{i}"]
            same(
                e["input"]["words"],
                linear((1, prior[i]["words"]), (1, weighted[i]["words"])),
            )
            phase_affine(e["input"], (1, prior[i]), (1, weighted[i]))
            same(e["output"], z[i])
            same(
                lin[i]["words"],
                linear((1, prior[i]["words"]), (1, z[i]["words"]), (-1, anyz["words"])),
            )
            phase_affine(lin[i], (1, prior[i]), (1, z[i]), (-1, anyz))
            if level in (3, 7):
                same(actual[p + f"refresh/{i}"]["input"], lin[i])
                same(actual[p + f"refresh/{i}"]["output"], out[i])
            else:
                same(lin[i], out[i])
        e = actual[p + "or/0/0"]
        same(e["input"]["words"], linear(*[(1, x["words"]) for x in z]))
        phase_affine(e["input"], *[(1, x) for x in z])
        same(e["output"], anyz)
    same(
        r["decoded"],
        [((x["phase"] + o.D // 2) % Q) // o.D for x in states["round/7/output"]],
    )


def chain(c, r, prep, family):
    same(
        set(r),
        {
            "type",
            "arm",
            "key_family",
            "original_active_sha256",
            "original_bits_sha256",
            "completed",
            "counts",
            "checkpoints",
            "traces",
            "outputs",
            "reductions",
            "decoded",
            "stock_variance_justified",
            "key_membership_attested",
        },
    )
    same(r["type"], "chain")
    arm = r["arm"]
    need(arm in ("plain", "shared_zero", "reset_plain"), "arm")
    same(r["key_family"], family)
    original_inputs(r, prep)
    same(
        r["completed"],
        True,
        "complete chain required; refusal prefix preserved but not promoted",
    )
    same(r["counts"], o.CM_COUNTS)
    same(r["stock_variance_justified"], False)
    same(r["key_membership_attested"], False)
    expected, rounds, final = o.chain(arm == "reset_plain")
    same(
        [(t["tag"], t["ct"]["lane"]) for t in r["traces"]],
        [(t, level) for t, level, _, _ in expected],
    )
    traces = {}
    for t, (tag, lane, v, d) in zip(r["traces"], expected):
        domain = (
            "CmSmall"
            if any(
                x in tag
                for x in (
                    "active_pack/",
                    "bit_pack/",
                    "z_input/",
                    "z_ks/",
                    "broadcast",
                    "update_sum/",
                    "update_input/",
                )
            )
            else "CmBig"
            if any(
                x in tag
                for x in (
                    "active_big/",
                    "/z/",
                    "/next/",
                    "update_big_sum/",
                    "root_extracted/",
                    "egress/extracted/",
                )
            )
            else "A44Small"
            if any(
                x in tag
                for x in ("root_bridge/", "pair_input/", "any_input", "egress/small/")
            )
            else "A44Big"
        )
        c.ct(t["ct"], domain, lane, expected=v, delta=d)
        traces[(tag, lane)] = t["ct"]
        if domain == "A44Small" and (
            "pair_input/" in tag or "any_input" in tag or "egress/small/" in tag
        ):
            c.center(t["ct"], v, d)

    def cm_from_tag(tag):
        xs = [traces[(tag, i)] for i in range(4)]
        need(
            all(x["words"][:-1] == xs[0]["words"][:-1] for x in xs), "trace shared mask"
        )
        return xs[0]["words"][:-1] + [x["words"][-1] for x in xs]

    tags = ["ingress"] + [
        f"round/{level}/{s}" for level in range(8) for s in ("input", "output")
    ]
    same([x["tag"] for x in r["checkpoints"]], tags)
    checkpoints = {x["tag"]: x for x in r["checkpoints"]}
    for cp in r["checkpoints"]:
        same(len(cp["states"]), 1)
        tag = cp["tag"]
        if tag == "ingress":
            val = o.ACTIVE
            counts = o.checkpoint_counts()
        else:
            _, level, stage = tag.split("/")
            level = int(level)
            val = rounds[level][0 if stage == "input" else 4]
            counts = o.checkpoint_counts(level, stage == "output")
        c.cm(cp["states"][0], True, val)
        same(cp["counts"], counts)
    same(
        checkpoints["ingress"]["states"][0]["words"],
        cm_from_tag("ingress/active_big/0"),
    )
    for level in range(8):
        source = (
            "ingress"
            if arm == "reset_plain" or level == 0
            else f"round/{level - 1}/output"
        )
        same(
            checkpoints[f"round/{level}/input"]["states"],
            checkpoints[source]["states"],
            "persistent exact full ciphertext feedback",
        )
        same(
            checkpoints[f"round/{level}/output"]["states"][0]["words"],
            cm_from_tag(f"round/{level}/next/0"),
        )
    stages = ["ingress/active_pack/0"] + [
        f"round/{level}/{s}"
        for level in range(8)
        for s in ("z_input/0", "update_input/0")
    ]
    same([x["stage"] for x in r["reductions"]], stages)
    for e in r["reductions"]:
        stage = e["stage"]
        before = c.cm(e["before"], False)
        corrected = c.cm(e["corrected"], False)
        same(before, cm_from_tag(stage))
        same(e["allowed"], True)
        same(e["pbs_executed"], True)
        zero = e["selected_zero"]
        zw = [0] * 776 if zero is None else c.cm(zero, False)
        same(
            corrected,
            linear((1, before), (1, zw)),
            "selected complete CM-zero addition",
        )
        for lane in range(4):
            same(
                e["corrected"]["lanes"][lane]["phase"],
                (
                    e["before"]["lanes"][lane]["phase"]
                    + (0 if zero is None else zero["lanes"][lane]["phase"])
                )
                % Q,
            )
        if arm == "shared_zero":
            same(e["policy"], "SharedZerosStockAssumption")
            same(e["chooser_invocations"], 1)
            same(e["estimator_satisfied"], True)
            same(e["status"], "SATISFYING_ESTIMATOR_ASSUMPTION_ONLY")
            same(e["assumed_normalized_input_variance"], 3.11402591442555e-5)
        else:
            same(e["policy"], "Plain")
            same(e["chooser_invocations"], 0)
            same(e["estimator_satisfied"], None)
            same(e["status"], "PLAIN_A132")
            same(e["assumed_normalized_input_variance"], None)
            same(zero, None)
        if zero is None:
            same(e["selected_index"], None)
            same(e["zero_additions"], 0)
            same(e["source_derived_zero_candidates_examined"], 0)
        else:
            integer(e["selected_index"], 1515)
            same(e["zero_additions"], 1)
            same(e["source_derived_zero_candidates_examined"], e["selected_index"] + 1)
        vals = [v for tag, lane, v, d in expected if tag == stage]
        for x, v in zip(e["corrected"]["lanes"], vals):
            c.center(x, v, o.C)
    # Public affine update and all ordinary root reductions are reconstructed wordwise.
    for level, (_, _, _, _, _) in enumerate(rounds):
        p = f"round/{level}/"
        a = checkpoints[p + "input"]["states"][0]["words"]
        z = cm_from_tag(p + "z/0")
        # Both actual KS input/output ciphertexts are retained; the key operation itself is source-bound.
        same(cm_from_tag(p + "update_big_sum/0"), linear((1, a), (1, z)))
        same(
            cm_from_tag(p + "z_input/0"),
            linear(
                (o.LAYOUTS[level][3], cm_from_tag(p + "z_ks/0")),
                (1, cm_from_tag(p + "bit_pack/0")),
            ),
        )
        for lane in range(4):
            phase_affine(
                traces[(p + "update_big_sum/0", lane)],
                (1, checkpoints[p + "input"]["states"][0]["lanes"][lane]),
                (1, traces[(p + "z/0", lane)]),
            )
            phase_affine(
                traces[(p + "z_input/0", lane)],
                (o.LAYOUTS[level][3], traces[(p + "z_ks/0", lane)]),
                (1, traces[(p + "bit_pack/0", lane)]),
            )
            phase_affine(
                traces[(p + "update_input/0", lane)],
                (1, traces[(p + "update_sum/0", lane)]),
                (-1, traces[(p + "broadcast", lane)]),
                constant=o.C,
            )
            same(
                traces[(p + f"root_extracted/{lane}", lane)],
                traces[(p + "z/0", lane)],
                "actual N4 root extraction input",
            )
        same(
            traces[(p + "any_big_sum", 0)]["words"],
            linear(
                (1, traces[(p + "pair/0", 0)]["words"]),
                (1, traces[(p + "pair/1", 0)]["words"]),
            ),
        )
        phase_affine(
            traces[(p + "any_big_sum", 0)],
            (1, traces[(p + "pair/0", 0)]),
            (1, traces[(p + "pair/1", 0)]),
        )
        upd = cm_from_tag(p + "update_sum/0")
        broadcast = cm_from_tag(p + "broadcast")
        expected_up = linear((1, upd), (-1, broadcast))
        expected_up[-4:] = [(x + o.C) % Q for x in expected_up[-4:]]
        same(cm_from_tag(p + "update_input/0"), expected_up)
        for pair in range(2):
            same(
                traces[(p + f"pair_input/{pair}", 0)]["words"],
                linear(
                    (1, traces[(p + f"root_bridge/{2 * pair}", 0)]["words"]),
                    (1, traces[(p + f"root_bridge/{2 * pair + 1}", 0)]["words"]),
                ),
            )
            phase_affine(
                traces[(p + f"pair_input/{pair}", 0)],
                (1, traces[(p + f"root_bridge/{2 * pair}", 0)]),
                (1, traces[(p + f"root_bridge/{2 * pair + 1}", 0)]),
            )
        need(len(a) == len(z) == 1540, "actual CM-big update shape")
    same(len(r["outputs"]), 4)
    for i, (x, v) in enumerate(zip(r["outputs"], final)):
        c.ct(x, "A44Big", expected=v)
        same(x, traces[(f"egress/output/{i}", 0)])
        same(
            traces[(f"egress/extracted/{i}", i)],
            checkpoints["round/7/output"]["states"][0]["lanes"][i],
            "actual final CM egress extraction",
        )
    same(r["decoded"], [((x["phase"] + o.D // 2) % Q) // o.D for x in r["outputs"]])


def verify(records, source, binary, pid):
    same(len(records), 8, "exact top-level cardinality")
    meta, key, prep, ordinary_record, *tail = records
    chains = tail[:3]
    summary = tail[3]
    same(
        meta,
        dict(
            type="meta",
            schema="a190-persistent-v1",
            source=source,
            binary=binary,
            pid=pid,
            fixture="n4_tie_dead_feedback_173_174",
            active=o.ACTIVE,
            values=o.VALUES,
            expected=[1, 0, 1, 0],
            reset_expected=[0, 1, 0, 0],
            fresh_keys=1,
            timing_claim=False,
            full_id_claim=False,
            actual_p_fail=None,
            client_local=True,
            actual_u8_extraction_inputs=False,
        ),
    )
    same(
        set(key),
        {
            "type",
            "family",
            "bindings",
            "domains",
            "secret_serialized",
            "membership_attested",
        },
    )
    same(key["type"], "key")
    same(
        key["domains"],
        dict(ordinary_small=859, ordinary_big=2048, cm_small=772, cm_big=1536, lanes=4),
    )
    same(key["secret_serialized"], False)
    same(key["membership_attested"], False)
    b = key["bindings"]
    same(
        set(b),
        {
            "ordinary_fourier_sha256",
            "cm_fourier_sha256",
            "ordinary_ksk_sha256",
            "cm_ksk_sha256",
            "packing_key_sha256",
            "lane_ksk_sha256",
            "zero_pool_sha256",
        },
    )
    same(len(b["lane_ksk_sha256"]), 4)
    need(len(set(b["lane_ksk_sha256"])) == 4, "independent lane KSK identity")
    for x in [v for v in b.values() if type(v) is str] + b["lane_ksk_sha256"]:
        need(
            type(x) is str and len(x) == 64 and set(x) <= set("0123456789abcdef"),
            "hash",
        )
    same(
        key["family"],
        hashlib.sha256(
            json.dumps(b, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest(),
        "public key-container family",
    )
    c = Checker()
    same(
        set(prep),
        {
            "type",
            "ordinary_pbs",
            "small_encrypted",
            "active",
            "bits",
            "traces",
            "inputs_unchanged",
        },
    )
    same(prep["type"], "preparation")
    same(prep["ordinary_pbs"], 36)
    same(prep["small_encrypted"], 36)
    same(prep["inputs_unchanged"], True)
    same(len(prep["active"]), 4)
    same(len(prep["bits"]), 8)
    for x, v in zip(prep["active"], o.ACTIVE):
        c.ct(x, "A44Big", expected=v)
        need(any(x["words"][:-1]), "nontrivial prepared active")
    expected_traces = [
        ("prepare/active/" + str(i), x) for i, x in enumerate(prep["active"])
    ]
    for level, (row, (bit, w, _, _, _)) in enumerate(zip(prep["bits"], o.LAYOUTS)):
        same(len(row), 4)
        for i, (x, v) in enumerate(zip(row, o.VALUES)):
            c.ct(x, "A44Big", expected=((v >> bit) & 1) * w)
            need(any(x["words"][:-1]), "nontrivial prepared bit")
            expected_traces.append((f"prepare/bit/{level}/{i}", x))
    same([(x["tag"], x["ct"]) for x in prep["traces"]], expected_traces)
    ordinary(c, ordinary_record, prep, key["family"])
    same([x["arm"] for x in chains], ["plain", "shared_zero", "reset_plain"])
    for r in chains:
        chain(c, r, prep, key["family"])
    flags = [1, 0, 1, 0]
    reset = [0, 1, 0, 0]
    predicates = dict(
        input_bytes_unchanged=True,
        preparation_exact_36=True,
        ordinary_graph_48=True,
        ordinary_flags=ordinary_record["decoded"] == flags,
        plain_complete=True,
        shared_complete=True,
        reset_complete=True,
        plain_flags=chains[0]["decoded"] == flags,
        shared_flags=chains[1]["decoded"] == flags,
        reset_wrong_flags_detected=chains[2]["decoded"] == reset and reset != flags,
        three_cm_ledgers=True,
    )
    same(
        summary,
        dict(
            type="summary",
            predicates=predicates,
            gate_pass=all(predicates.values()),
            status="FIRST_N4_NATIVE_FLAGS_COMPLETE_REPLAY_REQUIRED"
            if all(predicates.values())
            else "FAILED_OR_REFUSED_FIRST_N4",
            output_flags=16,
            key_resampling=False,
            stock_variance_justified=False,
            full_id_claim=False,
            timing_claim=False,
            actual_p_fail=None,
        ),
    )
    return dict(
        status="COMPLETE_FIRST_N4_RECORD_REPLAY",
        input_origin="36_SHARED_PREPARATION_PBS_NOT_U8_EXTRACTION_CORRECTIONS",
        records=8,
        native_gate_pass=summary["gate_pass"],
        semantic_checks=len(c.semantic),
        semantic_failures=c.semantic.count(False),
        support_checks=len(c.support),
        support_departures=c.support.count(False),
        gate_pass=summary["gate_pass"] and all(c.semantic) and all(c.support),
        actual_execution_or_membership_attested=False,
        stock_variance_justified=False,
        timing_claim=False,
        full_id_claim=False,
        actual_p_fail=None,
    )
