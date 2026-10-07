"""Exact synthetic ciphertext words with mock all-one phase function, never FHE evidence."""

import hashlib
import json
import oracle as o
import replay as r


class Factory:
    def __init__(self):
        self.counter = 1

    def words(self, value, delta, dim):
        self.counter += 1
        a = self.counter * (1 << 54) % o.Q
        return [a] + [0] * (dim - 1) + [(a + value * delta) % o.Q]

    def ct(self, words, domain, lane=0):
        dim = len(words) - 1
        dot = sum(words[:-1]) % o.Q
        poly = {"A44Small": 2048, "CmSmall": 512}.get(domain)
        coeff = None
        if poly:
            total = sum(r.ms(x, poly) for x in words[:-1]) % (2 * poly)
            coeff = dict(
                polynomial_size=poly,
                rounded_mask_sum_mod_2n=total,
                address=(r.ms(words[-1], poly) - total) % (2 * poly),
            )
        return dict(
            domain=domain,
            lane=lane,
            dimension=dim,
            words=list(words),
            sha256=r.hash_words(words),
            phase=(words[-1] - dot) % o.Q,
            mask_dot=dot,
            coefficientwise=coeff,
        )

    def new(self, value, delta, domain, lane=0):
        return self.ct(
            self.words(value, delta, {"A44Big": 2048, "A44Small": 859}[domain]),
            domain,
            lane,
        )

    def cm(self, values, big, words=None):
        dim = 1536 if big else 772
        if words is None:
            base = self.words(0, o.C, dim)
            words = base[:-1] + [(base[-1] + v * o.C) % o.Q for v in values]
        return dict(
            words=list(words),
            sha256=r.hash_words(words),
            dimension=dim,
            bodies=4,
            lanes=[
                self.ct(
                    words[:dim] + [words[dim + i]], "CmBig" if big else "CmSmall", i
                )
                for i in range(4)
            ],
        )


def make_ordinary(f, prep, family):
    states, expected = o.ordinary()
    actual = {"initial": prep["active"]}
    events = []
    cs = prep["active"]
    for level, layout in enumerate(o.LAYOUTS):
        p = f"round/{level}/"
        weighted = [
            f.ct(r.linear((1 if level == 5 else -1, x["words"])), "A44Big")
            for x in prep["bits"][level]
        ]
        actual[p + "weighted"] = weighted

        def pbs(tag, words, kind):
            ip, op, _ = expected[tag]
            e = dict(
                tag=tag,
                input=f.ct(words, "A44Big"),
                small=f.new(ip, o.D, "A44Small"),
                output=f.new(op, o.D, "A44Big"),
                lut_words=[0] * 2048
                + [
                    o.D if 64 <= i < (192 if kind == "target" else 1984) else 0
                    for i in range(2048)
                ],
            )
            e["lut_sha256"] = r.hash_words(e["lut_words"])
            events.append(e)
            return e["output"]

        z = [
            pbs(p + f"zero/{i}", r.linear((1, a["words"]), (1, b["words"])), "target")
            for i, (a, b) in enumerate(zip(cs, weighted))
        ]
        actual[p + "zero"] = z
        anyz = pbs(p + "or/0/0", r.linear(*[(1, x["words"]) for x in z]), "or")
        actual[p + "any"] = [anyz]
        lin = [
            f.ct(
                r.linear((1, a["words"]), (1, b["words"]), (-1, anyz["words"])),
                "A44Big",
            )
            for a, b in zip(cs, z)
        ]
        actual[p + "linear"] = lin
        cs = (
            [pbs(p + f"refresh/{i}", x["words"], "target") for i, x in enumerate(lin)]
            if level in (3, 7)
            else lin
        )
        actual[p + "output"] = cs
    return dict(
        type="ordinary",
        arm="ordinary_u8",
        key_family=family,
        original_active_sha256=[x["sha256"] for x in prep["active"]],
        original_bits_sha256=[[x["sha256"] for x in row] for row in prep["bits"]],
        ordinary_ks=48,
        ordinary_pbs=48,
        states=[dict(tag=k, values=v) for k, v in actual.items()],
        events=events,
        decoded=states["round/7/output"],
    )


def make_chain(f, prep, family, arm):
    expected, rounds, final = o.chain(arm == "reset_plain")
    t = {}
    cm = {}
    cp = []
    reds = []

    def putcm(tag, values, big, words=None):
        x = f.cm(values, big, words)
        cm[tag] = x
        for i, level in enumerate(x["lanes"]):
            t[(tag, i)] = level
        return x

    def putl(tag, value, delta, domain, words=None):
        x = f.new(value, delta, domain) if words is None else f.ct(words, domain)
        t[(tag, 0)] = x
        return x

    def reduction(tag):
        x = cm[tag]
        shared = arm == "shared_zero"
        reds.append(
            dict(
                stage=tag,
                policy="SharedZerosStockAssumption" if shared else "Plain",
                before=x,
                corrected=x,
                selected_zero=None,
                selected_index=None,
                chooser_invocations=int(shared),
                zero_additions=0,
                source_derived_zero_candidates_examined=0,
                assumed_normalized_input_variance=3.11402591442555e-5
                if shared
                else None,
                estimator_satisfied=True if shared else None,
                status="SATISFYING_ESTIMATOR_ASSUMPTION_ONLY"
                if shared
                else "PLAIN_A132",
                allowed=True,
                pbs_executed=True,
            )
        )

    putcm("ingress/active_pack/0", o.ACTIVE, False)
    initial = putcm("ingress/active_big/0", o.ACTIVE, True)
    state = initial
    reduction("ingress/active_pack/0")
    cp.append(dict(tag="ingress", counts=o.checkpoint_counts(), states=[state]))
    for level, (a, b, z, anyz, nxt) in enumerate(rounds):
        p = f"round/{level}/"
        _, _, _, alpha, beta = o.LAYOUTS[level]
        if arm == "reset_plain":
            state = initial
        cp.append(
            dict(tag=p + "input", counts=o.checkpoint_counts(level), states=[state])
        )
        bp = putcm(p + "bit_pack/0", [beta * x for x in b], False)
        zk = putcm(p + "z_ks/0", a, False)
        putcm(
            p + "z_input/0", [], False, r.linear((alpha, zk["words"]), (1, bp["words"]))
        )
        zb = putcm(p + "z/0", z, True)
        reduction(p + "z_input/0")
        for lane in range(4):
            t[(p + f"root_extracted/{lane}", lane)] = zb["lanes"][lane]
        bridges = [
            putl(p + f"root_bridge/{i}", v, o.C, "A44Small") for i, v in enumerate(z)
        ]
        pairs = []
        for i in range(2):
            total = sum(z[2 * i : 2 * i + 2])
            putl(
                p + f"pair_input/{i}",
                total,
                o.C,
                "A44Small",
                r.linear(
                    (1, bridges[2 * i]["words"]), (1, bridges[2 * i + 1]["words"])
                ),
            )
            pairs.append(putl(p + f"pair/{i}", int(total != 0), o.D, "A44Big"))
        putl(
            p + "any_big_sum",
            sum(int(sum(z[2 * i : 2 * i + 2]) != 0) for i in range(2)),
            o.D,
            "A44Big",
            r.linear((1, pairs[0]["words"]), (1, pairs[1]["words"])),
        )
        putl(
            p + "any_input",
            sum(int(sum(z[2 * i : 2 * i + 2]) != 0) for i in range(2)),
            o.D,
            "A44Small",
        )
        putl(p + "any", anyz, o.D, "A44Big")
        broadcast = putcm(p + "broadcast", [anyz] * 4, False)
        putcm(
            p + "update_big_sum/0",
            [],
            True,
            r.linear((1, state["words"]), (1, zb["words"])),
        )
        us = putcm(p + "update_sum/0", [x + y for x, y in zip(a, z)], False)
        ui = r.linear((1, us["words"]), (-1, broadcast["words"]))
        ui[-4:] = [(x + o.C) % o.Q for x in ui[-4:]]
        putcm(p + "update_input/0", [], False, ui)
        state = putcm(p + "next/0", nxt, True)
        reduction(p + "update_input/0")
        cp.append(
            dict(
                tag=p + "output",
                counts=o.checkpoint_counts(level, True),
                states=[state],
            )
        )
    outputs = []
    for i, v in enumerate(final):
        t[(f"egress/extracted/{i}", i)] = state["lanes"][i]
        putl(f"egress/small/{i}", v, o.C, "A44Small")
        outputs.append(putl(f"egress/output/{i}", v, o.D, "A44Big"))
    return dict(
        type="chain",
        arm=arm,
        key_family=family,
        original_active_sha256=[x["sha256"] for x in prep["active"]],
        original_bits_sha256=[[x["sha256"] for x in row] for row in prep["bits"]],
        completed=True,
        counts=o.CM_COUNTS.copy(),
        checkpoints=cp,
        traces=[dict(tag=tag, ct=t[(tag, lane)]) for tag, lane, _, _ in expected],
        outputs=outputs,
        reductions=reds,
        decoded=final,
        stock_variance_justified=False,
        key_membership_attested=False,
    )


def records(source="a" * 64, binary="b" * 64, pid=123):
    f = Factory()
    bindings = {
        k: hashlib.sha256(k.encode()).hexdigest()
        for k in (
            "ordinary_fourier_sha256",
            "cm_fourier_sha256",
            "ordinary_ksk_sha256",
            "cm_ksk_sha256",
            "packing_key_sha256",
            "zero_pool_sha256",
        )
    }
    bindings["lane_ksk_sha256"] = [
        hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)
    ]
    family = hashlib.sha256(
        json.dumps(bindings, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    meta = dict(
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
    )
    key = dict(
        type="key",
        family=family,
        bindings=bindings,
        domains=dict(
            ordinary_small=859, ordinary_big=2048, cm_small=772, cm_big=1536, lanes=4
        ),
        secret_serialized=False,
        membership_attested=False,
    )
    active = [f.new(v, o.D, "A44Big") for v in o.ACTIVE]
    bits = [
        [f.new(((v >> bit) & 1) * w, o.D, "A44Big") for v in o.VALUES]
        for bit, w, _, _, _ in o.LAYOUTS
    ]
    traces = [dict(tag=f"prepare/active/{i}", ct=x) for i, x in enumerate(active)] + [
        dict(tag=f"prepare/bit/{level}/{i}", ct=x)
        for level, row in enumerate(bits)
        for i, x in enumerate(row)
    ]
    prep = dict(
        type="preparation",
        ordinary_pbs=36,
        small_encrypted=36,
        active=active,
        bits=bits,
        traces=traces,
        inputs_unchanged=True,
    )
    ordinary = make_ordinary(f, prep, family)
    chains = [
        make_chain(f, prep, family, arm)
        for arm in ("plain", "shared_zero", "reset_plain")
    ]
    predicates = {
        k: True
        for k in (
            "input_bytes_unchanged",
            "preparation_exact_36",
            "ordinary_graph_48",
            "ordinary_flags",
            "plain_complete",
            "shared_complete",
            "reset_complete",
            "plain_flags",
            "shared_flags",
            "reset_wrong_flags_detected",
            "three_cm_ledgers",
        )
    }
    summary = dict(
        type="summary",
        predicates=predicates,
        gate_pass=True,
        status="FIRST_N4_NATIVE_FLAGS_COMPLETE_REPLAY_REQUIRED",
        output_flags=16,
        key_resampling=False,
        stock_variance_justified=False,
        full_id_claim=False,
        timing_claim=False,
        actual_p_fail=None,
    )
    return [meta, key, prep, ordinary, *chains, summary]
