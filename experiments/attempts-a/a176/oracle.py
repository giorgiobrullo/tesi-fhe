"""Independent finite graph and operation enumeration; no TFHE/candidate imports."""

A = 1 << 59
C = 1 << 61
FIELDS = ("packing", "cm_ks", "cm_pbs", "ordinary_ks", "ordinary_pbs", "extraction")
STAGES = ("n4-smoke", "n4-exhaustive", "n127")


def layout(bit):
    return (
        (8, 1, 1, 2)
        if bit == 2
        else (4, 1, 2, 1)
        if bit == 1
        else (2, 2, 2, 1)
        if bit == 0
        else (1, 4, 2, 1)
    )


def fixtures(stage):
    if stage not in STAGES:
        raise ValueError("unregistered stage")
    if stage == "n4-exhaustive":
        return [
            (
                f"boolean_{w:03}",
                [(w >> i) & 1 for i in range(4)],
                [(w >> (4 + i)) & 1 for i in range(4)],
            )
            for w in range(256)
        ]
    n = 127 if stage == "n127" else 4
    result = [("asymmetric_zero_first", [1] * n, [0] + [1] * (n - 1))]
    if n == 4:
        return result + [
            ("all_dead", [0] * 4, [0, 1, 1, 0]),
            ("all_one_keep", [1] * 4, [1] * 4),
            ("inactive_zero_does_not_eliminate", [0, 1, 1, 0], [0, 1, 1, 0]),
        ]
    result += [
        ("all_dead_tail", [0] * n, [0] * n),
        ("all_one_keep_tail", [1] * n, [1] * n),
    ]
    for i in (3, 4, 62, 124, 126):
        bits = [1] * n
        bits[i] = 0
        result.append((f"only_zero_{i}", [1] * n, bits))
    bits = [int(i not in (0, 4, 126)) for i in range(n)]
    return result + [("tie_across_groups_and_lanes", [1] * n, bits)]


def graph(active, bits, bit):
    """Trace order plus exact pre-BR checkpoints; refusal truncates before the PBS increment."""
    assert len(active) == len(bits) > 0 and all(x in (0, 1) for x in active + bits)
    n = len(active)
    g = (n + 3) // 4
    weight, rescale, alpha, beta = layout(bit)
    assert weight * rescale * A == beta * C
    aa = active + [0] * (4 * g - n)
    bb = bits + [0] * (4 * g - n)
    z = [a * (1 - b) for a, b in zip(aa, bb)]
    anyzero = int(any(z))
    survivors = [int(a == 1 and (not anyzero or b == 0)) for a, b in zip(active, bits)]
    phases = []
    events = []
    counts = {name: 0 for name in FIELDS}

    def put(tag, values, domain, delta=C):
        phases.extend((tag, i, domain, v, delta) for i, v in enumerate(values))

    def op(name, amount=1):
        counts[name] += amount

    def br(tag, values):
        events.append(
            dict(
                stage=tag,
                values=values.copy(),
                phase_prefix=len(phases),
                refused_counts=counts.copy(),
            )
        )
        op("cm_pbs")

    for i in range(n):
        put(f"input_active/{i}", [active[i]], "A44Big", A)
        put(f"input_bit/{i}", [bits[i] * weight], "A44Big", A)
    roots = []
    for j in range(g):
        a, b, zero = aa[4 * j : 4 * j + 4], bb[4 * j : 4 * j + 4], z[4 * j : 4 * j + 4]
        op("packing")
        put(f"active_pack/{j}", a, "CmSmall")
        br(f"active_pack/{j}", a)
        put(f"active_big/{j}", a, "CmBig")
        op("packing")
        put(f"bit_pack/{j}", [v * beta for v in b], "CmSmall")
        code = [x * alpha + y * beta for x, y in zip(a, b)]
        op("cm_ks")
        put(f"z_input/{j}", code, "CmSmall")
        br(f"z_input/{j}", code)
        put(f"z/{j}", zero, "CmBig")
        roots.append(zero)
    level = 0
    while len(roots) > 1:
        next_roots = []
        for node, start in enumerate(range(0, len(roots), 3)):
            chunk = roots[start : start + 3]
            if len(chunk) == 1:
                next_roots.append(chunk[0])
                continue
            sums = [sum(row[lane] for row in chunk) for lane in range(4)]
            tag = f"reduce_input/{level}/{node}"
            op("cm_ks")
            put(tag, sums, "CmSmall")
            br(tag, sums)
            out = [int(x != 0) for x in sums]
            put(f"reduce/{level}/{node}", out, "CmBig")
            next_roots.append(out)
        roots = next_roots
        level += 1
    for lane in range(4):
        op("extraction")
        op("ordinary_ks")
        put(f"root_bridge/{lane}", [roots[0][lane]], "A44Small")
    pairs = []
    for p in range(2):
        value = sum(roots[0][2 * p : 2 * p + 2])
        put(f"pair_input/{p}", [value], "A44Small")
        op("ordinary_pbs")
        flag = int(value != 0)
        pairs.append(flag)
        put(f"pair/{p}", [flag], "A44Big", A)
    op("ordinary_ks")
    put("any_input", [sum(pairs)], "A44Small", A)
    op("ordinary_pbs")
    put("any", [anyzero], "A44Big", A)
    op("packing")
    put("broadcast", [anyzero] * 4, "CmSmall")
    for j in range(g):
        sums = [aa[i] + z[i] for i in range(4 * j, 4 * j + 4)]
        op("cm_ks")
        put(f"update_sum/{j}", sums, "CmSmall")
        code = [x + 1 - anyzero for x in sums]
        tag = f"update_input/{j}"
        put(tag, code, "CmSmall")
        br(tag, code)
        put(f"next/{j}", [int(x == 2) for x in code], "CmBig")
    for i, value in enumerate(survivors):
        op("extraction")
        op("ordinary_ks")
        put(f"egress_small/{i}", [value], "A44Small")
        op("ordinary_pbs")
        put(f"output/{i}", [value], "A44Big", A)
    return dict(phases=phases, events=events, counts=counts, survivors=survivors)


def plan(stage):
    fs = fixtures(stage)
    n = len(fs[0][1])
    gr = graph(fs[0][1], fs[0][2], 7)
    pairs = 3 * len(fs) * 8
    rounds = 2 * pairs
    case_rows = len(gr["phases"]) + len(gr["events"]) + 2
    ledger = {k: rounds * v for k, v in gr["counts"].items()}
    anchor = dict(
        packing=15, cm_ks=11, cm_pbs=17, ordinary_ks=45, ordinary_pbs=59, extraction=40
    )
    for k in FIELDS:
        ledger[k] += 3 * anchor[k]
    ledger["ordinary_pbs"] += pairs * 2 * n
    return dict(
        stage=stage,
        n=n,
        fresh_keysets=3,
        fixtures_per_key=len(fs),
        layouts=8,
        pairs=pairs,
        positive_rounds=rounds,
        positive_round_counts=gr["counts"],
        positive_case_phase_rows=len(gr["phases"]),
        positive_case_cm_events=len(gr["events"]),
        successful_rows=2 + 3 * 384 + pairs * (2 + 2 * case_rows),
        reported_algorithm_counts=ledger,
        margin_body_additions=48,
        stock_output_extractions_outside_counts=24,
        diagnostic_trace_extractions_included=False,
        fixture_preparation_pbs=pairs * 2 * n,
        actual_cm_events=rounds * len(gr["events"]) + 54,
        positive_phase_rows=rounds * len(gr["phases"]),
        key_hash_independence_attested=False,
    )
