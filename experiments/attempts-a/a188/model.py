"""Clear CM feedback semantics and explicit primitive schedule; no ciphertexts."""

from collections import Counter

LAYOUTS = (
    (7, 1, 4, 2, 1),
    (6, 1, 4, 2, 1),
    (5, 1, 4, 2, 1),
    (4, 1, 4, 2, 1),
    (3, 1, 4, 2, 1),
    (2, 8, 1, 1, 2),
    (1, 4, 1, 2, 1),
    (0, 2, 2, 2, 1),
)
PRIMITIVES = ("packing", "cm_ks", "cm_pbs", "ordinary_ks", "ordinary_pbs", "extraction")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def boolean_vector(values):
    need(bool(values), "nonempty vector")
    need(
        all(type(x) is int and x in (0, 1) for x in values),
        "canonical Boolean integers",
    )


def round_clear(active, bits, layout, omit_offset=False):
    """Exact p2 center coding, including dead tail slots and four secret lanes."""
    boolean_vector(active)
    boolean_vector(bits)
    need(len(active) == len(bits), "aligned vectors")
    need(layout in LAYOUTS, "registered bit layout")
    _, weight, rescale, alpha, beta = layout
    need(weight * rescale == 4 * beta, "exact A44-to-CM scale")
    n = len(active)
    padding = (-n) % 4
    aa = list(active) + [0] * padding
    bb = list(bits) + [0] * padding
    zero = [int(alpha * a + beta * b == alpha) for a, b in zip(aa, bb)]
    roots = [zero[i : i + 4] for i in range(0, len(zero), 4)]
    while len(roots) > 1:
        following = []
        for i in range(0, len(roots), 3):
            chunk = roots[i : i + 3]
            sums = [sum(row[lane] for row in chunk) for lane in range(4)]
            need(all(0 <= x <= 3 for x in sums), "radix-three p2 support")
            following.append([int(x != 0) for x in sums])
        roots = following
    pairs = [int(sum(roots[0][i : i + 2]) != 0) for i in (0, 2)]
    any_zero = int(sum(pairs) != 0)
    codes = [a + z - any_zero + int(not omit_offset) for a, z in zip(aa, zero)]
    if not omit_offset:
        need(all(0 <= x <= 2 for x in codes), "offset avoids negative p2 codes")
    output = [int(x == 2) for x in codes]
    return output[:n], output[n:]


def chain_clear(active, values, reset_active=False):
    """Feedback of logical outputs; reset_active is an explicit invalid control."""
    boolean_vector(active)
    need(len(active) == len(values), "aligned byte values")
    need(all(type(x) is int and 0 <= x < 256 for x in values), "byte domain")
    state = list(active)
    trace = []
    for layout in LAYOUTS:
        bits = [(x >> layout[0]) & 1 for x in values]
        state, tail = round_clear(active if reset_active else state, bits, layout)
        trace.append(dict(bit=layout[0], active=state.copy(), tail=tail))
    return state, trace


def oracle(active, values):
    live = [v for a, v in zip(active, values) if a]
    return [
        int(bool(a) and bool(live) and v == min(live)) for a, v in zip(active, values)
    ]


def schedule(n, rounds=8, persistent=True):
    """Enumerate functional calls, excluding fixture prep and diagnostic copies."""
    need(type(n) is int and 1 <= n <= 128, "registered gallery domain")
    need(type(rounds) is int and 1 <= rounds <= 8, "registered round count")
    groups = (n + 3) // 4
    events = []

    def put(stage, primitive, count=1):
        events.extend((stage, primitive, i) for i in range(count))

    def ingress(stage):
        put(stage, "packing", groups)
        put(stage, "cm_pbs", groups)

    def egress(stage):
        for primitive in ("extraction", "ordinary_ks", "ordinary_pbs"):
            put(stage, primitive, n)

    if persistent:
        ingress("initial")
    for level in range(rounds):
        stage = f"round/{level}"
        if not persistent:
            ingress(stage + "/ordinary_feedback_ingress")
        put(stage + "/bits", "packing", groups)
        put(stage + "/z", "cm_ks", groups)
        put(stage + "/z", "cm_pbs", groups)
        nodes = groups
        depth = 0
        while nodes > 1:
            non_singletons = nodes // 3 + int(nodes % 3 == 2)
            for primitive in ("cm_ks", "cm_pbs"):
                put(stage + f"/reduce/{depth}", primitive, non_singletons)
            nodes = (nodes + 2) // 3
            depth += 1
        put(stage + "/roots", "extraction", 4)
        put(stage + "/roots", "ordinary_ks", 4)
        put(stage + "/pairs", "ordinary_pbs", 2)
        put(stage + "/any", "ordinary_ks")
        put(stage + "/any", "ordinary_pbs")
        put(stage + "/broadcast", "packing")
        put(stage + "/update", "cm_ks", groups)
        put(stage + "/update", "cm_pbs", groups)
        if not persistent:
            egress(stage + "/ordinary_feedback_egress")
    if persistent:
        egress("final")
    counts = Counter(primitive for _, primitive, _ in events)
    return dict(counts={k: counts[k] for k in PRIMITIVES}, events=events)


def report():
    result = {}
    for n in (4, 127, 128):
        persistent = schedule(n)["counts"]
        wrapped = schedule(n, persistent=False)["counts"]
        result[str(n)] = dict(
            one_c1_round=schedule(n, rounds=1)["counts"],
            persistent_cm_eight_rounds=persistent,
            repeated_ordinary_feedback_eight_rounds=wrapped,
            extra_calls_if_wrapped={k: wrapped[k] - persistent[k] for k in PRIMITIVES},
            planned_split_fixture_preparation_ordinary_pbs=9 * n,
            unchanged_prepare_inputs_eight_calls_ordinary_pbs=16 * n,
        )
    return dict(
        status="STATIC_FEEDBACK_INTERFACE_AND_LEDGER",
        galleries=result,
        actual_fhe=False,
        ciphertext_feedback_validated=False,
        input_variance_attested=False,
        timing_claim=False,
        full_exact_id_validated=False,
    )
