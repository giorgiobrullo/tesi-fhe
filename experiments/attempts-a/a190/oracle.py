"""Independent exact signed-center oracle and N4 functional ledger, no candidate imports."""

Q = 1 << 64
D = 1 << 59
C = 1 << 61
ACTIVE = [1, 1, 1, 0]
VALUES = [173, 174, 173, 0]
LAYOUTS = [
    (7, 1, 4, 2, 1),
    (6, 1, 4, 2, 1),
    (5, 1, 4, 2, 1),
    (4, 1, 4, 2, 1),
    (3, 1, 4, 2, 1),
    (2, 8, 1, 1, 2),
    (1, 4, 1, 2, 1),
    (0, 2, 2, 2, 1),
]
CM_COUNTS = dict(
    packing=17, cm_ks=16, cm_pbs=17, ordinary_ks=44, ordinary_pbs=28, extraction=36
)


def target(x):
    x %= 32
    return int(x == 1) - int(x == 17)


def or_lut(x):
    x %= 32
    return int(1 <= x <= 15) - int(17 <= x <= 31)


def ordinary(active=ACTIVE, values=VALUES):
    states = {"initial": list(active)}
    events = {}
    c = list(active)
    for level, (bit, w, _, _, _) in enumerate(LAYOUTS):
        weighted = [(w if level == 5 else -w) * ((v >> bit) & 1) for v in values]
        z = []
        for i, (a, b) in enumerate(zip(c, weighted)):
            z.append(target(a + b))
            events[f"round/{level}/zero/{i}"] = (a + b, z[-1], "target")
        anyz = or_lut(sum(z))
        events[f"round/{level}/or/0/0"] = (sum(z), anyz, "or")
        linear = [a + b - anyz for a, b in zip(c, z)]
        c = list(linear)
        if level in (3, 7):
            c = [target(x) for x in linear]
            for i, (x, y) in enumerate(zip(linear, c)):
                events[f"round/{level}/refresh/{i}"] = (x, y, "target")
        for name, val in [
            ("weighted", weighted),
            ("zero", z),
            ("any", [anyz]),
            ("linear", linear),
            ("output", c),
        ]:
            states[f"round/{level}/{name}"] = list(val)
    return states, events


def chain(reset=False, active=ACTIVE, values=VALUES):
    traces = []
    rounds = []

    def put(tag, values, delta):
        traces.extend((tag, lane, v, delta) for lane, v in enumerate(values))

    put("ingress/active_pack/0", active, C)
    put("ingress/active_big/0", active, C)
    state = list(active)
    for level, (bit, w, rescale, alpha, beta) in enumerate(LAYOUTS):
        if reset:
            state = list(active)
        before = list(state)
        b = [(v >> bit) & 1 for v in values]
        z = [a * (1 - bb) for a, bb in zip(state, b)]
        anyz = int(any(z))
        nxt = [int(a and (not anyz or not bb)) for a, bb in zip(state, b)]
        p = f"round/{level}/"
        for tag, val, delta in [
            ("bit_pack/0", [beta * x for x in b], C),
            ("z_ks/0", state, C),
            ("z_input/0", [alpha * a + beta * x for a, x in zip(state, b)], C),
            ("z/0", z, C),
        ]:
            put(p + tag, val, delta)
        for lane, v in enumerate(z):
            traces.append((p + f"root_extracted/{lane}", lane, v, C))
            put(p + f"root_bridge/{lane}", [v], C)
        pairs = []
        for pair in range(2):
            total = sum(z[2 * pair : 2 * pair + 2])
            pairs.append(int(total != 0))
            put(p + f"pair_input/{pair}", [total], C)
            put(p + f"pair/{pair}", [pairs[-1]], D)
        put(p + "any_big_sum", [sum(pairs)], D)
        put(p + "any_input", [sum(pairs)], D)
        put(p + "any", [anyz], D)
        put(p + "broadcast", [anyz] * 4, C)
        put(p + "update_big_sum/0", [a + x for a, x in zip(state, z)], C)
        put(p + "update_sum/0", [a + x for a, x in zip(state, z)], C)
        put(p + "update_input/0", [a + x - anyz + 1 for a, x in zip(state, z)], C)
        put(p + "next/0", nxt, C)
        rounds.append((before, b, z, anyz, nxt))
        state = nxt
    for i, v in enumerate(state):
        traces.append((f"egress/extracted/{i}", i, v, C))
        put(f"egress/small/{i}", [v], C)
        put(f"egress/output/{i}", [v], D)
    return traces, rounds, state


def checkpoint_counts(level=None, after=False):
    c = dict(packing=1, cm_ks=0, cm_pbs=1, ordinary_ks=0, ordinary_pbs=0, extraction=0)
    rounds = 0 if level is None else level + int(after)
    for k, v in dict(
        packing=2, cm_ks=2, cm_pbs=2, ordinary_ks=5, ordinary_pbs=3, extraction=4
    ).items():
        c[k] += rounds * v
    return c
