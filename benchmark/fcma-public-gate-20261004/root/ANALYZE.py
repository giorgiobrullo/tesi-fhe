from pathlib import Path
import hashlib, json, math, statistics
U = Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rot(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)
validation = [json.loads(x) for x in (U / "logs/validate.stdout").read_text().splitlines()]
oracle = json.loads((U / "logs/ORACLE.json").read_text())
assert oracle["status"] == "PASS" and oracle["input_sha256"] == sha(U / "logs/validate.stdout")
assert oracle["rows_checked"] == 8192
expected = {}
for backend in ("neon", "fcma"):
    checksum = 0x9e3779b97f4a7c15
    rows = [x for x in validation[1:-1] if x["case"] == 1]
    assert len(rows) == 2048 and [x["index"] for x in rows] == list(range(2048))
    for row in rows:
        real, imag = (int(x, 16) for x in row[backend + "_final"])
        checksum = rot(rot(checksum, 7) ^ real, 11) ^ imag
    expected[backend] = f"{checksum:016x}"
path = U / "logs/bench.stdout"
records = [json.loads(x) for x in path.read_text().splitlines()]
assert len(records) == 34
header, footer = records[0], records[-1]
assert header["schema"] == "fcma_public_bench_v1" and header["cases"] == 1 and header["dataset_case"] == 1
assert header["warmup_pairs"] == 64 and header["fpcr"] == footer["fpcr"] == oracle["fpcr"]
assert footer["status"] == "BENCH_COMPLETE" and footer["batches"] == 32
blocks, all_ns = [], {"neon": [], "fcma": []}
for block in range(8):
    rows = records[1 + 4 * block:5 + 4 * block]
    order = ["neon", "fcma", "fcma", "neon"] if block % 2 == 0 else ["fcma", "neon", "neon", "fcma"]
    assert [x["backend"] for x in rows] == order
    values = {"neon": [], "fcma": []}
    for position, row in enumerate(rows):
        assert row["block"] == block and row["position"] == position
        assert row["repetitions"] == 1000 and row["elapsed_ns"] > 0
        assert row["checksum"] == expected[row["backend"]]
        ns = row["elapsed_ns"] / 1000
        values[row["backend"]].append(ns)
        all_ns[row["backend"]].append(ns)
    n = math.sqrt(math.prod(values["neon"]))
    f = math.sqrt(math.prod(values["fcma"]))
    blocks.append({"block": block, "neon_ns_per_pair_geomean": n, "fcma_ns_per_pair_geomean": f, "fcma_over_neon": f / n})
ratios = [x["fcma_over_neon"] for x in blocks]
ratio = math.exp(statistics.mean(math.log(x) for x in ratios))
result = {"status": "PASS_RECORD_VALIDATION", "lead": "PUBLIC_GATE_FASTER" if ratio < 1 else "PUBLIC_GATE_REJECTED_SLOWER", "input_sha256": sha(path), "validation_sha256": sha(U / "logs/validate.stdout"), "batches": 32, "blocks": blocks, "fcma_over_neon_geomean": ratio, "relative_change_percent": 100 * (ratio - 1), "wins_of_8_blocks": sum(x < 1 for x in ratios), "ratio_min": min(ratios), "ratio_max": max(ratios), "median_ns_per_pair": {k: statistics.median(v) for k, v in all_ns.items()}, "expected_checksums": expected, "scope": "single-thread hot synthetic public pointwise boundary; host scheduling/load uncontrolled; no service/FHE/noise gain"}
with (U / "logs/ANALYSIS.json").open("x") as out: json.dump(result, out, indent=2); out.write("\n")
print(json.dumps({k: v for k, v in result.items() if k != "blocks"}))
