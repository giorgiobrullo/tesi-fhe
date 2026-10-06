import itertools
import pathlib
import unittest


LOW_SELECTION_RADIX = 7
SCAN_OUTPUT_RADIX = 5


def reduce_step2(values: tuple[int, ...]) -> int:
    level = list(values)
    if not level or any(value not in (0, 2) for value in level):
        raise ValueError("expected a non-empty vector of step-two flags")
    while len(level) > 1:
        next_level = []
        for start in range(0, len(level), LOW_SELECTION_RADIX):
            chunk = level[start : start + LOW_SELECTION_RADIX]
            next_level.append(chunk[0] if len(chunk) == 1 else 2 * int(any(chunk)))
        level = next_level
    return level[0]


def reduction_nodes(items: int, radix: int, *, forward_singletons: bool) -> int:
    if items < 1 or radix < 2:
        raise ValueError("invalid reduction shape")
    nodes = 0
    while items > 1:
        full, tail = divmod(items, radix)
        nodes += full + int(tail >= 2) if forward_singletons else full + int(tail != 0)
        items = full + int(tail != 0)
    return nodes


def a40_counts(gallery_size: int) -> tuple[int, int, int]:
    # A38's disjoint ledger changes only by the eight low-selection trees.
    a38 = {
        1: (25, 22, 30),
        2: (60, 54, 69),
        3: (85, 76, 98),
        64: (1835, 1643, 2113),
        127: (3655, 3274, 4206),
        128: (3682, 3298, 4237),
    }[gallery_size]
    old_nodes = reduction_nodes(gallery_size, SCAN_OUTPUT_RADIX, forward_singletons=False)
    new_nodes = reduction_nodes(gallery_size, LOW_SELECTION_RADIX, forward_singletons=True)
    saving = 8 * (old_nodes - new_nodes)
    return tuple(value - saving for value in a38)


def reference_exact_id(scores: tuple[int, ...], threshold: int = 1023) -> int:
    winner, minimum = min(enumerate(scores), key=lambda item: (item[1], item[0]))
    return winner + 1 if minimum <= threshold else 0


def a36_gate_coverage(scores: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    admitted = [score for score in scores if score <= 1023]
    minimum_high = min((score >> 8 for score in admitted), default=None)
    candidates = [
        minimum_high is not None and score <= 1023 and score >> 8 == minimum_high
        for score in scores
    ]
    active_counts = []
    forwarded_singletons = []
    for bit in range(7, -1, -1):
        level = [
            candidate and ((score >> bit) & 1) == 0
            for score, candidate in zip(scores, candidates)
        ]
        while len(level) > 1:
            next_level = []
            for start in range(0, len(level), LOW_SELECTION_RADIX):
                chunk = level[start : start + LOW_SELECTION_RADIX]
                if len(chunk) == 1:
                    forwarded_singletons.append(2 * int(chunk[0]))
                    next_level.append(chunk[0])
                else:
                    active_counts.append(sum(chunk))
                    next_level.append(any(chunk))
            level = next_level
        any_zero = level[0]
        selected_bit = 0 if any_zero else 1
        candidates = [
            candidate and ((score >> bit) & 1) == selected_bit
            for score, candidate in zip(scores, candidates)
        ]
    return tuple(active_counts), tuple(forwarded_singletons)


def radix7_count_scores(active_at_b6: int) -> tuple[int, ...]:
    return (63,) * active_at_b6 + (64,) * (LOW_SELECTION_RADIX - active_at_b6)


class A40StaticTests(unittest.TestCase):
    def test_radix7_singleton_forwarding_preserves_or(self) -> None:
        for size in range(1, 13):
            for bits in itertools.product((0, 1), repeat=size):
                self.assertEqual(reduce_step2(tuple(2 * bit for bit in bits)), 2 * int(any(bits)))

    def test_structural_counts(self) -> None:
        expected = {
            1: (25, 22, 30),
            2: (60, 54, 69),
            3: (85, 76, 98),
            64: (1795, 1603, 2073),
            127: (3551, 3170, 4102),
            128: (3586, 3202, 4141),
        }
        self.assertEqual(reduction_nodes(127, 5, forward_singletons=False), 35)
        self.assertEqual(reduction_nodes(127, 7, forward_singletons=True), 22)
        for gallery_size, counts in expected.items():
            self.assertEqual(a40_counts(gallery_size), counts)

    def test_exact_id_boundaries_reject_and_first_tie(self) -> None:
        fixtures = (
            ((1023,), 1),
            ((1024,), 0),
            ((1024, 1023), 2),
            ((1023, 1023), 1),
            ((511, 256, 256), 2),
            ((1000,) * 126 + (0,), 127),
            ((1000,) * 127 + (0,), 128),
            ((1000,) * 63 + (0,) + (1000,) * 62 + (0,), 64),
        )
        for scores, expected in fixtures:
            self.assertEqual(reference_exact_id(scores), expected)

    def test_targeted_fhe_fixtures_cover_every_count_and_both_singleton_values(self) -> None:
        covered_counts = set()
        for active_at_b6 in range(LOW_SELECTION_RADIX + 1):
            scores = radix7_count_scores(active_at_b6)
            counts, singletons = a36_gate_coverage(scores)
            self.assertFalse(singletons)
            self.assertIn(7, counts)
            self.assertIn(active_at_b6, counts)
            self.assertEqual(reference_exact_id(scores), 1)
            self.assertTrue(all(score - 63 in (0, 1) for score in scores))
            covered_counts.update(counts)
        self.assertEqual(covered_counts, set(range(8)))

        for scores in ((63,) * 7 + (64,), (63,) * 126 + (64,)):
            counts, singletons = a36_gate_coverage(scores)
            self.assertIn(7, counts)
            self.assertEqual(set(singletons), {0, 2})
            self.assertEqual(reference_exact_id(scores), 1)

    def test_rust_scope_guard_keeps_scan_output_radix5(self) -> None:
        root = pathlib.Path(__file__).parent
        source = (root / "src/private_argmin.rs").read_text()
        self.assertIn("const A40_LOW_SELECTION_RADIX: usize = 7;", source)
        self.assertIn("const A40_SCAN_OUTPUT_RADIX: usize = 5;", source)
        self.assertEqual(source.count(".par_chunks(A40_LOW_SELECTION_RADIX)"), 1)
        self.assertGreaterEqual(source.count(".par_chunks(A40_SCAN_OUTPUT_RADIX)"), 2)
        self.assertIn("body[box_size..15 * box_size]", source)
        self.assertIn("if chunk.len() == 1", source)

        harness = (root / "src/bin/a40_radix7_prototype.rs").read_text()
        self.assertIn("(0..=LOW_SELECTION_RADIX).map(radix7_count_case)", harness)
        self.assertIn('name: "n8_radix7_singleton_both_values"', harness)
        self.assertIn(
            'name: "n127_radix7_full_fanin_singleton_both_values"', harness
        )
        self.assertEqual(harness.count("threshold: 960"), 3)


if __name__ == "__main__":
    unittest.main()
