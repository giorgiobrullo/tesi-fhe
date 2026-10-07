#!/usr/bin/env python3
"""Audit the pinned EPFL 128-input priority RTL and compare only structural counts.

The script never downloads anything.  It accepts a caller-provided copy of the official RTL,
checks its SHA-256, evaluates diagnostic Boolean patterns, and reads the source-pinned A53 clear
model.  It does not turn the BOLT paper's gate counts into a matched runtime estimate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import runpy
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence


OFFICIAL_RTL_URL = (
    "https://raw.githubusercontent.com/lsils/benchmarks/"
    "master/random_control/priority.v"
)
OFFICIAL_RTL_SHA256 = "2b29f270d3f6db4cbf6307cb29d1a1192c82dd9ea08d9a8c7f8d02ef469b32f5"
A53_MODEL_RELATIVE = pathlib.Path(
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py"
)
A53_MODEL_SHA256 = "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f"
INPUTS = 128
OUTPUT_BITS = 7
BOLT_FINAL_GATE_NODES = 686
BOLT_RUNTIME_MS = 4_221
SINGH_FINAL_GATE_NODES = 681
SINGH_RUNTIME_MS = 7_342
YU_FINAL_GATE_NODES = 818
YU_RUNTIME_MS = 32_720


class AuditError(RuntimeError):
    """The source or its evaluated contract did not match the frozen audit."""


@dataclass(frozen=True)
class Output:
    index: int
    valid: int


@dataclass(frozen=True)
class StructuralComparison:
    input_flags: int
    epfl_output_index_bits: int
    epfl_output_valid_bits: int
    a53_output_p16_digits: int
    bolt_final_gate_nodes: int
    a53_blind_rotations: int
    a53_key_switches: int
    a53_marginals: int
    operation_count_ratio_a53_br_over_bolt_gate: float
    arithmetic_count_complement_percent: float
    bolt_gate_nodes_per_a53_blind_rotation: float


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def normalize_escaped_ports(text: str) -> str:
    # Verilog escaped identifiers end at whitespace.  The benchmark only uses this form for
    # A[i] and P[i], so normalize exactly that narrow grammar.
    return re.sub(r"\\([AP]\[\d+\])\s+", r"\1 ", text)


def parse_assignments(text: str) -> tuple[tuple[str, str], ...]:
    assignments: list[tuple[str, str]] = []
    for line in normalize_escaped_ports(text).splitlines():
        match = re.fullmatch(r"\s*assign\s+(\S+)\s*=\s*(.*?)\s*;\s*", line)
        if match is not None:
            assignments.append(match.groups())
    if not assignments:
        raise AuditError("no single-line assign statements found")
    outputs = [left for left, _ in assignments]
    if len(set(outputs)) != len(outputs):
        raise AuditError("assignment graph has duplicate producers")
    return tuple(assignments)


class ExpressionParser:
    def __init__(self, expression: str, environment: Mapping[str, int]) -> None:
        self.expression = expression
        self.environment = environment
        self.tokens = re.findall(
            r"~|&|\||\(|\)|[A-Za-z_][A-Za-z_0-9]*(?:\[\d+\])?",
            expression,
        )
        compact = re.sub(r"\s+", "", expression)
        if "".join(self.tokens) != compact:
            raise AuditError(f"unsupported expression token in {expression!r}")
        self.position = 0

    def evaluate(self) -> int:
        value = self._or_expression()
        if self.position != len(self.tokens):
            raise AuditError(f"unparsed expression suffix in {self.expression!r}")
        if value not in (0, 1):
            raise AuditError("Boolean expression escaped the 0/1 domain")
        return value

    def _atom(self) -> int:
        if self.position >= len(self.tokens):
            raise AuditError(f"truncated expression {self.expression!r}")
        token = self.tokens[self.position]
        if token == "~":
            self.position += 1
            return 1 - self._atom()
        if token == "(":
            self.position += 1
            value = self._or_expression()
            if self.position >= len(self.tokens) or self.tokens[self.position] != ")":
                raise AuditError(f"unbalanced expression {self.expression!r}")
            self.position += 1
            return value
        self.position += 1
        try:
            return self.environment[token]
        except KeyError as error:
            raise AuditError(f"missing producer for {token!r}") from error

    def _and_expression(self) -> int:
        value = self._atom()
        while self.position < len(self.tokens) and self.tokens[self.position] == "&":
            self.position += 1
            value &= self._atom()
        return value

    def _or_expression(self) -> int:
        value = self._and_expression()
        while self.position < len(self.tokens) and self.tokens[self.position] == "|":
            self.position += 1
            value |= self._and_expression()
        return value


class SymbolicExpressionParser:
    """Parse the same frozen RTL grammar into Z3 Boolean expressions."""

    def __init__(self, expression: str, environment: Mapping[str, Any]) -> None:
        import z3

        self.z3 = z3
        self.expression = expression
        self.environment = environment
        self.tokens = re.findall(
            r"~|&|\||\(|\)|[A-Za-z_][A-Za-z_0-9]*(?:\[\d+\])?",
            expression,
        )
        compact = re.sub(r"\s+", "", expression)
        if "".join(self.tokens) != compact:
            raise AuditError(f"unsupported expression token in {expression!r}")
        self.position = 0

    def evaluate(self) -> Any:
        value = self._or_expression()
        if self.position != len(self.tokens):
            raise AuditError(f"unparsed expression suffix in {self.expression!r}")
        return value

    def _atom(self) -> Any:
        if self.position >= len(self.tokens):
            raise AuditError(f"truncated expression {self.expression!r}")
        token = self.tokens[self.position]
        if token == "~":
            self.position += 1
            return self.z3.Not(self._atom())
        if token == "(":
            self.position += 1
            value = self._or_expression()
            if self.position >= len(self.tokens) or self.tokens[self.position] != ")":
                raise AuditError(f"unbalanced expression {self.expression!r}")
            self.position += 1
            return value
        self.position += 1
        try:
            return self.environment[token]
        except KeyError as error:
            raise AuditError(f"missing producer for {token!r}") from error

    def _and_expression(self) -> Any:
        value = self._atom()
        while self.position < len(self.tokens) and self.tokens[self.position] == "&":
            self.position += 1
            value = self.z3.And(value, self._atom())
        return value

    def _or_expression(self) -> Any:
        value = self._and_expression()
        while self.position < len(self.tokens) and self.tokens[self.position] == "|":
            self.position += 1
            value = self.z3.Or(value, self._and_expression())
        return value


def evaluate_assignments(
    assignments: Sequence[tuple[str, str]],
    inputs: Mapping[str, int],
) -> dict[str, int]:
    environment = dict(inputs)
    for output, expression in assignments:
        environment[output] = ExpressionParser(expression, environment).evaluate()
    return environment


def evaluate_priority(
    assignments: Sequence[tuple[str, str]], active: Iterable[int]
) -> Output:
    active_set = set(active)
    if any(index < 0 or index >= INPUTS for index in active_set):
        raise AuditError("active input index is outside 0..127")
    inputs = {f"A[{index}]": int(index in active_set) for index in range(INPUTS)}
    result = evaluate_assignments(assignments, inputs)
    try:
        output_index = sum(result[f"P[{bit}]"] << bit for bit in range(OUTPUT_BITS))
        valid = result["F"]
    except KeyError as error:
        raise AuditError(f"missing EPFL output {error.args[0]!r}") from error
    return Output(index=output_index, valid=valid)


def decode_reversed_exact_code(output: Output, input_flags: int = INPUTS) -> int:
    """Decode the reversed-input EPFL wire format into exact tie-first 0/ID."""

    if output.valid not in (0, 1):
        raise AuditError("priority valid flag escaped the Boolean domain")
    if output.index < 0 or output.index >= input_flags:
        raise AuditError("priority index is outside the declared input range")
    return input_flags - output.index if output.valid else 0


def formally_prove_reversed_exact_contract(
    assignments: Sequence[tuple[str, str]],
    *,
    input_flags: int = INPUTS,
    output_bits: int = OUTPUT_BITS,
) -> dict[str, object]:
    """Prove the parsed netlist plus public decode equals tie-first 0/ID.

    Original gallery flag ``g[i]`` is wired publicly to ``A[input_flags-1-i]``.
    The solver searches for any Boolean assignment on which the RTL valid/index
    output, decoded as ``valid ? input_flags-index : 0``, differs from the first
    active original gallery ID.  UNSAT is therefore exhaustive for the parsed
    Boolean model, not statistical sampling.
    """

    import z3

    if input_flags < 1 or output_bits < 1 or 1 << output_bits < input_flags:
        raise AuditError("invalid formal priority dimensions")
    gallery = [z3.Bool(f"g_{index}") for index in range(input_flags)]
    environment: dict[str, Any] = {
        f"A[{input_flags - 1 - index}]": flag
        for index, flag in enumerate(gallery)
    }
    for output, expression in assignments:
        environment[output] = SymbolicExpressionParser(
            expression, environment
        ).evaluate()
    try:
        valid = environment["F"]
        bits = [environment[f"P[{bit}]"] for bit in range(output_bits)]
    except KeyError as error:
        raise AuditError(f"missing EPFL output {error.args[0]!r}") from error

    encoded_index = z3.Sum(
        [z3.If(bit, 1 << position, 0) for position, bit in enumerate(bits)]
    )
    decoded_code = z3.If(valid, input_flags - encoded_index, 0)
    first_active_terms = []
    no_earlier = z3.BoolVal(True)
    for index, flag in enumerate(gallery):
        first_here = z3.And(no_earlier, flag)
        first_active_terms.append(z3.If(first_here, index + 1, 0))
        no_earlier = z3.And(no_earlier, z3.Not(flag))
    expected_code = z3.Sum(first_active_terms)
    expected_valid = z3.Or(gallery)

    solver = z3.Solver()
    solver.add(z3.Or(valid != expected_valid, decoded_code != expected_code))
    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        active = [
            index for index, flag in enumerate(gallery) if z3.is_true(model.eval(flag))
        ]
        raise AuditError(f"formal contract counterexample at active gallery flags {active}")
    if result != z3.unsat:
        raise AuditError(f"formal solver returned {result}")
    return {
        "status": "UNSAT_NO_COUNTEREXAMPLE",
        "solver": "Z3",
        "solver_version": z3.get_version_string(),
        "symbolic_boolean_inputs": input_flags,
        "covered_assignments": f"2^{input_flags}",
        "public_input_map": f"A[{input_flags - 1}-i] = gallery_flag[i]",
        "public_output_decode": f"code = 0 if F=0 else {input_flags}-P",
        "proved_contract": "0 reject; otherwise first active gallery index plus one",
    }


def load_a53_counts(root: pathlib.Path) -> tuple[int, int, int]:
    path = root / A53_MODEL_RELATIVE
    actual = sha256_file(path)
    if actual != A53_MODEL_SHA256:
        raise AuditError(f"A53 source drift: {actual}")
    namespace = runpy.run_path(str(path))
    counts = namespace["scan_counts"](INPUTS).total
    return counts.blind_rotations, counts.key_switches, counts.output_marginals


def structural_comparison(root: pathlib.Path | None = None) -> StructuralComparison:
    root = repository_root() if root is None else root
    blind_rotations, key_switches, marginals = load_a53_counts(root)
    ratio = blind_rotations / BOLT_FINAL_GATE_NODES
    return StructuralComparison(
        input_flags=INPUTS,
        epfl_output_index_bits=OUTPUT_BITS,
        epfl_output_valid_bits=1,
        a53_output_p16_digits=2,
        bolt_final_gate_nodes=BOLT_FINAL_GATE_NODES,
        a53_blind_rotations=blind_rotations,
        a53_key_switches=key_switches,
        a53_marginals=marginals,
        operation_count_ratio_a53_br_over_bolt_gate=ratio,
        arithmetic_count_complement_percent=100.0 * (1.0 - ratio),
        bolt_gate_nodes_per_a53_blind_rotation=BOLT_FINAL_GATE_NODES / blind_rotations,
    )


def audit_official_rtl(path: pathlib.Path) -> dict[str, object]:
    actual_sha256 = sha256_file(path)
    if actual_sha256 != OFFICIAL_RTL_SHA256:
        raise AuditError(f"official RTL hash drift: {actual_sha256}")
    assignments = parse_assignments(path.read_text())
    if len(assignments) != 978:
        raise AuditError(f"assignment count drift: {len(assignments)}")
    zero = evaluate_priority(assignments, ())
    one_hot = tuple(evaluate_priority(assignments, (index,)) for index in range(INPUTS))
    adjacent_pairs = tuple(
        evaluate_priority(assignments, (index, index + 1)) for index in range(INPUTS - 1)
    )
    endpoint_pair = evaluate_priority(assignments, (0, INPUTS - 1))
    all_active = evaluate_priority(assignments, range(INPUTS))
    formal_contract = formally_prove_reversed_exact_contract(assignments)
    if zero != Output(index=0, valid=0):
        raise AuditError(f"zero-input contract drift: {zero}")
    if any(output != Output(index=index, valid=1) for index, output in enumerate(one_hot)):
        raise AuditError("one-hot index mapping drift")
    if any(
        output != Output(index=index + 1, valid=1)
        for index, output in enumerate(adjacent_pairs)
    ):
        raise AuditError("adjacent-pair high-priority mapping drift")
    if endpoint_pair != Output(index=INPUTS - 1, valid=1):
        raise AuditError("endpoint priority direction drift")
    if all_active != Output(index=INPUTS - 1, valid=1):
        raise AuditError("all-active priority direction drift")
    return {
        "status": "PASS_STRUCTURAL_ONLY_NOT_MATCHED_RUNTIME",
        "rtl": {
            "url": OFFICIAL_RTL_URL,
            "sha256": actual_sha256,
            "assignments": len(assignments),
            "bolt_table_initial_gate_nodes": 974,
            "source_assignments_minus_bolt_initial_row": len(assignments) - 974,
            "input_flags": INPUTS,
            "output_index_bits": OUTPUT_BITS,
            "output_valid_bits": 1,
            "tested_patterns": 1 + INPUTS + (INPUTS - 1) + 2,
            "zero": asdict(zero),
            "one_hot_identity": True,
            "observed_priority_direction": "highest_active_input_index",
            "reversed_one_hot_exact_codes": [
                decode_reversed_exact_code(
                    evaluate_priority(assignments, (INPUTS - 1 - index,))
                )
                for index in range(INPUTS)
            ],
            "endpoint_pair": asdict(endpoint_pair),
            "all_active": asdict(all_active),
        },
        "formal_reversed_exact_contract": formal_contract,
        "paper_rows": {
            "yu": {"final_gate_nodes": YU_FINAL_GATE_NODES, "runtime_ms": YU_RUNTIME_MS},
            "singh": {
                "final_gate_nodes": SINGH_FINAL_GATE_NODES,
                "runtime_ms": SINGH_RUNTIME_MS,
            },
            "bolt": {
                "final_gate_nodes": BOLT_FINAL_GATE_NODES,
                "runtime_ms": BOLT_RUNTIME_MS,
            },
        },
        "a53_vs_bolt": asdict(structural_comparison()),
        "claim_boundary": {
            "structural_ratio_only": True,
            "matched_runtime": False,
            "same_parameters": False,
            "same_output_encoding": False,
            "same_operation_unit": False,
            "input_reversal_needed_for_a53_tie_left": True,
            "public_output_decode_needed": True,
            "public_output_decode_counted_as_fhe_work": False,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rtl", type=pathlib.Path)
    args = parser.parse_args(argv)
    print(json.dumps(audit_official_rtl(args.rtl), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
