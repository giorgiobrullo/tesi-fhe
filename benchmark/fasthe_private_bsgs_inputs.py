#!/usr/bin/env python3
"""Generate deterministic FastHE plumbing cases for private BSGS selection."""

import argparse
import hashlib
from pathlib import Path
from typing import List, Optional


DIMENSION = 512
CASES = ((64, 37), (128, 73))


def unit(axis: int) -> List[float]:
    values = [0.0] * DIMENSION
    values[axis] = 1.0
    return values


def write_case(path: Path, size: int, genuine_index: Optional[int]) -> None:
    query = unit(0)
    database = []
    for index in range(size):
        if index == genuine_index:
            database.append(query.copy())
        else:
            # Every impostor is exactly orthogonal to the query. The cases test
            # encrypted routing/selection, not a face model's accuracy.
            database.append(unit(index + 1))

    with path.open("w", encoding="ascii") as output:
        output.write("{}\n".format(size))
        output.write(" ".join(map(str, query)) + "\n")
        for vector in database:
            output.write(" ".join(map(str, vector)) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    for size, genuine_index in CASES:
        paths = (
            (args.output / "n{}_genuine.dat".format(size), genuine_index),
            (args.output / "n{}_zero_match.dat".format(size), None),
        )
        for path, target in paths:
            write_case(path, size, target)
            print("{}  {}".format(sha256(path), path))


if __name__ == "__main__":
    main()
