"""Compatibility entry point for the canonical demo calibration.

The historical version of this script used the random five-image embedding cache. It therefore
did not reproduce the deterministic 2+3 files used by the live demo and produced the obsolete
thresholds T=23/T=269.

The authoritative implementation is now demo/calibra.py. This wrapper forwards its command line
so old invocations run the audited path instead of silently regenerating stale claims.
"""

from __future__ import annotations

import pathlib
import runpy
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CALIBRATOR = ROOT / "demo" / "calibra.py"


if __name__ == "__main__":
    sys.argv = [str(CALIBRATOR), *sys.argv[1:]]
    runpy.run_path(str(CALIBRATOR), run_name="__main__")
