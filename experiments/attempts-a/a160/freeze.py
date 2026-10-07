"""Create A160 static evidence and source identity once; no child or FHE."""

import io
import json
import unittest

import audit
from audit import HERE, a158, sha
from run_gate import write_new
from test_gate import synthetic_chain


def main():
    for name in (
        "SOURCE_MANIFEST.json",
        "candidate/SOURCE_DIGEST.txt",
        "STATIC_RESULT.json",
        "ARTIFACT_MANIFEST.json",
    ):
        assert not (HERE / name).exists(), "frozen outputs must not be replaced"
    pins = audit.verify_origins()
    manifest = audit.source_manifest()
    source = audit.source_id(manifest)
    with (HERE / "SOURCE_MANIFEST.json").open("x") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    with (HERE / "candidate/SOURCE_DIGEST.txt").open("x") as f:
        f.write(source + "\n")
    assert audit.verify_source() == source
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromName("test_gate")
    )
    assert result.wasSuccessful(), stream.getvalue()
    artifacts = HERE / "static-artifacts"
    artifacts.mkdir(mode=0o700)
    cases = []
    for name, args in [
        ("safe", {}),
        ("native_pass_ms_fail", dict(error=1000 * a158.U, displacement64=True)),
    ]:
        records = synthetic_chain(**args)
        observed = a158.verify(records[0], records[2])
        write_new(
            artifacts / f"{name}.json",
            dict(
                evidence_kind="SYNTHETIC_NO_KEYS_NO_ENCRYPTION",
                records=records,
                a158_result=observed,
            ),
        )
        cases.append(
            dict(
                name=name,
                native_first_bit_decode_pass=observed["native_first_bit_decode_pass"],
                conditional_lut_address_pass=observed["conditional_lut_address_pass"],
                selected_prefix_gate_pass=observed["selected_prefix_gate_pass"],
            )
        )
    summary = dict(
        status="STATIC_SOURCE_AND_SYNTHETIC_READY",
        source_sha256=source,
        upstream_source_pins=pins,
        own_source_files=len(manifest),
        tests_run=result.testsRun,
        test_output=stream.getvalue(),
        cases=cases,
        rustfmt_parse_only=True,
        cargo_invoked=False,
        rust_typecheck=False,
        actual_fhe_execution=False,
        actual_input_records=False,
        actual_sampler_p_fail=None,
        static_artifacts_sha256={p.name: sha(p) for p in sorted(artifacts.iterdir())},
    )
    with (HERE / "STATIC_RESULT.json").open("x") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    files = sorted(p for p in HERE.rglob("*") if p.is_file())
    with (HERE / "ARTIFACT_MANIFEST.json").open("x") as f:
        json.dump(
            {str(p.relative_to(HERE)): sha(p) for p in files},
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")
    print(
        json.dumps(
            dict(
                source_sha256=source,
                files=len(files),
                tests=result.testsRun,
                manifest_sha256=sha(HERE / "ARTIFACT_MANIFEST.json"),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
