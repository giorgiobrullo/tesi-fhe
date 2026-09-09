"""Focused client regressions that do not load the face model or generate FHE keys."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from demo.client import app as client


class DemoClientTest(unittest.TestCase):
    key_fingerprint = "a" * 64
    snapshot = {
        "epoch": 91,
        "revision": 7,
        "nomi": ["alice"],
        "iscritti": 1,
        "chiave": True,
        "chiave_sha256": key_fingerprint,
        "contratto_esatto": {
            chiave: client.CFG["contratto_esatto"][chiave]
            for chiave in (
                "wire_version",
                "probe_layout",
                "score_delta_log",
                "low_mod16_offset",
                "low_mod16_delta_log",
                "output_mode",
                "code_delta_log",
                "codice",
                "un_solo_lwe",
            )
        },
    }

    def protocol_server(self) -> mock.Mock:
        def serve(
            path: str, *_args: object, **_kwargs: object
        ) -> tuple[bytes, dict[str, str]]:
            if path == "/stato":
                return json.dumps(self.snapshot).encode(), {}
            if path == "/varco":
                return b"result", {
                    "X-Tempo-Ms": "1.2",
                    "X-Pbs": "42",
                    "X-Varco-Contract": "exact-open-set-id-v2",
                }
            raise AssertionError(path)

        return mock.Mock(side_effect=serve)

    def decrypted(self, *, authorized: bool, index: int | None) -> dict[str, object]:
        return {
            "autorizzato": authorized,
            "indice": index,
            "codice": index + 1 if authorized and index is not None else 0,
            "iscritti": self.snapshot["iscritti"],
            "galleria_epoch": self.snapshot["epoch"],
            "galleria_revision": self.snapshot["revision"],
        }

    def verify_with(
        self, decrypted: dict[str, object], server: mock.Mock
    ) -> dict[str, object]:
        details = {"embedding_ms": 1.0, "frame": 3}
        with (
            mock.patch.object(client, "da_dataurl", return_value=object()),
            mock.patch.object(
                client,
                "embedding_fuso",
                return_value=(
                    client.np.zeros(int(client.CFG["dim"]), dtype=int),
                    details,
                ),
            ),
            mock.patch.object(client, "assicura_chiave"),
            mock.patch.object(
                client,
                "fingerprint_chiave_locale",
                return_value=self.key_fingerprint,
            ),
            mock.patch.object(client, "cifra", return_value=(b"probe", {})),
            mock.patch.object(client, "decifra", return_value=decrypted),
            mock.patch.object(client, "srv", server),
        ):
            return client.verifica(client.Frames(frames=["data:image/png;base64,AA=="]))

    def test_accepted_index_is_mapped_against_the_pre_query_snapshot(self) -> None:
        server = self.protocol_server()
        response = self.verify_with(self.decrypted(authorized=True, index=0), server)

        self.assertEqual(response["esito"], "aperto")
        self.assertEqual(response["identita"], "alice")
        self.assertEqual(response["protocollo_http"], "exact-open-set-id-v2")
        self.assertNotIn("template_primi", response)
        self.assertNotIn("cifrato_primi", response)
        self.assertEqual(
            [call.args[0] for call in server.call_args_list], ["/stato", "/varco"]
        )

    def test_rejection_releases_no_identity(self) -> None:
        response = self.verify_with(
            self.decrypted(authorized=False, index=None), self.protocol_server()
        )

        self.assertEqual(response["esito"], "negato")
        self.assertIsNone(response["identita"])

    def test_state_exposes_whether_this_process_has_loaded_the_model(self) -> None:
        with (
            mock.patch.object(
                client,
                "srv",
                return_value=(json.dumps(self.snapshot).encode(), {}),
            ),
            mock.patch.dict(client._emb, {}, clear=True),
        ):
            self.assertIs(client.stato()["client"]["modello_caricato"], False)
            client._emb["ec"] = object()
            self.assertIs(client.stato()["client"]["modello_caricato"], True)

    def test_missing_or_legacy_http_contract_fails_closed(self) -> None:
        for headers in ({}, {"X-Varco-Contract": "periodic-fold-v1"}):
            with self.subTest(headers=headers):
                server = self.protocol_server()

                def without_exact_header(
                    path: str, *_args: object, **_kwargs: object
                ) -> tuple[bytes, dict[str, str]]:
                    if path == "/stato":
                        return json.dumps(self.snapshot).encode(), {}
                    if path == "/varco":
                        return b"result", headers
                    raise AssertionError(path)

                server.side_effect = without_exact_header
                with self.assertRaisesRegex(RuntimeError, "contratto HTTP exact"):
                    self.verify_with(self.decrypted(authorized=True, index=0), server)

    def test_gallery_version_or_size_mismatch_fails_closed(self) -> None:
        for field in ("galleria_epoch", "galleria_revision", "iscritti"):
            with self.subTest(field=field):
                decrypted = self.decrypted(authorized=True, index=0)
                decrypted[field] = int(decrypted[field]) + 1
                with self.assertRaisesRegex(RuntimeError, "galleria e' cambiata"):
                    self.verify_with(decrypted, self.protocol_server())

    def test_invalid_or_legacy_decrypted_contract_fails_closed(self) -> None:
        snapshot = {
            "epoch": self.snapshot["epoch"],
            "revision": self.snapshot["revision"],
            "nomi": tuple(self.snapshot["nomi"]),
            "iscritti": self.snapshot["iscritti"],
        }
        invalid = [
            {"conteggio": 1, "indice": 0},
            self.decrypted(authorized=True, index=None),
            self.decrypted(authorized=False, index=0),
            {**self.decrypted(authorized=True, index=0), "codice": 0},
        ]
        for decrypted in invalid:
            with self.subTest(decrypted=decrypted):
                with self.assertRaises(RuntimeError):
                    client.identita_da_esito(decrypted, snapshot)

    def test_snapshot_rejects_an_incoherent_name_map(self) -> None:
        state = {**self.snapshot, "iscritti": 2}
        with (
            mock.patch.object(
                client, "srv", return_value=(json.dumps(state).encode(), {})
            ),
            mock.patch.object(
                client,
                "fingerprint_chiave_locale",
                return_value=self.key_fingerprint,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "mappa nomi"):
                client.snapshot_galleria()

    def test_snapshot_rejects_a_legacy_or_different_server_contract(self) -> None:
        for state, message in (
            (
                {
                    key: value
                    for key, value in self.snapshot.items()
                    if key != "contratto_esatto"
                },
                "mancano contratto_esatto",
            ),
            (
                {
                    **self.snapshot,
                    "contratto_esatto": {
                        **self.snapshot["contratto_esatto"],
                        "output_mode": 1,
                    },
                },
                "contratto di identificazione esatta",
            ),
        ):
            with self.subTest(state=state):
                with (
                    mock.patch.object(
                        client, "srv", return_value=(json.dumps(state).encode(), {})
                    ),
                    mock.patch.object(
                        client,
                        "fingerprint_chiave_locale",
                        return_value=self.key_fingerprint,
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, message):
                        client.snapshot_galleria()

    def test_snapshot_rejects_a_different_evaluation_key(self) -> None:
        state = {**self.snapshot, "chiave_sha256": "b" * 64}
        with (
            mock.patch.object(
                client, "srv", return_value=(json.dumps(state).encode(), {})
            ),
            mock.patch.object(
                client,
                "fingerprint_chiave_locale",
                return_value=self.key_fingerprint,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "non coincide"):
                client.snapshot_galleria()

    def test_local_evaluation_key_fingerprint_is_cached_and_tracks_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            keys = pathlib.Path(directory)
            key_path = keys / "server.key"
            key_path.write_bytes(b"first")
            with mock.patch.object(client, "CHIAVI", keys):
                client._CHIAVE_HASH_CACHE = None
                first = client.fingerprint_chiave_locale()
                cached = client.fingerprint_chiave_locale()
                self.assertEqual(first, hashlib.sha256(b"first").hexdigest())
                self.assertEqual(cached, first)

                key_path.write_bytes(b"replacement-with-different-size")
                second = client.fingerprint_chiave_locale()
                self.assertEqual(
                    second,
                    hashlib.sha256(b"replacement-with-different-size").hexdigest(),
                )
                self.assertNotEqual(second, first)

    def test_key_upload_is_verified_against_the_post_upload_state(self) -> None:
        raw_key = b"evaluation-key"
        fingerprint = hashlib.sha256(raw_key).hexdigest()
        responses = iter(
            (
                ({"chiave": False, "chiave_sha256": None}, "/stato"),
                ({"ok": True}, "/chiave"),
                (
                    {"chiave": True, "chiave_sha256": fingerprint},
                    "/stato",
                ),
            )
        )

        def server(path, *_args, **_kwargs):
            payload, expected_path = next(responses)
            self.assertEqual(path, expected_path)
            return json.dumps(payload).encode(), {}

        with tempfile.TemporaryDirectory() as directory:
            keys = pathlib.Path(directory)
            (keys / "server.key").write_bytes(raw_key)
            with (
                mock.patch.object(client, "CHIAVI", keys),
                mock.patch.object(client, "srv", side_effect=server),
                mock.patch.object(client, "log"),
            ):
                self.assertIs(client.assicura_chiave(), True)

    def test_existing_server_key_mismatch_fails_closed(self) -> None:
        state = {
            "chiave": True,
            "chiave_sha256": "b" * 64,
        }
        with (
            mock.patch.object(
                client,
                "srv",
                return_value=(json.dumps(state).encode(), {}),
            ),
            mock.patch.object(
                client,
                "fingerprint_chiave_locale",
                return_value=self.key_fingerprint,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "non coincide"):
                client.assicura_chiave()

    def test_encrypt_uses_the_fixed_dual_scale_wire_without_a_cli_delta(self) -> None:
        calls: list[tuple[object, ...]] = []

        def fake_run(*args: object) -> dict[str, object]:
            calls.append(args)
            client.pathlib.Path(args[3]).write_bytes(b"ciphertext")
            return {"encrypt_ms": 1.0, "probe_ct_b": 10}

        with mock.patch.object(client, "_run", side_effect=fake_run):
            ciphertext, _ = client.cifra([0] * int(client.CFG["dim"]))

        self.assertEqual(ciphertext, b"ciphertext")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "encrypt")
        self.assertEqual(len(calls[0]), 4)

    def test_enrollment_response_does_not_return_template_preview(self) -> None:
        details = {"embedding_ms": 1.0, "frame": 2}
        with (
            mock.patch.object(client, "da_dataurl", return_value=object()),
            mock.patch.object(
                client,
                "embedding_fuso",
                return_value=(
                    client.np.zeros(int(client.CFG["dim"]), dtype=int),
                    details,
                ),
            ),
            mock.patch.object(client, "assicura_chiave"),
            mock.patch.object(
                client, "srv", return_value=(b'{"ok":true,"indice":0}', {})
            ),
        ):
            response = client.iscrivi(
                client.Frames(frames=["data:image/png;base64,AA=="], nome="alice")
            )

        self.assertNotIn("template_primi", response)


if __name__ == "__main__":
    unittest.main()
