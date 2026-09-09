"""A bounded functional check against the newly owned demo, using public faces."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SERVER = "http://127.0.0.1:8005"
CLIENT = "http://127.0.0.1:8006"


def request(base: str, path: str, payload: dict | None = None, *,
            method: str | None = None, origin: str | None = None) -> tuple[int, dict, bytes]:
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    body = None if payload is None else json.dumps(payload).encode()
    query = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(query, timeout=120)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, {key.lower(): value for key, value in response.headers.items()}, raw


def document(base: str, path: str, payload: dict | None = None, **kwargs) -> dict:
    status, _, raw = request(base, path, payload, **kwargs)
    if status != 200:
        raise RuntimeError(f"{path}: HTTP {status}: {raw[:180]!r}")
    return json.loads(raw)


def check() -> dict:
    assert document(CLIENT, "/api/stato")["pronto"] is True
    gallery = document(SERVER, "/api/galleria")
    assert gallery["totale"] == 127
    assert all(entry["origine"] == "sintetico" for entry in gallery["iscritti"])
    initial_events = document(SERVER, "/api/richieste")["totale"]
    for path in ("/api/galleria", "/api/richieste", "/api/iscritti", "/api/reset", "/api/precarica"):
        assert request(CLIENT, path)[0] == 404
    assert request(CLIENT, "/api/accesso", {"frames": [], "nome": "non ammesso"})[0] == 400
    assert request(SERVER, "/api/iscritti", {}, origin="https://untrusted.invalid")[0] == 403
    first_photo = gallery["iscritti"][0]["foto_url"]
    status, headers, photo = request(SERVER, first_photo)
    assert status == 200 and len(photo) > 100 and headers["content-type"].startswith("image/")

    public_photos = sorted((ROOT / "datasets/digiface/estratto/999").glob("*.png"))[:2]
    assert len(public_photos) == 2
    frames = ["data:image/png;base64," + base64.b64encode(path.read_bytes()).decode()
              for path in public_photos]
    enrolled = document(SERVER, "/api/iscritti", {"nome": "Verifica sintetica temporanea",
                        "frames": frames, "soglia": 273}, origin=SERVER)
    identifier = enrolled["iscritto"]["id"]
    entry_path = "/api/iscritti/" + identifier
    try:
        assert enrolled["totale"] == 128
        changed = document(SERVER, entry_path, {"nome": "Verifica CRUD sintetica"}, method="PATCH", origin=SERVER)
        assert changed["iscritto"]["id"] == identifier
        assert changed["iscritto"]["nome"] == "Verifica CRUD sintetica"

        persisted = json.loads((ROOT / "demo/dual_view/.local/server/gallery.json").read_text())["iscritti"]
        query = next(entry["vettore"] for entry in persisted if entry["id"] == identifier)
        assert sum(value * value for value in query) <= 1024
        scores = [(sum(value * value for value in entry["vettore"])
                   - 2 * sum(a * b for a, b in zip(entry["vettore"], query, strict=True)), index)
                  for index, entry in enumerate(persisted)]
        winning_score, winning_index = min(scores)
        assert persisted[winning_index]["id"] == identifier
        assert winning_score <= persisted[winning_index]["soglia"]

        accepted = document(CLIENT, "/api/accesso", {"frames": frames}, origin=CLIENT)
        assert accepted["esito"] == "aperto"
        # The circuit score omits the query's squared norm; identical vectors have
        # score -||q||². A threshold below that raw score is the refusal control.
        assert winning_score > -4096
        document(SERVER, entry_path, {"soglia": -4096}, method="PATCH", origin=SERVER)
        refused = document(CLIENT, "/api/accesso", {"frames": frames}, origin=CLIENT)
        assert refused["esito"] == "negato"
        permitted_result = {"esito", "tempi_ms", "richiesta_id"}
        assert set(accepted) <= permitted_result and set(refused) <= permitted_result
        feed = document(SERVER, "/api/richieste")
        assert feed["totale"] == initial_events + 2
        allowed_event = {"id", "ora", "stato", "durata_ms", "byte_richiesta", "byte_risposta", "impronta", "errore"}
        for result in (accepted, refused):
            event = next(item for item in feed["richieste"] if item["id"] == result["richiesta_id"])
            assert set(event) <= allowed_event and event["stato"] == "completata"
            assert event["byte_richiesta"] > 1000 and event["byte_risposta"] > 100
    finally:
        removed = document(SERVER, entry_path, method="DELETE", origin=SERVER)
    assert removed["totale"] == 127
    assert request(SERVER, "/api/foto/" + identifier)[0] == 404
    assert document(SERVER, "/api/galleria") == gallery
    return {"passed": True, "initial_and_final_gallery": 127, "crud": True,
            "client_admin_routes_absent": True, "origin_rejection": True,
            "ciphertext_only_event_fields": True, "accepted": accepted, "refused": refused,
            "integer_oracle": {"winner_is_temporary_entry": True, "score": winning_score,
                               "accept_threshold": 273, "reject_threshold": -4096},
            "note": "Two functional encrypted requests, not a benchmark."}


if __name__ == "__main__":
    print(json.dumps(check(), ensure_ascii=False, indent=2))
