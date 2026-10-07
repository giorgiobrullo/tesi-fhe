#!/usr/bin/env python3
"""Restore one mapped attempt's source layout; never build or run its programs."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Optional

REPOSITORY = Path(__file__).resolve().parents[1]
MANIFEST = "experiments/attempts-a/SOURCE_MAP.json"
RECEIPT = "RESTORE_ATTEMPT.json"
LIMIT = "Sorgenti e input pubblici mappati; non certifica build, esecuzione o completezza delle dipendenze."


class RestoreError(ValueError):
    """A manifest, input or destination cannot safely be used."""


def relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        raise RestoreError("Percorso relativo non valido: {!r}".format(value))
    if PurePosixPath(value).is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise RestoreError("Percorso non canonico o traversal: {!r}".format(value))
    return value


def read_regular(root: Path, relative: str) -> bytes:
    """Refuse symbolic links and non-regular source leaves."""
    path = root
    for part in relative_path(relative).split("/"):
        path = path / part
        if path.is_symlink():
            raise RestoreError("Link simbolico non ammesso: {}".format(path))
    if not stat.S_ISREG(path.lstat().st_mode):
        raise RestoreError("Il sorgente non è un file regolare: {}".format(path))
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise RestoreError("Il sorgente non è un file regolare: {}".format(path))
        return handle.read()


def mapped_dependency(entry: dict) -> bool:
    return isinstance(entry.get("status"), str) and entry["status"].startswith("mapped_")


def load_manifest(root: Path) -> tuple:
    raw = read_regular(root, MANIFEST)
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schema") != "attempts-a-source-mapping.v1":
        raise RestoreError("Schema SOURCE_MAP non supportato")
    if not isinstance(manifest.get("files"), list) or not isinstance(manifest.get("literal_compile_dependencies"), list):
        raise RestoreError("SOURCE_MAP deve contenere files e literal_compile_dependencies")
    attempts = manifest.get("attempts", [])
    if not isinstance(attempts, list):
        raise RestoreError("Elenco attempts non valido")
    seen_ids = set()
    for attempt in attempts:
        identifier = attempt.get("id") if isinstance(attempt, dict) else None
        if not isinstance(identifier, str) or not re.fullmatch(r"A[0-9]+", identifier) or identifier in seen_ids:
            raise RestoreError("ID non valido o duplicato nell'elenco attempts")
        seen_ids.add(identifier)
    records = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            raise RestoreError("Mapping non valido")
        target = relative_path(entry.get("archive_relative"))
        relative_path(entry.get("canonical"))
        if target == RECEIPT or target.startswith(RECEIPT + "/"):
            raise RestoreError("Percorso riservato alla ricevuta: {}".format(target))
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise RestoreError("SHA-256 non valido per {}".format(target))
        if type(entry.get("bytes")) is not int or entry["bytes"] < 0:
            raise RestoreError("Dimensione non valida per {}".format(target))
        ids = entry.get("ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(value, str) or not re.fullmatch(r"A[0-9]+", value) for value in ids):
            raise RestoreError("Lista ID non valida per {}".format(target))
        if target in records:
            raise RestoreError("Destinazione duplicata nel manifest: {}".format(target))
        records[target] = entry
    for target in records:
        if any(str(parent) in records for parent in PurePosixPath(target).parents):
            raise RestoreError("Conflitto file/cartella nel manifest: {}".format(target))
    dependencies = {}
    for entry in manifest["literal_compile_dependencies"]:
        if not isinstance(entry, dict):
            raise RestoreError("Dipendenza non valida")
        source = relative_path(entry.get("source"))
        if mapped_dependency(entry):
            target = relative_path(entry.get("resolved_archive_relative"))
            if target not in records:
                raise RestoreError("Dipendenza dichiarata mappata ma assente: {}".format(target))
        dependencies.setdefault(source, []).append(entry)
    return manifest, records, dependencies, hashlib.sha256(raw).hexdigest()


def select_attempt(identifier: str, records: dict, dependencies: dict) -> tuple:
    direct = {path for path, entry in records.items() if identifier in entry["ids"]}
    if not direct:
        raise RestoreError("Nessun sorgente mappato per {}: consultare il catalogo, non implica che il tentativo non esista".format(identifier))
    selected = set(direct)
    pending = list(direct)
    while pending:
        for dependency in dependencies.get(pending.pop(), []):
            if not mapped_dependency(dependency):
                continue
            target = dependency["resolved_archive_relative"]
            if target not in selected:
                selected.add(target)
                pending.append(target)
    limitations = [entry for path in sorted(selected) for entry in dependencies.get(path, [])
                   if not mapped_dependency(entry)]
    return sorted(selected), sorted(selected - direct), limitations


def verify_sources(root: Path, paths: list, records: dict) -> dict:
    """Keep verified bytes so the later write cannot copy changed source bytes."""
    by_source = {}
    payloads = {}
    for path in paths:
        entry = records[path]
        source = entry["canonical"]
        if source not in by_source:
            by_source[source] = read_regular(root, source)
        data = by_source[source]
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RestoreError("Hash o dimensione non corrispondenti: {} → {}".format(source, path))
        payloads[path] = data
    return payloads


def new_destination(value: Path, root: Path) -> Path:
    if ".." in value.parts:
        raise RestoreError("La destinazione non può contenere '..'")
    destination = Path(os.path.abspath(value))
    if os.path.lexists(destination):
        raise RestoreError("La destinazione esiste già: {}".format(destination))
    for parent in destination.parents:
        if parent.is_symlink():
            raise RestoreError("Genitore simbolico della destinazione: {}".format(parent))
    if not destination.parent.is_dir():
        raise RestoreError("Creare prima la cartella genitore: {}".format(destination.parent))
    if destination == root or destination in root.parents:
        raise RestoreError("La destinazione non può contenere la repository sorgente")
    return destination


def restore(identifier: str, root: Path, output: Optional[Path] = None) -> dict:
    root = root.resolve(strict=True)
    manifest, records, dependencies, manifest_hash = load_manifest(root)
    paths, shared, limitations = select_attempt(identifier, records, dependencies)
    destination = new_destination(output, root) if output is not None else None
    payloads = verify_sources(root, paths, records)
    receipt = {
        "schema": "attempt-source-restoration.v1", "id": identifier,
        "mode": "check" if destination is None else "restore",
        "source_map_sha256": manifest_hash, "file_count": len(paths),
        "total_bytes": sum(len(data) for data in payloads.values()),
        "shared_dependency_files": shared, "unresolved_literal_dependencies": limitations,
        "scope": manifest.get("scope", ""), "limit": LIMIT,
        "runtime_dependency_limit": manifest.get("runtime_dependency_limit", ""),
        "files": [{"archive_relative": path, "canonical": records[path]["canonical"],
                   "sha256": records[path]["sha256"], "bytes": len(payloads[path])} for path in paths],
    }
    if destination is not None:
        destination.mkdir(mode=0o700)
        for path in paths:
            target = destination.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(payloads[path])
        with (destination / RECEIPT).open("x", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    return receipt


def list_attempts(root: Path) -> list:
    manifest, records, dependencies, _ = load_manifest(root)
    metadata = {entry["id"]: entry for entry in manifest.get("attempts", [])}
    mapped_ids = {identifier for entry in records.values() for identifier in entry["ids"]}
    identifiers = sorted(mapped_ids | set(metadata), key=lambda value: int(value[1:]))
    rows = []
    for identifier in identifiers:
        if identifier in mapped_ids:
            paths, shared, limitations = select_attempt(identifier, records, dependencies)
        else:
            paths, shared, limitations = [], [], []
        rows.append({"id": identifier, "mapped_files": len(paths), "shared_files": len(shared),
                     "unresolved_literal_dependencies": len(limitations),
                     "completeness": metadata.get(identifier, {}).get("completeness", "completezza non dichiarata")})
    return rows


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--id", help="ID del tentativo, per esempio A141")
    choice.add_argument("--list", action="store_true", help="Elenca gli ID censiti e i file mappati; non verifica gli hash")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--output", type=Path, help="Directory nuova, con genitore già esistente")
    mode.add_argument("--check", action="store_true", help="Verifica hash e mapping senza scrivere")
    args = parser.parse_args(argv)
    if args.list and (args.output is not None or args.check):
        parser.error("--list non ammette --output o --check")
    if args.id and not re.fullmatch(r"A[0-9]+", args.id):
        parser.error("--id deve avere la forma A141")
    if args.id and args.output is None and not args.check:
        parser.error("con --id scegliere --output oppure --check")
    try:
        if args.list:
            print("ID\tFile mappati\tDipendenze condivise\tDipendenze letterali non importate\tCompletezza dichiarata")
            for row in list_attempts(REPOSITORY):
                print("{id}\t{mapped_files}\t{shared_files}\t{unresolved_literal_dependencies}\t{completeness}".format(**row))
            print(LIMIT)
            print("Un conteggio zero delle dipendenze letterali non equivale a un pacchetto eseguibile completo; hash non verificati da --list.")
        else:
            receipt = restore(args.id, REPOSITORY, args.output)
            print(json.dumps({key: value for key, value in receipt.items() if key != "files"}, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print("Errore: {}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
