"""Public transport checks; no model, key generation or FHE dispatch lives here."""

import json
import math

from .ledger import composite_counts

COUNTS = ("br", "ks", "marginals", "pfks", "initial_samples")
IDENTITIES = ("params_id", "params_fingerprint_sha256", "variant_id", "circuit_sha256")
DYNAMIC_PROFILE = ("query_profile", "query_profile_id", "score_delta_log")


def strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("campo JSON duplicato: " + key)
            result[key] = value
        return result

    def invalid_constant(value):
        raise RuntimeError("valore JSON non finito: " + value)

    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("risposta JSON non valida") from exc


def integer(value, label, lower=0, upper=(1 << 64) - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise RuntimeError(label + " deve essere un intero nel dominio previsto")
    return value


def same(value, expected, label):
    if type(value) is not type(expected) or value != expected:
        raise RuntimeError(label + " diverso dal contratto atteso")


def fingerprint(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise RuntimeError("fingerprint SHA-256 della chiave server non valido")
    return value


def domain(value, label):
    if not isinstance(value, dict) or set(value) != {"l", "u", "larghezza"}:
        raise RuntimeError(label + " incompleto")
    low = integer(value["l"], label + ".l", -(1 << 63), (1 << 63) - 1)
    high = integer(value["u"], label + ".u", -(1 << 63), (1 << 63) - 1)
    width = integer(value["larghezza"], label + ".larghezza", 1, 4096)
    same(high - low + 1, width, label + ".larghezza")
    return dict(value)


def operation_counts(size, mode):
    """Refreshed-selector baseline before the existing public-plan savings."""
    integer(size, "iscritti", 1, 3374)
    if mode == "mixed_winner_threshold":
        values = (13 * size - 1, 9 * size, 19 * size - 3, 9 * size - 3, size)
    elif mode == "uniform_all_reject":
        values = (0, 0, 0, 0, 0)
    elif mode in ("uniform_sentinel", "uniform_all_accept"):
        merges = size if mode == "uniform_sentinel" else size - 1
        values = (6 * size + 6 * merges, 4 * size + 5 * merges,
                  6 * size + 10 * merges, 6 * merges, size)
    else:
        raise RuntimeError("modalità di esecuzione non riconosciuta")
    return dict(zip(COUNTS, values))


def validate_contract(contract, expected, size):
    if not isinstance(contract, dict):
        raise RuntimeError("contratto del server mancante")
    for name, value in expected.items():
        if name not in DYNAMIC_PROFILE:
            same(contract.get(name), value, "contratto." + name)
    profile = ("head51", 2, 51) if size else (None, 0, 0)
    for name, value in zip(DYNAMIC_PROFILE, profile):
        same(contract.get(name), value, "contratto." + name)


def validate_status(state, expected, allow_empty=False):
    """Check the server's declared plan and version; never select another plan."""
    if not isinstance(state, dict):
        raise RuntimeError("stato della galleria non valido")
    if "chiave_sha256" not in state:
        raise RuntimeError("fingerprint della chiave server mancante")
    size = integer(state.get("iscritti"), "iscritti", 0 if allow_empty else 1, 3374)
    epoch = integer(state.get("epoch"), "epoch")
    revision = integer(state.get("revision"), "revision")
    same(state.get("dim"), 512, "dimensione")
    names, thresholds = state.get("nomi"), state.get("soglie")
    if not isinstance(names, list) or len(names) != size or any(not isinstance(v, str) for v in names):
        raise RuntimeError("mappa nomi della galleria non valida")
    if not isinstance(thresholds, list) or len(thresholds) != size:
        raise RuntimeError("soglie della galleria non valide")
    for value in thresholds:
        integer(value, "soglia", -(1 << 63), (1 << 63) - 1)
    if type(state.get("chiave")) is not bool:
        raise RuntimeError("stato della chiave server non booleano")
    key_hash = state.get("chiave_sha256")
    if state["chiave"]:
        fingerprint(key_hash)
    elif key_hash is not None:
        raise RuntimeError("chiave assente con fingerprint non nullo")
    validate_contract(state.get("contratto_esatto"), expected, size)
    runtime = {"mode": expected["runtime_mode"], "service_source_sha256": expected["service_source_sha256"],
               "core_source_sha256": expected["core_source_sha256"], "rayon_threads": 16,
               "fft_plan_policy": "user-provided-dif4-polynomial2048-base1024-v1",
               "compiler_profile": "opt3-cgu1-no-lto-generic-no-pgo", "runtime_features": [],
               "query_admission": "one_synchronous_query_per_process", "shared_normalizers": "both",
               "classic_comparators": "parallel3_cutoff4", "id_cuts": "both", "public_thresholds": True,
               "public_digits": "repack", "selector_parallel": True, "g4": expected["g4_required"],
               "detector_only_alignment": True}
    reported_runtime = state.get("runtime_optimization")
    if not isinstance(reported_runtime, dict) or set(reported_runtime) != set(runtime):
        raise RuntimeError("metadati del runtime incompleti")
    for name, value in runtime.items():
        same(reported_runtime[name], value, "runtime." + name)
    required = expected["g4_required"]
    g4_hash = state.get("g4_sha256")
    if g4_hash is not None:
        fingerprint(g4_hash)
        if not required or not state["chiave"]:
            raise RuntimeError("chiave G4 incoerente con il circuito o la chiave di base")
    same(state.get("g4_ready"), not required or g4_hash is not None, "prontezza G4")

    plan_names = ("dominio", "dominio_esecuzione", "percorso_argmin", "endpoint_fhe",
                  "execution_mode", "soglia_uniforme", "sentinel_score", "conteggi")
    if any(name not in state for name in (*plan_names, "aligned_fast_path", "endpoint_domain_supported")):
        raise RuntimeError("piano pubblico incompleto")
    same(state["endpoint_domain_supported"], size > 0, "supporto del dominio")
    if type(state["aligned_fast_path"]) is not bool:
        raise RuntimeError("aligned_fast_path non booleano")
    if not size:
        if any(state[name] is not None for name in plan_names) or state["aligned_fast_path"]:
            raise RuntimeError("una galleria vuota non deve dichiarare un piano")
    else:
        cauchy = domain(state["dominio"], "dominio")
        execution = domain(state["dominio_esecuzione"], "dominio_esecuzione")
        if execution["l"] > cauchy["l"] or execution["u"] < cauchy["u"]:
            raise RuntimeError("il dominio di esecuzione non copre il dominio Cauchy")
        mode = state["execution_mode"]
        mixed = mode == "mixed_winner_threshold"
        same(state["percorso_argmin"], "fast_mixed_winner_threshold" if mixed else "fast_uniform", "percorso")
        same(state["endpoint_fhe"], "head_mean_mixed_parallel" if mixed else "head_mean_uniform_parallel", "endpoint")
        uniform = state["soglia_uniforme"]
        sentinel = state["sentinel_score"]
        if mixed:
            if uniform is not None or len(set(thresholds)) < 2 or state["aligned_fast_path"]:
                raise RuntimeError("piano misto incoerente con le soglie")
            same(execution, cauchy, "dominio misto")
        else:
            integer(uniform, "soglia uniforme", -(1 << 63), (1 << 63) - 1)
            if any(value != uniform for value in thresholds):
                raise RuntimeError("piano uniforme con soglie diverse")
            if state["aligned_fast_path"]:
                if mode != "uniform_sentinel" or execution["l"] != uniform - 1023 or execution["u"] != cauchy["u"]:
                    raise RuntimeError("piano allineato incoerente")
                same(sentinel, 1024, "sentinella allineata")
            else:
                same(execution, cauchy, "dominio uniforme generale")
                if mode == "uniform_all_reject" and not uniform < execution["l"]:
                    raise RuntimeError("rifiuto pubblico incoerente con la soglia")
                if mode == "uniform_all_accept" and not uniform >= execution["u"]:
                    raise RuntimeError("accettazione pubblica incoerente con la soglia")
                if mode == "uniform_sentinel" and not execution["l"] <= uniform < execution["u"]:
                    raise RuntimeError("sentinella fuori dal dominio generale")
        if mode == "uniform_sentinel":
            integer(sentinel, "sentinella", 1, 4095)
            same(sentinel, uniform - execution["l"] + 1, "normalizzazione sentinella")
        elif sentinel is not None:
            raise RuntimeError("sentinella presente in una modalità senza sentinella")
        counts = state["conteggi"]
        wanted = composite_counts(operation_counts(size, mode), size, mode, thresholds, execution)
        if not isinstance(counts, dict) or set(counts) != set(COUNTS):
            raise RuntimeError("conteggi pubblici incompleti")
        for name in COUNTS:
            same(counts[name], wanted[name], "conteggi." + name)

    return {"epoch": epoch, "revision": revision, "iscritti": size, "nomi": tuple(names),
            "chiave_sha256": key_hash, "query_profile": "head51" if size else None,
            "query_profile_id": 2 if size else 0,
            **{name: state[name] for name in (*plan_names, "aligned_fast_path", "endpoint_domain_supported")}}


def validate_headers(headers, expected, snapshot):
    normalized = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    bindings = {"contract": "http_contract", "params-id": "params_id",
                "params-fingerprint": "params_fingerprint_sha256", "variant-id": "variant_id",
                "circuit-sha256": "circuit_sha256"}
    for header, name in bindings.items():
        same(normalized.get("x-varco-" + header), expected[name], "header " + header)
    same(normalized.get("x-varco-query-profile"), snapshot["query_profile"], "profilo HTTP")
    names = {"pbs": "br", "ks": "ks", "pfks": "pfks", "marginals": "marginals", "initial-samples": "initial_samples"}
    for header, name in names.items():
        same(normalized.get("x-" + header), str(snapshot["conteggi"][name]), "header conteggi " + name)
    try:
        duration = float(normalized["x-tempo-ms"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("durata server mancante o non valida") from exc
    if not math.isfinite(duration) or duration < 0:
        raise RuntimeError("durata server fuori dominio")
    return normalized


def decode_identity(result, snapshot, expected):
    if not isinstance(result, dict):
        raise RuntimeError("esito cifrato non valido")
    required = ("autorizzato", "indice", "iscritti", "galleria_epoch", "galleria_revision",
                "codice", "low", "middle", "high", "query_profile", "query_profile_id", *IDENTITIES)
    if any(name not in result for name in required):
        raise RuntimeError("esito cifrato incompleto")
    for name in IDENTITIES:
        same(result[name], expected[name], "esito." + name)
    same(result["query_profile"], snapshot["query_profile"], "profilo esito")
    same(result["query_profile_id"], snapshot["query_profile_id"], "id profilo esito")
    for field, name in (("galleria_epoch", "epoch"), ("galleria_revision", "revision"), ("iscritti", "iscritti")):
        integer(result[field], field)
        same(result[field], snapshot[name], "versione della galleria")
    if type(result["autorizzato"]) is not bool:
        raise RuntimeError("campo autorizzato non booleano")
    digits = [integer(result[name], name, 0, 14) for name in ("low", "middle", "high")]
    code = integer(result["codice"], "codice", 0, snapshot["iscritti"])
    same(code, digits[0] + 15 * digits[1] + 225 * digits[2], "ricostruzione a tre cifre")
    if result["autorizzato"]:
        index = integer(result["indice"], "indice", 0, snapshot["iscritti"] - 1)
        same(code, index + 1, "codice identità")
        return snapshot["nomi"][index]
    if result["indice"] is not None or code != 0:
        raise RuntimeError("un rifiuto deve avere codice zero e indice nullo")
    return None
