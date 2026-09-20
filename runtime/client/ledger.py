"""Independent public-plan ledger; no ciphertexts, templates, models or native calls."""


def digit_constants(size, mode, thresholds, low, high):
    leaves = []
    for index in range(size):
        identity = index + 1
        if mode == "mixed_winner_threshold" and thresholds[index] < low:
            identity = 0
        digits = [identity % 15, (identity // 15) % 15, identity // 225]
        if mode == "mixed_winner_threshold":
            normalized = min(high, max(low, thresholds[index])) - low
            digits += [normalized >> 8, (normalized >> 4) & 15, normalized & 15]
        leaves.append([None, None, None, *digits])
    return leaves


def tree_savings(leaves, id_width):
    """Adjacent pairs carry odd tails unchanged; only equal public lanes propagate."""
    omitted_thresholds = 0
    omitted_payloads = 0
    omitted_rotations = 0
    current = leaves
    while len(current) > 1:
        following = []
        for index in range(0, len(current) - 1, 2):
            left, right = current[index:index + 2]
            known = [a if a is not None and a == b else None for a, b in zip(left, right)]
            mixed = len(known) == 9
            threshold_public = mixed and all(value is not None for value in known[6:9])
            omitted_thresholds += int(threshold_public)
            baseline_payloads = 3 + id_width + 3 * int(mixed and not threshold_public)
            baseline_rotations = 2 + int(mixed and not threshold_public)
            variable_payloads = sum(value is None for value in known[3:])
            planned_payloads = 3 + variable_payloads
            # Scores and variable public lanes share the same four-lane packing.
            planned_rotations = (planned_payloads + 3) // 4
            if planned_payloads > baseline_payloads or planned_rotations > baseline_rotations:
                raise RuntimeError("il piano pubblico supera il circuito di riferimento")
            omitted_payloads += baseline_payloads - planned_payloads
            omitted_rotations += baseline_rotations - planned_rotations
            following.append(known)
        if len(current) % 2:
            following.append(current[-1])
        current = following
    return omitted_thresholds, omitted_payloads, omitted_rotations


def composite_counts(baseline, size, mode, thresholds, execution):
    """Derive the selected shared-normalizer/ID-cut/threshold/repack five-field ledger."""
    counts = dict(baseline)
    if mode == "uniform_all_reject":
        return counts
    final_predicate = int(mode != "uniform_all_accept")
    removed_id_lanes = (size - 1 + final_predicate) * int(size <= 224) + 3 * final_predicate
    counts["br"] -= final_predicate + 2 * size
    counts["pfks"] -= removed_id_lanes
    counts["marginals"] -= removed_id_lanes
    leaves = digit_constants(size, mode, thresholds, execution["l"], execution["u"])
    threshold_omissions, payload_omissions, rotation_omissions = tree_savings(leaves, 2 if size <= 224 else 3)
    counts["br"] -= threshold_omissions + rotation_omissions
    counts["pfks"] -= 3 * threshold_omissions + payload_omissions
    counts["marginals"] -= 3 * threshold_omissions + payload_omissions
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise RuntimeError("conteggi del circuito composto fuori dominio")
    return counts
