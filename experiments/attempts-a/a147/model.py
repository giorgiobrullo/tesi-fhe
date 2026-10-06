"""Independent PFKS key-row measurement and contraction; synthetic/client-local only."""

from collections import defaultdict
from dataclasses import dataclass
import hashlib

Q = 1 << 64
MASK = Q - 1


def centered(word):
    word &= MASK
    return word - Q if word >= Q // 2 else word


def at(poly, degree):
    cycles, coefficient = divmod(degree, len(poly))
    return ((-1 if cycles & 1 else 1) * poly[coefficient]) & MASK


def multiply(left, right):
    """Independent full polynomial reference, used only for small synthetic fixtures."""
    n = len(left)
    assert len(right) == n
    out = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[(i + j) % n] += a * b * (-1 if i + j >= n else 1)
    return [word & MASK for word in out]


def full_phase(ciphertext, secret):
    n = len(secret[0])
    assert len(ciphertext) == (len(secret) + 1) * n
    out = ciphertext[-n:].copy()
    for j, poly in enumerate(secret):
        product = multiply(ciphertext[j * n : (j + 1) * n], poly)
        out = [(a - b) & MASK for a, b in zip(out, product)]
    return out


def rounded(word, base, levels):
    step = 1 << (64 - base * levels)
    return ((word + step // 2) & MASK) & ~(step - 1)


def digits(word, base, levels):
    """TFHE0.11.3 PFKS rounds first, then calls decompose(rounded), unlike plain KS."""
    retained = base * levels
    assert 0 < retained < 64
    state = rounded(word, base, levels) >> (64 - retained)
    if state > 1 << (retained - 1):
        state = (state - (1 << retained)) & MASK
    out = []
    for level in range(levels, 0, -1):
        residue = state & ((1 << base) - 1)
        state >>= base
        carry = (((residue - 1) & MASK | state) & residue) >> (base - 1)
        state = (state + carry) & MASK
        out.append((level, residue - (carry << base)))
    assert sum(d * (1 << (64 - base * level)) for level, d in out) & MASK == rounded(
        word, base, levels
    )
    return out


def words_hash(words):
    return hashlib.sha256(
        b"".join((x & MASK).to_bytes(8, "little") for x in words)
    ).hexdigest()


def key_id(rows):
    return words_hash([word for block in rows for row in block for word in row])


@dataclass
class Functional:
    """Prepared client-only linear functional: [phase(ciphertext)*kernel]_target."""

    secret_times_kernel: list
    kernel: list

    @classmethod
    def prepare(cls, secret, kernel):
        return cls([multiply(poly, kernel) for poly in secret], kernel.copy())

    def phase(self, ciphertext, target):
        n = len(self.kernel)
        assert len(ciphertext) == (len(self.secret_times_kernel) + 1) * n
        body = sum(ciphertext[-n + j] * at(self.kernel, target - j) for j in range(n))
        masks = sum(
            ciphertext[k * n + j] * at(poly, target - j)
            for k, poly in enumerate(self.secret_times_kernel)
            for j in range(n)
        )
        return (body - masks) & MASK


@dataclass
class ClientSamples:
    """Contains secret-derived errors. Never a service response or public row catalog."""

    key_id: str
    kernel_id: str
    function: list
    kernel: list
    base: int
    levels: int
    targets: tuple
    errors: dict
    row_count: int


def measure(
    rows, input_secret, output_secret, f_one, polynomial, kernel, targets, base, levels
):
    """No payload input or PFKS output parameter: samples cannot come from residual closure."""
    assert len(rows) == len(input_secret) + 1
    assert all(len(block) == levels for block in rows)
    assert all(s in (0, 1) for s in input_secret)
    n = len(polynomial)
    assert output_secret and all(len(poly) == n for poly in output_secret)
    width = (len(output_secret) + 1) * n
    assert all(len(row) == width for block in rows for row in block)
    assert all(0 <= word <= MASK for block in rows for row in block for word in row)
    assert len(kernel) == n and len(set(targets)) == len(targets)
    assert all(0 <= target < n for target in targets)
    function = [(f_one * coefficient) & MASK for coefficient in polynomial]
    transformed_function = multiply(function, kernel)
    functional = Functional.prepare(output_secret, kernel)
    samples = {}
    for row, (u, block) in enumerate(zip(input_secret + [-1], rows)):
        for index, ciphertext in enumerate(block):
            level = levels - index  # Stored order is levels, ..., 1.
            g = 1 << (64 - base * level)
            for target in targets:
                samples[row, level, target] = (
                    functional.phase(ciphertext, target)
                    - u * g * transformed_function[target]
                ) & MASK
    return ClientSamples(
        key_id(rows),
        words_hash(kernel),
        function,
        kernel.copy(),
        base,
        levels,
        tuple(targets),
        samples,
        len(rows),
    )


def contract(samples, payloads, target_degrees, weights=None):
    """Return exact modular prediction and a declared lift of measured row functionals."""
    assert 0 < len(payloads) == len(target_degrees) <= 8
    assert all(len(payload) == samples.row_count for payload in payloads)
    assert all(0 <= word <= MASK for payload in payloads for word in payload)
    weights = [1] * len(payloads) if weights is None else weights
    assert len(weights) == len(payloads)
    assert all(isinstance(weight, int) and -128 <= weight <= 128 for weight in weights)
    coefficients = defaultdict(int)
    n = len(samples.kernel)
    for ciphertext, degree, weight in zip(payloads, target_degrees, weights):
        cycles, coefficient = divmod(degree, n)
        assert coefficient in samples.targets
        sign = -1 if cycles & 1 else 1
        for row, word in enumerate(ciphertext):
            for level, digit in digits(word, samples.base, samples.levels):
                atom = (samples.key_id, samples.kernel_id, row, level, coefficient)
                coefficients[atom] -= weight * sign * digit
    coefficients = {atom: value for atom, value in coefficients.items() if value}
    lifted = sum(
        value * centered(samples.errors[row, level, coefficient])
        for (_, _, row, level, coefficient), value in coefficients.items()
    )
    return {
        "modular": lifted & MASK,
        "centered": centered(lifted),
        "lifted": lifted,
        "wrap_quotient": (lifted - centered(lifted)) // Q,
        "lift_basis": "centered measured row-functional values",
        "coefficients": coefficients,
    }


def pfks_ciphertext(rows, ciphertext, base, levels):
    """Separate source evaluator on actual GLWE ciphertext words, never on row errors."""
    assert rows and len(rows) == len(ciphertext)
    assert all(0 <= word <= MASK for word in ciphertext)
    assert all(len(block) == levels for block in rows)
    width = len(rows[0][0])
    assert all(len(row) == width for block in rows for row in block)
    out = [0] * width
    for block, word in zip(rows, ciphertext):
        for row, (_, digit) in zip(block, digits(word, base, levels)):
            out = [(a - digit * b) & MASK for a, b in zip(out, row)]
    return out


def observed_aggregate(
    output, ciphertext, input_secret, output_secret, samples, degree
):
    # Independent full-polynomial decryption/reference rather than Functional.phase.
    assert len(ciphertext) == len(input_secret) + 1 == samples.row_count
    rounded_phase = (
        rounded(ciphertext[-1], samples.base, samples.levels)
        - sum(
            s * rounded(a, samples.base, samples.levels)
            for a, s in zip(ciphertext, input_secret)
        )
    ) & MASK
    actual = at(multiply(full_phase(output, output_secret), samples.kernel), degree)
    ideal = rounded_phase * at(multiply(samples.function, samples.kernel), degree)
    return (actual - ideal) & MASK


def synthetic_key(input_secret, output_secret, f_one, polynomial, base, levels, seed=0):
    """Nontrivial masks plus explicit error polynomials; no RNG/security/noise sampling claim."""
    n = len(polynomial)
    rows, errors = [], {}
    for row, u in enumerate(input_secret + [-1]):
        block = []
        for level in range(levels, 0, -1):
            masks = [
                [
                    ((seed + 7) * (row + 3) * (level + 5) * (j + 11) * (k + 17)) & MASK
                    for j in range(n)
                ]
                for k in range(len(output_secret))
            ]
            eta = [((seed + row * 17 + level * 11 + j * 7) % 19 - 9) for j in range(n)]
            secret_product = [0] * n
            for mask, secret in zip(masks, output_secret):
                secret_product = [
                    (a + b) & MASK
                    for a, b in zip(secret_product, multiply(mask, secret))
                ]
            body = [
                (
                    secret_product[j]
                    + u * (1 << (64 - base * level)) * f_one * polynomial[j]
                    + eta[j]
                )
                & MASK
                for j in range(n)
            ]
            block.append([x for mask in masks for x in mask] + body)
            errors[row, level] = eta
        rows.append(block)
    return rows, errors
