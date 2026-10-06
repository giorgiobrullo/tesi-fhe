"""Bounded source/clear checker. No builds, keygen, FHE, benchmark, network, or signals."""
import hashlib
import itertools
import json
from pathlib import Path
import random

import model

HERE = Path(__file__).resolve().parent


def counterexamples():
    d = 1
    scale = 1 << model.MASKED_LOG
    # A direct canonical sentinel mask in a single antiperiodic output cannot work.
    return {
        "naive_direct_mask": {"digit": d, "phase_inactive": d,
            "phase_active": d+16, "requested_inactive_word": 16*scale,
            "requested_active_word": d*scale,
            "forced_active_word": model.word(-16*scale),
            "reason": "Stock PBS antipodal outputs negate; the desired pair does not.",
            "repair": "Signed mask output plus the original half-scale digit and public offset."},
        "naive_fixed_scale_min": {"left": 1, "right": 1, "expected": 1,
            "unnormalized_formula": 2,
            "reason": "The linear sum-minus-centered-absolute formula doubles the value at a fixed scale.",
            "repair": "Track and double the ciphertext scale at every reduction level; no encrypted division."},
        "naive_update_without_valid": {"active": [0,0], "digits": [0,15],
            "masked": [16,16], "minimum": 16, "equality_only_survivors": [1,1],
            "expected": [0,0], "repair": "One global valid PBS, fused as a padding flip in the update PBS."},
        "heterogeneous_prefilter": {"scores": [10,11], "thresholds": [9,100],
            "winner_then_own_threshold": 0, "prefilter_then_min": 2,
            "scope": "Uniform1023 A34 prefilter is valid; this does not license heterogeneous prefiltering."},
    }


def local_lemmas():
    mask_cases = 0
    for active, digit in itertools.product(range(2), range(16)):
        signed = model.lookup_degree(model.mask_words(), (digit + 16*active) * 128)
        got = model.word(signed + (digit << 51) + (16 << 51))
        assert got == (digit if active else 16) << 52
        mask_cases += 1
    minimum_cases = 0
    for log in range(52,59):
        for left, right in itertools.product(range(17), repeat=2):
            raw = model.lookup_degree(model.minimum_words(log), (left-right)*128)
            got = model.word(((left+right) << log) - raw - (8 << log))
            assert got == min(left,right) << (log+1)
            minimum_cases += 1
    update_cases = 0
    for smallest in range(17):
        valid = model.word(model.lookup_degree(model.valid_words(), smallest*128) + (1 << 58))
        assert valid == int(smallest < 16) << 59
        for masked in range(smallest,17):
            difference = masked-smallest
            phase = difference + (16 if smallest < 16 else 0)
            got = model.word(model.lookup_degree(model.update_words(), phase*128) + (1 << 58))
            assert got == int(smallest < 16 and masked == smallest) << 59
            update_cases += 1
    return dict(mask_states=mask_cases, minimum_pairs_across_seven_scales=minimum_cases,
                reachable_update_states=update_cases, validity_states=17)


def geometry():
    checked = 0
    tables = [(model.mask_words(), range(32)),
              (model.valid_words(), range(17)),
              (model.update_words(), list(range(17,32))+[0,16])]
    tables += [(model.minimum_words(log), range(-16,17)) for log in range(52,59)]
    for table, values in tables:
        for value in values:
            center = value * 128
            expected = model.lookup_degree(table, center)
            for offset in range(-64,64):
                assert model.lookup_degree(table, center+offset) == expected
                checked += 1
    return checked


def round_cases():
    exhaustive = 0
    for a0,a1,d0,d1 in itertools.product(range(2),range(2),range(16),range(16)):
        active, digits = [a0,a1],[d0,d1]
        got, _, _ = model.evaluate_round(active,digits)
        assert got == model.independent_round_oracle(active,digits)
        exhaustive += 1
    random_cases = 0
    rng = random.Random(135)
    for n in (1,4,5,16,64,127,128):
        for _ in range(12):
            active = [rng.randrange(2) for _ in range(n)]
            digits = [rng.randrange(16) for _ in range(n)]
            got, _, _ = model.evaluate_round(active,digits)
            assert got == model.independent_round_oracle(active,digits)
            random_cases += 1
        for active in ([0]*n,[1]*n):
            for digit in (0,15):
                got, _, _ = model.evaluate_round(active,[digit]*n)
                assert got == active
                random_cases += 1
    return dict(n2_exhaustive=exhaustive, bounded_gallery_rounds=random_cases)


def exact_id_cases():
    singleton = 0
    for score in range(4096):
        assert model.exact_uniform1023([score]) == model.independent_exact_id([score],[1023])
        singleton += 1
    cases = 0
    boundaries = [0,1,14,15,16,17,254,255,256,257,510,511,512,513,767,768,
                  1007,1008,1022,1023,1024,1025,2047,2048,4094,4095]
    for left,right in itertools.product(boundaries,repeat=2):
        assert model.exact_uniform1023([left,right]) == model.independent_exact_id([left,right],[1023,1023])
        cases += 1
    rng = random.Random(135012)
    for n in (4,64,127,128):
        fixtures = [[4095]*n, [1023]*n, [1024]*n, [0]*n]
        for index in (0,n//2,n-1):
            scores=[4095]*n
            scores[index]=1023
            fixtures.append(scores)
        tie=[4095]*n
        tie[1]=tie[n-1]=15
        fixtures.append(tie)
        for _ in range(12):
            fixtures.append([rng.randrange(4096) for _ in range(n)])
        for scores in fixtures:
            assert model.exact_uniform1023(scores) == model.independent_exact_id(scores,[1023]*n)
            flags=model.three_round_argmin_flags(scores)
            assert flags == [int(s == min(scores)) for s in scores]
            cases += 1
    return dict(all_12bit_singleton_scores=singleton, paired_boundary_and_gallery_cases=cases,
                three_round_argmin_gallery_cases=80)


def padding_alternative():
    # Frozen A66 A34 candidate LUT has only in-half inputs on its 64 enumerated states.
    codes=[30,28,3,31,0,0,0,0,2,4,29,1,0,0,0,0]
    a34_states=0
    for minimum_h,category in enumerate([1,3,7,0]):
        for high in range(16):
            phase=(codes[high]+category+4)%32
            assert phase < 16
            for log in (59,63):
                table=tuple(int(u in (3,14)) << log for u in range(16))
                assert model.lookup_degree(table,phase*128) == int(high == minimum_h) << log
                a34_states += 1
    local=0
    for a0,a1,d0,d1 in itertools.product(range(2),range(2),range(16),range(16)):
        expected=model.independent_round_oracle([a0,a1],[d0,d1])
        outputs,evaluation,_=model.evaluate_words([a0 << 63,a1 << 63],[d0 << 51,d1 << 51],
            active_log=63,valid_log=63,output_log=63)
        assert outputs == [a << 63 for a in expected]
        assert evaluation.pbs == evaluation.ks == 6
        local += 1
    cases=0
    rng=random.Random(135063)
    for n in (1,2,4,64,127,128):
        fixtures=[[0]*n,[1023]*n,[1024]*n,[4095]*n]
        for _ in range(12):
            fixtures.append([rng.randrange(4096) for _ in range(n)])
        for scores in fixtures:
            assert model.exact_uniform1023_padding(scores) == model.independent_exact_id(scores,[1023]*n)
            cases += 1
    return dict(n2_exhaustive_padding_rounds=local, exact_id_gallery_cases=cases,
                a34_rescaled_candidate_states=a34_states,
                same_br_ks_count=True, same_noise_law_assumed=False)


def verify_pins():
    pins=json.loads((HERE/'SOURCE_PINS.json').read_text())['files']
    for pin in pins:
        assert hashlib.sha256(Path(pin['path']).read_bytes()).hexdigest() == pin['sha256'], pin['path']
    return len(pins)


def run():
    result=dict(status='PASS_STATIC_EXACT_TORUS_ONLY', ciphertexts_created=0, rust_compiled=False,
                runtime_or_noise_claim=False, source_pins=verify_pins(), local_lemmas=local_lemmas(),
                stock_lut_interior_words=geometry(), round_cases=round_cases(),
                exact_id_cases=exact_id_cases(), ledgers=[model.ledger(n) for n in (4,64,127,128)],
                negatives=counterexamples(),padding_alternative=padding_alternative())
    return result


if __name__ == '__main__':
    print(json.dumps(run(),indent=2))
