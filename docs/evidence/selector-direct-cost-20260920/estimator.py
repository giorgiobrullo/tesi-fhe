"""Paired ratios, conditional resampling within each observed family/scene cell."""
import math
import random
import statistics

SEED = 20260919
DRAWS = 10000


def estimate(samples, intervals=False):
    if not samples:
        return None
    if not all(type(x[k]) is int and x[k] > 0 for x in samples for k in ('stock_ns', 'candidate_ns')):
        raise ValueError('durations must be positive integer nanoseconds')
    logs = [math.log(x['candidate_ns']) - math.log(x['stock_ns']) for x in samples]
    ratio = math.exp(math.fsum(logs) / len(logs))
    result = {'pairs': len(samples), 'families': len({x['family'] for x in samples}),
              'candidate_over_stock_geometric_ratio': ratio,
              'candidate_relative_cost_percent': 100 * (ratio - 1),
              'candidate_faster_pairs': sum(x < 0 for x in logs),
              'stock_mean_seconds': statistics.mean(x['stock_ns'] for x in samples) / 1e9,
              'candidate_mean_seconds': statistics.mean(x['candidate_ns'] for x in samples) / 1e9,
              'stock_median_seconds': statistics.median(x['stock_ns'] for x in samples) / 1e9,
              'candidate_median_seconds': statistics.median(x['candidate_ns'] for x in samples) / 1e9,
              'median_candidate_minus_stock_seconds': statistics.median(x['candidate_ns'] - x['stock_ns'] for x in samples) / 1e9}
    if intervals:
        strata = {}
        for sample, value in zip(samples, logs):
            strata.setdefault((sample['family'], sample['scene']), []).append(value)
        generator = random.Random(SEED)
        draws = []
        for _ in range(DRAWS):
            selected = [values[int(generator.random() * len(values))]
                        for _, values in sorted(strata.items()) for _ in values]
            draws.append(math.exp(math.fsum(selected) / len(selected)))
        draws.sort()
        result['conditional_bootstrap95_ratio'] = [draws[249], draws[9749]]
        result['bootstrap'] = {'draws': DRAWS, 'seed': SEED, 'strata': 'family x scene',
            'resampling_unit': 'whole paired log-ratio', 'families_resampled': False,
            'interpretation': 'Conditional on the observed key families; repeated pairs are not independent key families.'}
    return result
