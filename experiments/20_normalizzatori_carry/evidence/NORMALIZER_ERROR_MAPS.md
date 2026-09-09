# Exact replay of the carry-derived error maps

For the2048-coefficient negacyclic ring, let
Q = sum(j=1..15) X^(64j) - 15X^1024. The derived low channel applies2Q
in the residual normalizer andQ in the carry normalizer. The carry channel
is unchanged. Root reconstructs these coefficients separately from the
native implementation and reads the saved signed common-error polynomials.

For every one of96shared pairs, coefficient0 is exactly the signed sum
-sum(q_j * e_(2048-j)); it equals the recorded derived output error. The
preserved carry error equals both e_0 and the scalar carry error. Triangle
inequality gives |(Qe)_0| <= ||Q||_1 ||e||_infinity, without an independence
assumption. The residual/carry L1 norms are60/30, and squared L2 norms960/240.
L2 is a coefficient statistic here, not an applicable variance certificate.

Normalized output spacing is2^59 and half-spacing is2^58. Maximum observed
low errors use10.7838%/4.0052% of that half-spacing; the conservative bounds
from each saved common-error polynomial use at most45.0772%/23.2423%.
All96record-conditional low bounds pass. This does not bound the probability
of a future common error vector, a future modulus-switch address, or the
composed tournament. It complements the lane's separate exact decryption
replay; this root reader does not read secrets or rerun crypto.

Evidence: NORMALIZER_ERROR_MAP_REPLAY.json and check_normalizer_error_maps.py.
The first root reader divided by2^59 instead of2^58; exact integer maps were
already correct. Its source/result are preserved in
normalizer-error-map-first-denominator-correction. Only reported fractions
were corrected. Original native/independent lane evidence is unchanged.
