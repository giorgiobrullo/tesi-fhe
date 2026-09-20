# Carry-derived error maps

For the 2048-coefficient negacyclic ring, define

```text
Q = sum(j=1..15) X^(64j) - 15 X^1024.
```

The derived low channel applies `2Q` in the residual normalizer and `Q` in
the carry normalizer. The carry channel is unchanged. This analysis checks
96 shared error-polynomial pairs; it is distinct from the larger
[three-key extraction sweep](THREE_FAMILY_RESULT.json).

For each pair, coefficient 0 is exactly the signed sum
`-sum(q_j * e_(2048-j))`, equal to the recorded derived output error.
The preserved carry error equals both `e_0` and the scalar carry error.
The triangle inequality gives

```text
|(Qe)_0| <= ||Q||_1 ||e||_infinity
```

without an independence assumption. Residual/carry L1 norms are 60/30;
squared L2 norms are 960/240. The L2 value is a coefficient statistic, not
an applicable variance certificate.

Output spacing is `2^59`; its half-spacing is `2^58`. The maximum observed
low errors use **10.7838% / 4.0052%** of that half-spacing. Conservative
bounds computed from each observed common-error polynomial use at most
**45.0772% / 23.2423%**. All 96 record-conditional low bounds pass.

These bounds condition on the observed error vectors. They do not bound
the probability of a future vector, a future modulus-switch address or a
failure in the composed tournament. [Experiment and timing results](../README.md).
