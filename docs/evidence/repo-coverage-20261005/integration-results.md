# Integrazioni del 5 settembre: cifre, PFKS e common-mask

Estratti di risultati del 5 settembre 2026, collegati il 5 ottobre. Gli stati e i limiti appartengono alle prove descritte; le successive integrazioni sono distinte. Provenienza e intervalli nel manifest.

## Fonte 1: `docs/research-state/2026-09-05/integration-pass/RESULTS.md`

| Existing work | What this pass connected/tested | Current verdict |
|---|---|---|
| TFHE1.7 A126+A66+A53 baseline | 18 legal packed-query fixtures: threshold boundaries, rejection, stable ties, ID/base15 boundaries throughN128; both control/fused endpoints | 36/36 encrypted evaluations pass on1freshkey; separate integration runs add narrower fresh-key coverage |
| Actual two-digit application service | Existing real Python client → local HTTP server running the frozen1.7 fused core → actual client decoder | Original adapter:4/4 cases,12 tests,6 negatives. Selected N127-nibble/A126-fallback adapter:4/4 cases,14 tests,8 negatives |
| Head Start compensated original-message recurrence | Actual four-PBS Algorithm1 recurrence atDelta51, ending in reconstructed score and original b0consumer | 3/4 pass; one513→514 through amplified feedback error; keep this configuration out of the baseline |
| Precision nibble selection | Actual packed score → directDelta54 digits/Delta51 feedback → A34/nibble selection → unchangedA53 two-digitID | R2 serial N4/N127 gates pass; R3 passes 63 parallel correctness cases across six keys, all12 timing endpoints, and actual N127 service integration |
| Existing p128/CMNR upgrade | Same completeA126+A66+A53 graph with configured switching at all5ordinary+4manual source sites | Both4-case parameter arms pass;23clear tests perfeature; all3890CMNRcalls execute corrections |
| Existing PFKS comparator +D1 | Actual packed-score B0limb bridge → sentinel-first stable two-merge tree → finalID | FullN2 passes all4cases,36BR/30KS/8PFKS/56BR-outputmarginals perquery |
| Existing persistent common-mask selector | Actual extraction+A34 producer → retained8-roundCM selector/keybridges → unchangedA53 | N4 all3scenes×2policies pass,3120semantic and576support checks; complete costs below |

The last two rows establish useful complete small-gallery compositions. Larger
PFKS tournaments and common-mask gallery construction require subsequent code;
there is no already implemented fullN127 endpoint in these two integration
artifacts waiting for a routine rerun. Their leads remain open.

## Fonte 2: `docs/research-state/2026-09-05/integration-pass/RESULTS.md`

The final correctness schedule is 8 N=4 cases, 11 N=16, 33 N=127 across three keys,
and 11 N=128: **63 cases across six distinct keysets**. The first fixture of each
keyset also compares serial/parallel ciphertext bytes, checks the A126 reference
and wrong-scale control, and replays exact LUT/coefficient behavior. Those six
targets contain 9,580 traced events; other fixtures retain native digit/flag and
final-ID checks. The timed public endpoint passes all12 encrypted evaluations.
