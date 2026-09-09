# A50/A53 exact-ID: primary-source prior-art audit

Date: 2026-09-02

Status: literature audit, not a patent/FTO search and not evidence that a construction has been
implemented or benchmarked under FHE. The negative statements below are deliberately limited to
the searched corpus and to explicitly stated operation classes.

Evidence convention: statements about what A50/A53 construct or enumerate are project-reported
properties taken from the two local specifications named below; this audit did not rerun those
models. Claims about earlier techniques are tied to primary papers, official documentation, or
official source repositories with sections/pages or source-line locations. Every statement that an
exact construction was not found is corpus-scoped rather than absolute.

## Scope

This audit concerns four narrow project claims:

1. **A50 canonical-state specialization:** normalizing fresh candidate state to `0/1`, retaining
   live state at `1` while dead states stay in a proved non-positive reachable set, so that gallery
   OR reductions can use fan-in 15 under the selected p16/raw-`L1<=15` contract without changing
   the exact `0/ID` result.
2. **A53 group-4 signed selector:** computing local first position with
   `f + 4*c0 + 2*c1 + c2`, then selecting only the first active group with
   `x = local - 4*prefix`, whose reachable signed states are `{-4,...,+4}`.
3. **A53 per-group-offset, dual-sample base-15 layout:** for public group `g`, deriving the two
   exact digits of `id=4g+p` from one custom p16 blind rotation, sample extractions at degrees
   `0` and `N/2`, and two public group-specific corrections, then reconstructing
   `id = low + 15*high`.
4. **A53 scoped group-5 no-go:** no construction in the class
   `public_offset + a*group_flag + sum_i(w_i*c_i)`, with integer coefficients,
   raw `|a|+sum_i|w_i|<=15`, and one scalar p16 PBS can distinguish no-hit and all five
   first-position classes. The project reports exhaustive enumeration of 1,303,777 normalized
   coefficient vectors and all 32 Boolean patterns per vector.

The local specifications audited were A50's
`tmp/a50-canonical-radix15-model/README.md` and A53's
`tmp/a53-radix15-group4-scan-model/README.md`.

## Bottom line

| Claim | What is already established prior art | Residual corpus-level novelty signal | Assessment |
|---|---|---|---|
| A50 canonical state enabling fan-in-15 OR | Canonical encodings and PBS recanonicalization; equal-weight Hamming-sum OR; very high-fan-in one-bootstrap OR | The exact live-`1`/dead-nonpositive invariant integrated into this byte-selection state machine and exact `0/ID` pipeline | Narrow and weak-to-moderate; useful engineering contribution, not a new OR/PBS primitive |
| A53 group-4 signed selector | Priority encoders; affine phase maps; signed/negacyclic state layouts; automated coefficient search | The exact `f+4c0+2c1+c2`, followed by `local-4prefix`, for tie-first exact identity | Narrow and moderate if stated as an application-specific construction/lemma |
| A53 dual-sample base-15 layout | One blind rotation with many extracts; interleaved LUT packing; public corrections; multiple radix digits from one input; structured use of negacyclic spare states | The exact joint layout for nine reachable signed states, two correlated base-15 ID digits, public group-dependent corrections, and exact `0/ID` reconstruction | Strongest constructive signal, but only for the combination; none of its ingredients is new alone |
| Group `>=5` no-go | Collision-separation formulations and exact/SMT coefficient searches are prior art | The project-reported finite infeasibility certificate for this dependent-flag, first-position relation under this exact p16/raw-`L1`/one-scalar-PBS model | Potentially the cleanest formal contribution once the search space and certificate are independently reproducible |

No audited primary source disclosed the exact A50 or A53 construction. That is an absence in the
searched corpus, not a claim of worldwide priority.

## Critical distinction: stock TFHE-rs many-LUT capacity versus raw negacyclic capacity

The current TFHE-rs generic many-LUT builder is intentionally partitioned into independent
positive-degree sub-LUTs:

- it requires `function_count <= modulus_sup/2`;
- it sets `max_degree = modulus_sup/function_count - 1`;
- it allocates `(max_degree+1)*box_size` coefficients to each function.

See TFHE-rs,
[`fill_many_lut_accumulator`, source lines 155-234](https://raw.githubusercontent.com/zama-ai/tfhe-rs/main/tfhe/src/shortint/engine/mod.rs)
(accessed 2026-09-02). Therefore at total modulus 16 with two functions the stock builder exposes
input degrees `0..7`: eight ordinary positive input values.

This is an **API/layout contract**, not a mathematical statement that a p16 accumulator has only
eight useful states for two correlated outputs. The same TFHE-rs implementation performs one blind
rotation and then extracts each output at a stride-selected monomial degree; see
[`keyswitch_programmable_bootstrap_many_lut`, lines 311-353](https://docs.rs/tfhe/latest/src/tfhe/shortint/atomic_pattern/standard.rs.html#311-353)
and the PBS-then-KS variant at lines 355-398.

At the raw ring level the test polynomial is negacyclic: for p16, phases span 32 positions subject
to `F(x+16)=-F(x)`. Signed reachable states and correlations between outputs can exploit that
structure whenever all antipodal coefficient constraints are consistent. A53's nine-state set
`{-4,...,+4}` is therefore **one state outside the stock generic two-function builder's positive
degree contract**, but it is not "beyond TFHE capacity." It requires a custom joint accumulator
layout whose correctness must be proved against the negacyclic constraints.

Thesis-safe wording:

> The construction does not increase the capacity of programmable bootstrapping. It exploits a
> structured signed reachable set and output correlation that are not represented by TFHE-rs's
> generic independent-sub-LUT builder.

Wording to avoid:

- "TFHE-rs can only handle eight states." 
- "We fit nine states into a physically eight-state PBS."
- "Dual extraction is new."

## Claim 1: A50 canonical state enabling fan-in-15 OR

### Closest prior art

Bon, Pointcheval and Rivain explicitly define **canonical p-encodings** as singleton encodings and
show that an arbitrary valid encoding can be reset to a canonical one with a PBS
([BPR24, Definition 6 and Property 1, pp. 6-7](https://www.nicolasbon.com/assets/pdf/BPR24.pdf)).
They also describe sums of encodings followed by PBS recanonicalization (Section 3.2, pp. 7-10)
and public scalar switching from `{0}->{0}, {1}->{1}` to `{0}->{0}, {1}->{a}`
(Property 4, pp. 11-12). Thus neither the term *canonical*, the encoding `0/1`, nor PBS-based
recanonicalization is new.

Yu et al. explain that a symmetric Boolean gate can be compressed to the Hamming weight by giving
all inputs equal unit weights, yielding only `n+1` phase values
([WAHC 2024, Section 3.1.1, pp. 4-5](https://si2.epfl.ch/~demichel/publications/archive/2024/wahc06-yu.pdf)).
This directly covers the generic idea "sum Boolean inputs and apply an OR LUT."

AutoHoG goes substantially beyond fan-in 15: with `l_max=32` it gives 32-input AND and OR, both
with all weights equal to one, in one gate bootstrap
([AutoHoG, Table III and the discussion immediately below it, p. 9](https://eprint.iacr.org/2024/1250.pdf)).
Therefore **a 15-input OR in one PBS is not itself a novelty claim**.

### What remains specific to A50

The searched corpus did not disclose the same state-machine specialization:

- live candidates are represented by exactly `1`;
- dead candidates are allowed to accumulate only inside a proved non-positive reachable set;
- `z_i` and each OR output remain canonical `0/1`;
- refreshes at the existing byte boundaries restore `0/1`;
- the invariant is used specifically to raise the gallery-wide reduction fan-in while preserving
  exact minimum-byte selection, tie-first behavior, and final `0/ID` semantics.

This is best presented as **state/primitive co-design for this exact-ID pipeline**, supported by
the finite reachable-state proof. It should not be presented as a new canonical encoding, a new OR
gate, or a generic high-fan-in TFHE technique.

Defensible wording:

> We specialize the candidate-state invariant of the exact-ID selector so that every gallery OR
> consumes fresh `0/1` values and can use fan-in 15 under our p16/raw-`L1<=15` parameter contract.
> In the primary-source corpus we audited, we did not find this invariant integrated with an exact
> tie-first `0/ID` argmin state machine.

## Claim 2: A53 group-4 signed selector

### Closest prior art

Priority encoding is not new and appears as a 128-input, seven-bit-position-plus-valid benchmark
in the EPFL suite; the primary RTL exposes inputs `A[0..127]`, outputs `P[0..6]`, and valid `F`
([official LogikBench RTL](https://raw.githubusercontent.com/zeroasiccorp/logikbench/main/logikbench/benchmarks/epfl/priority/rtl/priority.v)).
Yu et al. and Carpov both report FHE mappings for this priority benchmark
([WAHC 2024, Table 1, pp. 10-11](https://si2.epfl.ch/~demichel/publications/archive/2024/wahc06-yu.pdf);
[Carpov 2024/1204, Table 1, pp. 12-13](https://eprint.iacr.org/2024/1204.pdf)).
Those results do not disclose A53's local coefficient vector, but they preclude claiming the
priority encoder or encrypted first-one scan itself as new.

Affine phase projection is also established. Carpov formalizes multi-input FBS as an integer
linear combination followed by one nonlinear test polynomial, with correctness requiring phase
separation for inputs with different outputs
([Sections 2.2.1-2.2.2, pp. 4-6](https://eprint.iacr.org/2024/1204.pdf)).
BPR24 gives an exact backtracking search and proves that increasing `p` finds the minimum feasible
`p` in its Boolean-output model (Section 4, especially Theorem 1, p. 15). AutoHoG similarly uses
solver-backed weight search. Thus neither hand-picked integer coefficients nor exhaustive search
over coefficients is generically new.

Legiest et al. are especially close conceptually: they map dependent signed inputs
`Delta_v,Delta_h in {-1,0,1}` and a Boolean equality flag through the dense key
`(Delta_v+1)+3(Delta_h+1)+9*EQ`, then exploit zeros and negacyclicity to fit 18 logical states into
a 16-value TFHE lookup
([USENIX Security 2025, Sections 3.1.1-3.1.2, pp. 6-8](https://www.usenix.org/system/files/usenixsecurity25-legiest.pdf)).
This shows that application-specific signed affine packing and structured "over-capacity" use of
negacyclicity are prior art in the broad sense.

### What remains specific to A53

No audited source disclosed the exact two-step priority specialization:

```text
f     = OR(c0,c1,c2,c3)
phase = f + 4*c0 + 2*c1 + c2
x     = local_first(phase) - 4*prefix
```

The construction's useful observation is relational: `c3` is carried through the dependent flag
`f`, the local map needs only phases `0..8`, and the signed selector has only the nine reachable
states `-4..4`. This should be a constructive lemma for the exact-ID scan, not a claim that signed
selectors, affine packing, or priority encoders are new.

Defensible wording:

> We give an application-specific group-4 affine selector whose proved reachable set is
> `{-4,...,+4}` after exclusive-prefix suppression. We found no identical coefficient map or
> reachable-state construction in the audited primary-source corpus.

## Claim 3: per-group-offset dual-sample base-15 layout

This is the closest thing to a new constructive result, but it must be separated from several
well-established ingredients.

### Multi-output PBS and multiple sample extraction are prior art

Chillotti et al.'s PBSmanyLUT performs one blind rotation and sample-extracts up to `2^theta`
coefficients, producing one ciphertext for each function at essentially the cost/noise of one PBS
apart from cheap extractions
([CLOT21, Section 4.3, Algorithm 6 and Theorem 7, pp. 20-21](https://eprint.iacr.org/2021/729.pdf)).

MOSFHET's Bootstrap ManyLUT interleaves `z` LUTs in one accumulator, applies a public centering
offset `q/(4Bz)`, performs one blind rotation, and extracts output `i` at degree `i*r`
([Guimaraes, Borin and Aranha, Algorithm 8, p. 8](https://eprint.iacr.org/2022/515.pdf)).
This is particularly close generic art for "packed accumulator + public input offset + one blind
rotation + several extraction degrees."

Current TFHE-rs directly implements this one-blind-rotation/many-extract pattern, as documented in
the source links above. A53 therefore must not claim that one BR can produce two outputs, that two
sample extractions can share a BR, or that the outputs are correlated because they share a BR.

The older multi-value bootstrap of Carpov, Izabachene and Mollimard likewise evaluates several
homomorphic operations in one bootstrapping call
([CT-RSA 2019/ePrint 2018/622, Section 3.4 "Multi-output version," p. 15, and Section 4.2,
pp. 16-17](https://eprint.iacr.org/2018/622.pdf)). Its per-output polynomial processing differs
from A53's extraction-only layout, but the same-selector multi-output principle is older prior art.

### Public corrections and offset tricks are prior art

CLOT21 applies output-specific public constants after PBSmanyLUT in its circuit-bootstrap
optimization (Section 5.2, Lemma 4, p. 28). Carpov handles same-valued negacyclic endpoints by
bootstrapping `F'=F-mu` and then adding public `mu`
([Section 2.2.2, pp. 5-6](https://eprint.iacr.org/2024/1204.pdf)).
Consequently, public post-extraction correction is not new. A53's residual distinction is that a
known group index selects a pair `(u_g,v_g)` making one custom joint layout encode the two exact ID
digits over its nine signed reachable states.

### Multiple radix digits from one encrypted input are prior art

Bergerat et al.'s radix modular reduction applies distinct LUTs to one most-significant encrypted
block to output its decomposition in several radix bases (Supplementary Algorithm 4, pp. 52-53).
They explicitly state that the `kappa` KS-PBS calls can be replaced by PBSmanyLUT or multi-value
bootstrapping because the procedures evaluate several LUTs on the same input
([Supplementary Material, p. 44](https://eprint.iacr.org/2022/704.pdf)).
Thus "one encrypted input produces several radix digits" is not new by itself.

### Structured negacyclic layouts are prior art

Carpov shows that a linear image may exceed the FBS size when negacyclicity is exploitable and gives
a nine-position Boolean map in `Z_6`
([Listing 3, p. 17](https://eprint.iacr.org/2024/1204.pdf)). Legiest et al.'s 18-in-16 construction
is an even closer application example. A53 should not claim the generic idea of using unreachable,
zero, or antipodally compatible states to exceed a stock LUT layout.

### Residual exact combination not found

Within the audited corpus, no source disclosed all of the following together:

- the exact nine-state signed selector `x in {-4,...,+4}` produced by group-4 first-one logic;
- public group `g` and exact tie-first identity `id=4g+p`;
- non-power-of-two internal digits `low=id mod 15`, `high=floor(id/15)`;
- one custom p16 accumulator sampled specifically at `0` and `N/2`;
- a group-specific pair of public post-extraction corrections `(u_g,v_g)`;
- exact reconstruction `id=low+15*high`, including `0` for reject;
- validity for all 32 group indices and all tail lengths 1 through 4.

That integrated relation/layout is the defensible novelty candidate. The search result should be
phrased as corpus-scoped and construction-specific.

Defensible wording:

> We construct a family of group-indexed p16 accumulators for the exact-ID relation. For each
> public group, one blind rotation and the degree-`0`/degree-`N/2` samples, followed by two public
> corrections, encode the base-15 low and high digits for every reachable signed selector state.
> We found no identical layout in the primary-source corpus audited through 2 September 2026.

Wording to avoid:

- "We invented multi-output PBS."
- "We are the first to obtain two digits from one bootstrap."
- "Base 15 is novel."
- "Public output offsets are novel."
- "Nine states in a two-output p16 PBS were previously impossible."

## Claim 4: scoped no-go for group size five and above

The local result is meaningful only with its quantifiers fixed:

```text
c_i in {0,1}
group_flag = OR(c_0,...,c_4)             # fresh dependent marginal
phase = public_offset + a*group_flag + sum_i(w_i*c_i)
a,w_i are signed integers
|a| + sum_i |w_i| <= 15
one scalar p16 PBS must distinguish no-hit and each first-position class
```

The reported enumeration found that every coefficient vector causes at least two distinct
first-position classes to collide at the same phase modulo 32. An input offset translates both
phases equally, and an output offset cannot make one scalar-PBS input produce two different local
classes. If the enumeration is complete, group sizes above five are excluded in the same class by
restricting later candidates to zero.

### Closest prior art

BPR24 formalizes the same general collision-separation requirement for affine sums of canonical
Boolean encodings, supplies an exact search, and proves minimum-`p` optimality in its model
(Section 4, Lemmas 1-2 and Theorem 1, pp. 12-15). AutoHoG uses integer/SMT search and reports that,
for its `l_max=32` gate model, every Boolean gate through five inputs can be represented but not
every gate with six or more inputs (Section III and Table III, p. 9). These works mean that
"coefficient search proves some one-PBS functions infeasible" is not a new methodology.

However, they do not state A53's exact dependent-`group_flag`, six-marginal input relation; the
multi-valued `none/first-1/.../first-5` output partition; raw `L1<=15`; or the same-phase-mod-32
collision certificate. Carpov's priority benchmark is a mapped whole circuit and does not supply
this local lower bound.

### Defensible proposition

> For the specified one-flag affine projection with signed integer coefficients of raw
> `L1<=15`, followed by one scalar p16 PBS, no group-5 exact first-position selector exists. The
> result is a finite, machine-checkable infeasibility certificate; it does not rule out other
> operation classes.

Never shorten this to "group 4 is optimal" without immediately preserving the scope. The result
does **not** exclude:

- two or more nonlinear/PBS stages;
- PFKS or programmable packing;
- multi-output or ciphertext-multilane constructions;
- another fresh dependent marginal;
- different plaintext/ring geometry;
- parameter sets allowing raw `L1>15`;
- constructions outside integer affine preprocessing.

For publication-quality evidence, freeze and expose:

1. the exact truth relation, including the dependency of `group_flag`;
2. the normalized coefficient domain and every symmetry quotient;
3. a proof that the 1,303,777 enumerated vectors cover the full stated domain;
4. the checker source, input/output hash, and zero-solution log;
5. preferably a second independent checker or a compact SAT/SMT UNSAT certificate;
6. the short restriction proof from group `>5` to group 5.

## Construction-specific base-16 no-go

A53 also reports that direct base-16 low/high output fails for degree-`0`/degree-`N/2` extraction,
and remains infeasible across all 15 box-aligned second degrees and all `32^2` public output-offset
pairs for full groups 3, 11, 19 and 27. This is useful motivation for base 15, but it is **not** a
universal p16 no-go: sub-box extraction degrees and other output mechanisms are outside the tested
class. It should remain a construction-specific lemma, not a headline impossibility result.

## Primary-source comparison ledger

| Source | Precise relevant place | What it establishes | Gap relative to A50/A53 |
|---|---|---|---|
| Bon, Pointcheval, Rivain, *Optimized Homomorphic Evaluation of Boolean Functions* (TCHES 2024) | Definitions 5-6 and Property 1, pp. 6-7; Section 3.3, pp. 11-12; Section 4, pp. 12-15 | Canonical encodings, PBS recanonicalization, affine/sum separation, exact search/minimum `p` | Boolean-output framework; no exact-ID signed group-4/base-15 dual-sample layout |
| Yu et al., *On the Synthesis of High-performance Homomorphic Boolean Circuits* (WAHC 2024) | Section 2.2.2, p. 2; Section 2.4.2, pp. 3-4; Section 3.1.1, p. 4; Table 1, pp. 10-11 | Hamming-weight compression, same-weight multi-output gates, mapped priority encoder | Aggregate circuit mapping, not A53 coefficients or joint digit layout |
| Guan et al., *AutoHoG* (TCAD 2024/ePrint 2024/1250) | Section III and Table III, p. 9; [official solver, lines 9-40](https://raw.githubusercontent.com/Lavendes/AutoHog/main/T_construct_solver.py) | Solver-backed affine gate synthesis; one-bootstrap 32-input OR; arbitrary gates through five inputs | Different Boolean gate model and parameter limit; no dependent flag/first-position certificate |
| Carpov, *A Fast Heuristic for Mapping Boolean Circuits to Functional Bootstrapping* (2024/1204, TCHES 2025) | Sections 2.2.1-2.2.2, pp. 4-6; Table 1, pp. 12-13; Listing 3, p. 17 | Affine phase separation, public correction, priority benchmark, negacyclic image larger than FBS size | No A53 exact relation/layout or local group-5 proof |
| Chillotti et al., *Improved Programmable Bootstrapping...* (ASIACRYPT 2021/ePrint 2021/729) | Section 4.3, Algorithm 6/Theorem 7, pp. 20-21; Section 5.2, Lemma 4, p. 28 | One BR with many sample extracts; output-specific public constants | Generic independent functions, not A53's nine-state correlated digit relation |
| Guimaraes, Borin, Aranha, *MOSFHET* (JCE 2024/ePrint 2022/515) | Algorithm 8, p. 8 | Interleaved accumulator, public centering offset, one BR, extractions at `i*r` | Generic ManyLUT partitions capacity across outputs; no A53 group-indexed signed layout |
| Bergerat et al., *Parameter Optimization and Larger Precision for (T)FHE* (J. Cryptology 2023/ePrint 2022/704) | Section 4.3; Supplementary Algorithms 4-5, pp. 52-53; note on p. 44 | Radix integers; multiple digit/decomposition LUTs on one input can use PBSmanyLUT | Different arithmetic modular-reduction relation |
| Legiest et al., *Leuvenshtein* (USENIX Security 2025) | Sections 3.1.1-3.1.2 and Table 2, pp. 6-8 | Shared nonlinear core, signed dense key, 18 logical states in a 16-value negacyclic LUT | Single nonlinear value plus affine reconstruction; no base-15 dual extraction or priority ID |
| Carpov, Izabachene, Mollimard, *New Techniques for Multi-value Input Homomorphic Evaluation* (CT-RSA 2019/ePrint 2018/622) | Section 3.4, multi-output version, p. 15; Section 4.2, pp. 16-17 | Several same-input functions share the blind-rotation work; per-output polynomial processing follows | Uses per-output processing rather than A53's exact extraction-only relation |
| TFHE-rs source (accessed 2026-09-02) | `fill_many_lut_accumulator`, lines 155-234; standard atomic-pattern many-LUT methods, lines 311-398 | Stock positive-degree partition and actual one-BR/many-extract implementation | API builder is more restrictive than raw signed negacyclic layouts |
| Chaturvedi et al., [*BOLT* (ePrint 2026/153)](https://eprint.iacr.org/2026/153) | Tables I and III, pp. 2 and 6; Tables V-VI, p. 11; conclusion, p. 13 | Gate-based Boolean resynthesis, affine gate preprocessing, one-bootstrap gate-chain maps, bootstrapping-depth/count-aware DAG mapping, generic priority-encoder benchmark | No A53 nine-state coefficient search, dual correlated samples or exact-ID reconstruction; adapting conventional LUT optimizations to LUT-based FHE is stated as future work |

## Claims that are safe versus unsafe

Safe, with evidence and explicit scope:

- "We specialize the selector's state invariant to enable fan-in-15 OR under our selected raw
  noise contract."
- "We construct the exact group-4 signed selector shown by the stated coefficients."
- "We construct and exhaustively validate a group-indexed dual-sample base-15 layout for the
  nine reachable selector states."
- "Within the audited primary-source corpus, we found no identical exact-ID layout."
- "We give a finite no-go for group 5 in the stated one-flag + affine + one-scalar-p16-PBS class."

Unsafe or contradicted by prior art:

- "Canonical Boolean state is new."
- "A high-fan-in OR in one PBS is new."
- "Priority encoding under TFHE is new."
- "Affine packing or signed negacyclic lookup extension is new."
- "One blind rotation yielding multiple outputs is new."
- "Public offsets around PBS are new."
- "Producing multiple radix digits from one encrypted input is new."
- "Group 4 is universally optimal."
- "This is the first such method" or any absolute novelty claim based on this audit.

## Remaining audit gaps

- This was a focused scholarly-source audit, not an exhaustive search of patents, theses, private
  code, or every non-English venue.
- BOLT's full 14-page official PDF was inspected and source-locked in the companion A81 report.
  It closes that document-access gap without disclosing the A53 construction. Its generic
  bootstrapping-aware DAG mapper remains relevant prior art and motivates a separate heterogeneous
  exact-ID mapping lead.
- The aggregate priority-encoder rows in WAHC 2024 and Carpov 2024/1204 do not expose every local
  coefficient vector. Their released/generated netlists should be inspected if available before a
  publication-level priority claim.
- The A53 base-16 negative search covers box-aligned sample degrees; sub-box extraction remains
  outside that result.
- The group-5 result becomes citable evidence only after the enumerator, normalized domain, and
  reproducible certificate are frozen in the repository.
- A final paper should rerun the literature search immediately before submission, because this is
  an active research area and the audit cutoff is 2026-09-02.

## Recommended thesis positioning

Position A50 and A53 as a sequence of **exact-ID-specific co-design lemmas**, not as new primitive
cryptography:

1. A50 proves an invariant that makes an already-known high-fan-in Boolean technique usable in the
   exact minimum selector.
2. A53 gives a new-to-this-corpus local first-position affine construction and a custom joint
   accumulator layout for the exact two-digit ID relation.
3. The group-5 certificate explains why the chosen group size is maximal **inside the explicit
   implementation class**, while leaving PFKS, multi-stage, multilane, and higher-noise-budget
   designs open.

This formulation is both useful and defensible: the contribution is not that TFHE supports OR,
priority, affine phases, negacyclicity, or multi-output PBS; it is the exact combination that
reduces this privacy-preserving `0/ID` pipeline under its concrete parameter and correctness
constraints.
