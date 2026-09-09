//! Explicit three-root A53 adaptation: one dual and one single selector PBS per group.
//! The inherited backend, local-first, prefix and radix15 reduction primitives are unchanged.
use super::*;
use crate::a53_scan::wide as static_wide;

#[derive(Clone, Debug)]
pub struct A53WideFheOutput<Lwe> {
    pub low_digit: Lwe,
    pub middle_digit: Lwe,
    pub high_digit: Lwe,
    pub expected_counts: PrimitiveCounts,
    pub observed_counts: PrimitiveCounts,
}

pub fn materialize_a53_scan_wide<B: A53FheBackend>(
    gate: &FutureFheGate<'_>,
    backend: &B,
    candidates: &[B::Lwe],
) -> Result<A53WideFheOutput<B::Lwe>, FutureFheError<B::Error>> {
    validate_future_fhe_gate(gate).map_err(FutureFheError::Gate)?;
    if candidates.is_empty() || candidates.len() > static_wide::MAX_GALLERY_SIZE {
        return Err(FutureFheError::Static(A53StaticError::GallerySize));
    }
    let before = backend.counters();
    let boolean_scale = OutputScale::BooleanDigit;
    let or_body = torus_body(
        &slot_lut_residue_body(&GROUP_OR_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );
    let local_body = torus_body(
        &slot_lut_residue_body(&LOCAL_FIRST_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );
    let identity_body = torus_body(
        &slot_lut_residue_body(&DIGIT_IDENTITY_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );

    let group_count = candidates.len().div_ceil(GROUP_SIZE);
    let or_accumulator = if candidates.len() > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&or_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let local_accumulator = if candidates.len() > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&local_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let identity_accumulator = if group_count > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&identity_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let layouts = collect_ordered_results(
        candidates
            .chunks(GROUP_SIZE)
            .enumerate()
            .map(|(group_index, group)| static_wide::selector_layout(group_index, group.len()))
            .collect(),
    )
    .map_err(FutureFheError::Static)?;
    // Selector accumulator preparation and group flags are independent after layouts/shared LUTs.
    let (selector_accumulators_result, flags_result) = rayon::join(
        || {
            collect_ordered_results(
                layouts
                    .par_iter()
                    .map(|layout| {
                        let dual_body = torus_body(&layout.dual_residue_body, boolean_scale);
                        let single_body = torus_body(&layout.single_residue_body, boolean_scale);
                        Ok((backend.prepare_raw_accumulator(&dual_body)?,
                            backend.prepare_raw_accumulator(&single_body)?))
                    })
                    .collect(),
            )
        },
        || {
            collect_ordered_results(
                candidates
                    .par_chunks(GROUP_SIZE)
                    .map(|group| or_gate(backend, group, or_accumulator.as_ref()))
                    .collect(),
            )
        },
    );
    let selector_accumulators = selector_accumulators_result.map_err(FutureFheError::Backend)?;
    let flags = flags_result.map_err(FutureFheError::Backend)?;

    // Both branches consume flags but neither consumes the other's output.
    let (local_first_result, prefixes_result) = rayon::join(
        || {
            collect_ordered_results(
                candidates
                    .par_chunks(GROUP_SIZE)
                    .zip(flags.par_iter())
                    .map(|(group, flag)| {
                        if group.len() == 1 {
                            return Ok(flag.clone());
                        }
                        let mut encoded = flag.clone();
                        add_scaled(backend, &mut encoded, &group[0], 4);
                        add_scaled(backend, &mut encoded, &group[1], 2);
                        if group.len() >= 3 {
                            add_scaled(backend, &mut encoded, &group[2], 1);
                        }
                        backend.pbs_prepared(
                            &encoded,
                            local_accumulator.as_ref().expect(
                                "multi-candidate scan prepares the local-first accumulator",
                            ),
                        )
                    })
                    .collect(),
            )
        },
        || encrypted_exclusive_prefix(backend, &flags, or_accumulator.as_ref()),
    );
    let local_first = local_first_result.map_err(FutureFheError::Backend)?;
    let prefixes = prefixes_result.map_err(FutureFheError::Backend)?;
    let selector_outputs = collect_ordered_results(
        selector_accumulators.into_par_iter().enumerate()
            .map(|(group_index, (dual_accumulator, single_accumulator))| {
                let layout = &layouts[group_index];
                let mut encoded = local_first[group_index].clone();
                add_scaled(backend, &mut encoded, &prefixes[group_index], -(GROUP_SIZE as i32));
                let (mut first, mut second) = backend.pbs_dual_prepared(
                    &encoded, dual_accumulator, 0, SELECTOR_SECOND_SAMPLE_DEGREE)?;
                backend.add_plaintext_assign(&mut first, torus_plaintext(layout.offsets.low, boolean_scale));
                backend.add_plaintext_assign(&mut second, torus_plaintext(layout.offsets.high, boolean_scale));
                // Deliberately retain a separate KS/BR; shared-KS reuse is a different optimization.
                let single = backend.pbs_prepared(&encoded, &single_accumulator)?;
                let mut digits = [None, None, None];
                digits[layout.dual_lanes[0]] = Some(first);
                digits[layout.dual_lanes[1]] = Some(second);
                digits[layout.single_lane] = Some(single);
                Ok(digits.map(|digit| digit.expect("public lane map is a permutation")))
            }).collect(),
    ).map_err(FutureFheError::Backend)?;
    let roots = if group_count == 1 {
        selector_outputs.into_iter().next().expect("one nonempty selector group")
    } else {
        let mut lanes: [Vec<B::Lwe>; 3] = std::array::from_fn(|_| Vec::with_capacity(group_count));
        for row in selector_outputs {
            for (lane, value) in lanes.iter_mut().zip(row) {
                lane.push(value);
            }
        }
        let identity_accumulator = identity_accumulator.as_ref()
            .expect("multiple groups prepare the digit accumulator");
        let roots = collect_ordered_results(lanes.into_par_iter()
            .map(|lane| reduce_digit(backend, lane, identity_accumulator)).collect())
            .map_err(FutureFheError::Backend)?;
        roots.try_into().map_err(|_| FutureFheError::Static(A53StaticError::ContractViolation))?
    };
    let after = backend.counters();
    let observed = subtract_counts(after, before).ok_or(FutureFheError::CounterUnderflow)?;
    let expected = static_wide::scan_counts(candidates.len()).map_err(FutureFheError::Static)?.total;
    if observed != expected {
        return Err(FutureFheError::CounterMismatch { expected, observed });
    }
    let [low_digit, middle_digit, high_digit] = roots;
    Ok(A53WideFheOutput { low_digit, middle_digit, high_digit,
        expected_counts: expected, observed_counts: observed })
}
