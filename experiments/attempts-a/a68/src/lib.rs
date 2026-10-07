//! A68: an intentionally slow, checked-only exact-ID reference circuit.
//!
//! Every logical encrypted bit is a one-block `RadixCiphertext`.  The only
//! encrypted Boolean gates are the three checked integer APIs wrapped by
//! `CheckedGates`.  A checked failure aborts evaluation before a response is
//! constructed.

use std::fmt;

use tfhe::integer::{RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::CheckError;

pub const DIMENSION: usize = 512;
pub const SELECTORS_PER_COORDINATE: usize = 7;
pub const COORDINATE_MIN: i8 = -3;
pub const COORDINATE_MAX: i8 = 3;
pub const PROBE_NORM2_MAX: u16 = 1024;
pub const MAX_GALLERY_SIZE: usize = 128;

pub const QUERY_SQUARE_BITS: usize = 4;
pub const QUERY_NORM_BITS: usize = 13;
pub const DISTANCE_CONTRIBUTION_BITS: usize = 6;
pub const DISTANCE_BITS: usize = 14;
pub const THRESHOLD_BITS: usize = 15;
pub const ID_BITS: usize = 8;

pub const SCORE_MIN: i32 = -4608;
pub const SCORE_MAX: i32 = 13_824;

pub const A64_LEDGER_INTERCEPT: u64 = 24_029;
pub const A64_LEDGER_PER_GALLERY_ENTRY: u64 = 18_984;

pub const fn worst_case_checked_gate_calls(gallery_size: usize) -> u64 {
    A64_LEDGER_INTERCEPT + A64_LEDGER_PER_GALLERY_ENTRY * gallery_size as u64
}

#[derive(Debug)]
pub enum ProtocolError {
    Contract(String),
    CheckedGate(CheckError),
    InternalInvariant(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "contract error: {message}"),
            Self::CheckedGate(error) => write!(formatter, "checked gate refused input: {error:?}"),
            Self::InternalInvariant(message) => {
                write!(formatter, "internal invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<CheckError> for ProtocolError {
    fn from(error: CheckError) -> Self {
        Self::CheckedGate(error)
    }
}

#[derive(Clone, Debug)]
pub struct GalleryEntry {
    template: Vec<i8>,
    threshold: i32,
}

impl GalleryEntry {
    pub fn new(template: Vec<i8>, threshold: i32) -> Result<Self, ProtocolError> {
        if template.len() != DIMENSION {
            return Err(ProtocolError::Contract(format!(
                "template has {} coordinates; expected {DIMENSION}",
                template.len()
            )));
        }
        if template
            .iter()
            .any(|coordinate| !(COORDINATE_MIN..=COORDINATE_MAX).contains(coordinate))
        {
            return Err(ProtocolError::Contract(
                "template coordinate outside [-3, 3]".to_owned(),
            ));
        }
        if !(SCORE_MIN..=SCORE_MAX).contains(&threshold) {
            return Err(ProtocolError::Contract(format!(
                "threshold {threshold} outside [{SCORE_MIN}, {SCORE_MAX}]"
            )));
        }
        Ok(Self {
            template,
            threshold,
        })
    }
}

#[derive(Clone)]
struct Bit(RadixCiphertext);

impl Bit {
    fn encrypt(value: bool, client_key: &RadixClientKey, server_key: &ServerKey) -> Self {
        Self(
            client_key
                .encrypt_bool(value)
                .into_radix::<RadixCiphertext>(1, server_key),
        )
    }

    fn trivial(value: bool, server_key: &ServerKey) -> Self {
        let ciphertext: RadixCiphertext = server_key.create_trivial_radix(u64::from(value), 1);
        Self(ciphertext)
    }

    fn into_ciphertext(self) -> RadixCiphertext {
        self.0
    }
}

pub struct EncryptedQuery {
    coordinates: Vec<[Bit; SELECTORS_PER_COORDINATE]>,
}

pub struct EncryptedIdentity {
    bits_le: [RadixCiphertext; ID_BITS],
}

impl EncryptedIdentity {
    pub fn bits_le(&self) -> &[RadixCiphertext; ID_BITS] {
        &self.bits_le
    }
}

pub struct Evaluation {
    pub identity: EncryptedIdentity,
    pub checked_gate_calls: u64,
    pub worst_case_checked_gate_calls: u64,
}

struct CheckedGates<'key> {
    server_key: &'key ServerKey,
    calls: u64,
}

impl<'key> CheckedGates<'key> {
    fn new(server_key: &'key ServerKey) -> Self {
        Self {
            server_key,
            calls: 0,
        }
    }

    fn and_gate(&mut self, left: &Bit, right: &Bit) -> Result<Bit, ProtocolError> {
        let output = self.server_key.checked_bitand(&left.0, &right.0)?;
        self.calls += 1;
        Ok(Bit(output))
    }

    fn or_gate(&mut self, left: &Bit, right: &Bit) -> Result<Bit, ProtocolError> {
        let output = self.server_key.checked_bitor(&left.0, &right.0)?;
        self.calls += 1;
        Ok(Bit(output))
    }

    fn xor_gate(&mut self, left: &Bit, right: &Bit) -> Result<Bit, ProtocolError> {
        let output = self.server_key.checked_bitxor(&left.0, &right.0)?;
        self.calls += 1;
        Ok(Bit(output))
    }

    fn not(&mut self, value: &Bit) -> Result<Bit, ProtocolError> {
        let one = Bit::trivial(true, self.server_key);
        self.xor_gate(value, &one)
    }

    fn mux(&mut self, take_left: &Bit, left: &Bit, right: &Bit) -> Result<Bit, ProtocolError> {
        let delta = self.xor_gate(left, right)?;
        let masked = self.and_gate(take_left, &delta)?;
        self.xor_gate(right, &masked)
    }
}

pub fn encrypt_query(
    query: &[i8],
    client_key: &RadixClientKey,
    server_key: &ServerKey,
) -> Result<EncryptedQuery, ProtocolError> {
    if query.len() != DIMENSION {
        return Err(ProtocolError::Contract(format!(
            "query has {} coordinates; expected {DIMENSION}",
            query.len()
        )));
    }
    if query
        .iter()
        .any(|coordinate| !(COORDINATE_MIN..=COORDINATE_MAX).contains(coordinate))
    {
        return Err(ProtocolError::Contract(
            "query coordinate outside [-3, 3]".to_owned(),
        ));
    }

    let mut coordinates = Vec::with_capacity(DIMENSION);
    for &coordinate in query {
        let mut selectors = Vec::with_capacity(SELECTORS_PER_COORDINATE);
        for candidate in COORDINATE_MIN..=COORDINATE_MAX {
            selectors.push(Bit::encrypt(
                candidate == coordinate,
                client_key,
                server_key,
            ));
        }
        let selector_array = selectors.try_into().map_err(|_| {
            ProtocolError::InternalInvariant("one-hot selector width changed during encryption")
        })?;
        coordinates.push(selector_array);
    }
    Ok(EncryptedQuery { coordinates })
}

pub fn decrypt_identity(
    identity: &EncryptedIdentity,
    client_key: &RadixClientKey,
) -> Result<u8, ProtocolError> {
    let mut value = 0_u16;
    for (index, ciphertext) in identity.bits_le.iter().enumerate() {
        let bit: u8 = client_key.decrypt(ciphertext);
        if bit > 1 {
            return Err(ProtocolError::InternalInvariant(
                "response block did not decrypt to a bit",
            ));
        }
        value += u16::from(bit) * 2_u16.pow(index as u32);
    }
    u8::try_from(value)
        .map_err(|_| ProtocolError::InternalInvariant("eight response bits exceeded u8"))
}

fn validate_gallery(gallery: &[GalleryEntry]) -> Result<(), ProtocolError> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery.len()) {
        return Err(ProtocolError::Contract(format!(
            "gallery size {} outside 1..={MAX_GALLERY_SIZE}",
            gallery.len()
        )));
    }
    for entry in gallery {
        if entry.template.len() != DIMENSION {
            return Err(ProtocolError::Contract(
                "gallery entry dimension changed after construction".to_owned(),
            ));
        }
        if entry
            .template
            .iter()
            .any(|coordinate| !(COORDINATE_MIN..=COORDINATE_MAX).contains(coordinate))
        {
            return Err(ProtocolError::Contract(
                "gallery coordinate changed after construction".to_owned(),
            ));
        }
        if !(SCORE_MIN..=SCORE_MAX).contains(&entry.threshold) {
            return Err(ProtocolError::Contract(
                "gallery threshold changed after construction".to_owned(),
            ));
        }
    }
    Ok(())
}

fn bit_is_set(value: u64, bit_index: usize) -> bool {
    value / 2_u64.pow(bit_index as u32) % 2 == 1
}

fn public_unsigned_bits(value: u64, width: usize, server_key: &ServerKey) -> Vec<Bit> {
    (0..width)
        .map(|index| Bit::trivial(bit_is_set(value, index), server_key))
        .collect()
}

fn public_signed_bits(value: i32, width: usize, server_key: &ServerKey) -> Vec<Bit> {
    let modulus = 2_i64.pow(width as u32);
    let encoded = i64::from(value).rem_euclid(modulus) as u64;
    public_unsigned_bits(encoded, width, server_key)
}

fn half_adder(
    gates: &mut CheckedGates<'_>,
    left: &Bit,
    right: &Bit,
) -> Result<(Bit, Bit), ProtocolError> {
    let sum = gates.xor_gate(left, right)?;
    let carry = gates.and_gate(left, right)?;
    Ok((sum, carry))
}

fn full_adder(
    gates: &mut CheckedGates<'_>,
    left: &Bit,
    right: &Bit,
    carry: &Bit,
) -> Result<(Bit, Bit), ProtocolError> {
    let pair_xor = gates.xor_gate(left, right)?;
    let sum = gates.xor_gate(&pair_xor, carry)?;
    let direct = gates.and_gate(left, right)?;
    let via_carry = gates.and_gate(carry, &pair_xor)?;
    let carry_out = gates.or_gate(&direct, &via_carry)?;
    Ok((sum, carry_out))
}

fn add_bits(
    gates: &mut CheckedGates<'_>,
    left: &[Bit],
    right: &[Bit],
    keep_carry: bool,
) -> Result<Vec<Bit>, ProtocolError> {
    if left.len() != right.len() || left.len() < 2 {
        return Err(ProtocolError::InternalInvariant(
            "adder operands need equal widths of at least two",
        ));
    }

    let (first_sum, mut carry) = half_adder(gates, &left[0], &right[0])?;
    let mut output = Vec::with_capacity(left.len() + usize::from(keep_carry));
    output.push(first_sum);

    for index in 1..left.len() {
        if index + 1 == left.len() && !keep_carry {
            let pair_xor = gates.xor_gate(&left[index], &right[index])?;
            output.push(gates.xor_gate(&pair_xor, &carry)?);
        } else {
            let (sum, next_carry) = full_adder(gates, &left[index], &right[index], &carry)?;
            output.push(sum);
            carry = next_carry;
        }
    }
    if keep_carry {
        output.push(carry);
    }
    Ok(output)
}

fn sum_tree(
    gates: &mut CheckedGates<'_>,
    mut nodes: Vec<Vec<Bit>>,
    discard_final_carry: bool,
) -> Result<Vec<Bit>, ProtocolError> {
    if nodes.is_empty() || !nodes.len().is_power_of_two() {
        return Err(ProtocolError::InternalInvariant(
            "sum tree requires a nonempty power-of-two leaf count",
        ));
    }
    while nodes.len() > 1 {
        let final_pair = nodes.len() == 2;
        let keep_carry = !(discard_final_carry && final_pair);
        let mut next = Vec::with_capacity(nodes.len() / 2);
        let mut iterator = nodes.into_iter();
        while let Some(left) = iterator.next() {
            let right = iterator.next().ok_or(ProtocolError::InternalInvariant(
                "sum tree lost a right operand",
            ))?;
            next.push(add_bits(gates, &left, &right, keep_carry)?);
        }
        nodes = next;
    }
    nodes
        .pop()
        .ok_or(ProtocolError::InternalInvariant("sum tree lost its root"))
}

fn unsigned_lt(
    gates: &mut CheckedGates<'_>,
    left: &[Bit],
    right: &[Bit],
) -> Result<Bit, ProtocolError> {
    if left.len() != right.len() || left.is_empty() {
        return Err(ProtocolError::InternalInvariant(
            "comparator operands need equal nonzero widths",
        ));
    }
    let differing = gates.xor_gate(&left[0], &right[0])?;
    let mut borrow = gates.and_gate(&right[0], &differing)?;
    for (left_bit, right_bit) in left.iter().skip(1).zip(right.iter().skip(1)) {
        let differing = gates.xor_gate(left_bit, right_bit)?;
        let right_vs_borrow = gates.xor_gate(right_bit, &borrow)?;
        let change = gates.and_gate(&differing, &right_vs_borrow)?;
        borrow = gates.xor_gate(&borrow, &change)?;
    }
    Ok(borrow)
}

fn signed_lt(
    gates: &mut CheckedGates<'_>,
    left: &[Bit],
    right: &[Bit],
) -> Result<Bit, ProtocolError> {
    let unsigned_result = unsigned_lt(gates, left, right)?;
    let left_sign = left
        .last()
        .ok_or(ProtocolError::InternalInvariant("missing left sign bit"))?;
    let right_sign = right
        .last()
        .ok_or(ProtocolError::InternalInvariant("missing right sign bit"))?;
    let sign_differs = gates.xor_gate(left_sign, right_sign)?;
    gates.xor_gate(&unsigned_result, &sign_differs)
}

fn signed_le(
    gates: &mut CheckedGates<'_>,
    left: &[Bit],
    right: &[Bit],
) -> Result<Bit, ProtocolError> {
    let right_lt_left = signed_lt(gates, right, left)?;
    gates.not(&right_lt_left)
}

fn exactly_one_of_seven(
    gates: &mut CheckedGates<'_>,
    selectors: &[Bit; SELECTORS_PER_COORDINATE],
) -> Result<Bit, ProtocolError> {
    let mut duplicate = gates.and_gate(&selectors[0], &selectors[1])?;
    let mut seen = gates.or_gate(&selectors[0], &selectors[1])?;
    for selector in selectors.iter().skip(2) {
        let collision = gates.and_gate(&seen, selector)?;
        duplicate = gates.or_gate(&duplicate, &collision)?;
        seen = gates.or_gate(&seen, selector)?;
    }
    let no_duplicate = gates.not(&duplicate)?;
    gates.and_gate(&seen, &no_duplicate)
}

fn and_reduce(gates: &mut CheckedGates<'_>, values: &[Bit]) -> Result<Bit, ProtocolError> {
    let mut output = values
        .first()
        .ok_or(ProtocolError::InternalInvariant("empty AND reduction"))?
        .clone();
    for value in values.iter().skip(1) {
        output = gates.and_gate(&output, value)?;
    }
    Ok(output)
}

fn or_reduce(gates: &mut CheckedGates<'_>, values: &[Bit]) -> Result<Bit, ProtocolError> {
    let mut output = values
        .first()
        .ok_or(ProtocolError::InternalInvariant("empty OR reduction"))?
        .clone();
    for value in values.iter().skip(1) {
        output = gates.or_gate(&output, value)?;
    }
    Ok(output)
}

fn xor_lookup(
    gates: &mut CheckedGates<'_>,
    selectors: &[Bit; SELECTORS_PER_COORDINATE],
    clear_values: &[u16; SELECTORS_PER_COORDINATE],
    width: usize,
) -> Result<Vec<Bit>, ProtocolError> {
    let mut output = Vec::with_capacity(width);
    for bit_index in 0..width {
        let chosen: Vec<usize> = clear_values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| bit_is_set(u64::from(*value), bit_index).then_some(index))
            .collect();
        let Some((&first, remaining)) = chosen.split_first() else {
            output.push(Bit::trivial(false, gates.server_key));
            continue;
        };
        let mut bit = selectors[first].clone();
        for &index in remaining {
            bit = gates.xor_gate(&bit, &selectors[index])?;
        }
        output.push(bit);
    }
    Ok(output)
}

fn query_square_lookup(
    gates: &mut CheckedGates<'_>,
    selectors: &[Bit; SELECTORS_PER_COORDINATE],
) -> Result<Vec<Bit>, ProtocolError> {
    let clear_values = [9, 4, 1, 0, 1, 4, 9];
    xor_lookup(gates, selectors, &clear_values, QUERY_SQUARE_BITS)
}

fn distance_lookup(
    gates: &mut CheckedGates<'_>,
    selectors: &[Bit; SELECTORS_PER_COORDINATE],
    template_coordinate: i8,
) -> Result<Vec<Bit>, ProtocolError> {
    let mut clear_values = [0_u16; SELECTORS_PER_COORDINATE];
    for (index, query_coordinate) in (COORDINATE_MIN..=COORDINATE_MAX).enumerate() {
        let difference = i16::from(query_coordinate) - i16::from(template_coordinate);
        clear_values[index] = (difference * difference) as u16;
    }
    xor_lookup(gates, selectors, &clear_values, DISTANCE_CONTRIBUTION_BITS)
}

fn encrypted_query_norm(
    gates: &mut CheckedGates<'_>,
    query: &EncryptedQuery,
) -> Result<Vec<Bit>, ProtocolError> {
    let mut leaves = Vec::with_capacity(DIMENSION);
    for selectors in &query.coordinates {
        leaves.push(query_square_lookup(gates, selectors)?);
    }
    let norm = sum_tree(gates, leaves, false)?;
    if norm.len() != QUERY_NORM_BITS {
        return Err(ProtocolError::InternalInvariant(
            "query norm tree did not produce thirteen bits",
        ));
    }
    Ok(norm)
}

fn encrypted_norm_within_bound(
    gates: &mut CheckedGates<'_>,
    norm: &[Bit],
) -> Result<Bit, ProtocolError> {
    if norm.len() != QUERY_NORM_BITS {
        return Err(ProtocolError::InternalInvariant(
            "norm predicate expected thirteen bits",
        ));
    }
    let low_nonzero = or_reduce(gates, &norm[0..10])?;
    let over_1024_at_bit_10 = gates.and_gate(&norm[10], &low_nonzero)?;
    let high_or_middle = gates.or_gate(&norm[11], &over_1024_at_bit_10)?;
    let exceeds_bound = gates.or_gate(&norm[12], &high_or_middle)?;
    gates.not(&exceeds_bound)
}

fn encrypted_distance(
    gates: &mut CheckedGates<'_>,
    query: &EncryptedQuery,
    template: &[i8],
) -> Result<Vec<Bit>, ProtocolError> {
    let mut leaves = Vec::with_capacity(DIMENSION);
    for (selectors, &template_coordinate) in query.coordinates.iter().zip(template) {
        leaves.push(distance_lookup(gates, selectors, template_coordinate)?);
    }
    let distance = sum_tree(gates, leaves, true)?;
    if distance.len() != DISTANCE_BITS {
        return Err(ProtocolError::InternalInvariant(
            "distance tree did not produce fourteen bits",
        ));
    }
    Ok(distance)
}

fn mux_bits(
    gates: &mut CheckedGates<'_>,
    take_left: &Bit,
    left: &[Bit],
    right: &[Bit],
) -> Result<Vec<Bit>, ProtocolError> {
    if left.len() != right.len() {
        return Err(ProtocolError::InternalInvariant(
            "mux operands have different widths",
        ));
    }
    left.iter()
        .zip(right)
        .map(|(left_bit, right_bit)| gates.mux(take_left, left_bit, right_bit))
        .collect()
}

fn select_public_challenger(
    gates: &mut CheckedGates<'_>,
    take: &Bit,
    not_take: &Bit,
    old: &[Bit],
    challenger_value: u64,
) -> Result<Vec<Bit>, ProtocolError> {
    old.iter()
        .enumerate()
        .map(|(index, old_bit)| {
            if bit_is_set(challenger_value, index) {
                gates.or_gate(old_bit, take)
            } else {
                gates.and_gate(old_bit, not_take)
            }
        })
        .collect()
}

fn signed_encoding(value: i32, width: usize) -> u64 {
    let modulus = 2_i64.pow(width as u32);
    i64::from(value).rem_euclid(modulus) as u64
}

pub fn evaluate_exact_identity(
    query: &EncryptedQuery,
    gallery: &[GalleryEntry],
    server_key: &ServerKey,
) -> Result<Evaluation, ProtocolError> {
    validate_gallery(gallery)?;
    if query.coordinates.len() != DIMENSION {
        return Err(ProtocolError::Contract(
            "encrypted query does not contain 512 coordinates".to_owned(),
        ));
    }

    let mut gates = CheckedGates::new(server_key);

    let mut coordinate_validity = Vec::with_capacity(DIMENSION);
    for selectors in &query.coordinates {
        coordinate_validity.push(exactly_one_of_seven(&mut gates, selectors)?);
    }
    let one_hot_valid = and_reduce(&mut gates, &coordinate_validity)?;

    let query_norm = encrypted_query_norm(&mut gates, query)?;
    let norm_valid = encrypted_norm_within_bound(&mut gates, &query_norm)?;
    let valid = gates.and_gate(&one_hot_valid, &norm_valid)?;

    let first = gallery.first().ok_or(ProtocolError::InternalInvariant(
        "validated gallery became empty",
    ))?;
    let mut best_distance = encrypted_distance(&mut gates, query, &first.template)?;
    let mut selected_id = public_unsigned_bits(1, ID_BITS, server_key);
    let mut selected_threshold = public_signed_bits(first.threshold, THRESHOLD_BITS, server_key);

    for (index, challenger) in gallery.iter().enumerate().skip(1) {
        let challenger_distance = encrypted_distance(&mut gates, query, &challenger.template)?;
        let take = unsigned_lt(&mut gates, &challenger_distance, &best_distance)?;
        best_distance = mux_bits(&mut gates, &take, &challenger_distance, &best_distance)?;

        let not_take = gates.not(&take)?;
        selected_id = select_public_challenger(
            &mut gates,
            &take,
            &not_take,
            &selected_id,
            (index + 1) as u64,
        )?;
        selected_threshold = select_public_challenger(
            &mut gates,
            &take,
            &not_take,
            &selected_threshold,
            signed_encoding(challenger.threshold, THRESHOLD_BITS),
        )?;
    }

    let mut extended_norm = query_norm;
    while extended_norm.len() < THRESHOLD_BITS {
        extended_norm.push(Bit::trivial(false, server_key));
    }
    let threshold_rhs = add_bits(&mut gates, &extended_norm, &selected_threshold, false)?;

    let mut extended_distance = best_distance;
    extended_distance.push(Bit::trivial(false, server_key));
    let accepted = signed_le(&mut gates, &extended_distance, &threshold_rhs)?;
    let allow = gates.and_gate(&valid, &accepted)?;

    let mut response_bits = Vec::with_capacity(ID_BITS);
    for identity_bit in &selected_id {
        response_bits.push(gates.and_gate(&allow, identity_bit)?.into_ciphertext());
    }
    let bits_le = response_bits.try_into().map_err(|_| {
        ProtocolError::InternalInvariant("response did not contain exactly eight bits")
    })?;

    let worst_case = worst_case_checked_gate_calls(gallery.len());
    if gates.calls > worst_case {
        return Err(ProtocolError::InternalInvariant(
            "materialized circuit exceeded the pinned A64 gate ledger",
        ));
    }

    Ok(Evaluation {
        identity: EncryptedIdentity { bits_le },
        checked_gate_calls: gates.calls,
        worst_case_checked_gate_calls: worst_case,
    })
}

pub fn clear_reference_identity(
    query: &[i8],
    gallery: &[GalleryEntry],
) -> Result<u8, ProtocolError> {
    validate_gallery(gallery)?;
    if query.len() != DIMENSION
        || query
            .iter()
            .any(|coordinate| !(COORDINATE_MIN..=COORDINATE_MAX).contains(coordinate))
    {
        return Ok(0);
    }
    let query_norm: i32 = query
        .iter()
        .map(|coordinate| i32::from(*coordinate).pow(2))
        .sum();
    if query_norm > i32::from(PROBE_NORM2_MAX) {
        return Ok(0);
    }

    let mut winner = 0_usize;
    let mut best_distance = i32::MAX;
    for (index, entry) in gallery.iter().enumerate() {
        let distance: i32 = query
            .iter()
            .zip(&entry.template)
            .map(|(query_coordinate, template_coordinate)| {
                (i32::from(*query_coordinate) - i32::from(*template_coordinate)).pow(2)
            })
            .sum();
        if distance < best_distance {
            winner = index;
            best_distance = distance;
        }
    }

    if best_distance <= query_norm + gallery[winner].threshold {
        Ok((winner + 1) as u8)
    } else {
        Ok(0)
    }
}
