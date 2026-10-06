//! Disabled-by-default observation of actual first-level stock PFKS calls.
//! Records contain public role, mask classification and wall duration only.
use crate::{h_untraced, public_digits, Lwe};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const EXPECTED_BY_LANE: [usize; 5] = [60, 60, 60, 60, 4];
const EXPECTED_CALLS: usize = 244;
static QUERY_ACTIVE: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static FIRST_LEVEL: AtomicBool = AtomicBool::new(false);
static RECORDS: Mutex<Vec<Record>> = Mutex::new(Vec::new());
static FULL_WORK: Mutex<Option<h_untraced::Counts>> = Mutex::new(None);

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Score,
    IdLow,
    IdMiddle,
}

#[derive(Clone, Serialize)]
pub struct Record {
    lane: usize,
    role: Role,
    mask_all_zero: bool,
    primitive_duration_ns: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub enabled: bool,
    pub calls: usize,
    pub full_work: serde_json::Value,
    by_lane: [usize; 5],
    score_calls: usize,
    id_low_calls: usize,
    id_middle_calls: usize,
    mask_zero_by_lane: [usize; 5],
    primitive_duration_sum_ns_by_lane: [u64; 5],
    records: Vec<Record>,
}

/// Coordinator-only query boundary; construction is outside the evaluation clock.
pub struct QueryGuard {
    enabled: bool,
}

impl QueryGuard {
    pub fn begin(enabled: bool) -> Result<Self, String> {
        QUERY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "profiling queries must be joined and serialized")?;
        let guard = Self { enabled };
        FIRST_LEVEL.store(false, Ordering::Release);
        *RECORDS.lock().map_err(|_| "profile record lock")? = if enabled {
            Vec::with_capacity(EXPECTED_CALLS)
        } else {
            Vec::new()
        };
        *FULL_WORK.lock().map_err(|_| "full work record lock")? = None;
        ENABLED.store(enabled, Ordering::Release);
        Ok(guard)
    }

    /// Called after the evaluation clock has stopped and every worker has joined.
    pub fn finish(self) -> Result<Report, String> {
        if FIRST_LEVEL.load(Ordering::Acquire) {
            return Err("first-level workers did not finish the profile boundary".into());
        }
        ENABLED.store(false, Ordering::Release);
        let records = std::mem::take(&mut *RECORDS.lock().map_err(|_| "profile record lock")?);
        let full_work = FULL_WORK
            .lock()
            .map_err(|_| "full work record lock")?
            .take()
            .ok_or("missing actual full-query work record")?;
        let mut by_lane = [0usize; 5];
        let mut mask_zero_by_lane = [0usize; 5];
        let mut durations = [0u64; 5];
        for record in &records {
            by_lane[record.lane] += 1;
            mask_zero_by_lane[record.lane] += usize::from(record.mask_all_zero);
            durations[record.lane] = durations[record.lane]
                .checked_add(record.primitive_duration_ns)
                .ok_or("primitive duration aggregate range")?;
            if record.lane >= 3 && !record.mask_all_zero {
                return Err("first-level ID input is not truly trivial".into());
            }
        }
        if self.enabled {
            if records.len() != EXPECTED_CALLS || by_lane != EXPECTED_BY_LANE {
                return Err("first-level stock PFKS count differs from the bound layout".into());
            }
        } else if !records.is_empty() {
            return Err("disabled profile collected records".into());
        }
        Ok(Report {
            enabled: self.enabled,
            calls: records.len(),
            full_work: full_work.json(),
            by_lane,
            score_calls: by_lane[..3].iter().sum(),
            id_low_calls: by_lane[3],
            id_middle_calls: by_lane[4],
            mask_zero_by_lane,
            primitive_duration_sum_ns_by_lane: durations,
            records,
        })
    }
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        FIRST_LEVEL.store(false, Ordering::Release);
        ENABLED.store(false, Ordering::Release);
        QUERY_ACTIVE.store(false, Ordering::Release);
    }
}

/// Admission check against the same public Repack plan, before generating keys.
pub fn validate_source_layout() -> Result<(), String> {
    let plan = public_digits::uniform(120, public_digits::Mode::Repack);
    let first = plan
        .levels
        .first()
        .ok_or("missing first-level public plan")?;
    if first.len() != 60 {
        return Err("first-level public plan must have60 nodes".into());
    }
    let mut by_lane = [0usize; 5];
    for node in first {
        for &lane in node.groups.iter().flatten() {
            if lane >= by_lane.len() {
                return Err("unexpected selected first-level payload lane".into());
            }
            by_lane[lane] += 1;
        }
    }
    if by_lane != EXPECTED_BY_LANE {
        return Err("first-level source layout differs from244 bound PFKS calls".into());
    }
    Ok(())
}

/// Coordinator stores only at level boundaries, before workers start.
pub(crate) fn configure_level(level: usize, candidates: usize) {
    FIRST_LEVEL.store(
        ENABLED.load(Ordering::Acquire) && level == 0 && candidates == 120,
        Ordering::Release,
    );
}

/// Coordinator clears only after the entire level's workers have joined.
pub(crate) fn finish_level() {
    FIRST_LEVEL.store(false, Ordering::Release);
}

/// Copy the actual full ledger once on the joined coordinator return boundary.
/// Serialization/report validation happen later, outside the evaluation clock.
pub(crate) fn record_full_work(counts: h_untraced::Counts) {
    if !QUERY_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let mut work = FULL_WORK.lock().expect("full work record lock");
    assert!(work.is_none(), "full query work must be recorded once");
    *work = Some(counts);
}

pub(crate) struct InputClass {
    lane: usize,
    role: Role,
    mask_all_zero: bool,
}

/// Read/classify the public ciphertext mask before the primitive timer starts.
pub(crate) fn classify(lane: usize, input: &Lwe) -> Option<InputClass> {
    if !FIRST_LEVEL.load(Ordering::Acquire) {
        return None;
    }
    assert_eq!(input.lwe_size().0, 2049, "bound PFKS input geometry");
    let role = match lane {
        0..=2 => Role::Score,
        3 => Role::IdLow,
        4 => Role::IdMiddle,
        _ => panic!("unexpected selected first-level payload lane"),
    };
    let mask_all_zero = input.get_mask().as_ref().iter().all(|v| *v == 0);
    assert!(
        lane < 3 || mask_all_zero,
        "first-level ID input must be trivial"
    );
    Some(InputClass {
        lane,
        role,
        mask_all_zero,
    })
}

/// Append only after elapsed time has been read; no primitive payload is retained.
pub(crate) fn record(class: InputClass, elapsed_ns: u128) {
    let primitive_duration_ns = elapsed_ns.try_into().expect("primitive duration range");
    let mut records = RECORDS.lock().expect("profile record lock");
    assert!(
        records.len() < EXPECTED_CALLS,
        "too many first-level PFKS calls"
    );
    records.push(Record {
        lane: class.lane,
        role: class.role,
        mask_all_zero: class.mask_all_zero,
        primitive_duration_ns,
    });
}
