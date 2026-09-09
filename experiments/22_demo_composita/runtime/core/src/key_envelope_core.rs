//! Exact residual reduction and a payload-silent unwind boundary. No FHE or output here.
use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

static HOOK_LOCK: Mutex<()> = Mutex::new(());

// An unwind payload can contain secrets or have a printing/panicking destructor.
// Neither the hook, formatting, downcasting nor the payload destructor may expose it.
pub(super) fn silent_boundary<T>(work: impl FnOnce() -> T) -> Result<T, ()> {
    let _lock = HOOK_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(work));
    let result = match result {
        Ok(value) => Ok(value),
        Err(payload) => { std::mem::forget(payload); Err(()) }
    };
    panic::set_hook(original_hook);
    result
}

#[derive(Default)]
pub(super) struct Maximum {
    value: u64,
    pub coefficients: usize,
}

impl Maximum {
    pub fn inspect(&mut self, phase: u64, row_multiplier: u64, window: u64) {
        let plaintext = row_multiplier.wrapping_shl(42).wrapping_mul(window);
        let residual = phase.wrapping_sub(plaintext);
        let magnitude = (residual as i64 as i128).unsigned_abs() as u64;
        self.value = self.value.max(magnitude);
        self.coefficients += 1;
    }

    pub fn complete_value(&self, expected_coefficients: usize) -> Option<u64> {
        (self.coefficients == expected_coefficients).then_some(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[test]
    fn zero_one_body_and_all_positions() {
        let window = [0, 1, 0, 1];
        let mut maximum = Maximum::default();
        for (row, multiplier) in [0u64, 1, u64::MAX].into_iter().enumerate() {
            for (coefficient, w) in window.into_iter().enumerate() {
                let error = if row == 2 && coefficient == 2 { -700_000i64 } else { 629_833 };
                let phase = multiplier.wrapping_shl(42).wrapping_mul(w).wrapping_add(error as u64);
                maximum.inspect(phase, multiplier, w);
            }
        }
        assert_eq!(maximum.complete_value(12), Some(700_000));
        assert_eq!(maximum.complete_value(13), None);
    }

    #[test]
    fn signed_minimum_magnitude_is_included() {
        let mut maximum = Maximum::default();
        maximum.inspect(1u64 << 63, 0, 0);
        assert_eq!(maximum.complete_value(1), Some(1u64 << 63));
    }

    #[test]
    fn panic_hook_and_payload_are_silent_and_hook_is_restored() {
        struct Payload(Arc<AtomicUsize>);
        impl Drop for Payload { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let drops = Arc::new(AtomicUsize::new(0));
        let hooks = Arc::new(AtomicUsize::new(0));
        let saved = panic::take_hook();
        let hook_counter = hooks.clone();
        panic::set_hook(Box::new(move |_| { hook_counter.fetch_add(1, Ordering::SeqCst); }));
        let result: Result<(), ()> = silent_boundary(|| panic::panic_any(Payload(drops.clone())));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(hooks.load(Ordering::SeqCst), 0);
        let _ = panic::catch_unwind(|| panic!("public hook restoration control"));
        panic::set_hook(saved);
        assert_eq!(hooks.load(Ordering::SeqCst), 1);
    }
}
