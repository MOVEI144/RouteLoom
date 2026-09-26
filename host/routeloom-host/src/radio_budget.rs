//! Daemon-wide RF diagnostic budget shared by telemetry and remote observation.

use std::sync::Mutex;

const INTERVAL_MS: u64 = 2_000; // 0.5 transaction/second.

#[derive(Default)]
struct Budget {
    active: Option<u64>,
    next_at_ms: u64,
}

#[derive(Default)]
pub struct RadioBudget(Mutex<Budget>);

impl RadioBudget {
    pub fn active(&self) -> Option<u64> {
        self.0.lock().expect("radio budget poisoned").active
    }

    pub fn release(&self, request: u64) {
        let mut budget = self.0.lock().expect("radio budget poisoned");
        if budget.active == Some(request) {
            budget.active = None;
        }
    }

    /// The serial writer may sit behind other frames after admission. Keep
    /// the next radio slot two seconds past the actual write attempt too.
    pub fn note_transmit_attempt(&self, request: u64, now_ms: u64) {
        let mut budget = self.0.lock().expect("radio budget poisoned");
        if budget.active == Some(request) {
            budget.next_at_ms = budget.next_at_ms.max(now_ms.saturating_add(INTERVAL_MS));
        }
    }

    pub fn send(&self, request: u64, now_ms: u64, enqueue: impl FnOnce() -> bool) -> bool {
        let mut budget = self.0.lock().expect("radio budget poisoned");
        if budget.active.is_some() || now_ms < budget.next_at_ms {
            return false;
        }
        if !enqueue() {
            return false;
        }
        budget.active = Some(request);
        budget.next_at_ms = now_ms.saturating_add(INTERVAL_MS);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::RadioBudget;

    #[test]
    fn delayed_writer_preserves_two_second_radio_interval() {
        let budget = RadioBudget::default();
        assert!(budget.send(1, 1_000, || true));
        budget.note_transmit_attempt(1, 3_400);
        budget.release(1);
        assert!(!budget.send(2, 3_500, || true));
        assert!(budget.send(2, 5_400, || true));
    }
}
