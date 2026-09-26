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
