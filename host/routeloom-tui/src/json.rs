//! Minimal JSON parser — the implementation lives in the shared
//! `routeloom-json` crate (also used by the daemon's API1 IPC path); this
//! module re-exports it so `crate::json::parse` paths keep working.

pub use routeloom_json::*;
