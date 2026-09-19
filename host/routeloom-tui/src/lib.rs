//! RouteLoom TUI core.
//!
//! This crate is an *observer* of the `routeloom-host` daemon: it talks only
//! to the daemon's line-oriented Unix-socket API and never opens the USB/TTY
//! adapter itself. The data model and renderer are a pure, testable layer —
//! `model::State` holds what the daemon reports (distinguishing observed,
//! estimated and unknown values) and `render::render` produces frame text.
//! Terminal IO lives in `main.rs` (crossterm).

pub mod client;
pub mod json;
pub mod model;
pub mod render;
