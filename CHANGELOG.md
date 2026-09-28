# Changelog

All notable changes to RouteLoom are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the SDK version
follows [Semantic Versioning](https://semver.org/); the per-surface versions
(C ABI, wire, HostLink, storage) are listed in `docs/spec/compatibility.md`.

Each pull request adds a fragment under `changelog.d/` instead of editing
this file; the fragments are merged into a release section when a version is
tagged (see `changelog.d/README.md`).

## [Unreleased]

### Added

- `protocol/manifest.json` as the single source of the SDK version and every
  surface, storage and reason-code number; `tools/gen_manifest.py` generates
  `routeloom/version.h`, `routeloom_protocol::manifest` and the compatibility
  tables, and fails CI on drift.
- `AGENTS.md`, `docs/development/` (design principles, coding standards),
  `.clang-format` and `ruff.toml`.

### Changed

- The SDK version is `2.0.0-dev` for the ESP-IDF components, the Rust
  workspace and meshviz (was `0.1.0`). v2.0.0 is the first numbered release;
  there is no 1.x.
