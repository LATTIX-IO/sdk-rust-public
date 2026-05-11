# Changelog

All notable changes to `sdk-rust` are documented in this file.

## [Unreleased]

## [0.1.1] - 2026-05-11

### Added
- Local protection and managed-key runtime support for TDF, envelope, and detached-signature workflows.
- Additional local and managed-provider test coverage, including release-ready FFI smoke coverage for local protection.
- Local pre-commit and pre-push quality gates with automated fixes, security scans, tests, release builds, and cleanup.
- Maintainer release scaffolding for changelog-first releases and native asset pairing notes.

### Changed
- Aligned the SDK auth contract with the direct bearer plus proof-of-possession control-plane surface.
- Added integration-full CI dispatch coverage for the shared runner path used by downstream SDK bindings.

### Fixed
- Updated managed envelope integration-full flows to use the required managed key source references.
- Hardened release CI so package verification runs cleanly before mirroring and crates.io publication.

## [0.1.0] - 2026-04-17

### Added
- Canonical Rust control-plane client for `/v1/sdk/*` metadata-only enforcement workflows.
- Typed request and response models for capabilities, bootstrap, protection planning, policy resolution, key access planning, artifact registration, and evidence ingestion.
- Canonical C ABI in `include/lattix_sdk.h` for downstream Go and Python bindings.
- FFI smoke tests covering bootstrap, protection-plan, and thread-local error propagation.
- Proprietary licensing and maintainer release documentation.

### Changed
- Replaced the legacy uploader-oriented example surface with the current metadata-only control-plane flow.
- Clarified the README as the supported per-language Rust reference surface.

### Removed
- Legacy uploader modules and example code that no longer matched the Rust-core SDK architecture.