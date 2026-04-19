# Releasing `sdk-rust`

Treat tagged releases as the supported distribution for the Rust core, the C
ABI header, and the native libraries consumed by `sdk-go` and `sdk-python`.

The supported automation path is:

- `push` / `pull_request` CI for fmt, clippy, test, release build, and package verification
- tag-triggered GitHub release creation with native bundles attached
- crates.io publication after the native bundles and release notes are ready

The repository itself may remain private if crates.io is the public source of
truth for Rust consumers. The release workflow requires a
`CARGO_REGISTRY_TOKEN` GitHub Actions secret to perform the real publish step.
The workflow also requires a `GH_PAT` secret with push
access to `LATTIX-IO/sdk-rust-public` so the public mirror repository receives
the same source snapshot, tag, and native release assets.

## Before tagging

1. Confirm the package metadata in `Cargo.toml` is current.
2. Update `CHANGELOG.md` with the release date and highlights.
2. Run:
   - `cargo fmt --all --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test`
   - `cargo build --release`
   - `cargo package --allow-dirty`
3. Review `include/lattix_sdk.h` for intentional ABI changes.
4. Ensure the README and example still reflect the current `/v1/sdk/*` surface.
5. Refresh `.github/release.yml` and `.github/RELEASE_TEMPLATE.md` if the native-asset pairing story has changed.

## Release steps

1. Update `version` in `Cargo.toml`.
2. Commit the version bump.
3. Create and push a tag such as `v0.1.0`.
4. Let `.github/workflows/release.yml` build and attach the native archives:
   - `sdk-rust-native-windows-x86_64.zip`
   - `sdk-rust-native-linux-x86_64.tar.gz`
   - `sdk-rust-native-macos-x86_64.tar.gz`
   - `sdk-rust-native-macos-aarch64.tar.gz`
5. Confirm the release notes generated from `.github/release.yml` and `.github/RELEASE_TEMPLATE.md` call out any ABI changes explicitly.
6. Confirm the `CARGO_REGISTRY_TOKEN` secret is configured for the repository.
7. Confirm the `GH_PAT` secret is configured for the repository and can push to `LATTIX-IO/sdk-rust-public`.
8. Let the workflow publish the crate to crates.io after both the private release and the `sdk-rust-public` mirror release exist with the native assets attached.

## Notes

- The public site at `https://lattix.io/docs` intentionally omits SDK API
  reference details. The README and packaged API docs remain the canonical Rust
  reference surface.
- Keep the release version aligned with the native assets used by downstream Go
  and Python bindings.
- The public mirror repository is the supported unauthenticated download source
  for `sdk-go` and any other consumers that need the native bundles without
  access to the private `sdk-rust` repository.
- Use workflow dispatch or local dry runs (`cargo package --locked`) for release rehearsals before the first real publish.