# sdk-rust

`sdk-rust` is the canonical Lattix SDK core for the metadata-only `lattix-platform-api` control plane. It owns the HTTP behavior, typed request/response models, and the C ABI consumed by the Go and Python bindings.

The public Lattix docs at `https://lattix.io/docs` intentionally stay focused on platform concepts and operator-facing guidance. Per-language SDK reference material lives with each SDK package, so this README is part of the supported Rust reference surface.

## Installation

Install the published crate from crates.io:

```bash
cargo add sdk-rust
```

Tagged GitHub releases in the public mirror repository
`https://github.com/LATTIX-IO/sdk-rust-public/releases` publish version-matched
native bundles for downstream bindings and non-Cargo consumers:

- `sdk-rust-native-linux-x86_64.tar.gz`
- `sdk-rust-native-macos-x86_64.tar.gz`
- `sdk-rust-native-macos-aarch64.tar.gz`
- `sdk-rust-native-windows-x86_64.zip`

Each archive contains the native library plus `include/lattix_sdk.h`.

## What it exposes

The Rust client currently supports the `/v1/sdk/*` control-plane operations used by embedded enforcement flows:

- `capabilities()`
- `whoami()`
- `bootstrap()`
- `protection_plan(...)`
- `policy_resolve(...)`
- `key_access_plan(...)`
- `artifact_register(...)`
- `evidence(...)`
- `prepare_local_protection(...)`
- `generate_cid_binding(...)`
- `protect_bytes_with_envelope(...)`
- `access_bytes_with_envelope(...)`

The control-plane operations are intentionally **metadata only**. Applications protect or access content locally; the platform resolves policy, identity, and key-handling plans from metadata. The local helper methods build on top of that control plane while keeping plaintext in-process.

`prepare_local_protection(...)` is the first embedded-enforcement helper on top of that control plane. It digests content in-process, derives a raw SHA-256 CID/digest binding, calls `bootstrap`, `policy_resolve`, and `protection_plan`, and fails closed if the platform contract stops requiring local-only handling.

`generate_cid_binding(...)` exposes the portable tenant/resource/policy binding directly, so callers can persist or inspect the deterministic CID linkage before encrypting or signing bytes.

`protect_bytes_with_envelope(...)` and `access_bytes_with_envelope(...)` extend that into a real in-process envelope workflow for the envelope artifact profile. The current implementation uses a caller-supplied symmetric key, keeps plaintext in-process, binds metadata as AEAD AAD, and still calls key planning, artifact registration, and evidence ingestion.

## Usage

```rust
use sdk_rust::{
    ArtifactProfile, Client, ProtectionOperation, ResourceDescriptor, SdkProtectionPlanRequest,
    WorkloadDescriptor,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.lattix.io")
        .with_bearer_token("replace-me")
        .with_tenant_id("tenant-a")
        .with_user_id("user-a")
        .build()?;

    let bootstrap = client.bootstrap()?;
    println!("bootstrap mode: {}", bootstrap.enforcement_model);

    let plan = client.protection_plan(&SdkProtectionPlanRequest {
        operation: ProtectionOperation::Protect,
        workload: WorkloadDescriptor {
            application: "example-app".to_string(),
            environment: Some("dev".to_string()),
            component: Some("worker".to_string()),
        },
        resource: ResourceDescriptor {
            kind: "document".to_string(),
            id: Some("doc-123".to_string()),
            mime_type: Some("application/pdf".to_string()),
        },
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        content_digest: Some("sha256:example".to_string()),
        content_size_bytes: Some(1024),
        purpose: Some("store".to_string()),
        labels: vec!["confidential".to_string()],
        attributes: std::collections::BTreeMap::new(),
    })?;

    println!("protect locally: {}", plan.execution.protect_locally);

    let prepared = client.prepare_local_protection(
        b"hello world",
        sdk_rust::LocalProtectionRequest {
            workload: WorkloadDescriptor {
                application: "example-app".to_string(),
                environment: Some("dev".to_string()),
                component: Some("worker".to_string()),
            },
            resource: ResourceDescriptor {
                kind: "document".to_string(),
                id: Some("doc-123".to_string()),
                mime_type: Some("application/pdf".to_string()),
            },
            preferred_artifact_profile: Some(ArtifactProfile::Tdf),
            purpose: Some("store".to_string()),
            labels: vec!["confidential".to_string()],
            attributes: std::collections::BTreeMap::new(),
        },
    )?;

    println!("content digest: {}", prepared.content_binding.content_digest);

    let cid_binding = client.generate_cid_binding(
        b"hello world",
        sdk_rust::LocalProtectionRequest {
            workload: WorkloadDescriptor {
                application: "example-app".to_string(),
                environment: Some("dev".to_string()),
                component: Some("worker".to_string()),
            },
            resource: ResourceDescriptor {
                kind: "document".to_string(),
                id: Some("doc-123".to_string()),
                mime_type: Some("application/pdf".to_string()),
            },
            preferred_artifact_profile: Some(ArtifactProfile::Envelope),
            purpose: Some("store".to_string()),
            labels: vec!["confidential".to_string()],
            attributes: std::collections::BTreeMap::from([
                ("region".to_string(), "us".to_string()),
            ]),
        },
    )?;

    println!("cid binding hash: {}", cid_binding.binding_hash);

    let key = sdk_rust::LocalSymmetricKey::from([7u8; 32]);
    let protected = client.protect_bytes_with_envelope(
        &key,
        b"hello world",
        sdk_rust::LocalProtectionRequest {
            workload: WorkloadDescriptor {
                application: "example-app".to_string(),
                environment: Some("dev".to_string()),
                component: Some("worker".to_string()),
            },
            resource: ResourceDescriptor {
                kind: "document".to_string(),
                id: Some("doc-123".to_string()),
                mime_type: Some("application/pdf".to_string()),
            },
            preferred_artifact_profile: Some(ArtifactProfile::Envelope),
            purpose: Some("store".to_string()),
            labels: vec!["confidential".to_string()],
            attributes: std::collections::BTreeMap::new(),
        },
    )?;

    let accessed = client.access_bytes_with_envelope(&key, &protected.artifact.artifact_bytes)?;
    println!("decrypted bytes: {}", String::from_utf8_lossy(&accessed.plaintext));
    Ok(())
}
```

The returned `LocalArtifactBinding` is the portable metadata object that links tenant, workload, resource, digest, raw CID, and policy-binding targets. It is the simplest entry point when you want deterministic CID lineage without yet creating a protected artifact.

Run the example with:

```bash
cargo run --example platform_api
```

## Binding expectations

This crate is also the native library consumed by `sdk-go` and `sdk-python`.

- canonical C header: `include/lattix_sdk.h`
- crate outputs: `rlib`, `cdylib`, `staticlib`
- Windows native library: `target/release/sdk_rust.dll`
- macOS native library: `target/release/libsdk_rust.dylib`
- Linux native library: `target/release/libsdk_rust.so`

Downstream bindings should treat `include/lattix_sdk.h` as the ABI source of truth and avoid maintaining hand-edited copies when possible.

### C ABI contract

- all exported functions use UTF-8 JSON payloads and JSON string responses
- strings returned by the library must be released with `lattix_sdk_string_free(...)`
- client handles returned by `lattix_sdk_client_new(...)` must be released with `lattix_sdk_client_free(...)`
- null returns indicate failure; call `lattix_sdk_last_error_message()` for the thread-local error string

## Testing

Run Rust unit tests plus FFI smoke tests with:

```bash
cargo test
```

The integration-full contract tests use the versioned
`testdata/integration_full_manifest.json` fixture so this repository's required
CI does not depend on another private checkout. Set
`SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH` only to test a different compatible
fixture explicitly.

To run the optional composed-environment smoke against a real target, provide
the composed endpoint env and execute the dedicated integration test:

```bash
SDK_API_E2E_INTEGRATION_FULL_BASE_URL=https://api.example \
SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH=/path/to/integration_full_manifest.json \
cargo test --test integration_full_composed -- --nocapture
```

Build the native artifacts used by downstream bindings with:

```bash
cargo build --release
```

## Local quality gate

Run the local quality gate before committing when you want the same style of
checks that would otherwise burn CI time:

```bash
./precommit.sh
```

On Windows:

```powershell
./precommit.ps1
```

The script applies safe automated fixes first, then runs linting, SAST, secret
scanning, tests, a release build, and finally cleans local build artifacts.

To wire the same checks into local Git commits and pushes:

```bash
./install-hooks.sh
```

or:

```powershell
./install-hooks.ps1
```

The installed `pre-commit` hook runs a faster version of the gate; the
installed `pre-push` hook runs the full gate.

## Release process

Tagged release steps for maintainers are documented in `RELEASING.md`. The
release workflow publishes to crates.io and attaches the version-matched native
archives to the GitHub release.

## License

Distributed under the proprietary Lattix SDK License in `LICENSE`.
