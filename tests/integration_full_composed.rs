use std::{collections::BTreeMap, env, fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sdk_rust::{
    Client, InMemoryManagedSymmetricKeyProvider, LocalSymmetricKey, load_integration_full_manifest,
    run_integration_full_scenario,
};

const BASE_URL_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_BASE_URL";
const BEARER_TOKEN_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_BEARER_TOKEN";
const TENANT_ID_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_TENANT_ID";
const USER_ID_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_USER_ID";
const MANIFEST_PATH_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH";
const ARTIFACT_DIR_ENV: &str = "SDK_API_E2E_INTEGRATION_FULL_ARTIFACT_DIR";

#[test]
fn runs_integration_full_scenario_against_composed_environment() {
    let Some(base_url) = env_value(BASE_URL_ENV) else {
        eprintln!("skipping composed integration-full scenario; set {BASE_URL_ENV}");
        return;
    };

    let manifest = load_integration_full_manifest(manifest_path()).expect("manifest should load");

    let mut keys = BTreeMap::new();
    keys.insert(
        manifest.managed_key_reference.clone(),
        LocalSymmetricKey::new(decode_test_key(&manifest.managed_key_b64)),
    );
    keys.insert(
        manifest.managed_rewrap_key_reference.clone(),
        LocalSymmetricKey::new(decode_test_key(&manifest.managed_rewrap_key_b64)),
    );

    let mut builder = Client::builder(base_url).with_managed_symmetric_key_provider(
        InMemoryManagedSymmetricKeyProvider::new(manifest.managed_key_provider_name.clone(), keys),
    );
    if let Some(token) = env_value(BEARER_TOKEN_ENV) {
        builder = builder.with_bearer_token(token);
    }
    if let Some(tenant_id) = env_value(TENANT_ID_ENV) {
        builder = builder.with_tenant_id(tenant_id);
    }
    if let Some(user_id) = env_value(USER_ID_ENV) {
        builder = builder.with_user_id(user_id);
    }

    let client = builder.build().expect("client should build");
    let summary = run_integration_full_scenario(&client, &manifest).expect("runner should succeed");

    assert_eq!(summary.runner, "sdk-rust");
    assert_eq!(summary.steps.len(), 15);

    let artifact_dir = artifact_dir();
    fs::create_dir_all(&artifact_dir).expect("artifact dir should be created");
    let summary_json = serde_json::to_string_pretty(&summary).expect("summary should serialize");
    fs::write(artifact_dir.join("summary.json"), summary_json)
        .expect("summary artifact should be written");
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn manifest_path() -> PathBuf {
    if let Some(path) = env_value(MANIFEST_PATH_ENV) {
        return PathBuf::from(path);
    }

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        base.join("..")
            .join("prop-system-tests")
            .join("fixtures")
            .join("sdk_api_e2e")
            .join("integration_full_manifest.json"),
        base.join("prop-system-tests")
            .join("fixtures")
            .join("sdk_api_e2e")
            .join("integration_full_manifest.json"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    panic!("integration-full manifest not found; set {MANIFEST_PATH_ENV}")
}

fn artifact_dir() -> PathBuf {
    env_value(ARTIFACT_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("output").join("sdk_rust_integration_full"))
}

fn decode_test_key(value: &str) -> [u8; 32] {
    let bytes = BASE64_STANDARD.decode(value).expect("valid test key");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
