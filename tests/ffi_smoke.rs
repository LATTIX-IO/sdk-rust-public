use std::ffi::{CStr, CString, c_char};

use mockito::{Matcher, Server};
use sdk_rust::ffi::{
    lattix_sdk_bootstrap, lattix_sdk_client_free, lattix_sdk_client_new,
    lattix_sdk_last_error_message, lattix_sdk_protection_plan, lattix_sdk_string_free,
};
use serde_json::{Value, json};

fn take_rust_string(value: *mut c_char) -> String {
    assert!(!value.is_null(), "expected Rust SDK to return a string");

    unsafe {
        let output = CStr::from_ptr(value).to_string_lossy().into_owned();
        lattix_sdk_string_free(value);
        output
    }
}

#[test]
fn ffi_bootstrap_smoke_returns_typed_json() {
    let mut server = Server::new();
    let _mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{
                    "tenant_id":"tenant-a",
                    "principal_id":"user-a",
                    "subject":"user-a",
                    "auth_source":"bearer_token",
                    "scopes":["platform-api.access"]
                },
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect"],
                "supported_artifact_profiles":["tdf"],
                "platform_domains":[{"domain":"policy","configured":true,"reason":"metadata-only"}]
            }"#,
        )
        .create();

    let options = CString::new(json!({ "base_url": server.url() }).to_string()).unwrap();
    let handle = lattix_sdk_client_new(options.as_ptr());
    assert!(!handle.is_null(), "expected ffi client handle");

    let response = take_rust_string(lattix_sdk_bootstrap(handle));
    let response_json: Value = serde_json::from_str(&response).expect("valid JSON response");
    assert_eq!(response_json["service"], "lattix-platform-api");
    assert_eq!(response_json["enforcement_model"], "embedded_local_library");

    unsafe { lattix_sdk_client_free(handle) };
}

#[test]
fn ffi_protection_plan_smoke_posts_metadata_only_payload() {
    let mut server = Server::new();
    let _mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"operation\":\"protect\"".into()),
            Matcher::Regex("\"content_digest\":\"sha256:abc123\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{
                    "tenant_id":"tenant-a",
                    "principal_id":"user-a",
                    "subject":"user-a",
                    "auth_source":"bearer_token",
                    "scopes":[]
                },
                "request_summary":{
                    "operation":"protect",
                    "workload_application":"example-app",
                    "resource_kind":"document",
                    "preferred_artifact_profile":"tdf",
                    "content_digest_present":true,
                    "label_count":1,
                    "attribute_count":1
                },
                "decision":{
                    "allow":true,
                    "required_scopes":[],
                    "handling_mode":"local_embedded_enforcement",
                    "plaintext_transport":"forbidden_by_default"
                },
                "execution":{
                    "protect_locally":true,
                    "local_enforcement_library":"sdk_embedded_library_or_local_sidecar",
                    "send_plaintext_to_platform":false,
                    "send_only":["content digest"],
                    "artifact_profile":"tdf",
                    "key_strategy":"local",
                    "policy_resolution":"metadata_only"
                },
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let options = CString::new(json!({ "base_url": server.url() }).to_string()).unwrap();
    let request = CString::new(
        json!({
            "operation": "protect",
            "workload": { "application": "example-app" },
            "resource": { "kind": "document" },
            "preferred_artifact_profile": "tdf",
            "content_digest": "sha256:abc123",
            "labels": ["confidential"],
            "attributes": { "region": "us" }
        })
        .to_string(),
    )
    .unwrap();

    let handle = lattix_sdk_client_new(options.as_ptr());
    assert!(!handle.is_null(), "expected ffi client handle");

    let response = take_rust_string(lattix_sdk_protection_plan(handle, request.as_ptr()));
    let response_json: Value = serde_json::from_str(&response).expect("valid JSON response");
    assert_eq!(response_json["execution"]["protect_locally"], true);
    assert_eq!(
        response_json["request_summary"]["resource_kind"],
        "document"
    );

    unsafe { lattix_sdk_client_free(handle) };
}

#[test]
fn ffi_reports_builder_errors_via_last_error_message() {
    let options = CString::new(json!({ "base_url": "   " }).to_string()).unwrap();
    let handle = lattix_sdk_client_new(options.as_ptr());
    assert!(handle.is_null(), "expected ffi client creation to fail");

    let message = take_rust_string(lattix_sdk_last_error_message());
    assert!(message.contains("base_url cannot be empty"));
}
