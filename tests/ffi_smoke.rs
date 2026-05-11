use std::ffi::{CStr, CString, c_char};

use mockito::{Matcher, Server};
use sdk_rust::ffi::{
    lattix_sdk_access_bytes_with_tdf, lattix_sdk_bootstrap, lattix_sdk_client_free,
    lattix_sdk_client_new, lattix_sdk_last_error_message, lattix_sdk_prepare_local_protection,
    lattix_sdk_protect_bytes_with_tdf, lattix_sdk_protection_plan, lattix_sdk_string_free,
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
                "auth_configuration":{
                    "mode":"oauth_client_credentials",
                    "proof_of_possession":"mtls",
                    "oidc_issuer":"https://issuer.example",
                    "oidc_audience":"lattix-platform-api",
                    "oidc_issuer_ready":true,
                    "mtls_ready":true
                },
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
    assert_eq!(
        response_json["auth_configuration"]["mode"],
        "oauth_client_credentials"
    );

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
fn ffi_prepare_local_protection_smoke_returns_content_binding() {
    let mut server = Server::new();
    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect"],
                "supported_artifact_profiles":["envelope"],
                "platform_domains":[]
            }"#,
        )
        .create();
    let _policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::Regex("\"content_digest\":\"sha256:".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();
    let _plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::Regex("\"preferred_artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let options = CString::new(json!({ "base_url": server.url() }).to_string()).unwrap();
    let request = CString::new(
        json!({
            "content_b64": "aGVsbG8gd29ybGQ=",
            "request": {
                "workload": { "application": "example-app" },
                "resource": { "kind": "document" },
                "preferred_artifact_profile": "envelope"
            }
        })
        .to_string(),
    )
    .unwrap();

    let handle = lattix_sdk_client_new(options.as_ptr());
    assert!(!handle.is_null(), "expected ffi client handle");

    let response = take_rust_string(lattix_sdk_prepare_local_protection(
        handle,
        request.as_ptr(),
    ));
    let response_json: Value = serde_json::from_str(&response).expect("valid JSON response");
    assert_eq!(response_json["content_binding"]["tenant_id"], "tenant-a");
    assert_eq!(
        response_json["protection_plan"]["execution"]["artifact_profile"],
        "envelope"
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

#[test]
fn ffi_managed_tdf_round_trip_smoke_uses_registered_provider() {
    let mut server = Server::new();

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect","access"],"supported_artifact_profiles":["tdf"],"platform_domains":[]}"#)
        .expect(1)
        .create();
    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"access\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"access","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"preferred_artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _wrap_key_access_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"key_reference\":\"tenant-key-ffi\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _unwrap_key_access_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"key_reference\":\"tenant-key-ffi\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"unwrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"unwrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"key_reference\":\"tenant-key-ffi\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();
    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\"".into()))
        .with_status(200)
        .with_body(r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"access","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#)
        .expect(1)
        .create();

    let options = CString::new(
        json!({
            "base_url": server.url(),
            "managed_symmetric_key_providers": [
                {
                    "name": "memory",
                    "keys": {
                        "tenant-key-ffi": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
                    }
                }
            ]
        })
        .to_string(),
    )
    .unwrap();
    let handle = lattix_sdk_client_new(options.as_ptr());
    assert!(!handle.is_null(), "expected ffi client handle");

    let protect_request = CString::new(
        json!({
            "key_source": {
                "kind": "managed_reference",
                "provider_name": "memory",
                "key_reference": "tenant-key-ffi"
            },
            "plaintext_b64": "aGVsbG8gd29ybGQ=",
            "request": {
                "workload": { "application": "example-app" },
                "resource": { "kind": "document" },
                "preferred_artifact_profile": "tdf",
                "purpose": "store",
                "labels": ["confidential"],
                "attributes": { "region": "us" }
            }
        })
        .to_string(),
    )
    .unwrap();
    let protected: Value = serde_json::from_str(&take_rust_string(
        lattix_sdk_protect_bytes_with_tdf(handle, protect_request.as_ptr()),
    ))
    .expect("valid protected TDF response");
    assert_eq!(
        protected["artifact"]["tdf"]["policy_context"]["workload"]["application"],
        "example-app"
    );

    let access_request = CString::new(
        json!({
            "key_source": {
                "kind": "managed_reference",
                "provider_name": "memory",
                "key_reference": "tenant-key-ffi"
            },
            "artifact_bytes_b64": protected["artifact"]["artifact_bytes_b64"]
        })
        .to_string(),
    )
    .unwrap();
    let accessed: Value = serde_json::from_str(&take_rust_string(
        lattix_sdk_access_bytes_with_tdf(handle, access_request.as_ptr()),
    ))
    .expect("valid accessed TDF response");
    assert_eq!(accessed["plaintext_b64"], "aGVsbG8gd29ybGQ=");

    unsafe { lattix_sdk_client_free(handle) };
}
