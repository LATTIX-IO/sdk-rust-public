use std::collections::BTreeMap;

use mockito::{Matcher, Server};
use sdk_rust::{
    ArtifactProfile, Client, InMemoryManagedSymmetricKeyProvider, KeyTransportMode,
    LocalAttributeEdit, LocalProtectionRequest, LocalSigningKey, LocalSymmetricKey,
    LocalSymmetricKeySource, ResourceDescriptor, WorkloadDescriptor,
};

#[test]
fn prepare_local_protection_computes_digest_and_validates_local_contract() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
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
                "supported_operations":["protect","access","rewrap"],
                "supported_artifact_profiles":["tdf","envelope","detached_signature"],
                "platform_domains":[]
            }"#,
        )
        .create();

    let _policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex(format!("\"content_digest\":\"{expected_digest}\"")),
            Matcher::Regex("\"content_size_bytes\":11".into()),
            Matcher::Regex("\"application\":\"example-app\"".into()),
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
                    "scopes":["platform-api.access"]
                },
                "request_summary":{
                    "operation":"protect",
                    "workload_application":"example-app",
                    "workload_environment":"dev",
                    "workload_component":"worker",
                    "resource_kind":"document",
                    "resource_id":"doc-123",
                    "mime_type":"application/pdf",
                    "content_digest_present":true,
                    "content_size_bytes":11,
                    "purpose":"store",
                    "label_count":1,
                    "attribute_count":1
                },
                "decision":{
                    "allow":true,
                    "enforcement_mode":"local_embedded_enforcement",
                    "required_scopes":["platform-api.access"],
                    "policy_inputs":["content_digest","labels"],
                    "required_actions":["artifact_register","evidence"]
                },
                "handling":{
                    "protect_locally":true,
                    "plaintext_transport":"forbidden_by_default",
                    "bind_policy_to":["artifact_digest","content_digest"],
                    "evidence_expected":["protect"]
                },
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex(format!("\"content_digest\":\"{expected_digest}\"")),
            Matcher::Regex("\"content_size_bytes\":11".into()),
            Matcher::Regex("\"preferred_artifact_profile\":\"tdf\"".into()),
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
                    "scopes":["platform-api.access"]
                },
                "request_summary":{
                    "operation":"protect",
                    "workload_application":"example-app",
                    "workload_environment":"dev",
                    "workload_component":"worker",
                    "resource_kind":"document",
                    "resource_id":"doc-123",
                    "mime_type":"application/pdf",
                    "preferred_artifact_profile":"tdf",
                    "content_digest_present":true,
                    "content_size_bytes":11,
                    "purpose":"store",
                    "label_count":1,
                    "attribute_count":1
                },
                "decision":{
                    "allow":true,
                    "required_scopes":["platform-api.access"],
                    "handling_mode":"local_embedded_enforcement",
                    "plaintext_transport":"forbidden_by_default"
                },
                "execution":{
                    "protect_locally":true,
                    "local_enforcement_library":"sdk_embedded_library",
                    "send_plaintext_to_platform":false,
                    "send_only":["content digest","policy metadata"],
                    "artifact_profile":"tdf",
                    "key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release",
                    "policy_resolution":"platform_api_resolves_policy_from_metadata_only"
                },
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let prepared = client
        .prepare_local_protection(
            b"hello world",
            LocalProtectionRequest {
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
                attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
            },
        )
        .expect("prepared local protection");

    assert_eq!(prepared.content_binding.tenant_id, "tenant-a");
    assert_eq!(prepared.content_binding.content_digest, expected_digest);
    assert_eq!(prepared.content_binding.raw_cid, expected_digest);
    assert_eq!(prepared.content_binding.content_size_bytes, 11);
    assert_eq!(prepared.artifact_binding.raw_cid, expected_digest);
    assert_eq!(
        prepared.artifact_binding.binding_targets,
        vec!["artifact_digest".to_string(), "content_digest".to_string()]
    );
    assert!(
        prepared
            .artifact_binding
            .binding_hash
            .starts_with("sha256:")
    );
    assert_eq!(prepared.resolved_artifact_profile(), ArtifactProfile::Tdf);
    assert!(prepared.policy_resolution.handling.protect_locally);
    assert!(prepared.protection_plan.execution.protect_locally);
}

#[test]
fn generate_cid_binding_returns_portable_binding_metadata() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
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
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let binding = client
        .generate_cid_binding(
            b"hello world",
            LocalProtectionRequest {
                workload: WorkloadDescriptor {
                    application: "example-app".to_string(),
                    environment: None,
                    component: None,
                },
                resource: ResourceDescriptor {
                    kind: "document".to_string(),
                    id: None,
                    mime_type: None,
                },
                preferred_artifact_profile: Some(ArtifactProfile::Envelope),
                purpose: Some("store".to_string()),
                labels: vec!["confidential".to_string()],
                attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
            },
        )
        .expect("generated CID binding");

    assert_eq!(binding.tenant_id, "tenant-a");
    assert_eq!(binding.raw_cid, expected_digest);
    assert_eq!(binding.content_digest, expected_digest);
    assert_eq!(
        binding.binding_targets,
        vec!["artifact_digest", "content_digest"]
    );
    assert!(binding.binding_hash.starts_with("sha256:"));
}

#[test]
fn prepare_local_protection_rejects_plaintext_transport_from_policy_resolution() {
    let mut server = Server::new();

    let _bootstrap_mock = server
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
                "platform_domains":[]
            }"#,
        )
        .create();

    let _policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
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
                    "scopes":["platform-api.access"]
                },
                "request_summary":{
                    "operation":"protect",
                    "workload_application":"example-app",
                    "workload_environment":null,
                    "workload_component":null,
                    "resource_kind":"document",
                    "resource_id":null,
                    "mime_type":null,
                    "content_digest_present":true,
                    "content_size_bytes":4,
                    "purpose":null,
                    "label_count":0,
                    "attribute_count":0
                },
                "decision":{
                    "allow":true,
                    "enforcement_mode":"local_embedded_enforcement",
                    "required_scopes":[],
                    "policy_inputs":[],
                    "required_actions":[]
                },
                "handling":{
                    "protect_locally":true,
                    "plaintext_transport":"allowed",
                    "bind_policy_to":[],
                    "evidence_expected":[]
                },
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let error = client
        .prepare_local_protection(
            b"test",
            LocalProtectionRequest {
                workload: WorkloadDescriptor {
                    application: "example-app".to_string(),
                    environment: None,
                    component: None,
                },
                resource: ResourceDescriptor {
                    kind: "document".to_string(),
                    id: None,
                    mime_type: None,
                },
                preferred_artifact_profile: Some(ArtifactProfile::Tdf),
                purpose: None,
                labels: Vec::new(),
                attributes: BTreeMap::new(),
            },
        )
        .expect_err("policy plaintext transport should fail closed");

    match error {
        sdk_rust::SdkError::InvalidInput(message) => {
            assert!(message.contains("plaintext transport"));
        }
        other => panic!("expected invalid input error, got {other:?}"),
    }
}

#[test]
fn protect_with_envelope_rejects_provider_capability_mismatch_for_wrapped_key_mode() {
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
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"content_size_bytes":11,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release","policy_resolution":"metadata_only"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _key_access_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"wrap\".*\"artifact_profile\":\"envelope\".*\"key_reference\":\"tenant-key-01\""
                .into(),
        ))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url())
        .with_managed_symmetric_key_provider(
            InMemoryManagedSymmetricKeyProvider::new(
                "memory",
                BTreeMap::from([(
                    "tenant-key-01".to_string(),
                    LocalSymmetricKey::from([7u8; 32]),
                )]),
            )
            .with_supported_transport_modes(vec![KeyTransportMode::AuthorizedKeyRelease]),
        )
        .build()
        .expect("client");
    let error = client
        .protect_bytes_with_envelope_using_key_source(
            &LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-01"),
            b"hello world",
            LocalProtectionRequest {
                workload: WorkloadDescriptor {
                    application: "example-app".to_string(),
                    environment: None,
                    component: None,
                },
                resource: ResourceDescriptor {
                    kind: "document".to_string(),
                    id: None,
                    mime_type: None,
                },
                preferred_artifact_profile: Some(ArtifactProfile::Envelope),
                purpose: None,
                labels: Vec::new(),
                attributes: BTreeMap::new(),
            },
        )
        .expect_err("wrapped key reference mode should fail closed");

    match error {
        sdk_rust::SdkError::InvalidInput(message) => {
            assert!(message.contains("memory"));
            assert!(message.contains("wrapped_key_reference"));
        }
        other => panic!("expected invalid input error, got {other:?}"),
    }
}

#[test]
fn protect_with_envelope_rejects_managed_key_reference_for_local_provided_mode() {
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
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"content_size_bytes":11,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only","key_transport":{"mode":"local_provided","key_material_origin":"application_supplied","stable_key_reference_preferred":false,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let _key_access_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"wrap\".*\"artifact_profile\":\"envelope\".*\"key_reference\":\"tenant-key-02\""
                .into(),
        ))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
                "request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"purpose":null,"label_count":0,"attribute_count":0},
                "decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane","key_transport":{"mode":"local_provided","key_material_origin":"application_supplied","stable_key_reference_preferred":false,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let error = client
        .protect_bytes_with_envelope_using_key_source(
            &LocalSymmetricKeySource::managed_reference("tenant-key-02"),
            b"hello world",
            LocalProtectionRequest {
                workload: WorkloadDescriptor {
                    application: "example-app".to_string(),
                    environment: None,
                    component: None,
                },
                resource: ResourceDescriptor {
                    kind: "document".to_string(),
                    id: None,
                    mime_type: None,
                },
                preferred_artifact_profile: Some(ArtifactProfile::Envelope),
                purpose: None,
                labels: Vec::new(),
                attributes: BTreeMap::new(),
            },
        )
        .expect_err("managed reference should fail until provider execution exists");

    match error {
        sdk_rust::SdkError::InvalidInput(message) => {
            assert!(message.contains("requires an inline symmetric key"));
            assert!(message.contains("tenant-key-02"));
        }
        other => panic!("expected invalid input error, got {other:?}"),
    }
}

#[test]
fn protect_and_access_envelope_with_managed_key_reference_uses_registered_provider() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

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
                "supported_operations":["protect","access"],
                "supported_artifact_profiles":["envelope"],
                "platform_domains":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"protect\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"preferred_artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"key_reference\":\"tenant-key-01\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"key_reference\":\"tenant-key-01\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":0,"attribute_count":0},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"label_count":0,"attribute_count":0},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"access\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"access","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _unwrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"key_reference\":\"tenant-key-01\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"unwrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"operation":"unwrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true,"public_key_distribution":null,"exchange_algorithm":null}},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"access","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"label_count":0,"attribute_count":0},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url())
        .with_managed_symmetric_key_provider(InMemoryManagedSymmetricKeyProvider::new(
            "memory",
            BTreeMap::from([(
                "tenant-key-01".to_string(),
                LocalSymmetricKey::from([7u8; 32]),
            )]),
        ))
        .build()
        .expect("client");

    let request = LocalProtectionRequest {
        workload: WorkloadDescriptor {
            application: "example-app".to_string(),
            environment: None,
            component: None,
        },
        resource: ResourceDescriptor {
            kind: "document".to_string(),
            id: None,
            mime_type: None,
        },
        preferred_artifact_profile: Some(ArtifactProfile::Envelope),
        purpose: None,
        labels: Vec::new(),
        attributes: BTreeMap::new(),
    };

    let key_source =
        LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-01");
    let protected = client
        .protect_bytes_with_envelope_using_key_source(&key_source, b"hello world", request)
        .expect("protect should succeed with provider");
    let accessed = client
        .access_bytes_with_envelope_using_key_source(
            &key_source,
            &protected.artifact.artifact_bytes,
        )
        .expect("access should succeed with provider");

    assert_eq!(
        protected.prepared.content_binding.content_digest,
        expected_digest
    );
    assert_eq!(accessed.plaintext, b"hello world");
}

#[test]
fn protect_and_access_bytes_with_envelope_round_trip_and_emit_metadata_events() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect","access","rewrap"],
                "supported_artifact_profiles":["tdf","envelope","detached_signature"],
                "platform_domains":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\"operation\":\"protect\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":["content_digest"],"required_actions":["artifact_register","evidence"]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":["protect","access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex(format!("\"preferred_artifact_profile\":\"envelope\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","preferred_artifact_profile":"envelope","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":["content digest","policy metadata"],"artifact_profile":"envelope","key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release","policy_resolution":"platform_api_resolves_policy_from_metadata_only"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"artifact_profile\":\"envelope\".*\"key_reference\":\"local-symmetric-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"wrap","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"wrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":["content digest","artifact digest"],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"artifact_profile\":\"envelope\".*\"key_reference\":\"local-symmetric-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"envelope","artifact_digest":"sha256:artifact","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "registration":{"accepted":true,"required_scopes":["platform-api.access"],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":["record_artifact"],"evidence_expected":["protect","access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"event_type":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"outcome":"success","occurred_at":null,"purpose":"store","label_count":1,"attribute_count":1},
                "ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":["artifact digest","tenant metadata"],"correlate_by":["artifact_digest","tenant_id"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\"operation\":\"access\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"access","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":["content_digest"],"required_actions":["evidence"]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":["access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _unwrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"artifact_profile\":\"envelope\".*\"key_reference\":\"local-symmetric-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"unwrap","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"unwrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":["content digest","artifact digest"],"artifact_profile":"envelope","authorization_strategy":"metadata_only_control_plane"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"event_type":"access","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"outcome":"success","occurred_at":null,"purpose":"store","label_count":1,"attribute_count":1},
                "ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":["artifact digest","tenant metadata"],"correlate_by":["artifact_digest","tenant_id"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let request = LocalProtectionRequest {
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
        attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
    };

    let key = LocalSymmetricKey::from([7u8; 32]);
    let protected = client
        .protect_bytes_with_envelope(&key, b"hello world", request)
        .expect("protect should succeed");

    assert_eq!(
        protected.prepared.content_binding.content_digest,
        expected_digest
    );
    assert_eq!(
        protected.artifact.envelope.binding_hash,
        protected.prepared.artifact_binding.binding_hash
    );
    assert_eq!(
        protected.artifact.envelope.binding_targets,
        protected.prepared.artifact_binding.binding_targets
    );
    assert_eq!(
        protected.artifact.envelope.artifact_profile,
        ArtifactProfile::Envelope
    );
    assert!(!protected.artifact.artifact_bytes.is_empty());
    assert!(protected.artifact.artifact_digest.starts_with("sha256:"));

    let accessed = client
        .access_bytes_with_envelope(&key, &protected.artifact.artifact_bytes)
        .expect("access should succeed");

    assert_eq!(accessed.plaintext, b"hello world");
    assert_eq!(accessed.artifact.content_digest, expected_digest);
}

#[test]
fn protect_and_access_bytes_with_tdf_round_trip_and_emit_metadata_events() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect","access","rewrap"],
                "supported_artifact_profiles":["tdf","envelope","detached_signature"],
                "platform_domains":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\"operation\":\"protect\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":["content_digest"],"required_actions":["artifact_register","evidence"]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":["protect","access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex(format!("\"preferred_artifact_profile\":\"tdf\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","preferred_artifact_profile":"tdf","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},
                "execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":["content digest","policy metadata"],"artifact_profile":"tdf","key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release","policy_resolution":"platform_api_resolves_policy_from_metadata_only"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"wrap","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"wrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":["content digest","artifact digest"],"artifact_profile":"tdf","authorization_strategy":"metadata_only_control_plane"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"tdf","artifact_digest":"sha256:artifact","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "registration":{"accepted":true,"required_scopes":["platform-api.access"],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":["record_artifact"],"evidence_expected":["protect","access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"event_type":"protect","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"outcome":"success","occurred_at":null,"purpose":"store","label_count":1,"attribute_count":1},
                "ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":["artifact digest","tenant metadata"],"correlate_by":["artifact_digest","tenant_id"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\"operation\":\"access\".*\"content_digest\":\"{expected_digest}\"")))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"access","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","content_digest_present":true,"content_size_bytes":11,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":["content_digest"],"required_actions":["evidence"]},
                "handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":["access"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _unwrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"operation":"unwrap","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"purpose":"store","label_count":1,"attribute_count":1},
                "decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"unwrap","key_reference_present":true},
                "execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":["content digest","artifact digest"],"artifact_profile":"tdf","authorization_strategy":"metadata_only_control_plane"},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\".*\"artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "request_summary":{"event_type":"access","workload_application":"example-app","workload_environment":"dev","workload_component":"worker","resource_kind":"document","resource_id":"doc-123","mime_type":"application/pdf","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"outcome":"success","occurred_at":null,"purpose":"store","label_count":1,"attribute_count":1},
                "ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":["artifact digest","tenant metadata"],"correlate_by":["artifact_digest","tenant_id"]},
                "platform_domains":[],
                "warnings":[]
            }"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let request = LocalProtectionRequest {
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
        attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
    };

    let key = LocalSymmetricKey::from([9u8; 32]);
    let protected = client
        .protect_bytes_with_tdf(&key, b"hello world", request)
        .expect("protect should succeed");

    assert_eq!(
        protected.prepared.content_binding.content_digest,
        expected_digest
    );
    assert_eq!(
        protected.artifact.tdf.binding_hash,
        protected.prepared.artifact_binding.binding_hash
    );
    assert_eq!(
        protected.artifact.tdf.binding_targets,
        protected.prepared.artifact_binding.binding_targets
    );
    assert_eq!(
        protected.artifact.tdf.artifact_profile,
        ArtifactProfile::Tdf
    );
    assert!(!protected.artifact.artifact_bytes.is_empty());
    assert!(protected.artifact.artifact_digest.starts_with("sha256:"));

    let accessed = client
        .access_bytes_with_tdf(&key, &protected.artifact.artifact_bytes)
        .expect("access should succeed");

    assert_eq!(accessed.plaintext, b"hello world");
    assert_eq!(accessed.artifact.content_digest, expected_digest);
    assert_eq!(accessed.manifest.workload.application, "example-app");
}

#[test]
fn edit_tdf_attributes_rewrites_metadata_without_changing_plaintext_binding() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect","access","rewrap"],
                "supported_artifact_profiles":["tdf"],
                "platform_domains":[]
            }"#,
        )
        .expect(2)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"protect\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"preferred_artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":["platform-api.access"],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":["platform-api.access"],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _edit_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex(format!("\\\"operation\\\":\\\"rewrap\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")),
            Matcher::Regex("\"project\":\"atlas\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":2},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _edit_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"operation\":\"rewrap\".*\"preferred_artifact_profile\":\"tdf\"".into()),
            Matcher::Regex("\"project\":\"atlas\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"label_count":1,"attribute_count":2},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _edit_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"operation\":\"rewrap\".*\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()),
            Matcher::Regex("\"project\":\"atlas\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":2},"decision":{"allow":true,"required_scopes":[],"operation":"rewrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _edit_register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"operation\":\"rewrap\".*\"artifact_profile\":\"tdf\"".into()),
            Matcher::Regex("\"project\":\"atlas\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":2},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _edit_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"event_type\":\"rewrap\".*\"artifact_profile\":\"tdf\"".into()),
            Matcher::Regex("\"project\":\"atlas\"".into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":2},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"access\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"access","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":2},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _unwrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"artifact_profile\":\"tdf\".*\"key_reference\":\"local-tdf-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"unwrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":2},"decision":{"allow":true,"required_scopes":[],"operation":"unwrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\".*\"artifact_profile\":\"tdf\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"access","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":2},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let request = LocalProtectionRequest {
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
        attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
    };

    let key = LocalSymmetricKey::from([9u8; 32]);
    let protected = client
        .protect_bytes_with_tdf(&key, b"hello world", request)
        .expect("protect should succeed");

    let edited = client
        .edit_tdf_attributes(
            &key,
            &protected.artifact.artifact_bytes,
            LocalAttributeEdit {
                set: BTreeMap::from([("project".to_string(), "atlas".to_string())]),
                remove: vec!["obsolete".to_string()],
            },
        )
        .expect("attribute edit should succeed");

    assert_eq!(edited.content_binding.content_digest, expected_digest);
    assert_eq!(edited.content_binding, protected.prepared.content_binding);
    assert_eq!(
        edited.original_artifact_digest,
        protected.artifact.artifact_digest
    );
    assert_eq!(edited.artifact.tdf.meta_version, 2);
    assert_eq!(
        edited.manifest.attributes.get("region"),
        Some(&"us".to_string())
    );
    assert_eq!(
        edited.manifest.attributes.get("project"),
        Some(&"atlas".to_string())
    );
    assert_ne!(
        edited.artifact.artifact_digest,
        protected.artifact.artifact_digest
    );
    assert_ne!(
        edited.artifact.artifact_bytes,
        protected.artifact.artifact_bytes
    );

    let accessed = client
        .access_bytes_with_tdf(&key, &edited.artifact.artifact_bytes)
        .expect("access should succeed after metadata edit");

    assert_eq!(accessed.plaintext, b"hello world");
    assert_eq!(accessed.artifact.content_digest, expected_digest);
    assert_eq!(accessed.artifact.meta_version, 2);
    assert_eq!(
        accessed.manifest.attributes.get("project"),
        Some(&"atlas".to_string())
    );
}

#[test]
fn rewrap_bytes_with_envelope_reencrypts_artifact_without_changing_content_binding() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect","rewrap"],
                "supported_artifact_profiles":["envelope"],
                "platform_domains":[]
            }"#,
        )
        .expect(2)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"preferred_artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _rewrap_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"rewrap\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _rewrap_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\".*\"preferred_artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _rewrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"rewrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _rewrap_register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _rewrap_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"rewrap\".*\"artifact_profile\":\"envelope\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"rewrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"envelope","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let request = LocalProtectionRequest {
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
        attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
    };

    let old_key = LocalSymmetricKey::from([7u8; 32]);
    let new_key = LocalSymmetricKey::from([8u8; 32]);
    let protected = client
        .protect_bytes_with_envelope(&old_key, b"hello world", request)
        .expect("protect should succeed");

    let rewrapped = client
        .rewrap_bytes_with_envelope(&old_key, &new_key, &protected.artifact.artifact_bytes)
        .expect("rewrap should succeed");

    assert_eq!(rewrapped.content_binding.content_digest, expected_digest);
    assert_eq!(
        rewrapped.original_artifact_digest,
        protected.artifact.artifact_digest
    );
    assert_eq!(rewrapped.artifact.envelope.content_digest, expected_digest);
    assert_ne!(
        rewrapped.artifact.artifact_digest,
        protected.artifact.artifact_digest
    );
    assert_ne!(
        rewrapped.artifact.artifact_bytes,
        protected.artifact.artifact_bytes
    );
}

#[test]
fn sign_and_verify_bytes_with_detached_signature_round_trip_and_emit_metadata_events() {
    let mut server = Server::new();
    let expected_digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let _bootstrap_mock = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},
                "enforcement_model":"embedded_local_library",
                "plaintext_to_platform":false,
                "policy_resolution_mode":"metadata_only_control_plane",
                "supported_operations":["protect","access"],
                "supported_artifact_profiles":["detached_signature"],
                "platform_domains":[]
            }"#,
        )
        .expect(1)
        .create();

    let _protect_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"protect\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_plan_mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\".*\"preferred_artifact_profile\":\"detached_signature\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"detached_signature","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":["platform-api.access"],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"detached_signature","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _wrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"wrap\".*\"artifact_profile\":\"detached_signature\".*\"key_reference\":\"local-detached-signature-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"detached_signature","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _register_mock = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex("\"artifact_profile\":\"detached_signature\".*\"key_reference\":\"local-detached-signature-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":["platform-api.access"],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":["record_artifact"],"evidence_expected":["protect","access"]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _protect_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\".*\"artifact_profile\":\"detached_signature\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":["artifact_digest","tenant_id"]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_policy_mock = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex(format!("\\\"operation\\\":\\\"access\\\".*\\\"content_digest\\\":\\\"{expected_digest}\\\"")))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"access","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":["platform-api.access"],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _unwrap_key_plan_mock = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex("\"operation\":\"unwrap\".*\"artifact_profile\":\"detached_signature\".*\"key_reference\":\"local-detached-signature-key\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"operation":"unwrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":["platform-api.access"],"operation":"unwrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"detached_signature","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let _access_evidence_mock = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\".*\"artifact_profile\":\"detached_signature\"".into()))
        .with_status(200)
        .with_body(
            r#"{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"request_summary":{"event_type":"access","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":["platform-api.access"],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":["artifact_digest","tenant_id"]},"platform_domains":[],"warnings":[]}"#,
        )
        .expect(1)
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let request = LocalProtectionRequest {
        workload: WorkloadDescriptor {
            application: "example-app".to_string(),
            environment: None,
            component: None,
        },
        resource: ResourceDescriptor {
            kind: "document".to_string(),
            id: None,
            mime_type: None,
        },
        preferred_artifact_profile: None,
        purpose: Some("sign".to_string()),
        labels: vec!["confidential".to_string()],
        attributes: BTreeMap::from([("region".to_string(), "us".to_string())]),
    };

    let signing_key = LocalSigningKey::from([3u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let signed = client
        .sign_bytes_with_detached_signature(&signing_key, b"hello world", request)
        .expect("sign should succeed");

    assert_eq!(
        signed.prepared.content_binding.content_digest,
        expected_digest
    );
    assert_eq!(
        signed.artifact.detached_signature.binding_hash,
        signed.prepared.artifact_binding.binding_hash
    );
    assert_eq!(
        signed.artifact.detached_signature.binding_targets,
        signed.prepared.artifact_binding.binding_targets
    );
    assert_eq!(
        signed.artifact.detached_signature.artifact_profile,
        ArtifactProfile::DetachedSignature
    );
    assert!(!signed.artifact.artifact_bytes.is_empty());
    assert!(signed.artifact.artifact_digest.starts_with("sha256:"));

    let verified = client
        .verify_bytes_with_detached_signature(
            &verifying_key,
            b"hello world",
            &signed.artifact.artifact_bytes,
        )
        .expect("verify should succeed");

    assert_eq!(verified.artifact.content_digest, expected_digest);
    assert_eq!(verified.content_binding.raw_cid, expected_digest);
    assert_eq!(verified.artifact_digest, signed.artifact.artifact_digest);
}
