use mockito::{Matcher, Server};
use sdk_rust::{
    ArtifactProfile, Client, ProtectionOperation, ResourceDescriptor, SdkProtectionPlanRequest,
    WorkloadDescriptor,
};

#[test]
fn builder_rejects_empty_base_url() {
    let error = Client::builder("   ")
        .build()
        .err()
        .expect("builder should fail");
    assert!(matches!(error, sdk_rust::SdkError::InvalidInput(_)));
}

#[test]
fn capabilities_sends_auth_and_identity_headers() {
    let mut server = Server::new();
    let _mock = server
        .mock("GET", "/v1/sdk/capabilities")
        .match_header("authorization", "Bearer test-token")
        .match_header("x-lattix-tenant-id", "tenant-a")
        .match_header("x-lattix-user-id", "user-a")
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
                "default_required_scopes":["platform-api.access"],
                "routes":[
                    {
                        "route":"/v1/sdk/protection-plan",
                        "domain":"policy",
                        "configured":true,
                        "required_scopes":["policy.read"]
                    }
                ]
            }"#,
        )
        .create();

    let client = Client::builder(server.url())
        .with_bearer_token("test-token")
        .with_tenant_id("tenant-a")
        .with_user_id("user-a")
        .build()
        .expect("client");

    let response = client.capabilities().expect("capabilities response");
    assert_eq!(response.service, "lattix-platform-api");
    assert_eq!(response.caller.tenant_id, "tenant-a");
    assert_eq!(response.routes.len(), 1);
}

#[test]
fn sdk_client_credentials_exchange_short_lived_session_and_cache_it() {
    let mut server = Server::new();
    let _session_mock = server
        .mock("POST", "/v1/sdk/session")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"tenant_id\":\"tenant-a\"".into()),
            Matcher::Regex("\"client_id\":\"sdk-client\"".into()),
            Matcher::Regex(r#""requested_scopes":\["platform-api.access"\]"#.into()),
        ]))
        .with_status(200)
        .with_body(
            r#"{
                "access_token":"sdk-session-token",
                "token_type":"Bearer",
                "expires_in":900,
                "scope":"platform-api.access",
                "tenant_id":"tenant-a",
                "client_id":"sdk-client",
                "subject":"sdk:sdk-client"
            }"#,
        )
        .expect(1)
        .create();
    let _capabilities_mock = server
        .mock("GET", "/v1/sdk/capabilities")
        .match_header("authorization", "Bearer sdk-session-token")
        .with_status(200)
        .with_body(
            r#"{
                "service":"lattix-platform-api",
                "status":"ready",
                "auth_mode":"bearer_token",
                "caller":{
                    "tenant_id":"tenant-a",
                    "principal_id":"sdk-client",
                    "subject":"sdk:sdk-client",
                    "auth_source":"sdk_client_credentials",
                    "scopes":["platform-api.access"]
                },
                "default_required_scopes":["platform-api.access"],
                "routes":[]
            }"#,
        )
        .expect(2)
        .create();

    let client = Client::builder(server.url())
        .with_tenant_id("tenant-a")
        .with_client_id("sdk-client")
        .with_client_secret("super-secret")
        .with_requested_scopes(["platform-api.access"])
        .build()
        .expect("client");

    let first = client.capabilities().expect("capabilities response");
    let second = client.capabilities().expect("capabilities response");

    assert_eq!(first.caller.principal_id, "sdk-client");
    assert_eq!(second.caller.subject, "sdk:sdk-client");
}

#[test]
fn bootstrap_returns_typed_response() {
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
                "supported_operations":["protect","access","rewrap"],
                "supported_artifact_profiles":["tdf","envelope"],
                "platform_domains":[
                    {
                        "domain":"policy",
                        "configured":true,
                        "reason":"metadata-only"
                    }
                ]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let response = client.bootstrap().expect("bootstrap response");

    assert_eq!(response.enforcement_model, "embedded_local_library");
    assert!(!response.plaintext_to_platform);
    assert_eq!(response.supported_operations.len(), 3);
}

#[test]
fn protection_plan_posts_metadata_only_payload() {
    let mut server = Server::new();
    let _mock = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("\"operation\":\"protect\"".into()),
            Matcher::Regex("\"content_digest\":\"sha256:abc123\"".into()),
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
                    "preferred_artifact_profile":"tdf",
                    "content_digest_present":true,
                    "content_size_bytes":1024,
                    "label_count":1,
                    "attribute_count":1,
                    "purpose":"store"
                },
                "decision":{
                    "allow":true,
                    "required_scopes":["platform-api.access"],
                    "handling_mode":"local_embedded_enforcement",
                    "plaintext_transport":"forbidden_by_default"
                },
                "execution":{
                    "protect_locally":true,
                    "local_enforcement_library":"sdk_embedded_library_or_local_sidecar",
                    "send_plaintext_to_platform":false,
                    "send_only":["policy metadata","content digest"],
                    "artifact_profile":"tdf",
                    "key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release",
                    "policy_resolution":"platform_api_resolves_policy_from_metadata_only"
                },
                "platform_domains":[
                    {
                        "domain":"policy",
                        "configured":true,
                        "reason":"metadata-only"
                    }
                ],
                "warnings":[]
            }"#,
        )
        .create();

    let client = Client::builder(server.url()).build().expect("client");
    let response = client
        .protection_plan(&SdkProtectionPlanRequest {
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
            content_digest: Some("sha256:abc123".to_string()),
            content_size_bytes: Some(1024),
            purpose: Some("store".to_string()),
            labels: vec!["confidential".to_string()],
            attributes: std::collections::BTreeMap::from([(
                "region".to_string(),
                "us".to_string(),
            )]),
        })
        .expect("protection plan");

    assert!(response.execution.protect_locally);
    assert!(!response.execution.send_plaintext_to_platform);
    assert_eq!(response.request_summary.resource_kind, "document");
}
