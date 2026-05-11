use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mockito::{Matcher, Server};
use sdk_rust::{
    ArtifactProfile, Client, CommandManagedSymmetricKeyProvider,
    InMemoryManagedSymmetricKeyProvider, LocalAttributeEdit, LocalProtectionRequest,
    LocalSymmetricKey, LocalSymmetricKeySource, ManagedSymmetricKeyProvider,
    ManagedSymmetricKeyReference, ResourceDescriptor, WorkloadDescriptor,
};

const EXPECTED_DIGEST: &str =
    "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn json_array(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(",")
}

fn bootstrap_body(operations: &[&str]) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "auth_mode":"bearer_token",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "enforcement_model":"embedded_local_library",
            "plaintext_to_platform":false,
            "policy_resolution_mode":"metadata_only_control_plane",
            "supported_operations":[{}],
            "supported_artifact_profiles":["tdf"],
            "platform_domains":[]
        }}"#,
        json_array(operations)
    )
}

fn policy_resolve_body(operation: &str, attribute_count: usize) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "request_summary":{{
                "operation":"{operation}",
                "workload_application":"example-app",
                "resource_kind":"document",
                "content_digest_present":true,
                "content_size_bytes":11,
                "purpose":"store",
                "label_count":1,
                "attribute_count":{attribute_count}
            }},
            "decision":{{
                "allow":true,
                "enforcement_mode":"local_embedded_enforcement",
                "required_scopes":[],
                "policy_inputs":[],
                "required_actions":[]
            }},
            "handling":{{
                "protect_locally":true,
                "plaintext_transport":"forbidden_by_default",
                "bind_policy_to":["artifact_digest","content_digest"],
                "evidence_expected":[]
            }},
            "platform_domains":[],
            "warnings":[]
        }}"#,
    )
}

fn protection_plan_body(operation: &str) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "request_summary":{{
                "operation":"{operation}",
                "workload_application":"example-app",
                "resource_kind":"document",
                "preferred_artifact_profile":"tdf",
                "content_digest_present":true,
                "content_size_bytes":11,
                "purpose":"store",
                "label_count":1,
                "attribute_count":1
            }},
            "decision":{{
                "allow":true,
                "required_scopes":[],
                "handling_mode":"local_embedded_enforcement",
                "plaintext_transport":"forbidden_by_default"
            }},
            "execution":{{
                "protect_locally":true,
                "local_enforcement_library":"sdk_embedded_library",
                "send_plaintext_to_platform":false,
                "send_only":["content digest","policy metadata"],
                "artifact_profile":"tdf",
                "key_strategy":"encrypt_locally_then_wrap_or_authorize_key_release",
                "policy_resolution":"metadata_only",
                "key_transport":{{
                    "mode":"wrapped_key_reference",
                    "key_material_origin":"kms",
                    "stable_key_reference_preferred":true,
                    "raw_key_delivery_forbidden":true,
                    "public_key_distribution":null,
                    "exchange_algorithm":null
                }}
            }},
            "platform_domains":[],
            "warnings":[]
        }}"#,
    )
}

fn key_access_plan_body(operation: &str) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "request_summary":{{
                "operation":"{operation}",
                "workload_application":"example-app",
                "resource_kind":"document",
                "artifact_profile":"tdf",
                "key_reference_present":true,
                "content_digest_present":true,
                "purpose":"store",
                "label_count":1,
                "attribute_count":1
            }},
            "decision":{{
                "allow":true,
                "required_scopes":[],
                "operation":"{operation}",
                "key_reference_present":true
            }},
            "execution":{{
                "local_cryptographic_operation":true,
                "platform_role":"authorize_only",
                "send_plaintext_to_platform":false,
                "send_only":["content digest","artifact digest"],
                "artifact_profile":"tdf",
                "authorization_strategy":"metadata_only_control_plane",
                "key_transport":{{
                    "mode":"wrapped_key_reference",
                    "key_material_origin":"kms",
                    "stable_key_reference_preferred":true,
                    "raw_key_delivery_forbidden":true,
                    "public_key_distribution":null,
                    "exchange_algorithm":null
                }}
            }},
            "platform_domains":[],
            "warnings":[]
        }}"#,
    )
}

fn artifact_register_body(operation: &str) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "request_summary":{{
                "operation":"{operation}",
                "workload_application":"example-app",
                "resource_kind":"document",
                "artifact_profile":"tdf",
                "artifact_digest":"sha256:any",
                "artifact_locator_present":false,
                "decision_id_present":false,
                "key_reference_present":true,
                "purpose":"store",
                "label_count":1,
                "attribute_count":1
            }},
            "registration":{{
                "accepted":true,
                "required_scopes":[],
                "artifact_transport":"metadata_only",
                "send_plaintext_to_platform":false,
                "catalog_actions":[],
                "evidence_expected":[]
            }},
            "platform_domains":[],
            "warnings":[]
        }}"#,
    )
}

fn evidence_body(event_type: &str) -> String {
    format!(
        r#"{{
            "service":"lattix-platform-api",
            "status":"ready",
            "caller":{{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]}},
            "request_summary":{{
                "event_type":"{event_type}",
                "workload_application":"example-app",
                "resource_kind":"document",
                "artifact_profile":"tdf",
                "artifact_digest_present":true,
                "decision_id_present":false,
                "outcome":"success",
                "occurred_at":null,
                "purpose":"store",
                "label_count":1,
                "attribute_count":1
            }},
            "ingestion":{{
                "accepted":true,
                "required_scopes":[],
                "plaintext_transport":"forbidden_by_default",
                "send_only":[],
                "correlate_by":[]
            }},
            "platform_domains":[],
            "warnings":[]
        }}"#,
    )
}

fn tdf_request() -> LocalProtectionRequest {
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
        purpose: Some("store".to_string()),
        labels: vec!["confidential".to_string()],
        attributes: BTreeMap::from([
            ("region".to_string(), "us".to_string()),
            ("legacy".to_string(), "1".to_string()),
        ]),
    }
}

#[test]
fn protect_and_access_tdf_with_managed_reference_uses_provider_runtime() {
    let mut server = Server::new();

    let _bootstrap = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(bootstrap_body(&["protect", "access"]))
        .expect(1)
        .create();
    let _protect_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("protect", 2))
        .expect(1)
        .create();
    let _access_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"access\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("access", 2))
        .expect(1)
        .create();
    let _protect_plan = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"protect\".*\"preferred_artifact_profile\":\"tdf\"".into(),
        ))
        .with_status(200)
        .with_body(protection_plan_body("protect"))
        .expect(1)
        .create();
    let _wrap_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"wrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("wrap"))
        .expect(1)
        .create();
    let _unwrap_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"unwrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("unwrap"))
        .expect(1)
        .create();
    let _register = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex(
            "\"operation\":\"protect\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(artifact_register_body("protect"))
        .expect(1)
        .create();
    let _protect_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\"".into()))
        .with_status(200)
        .with_body(evidence_body("protect"))
        .expect(1)
        .create();
    let _access_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\"".into()))
        .with_status(200)
        .with_body(evidence_body("access"))
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

    let key_source =
        LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-01");
    let protected = client
        .protect_bytes_with_tdf_using_key_source(&key_source, b"hello world", tdf_request())
        .expect("protect should succeed");
    assert_eq!(
        protected.prepared.content_binding.content_digest,
        EXPECTED_DIGEST
    );
    assert_eq!(
        protected
            .artifact
            .tdf
            .policy_context
            .as_ref()
            .expect("policy context")
            .workload
            .application,
        "example-app"
    );

    let accessed = client
        .access_bytes_with_tdf_using_key_source(&key_source, &protected.artifact.artifact_bytes)
        .expect("access should succeed");
    assert_eq!(accessed.plaintext, b"hello world");
    assert_eq!(
        accessed.manifest.attributes.get("region"),
        Some(&"us".to_string())
    );
}

#[test]
fn edit_tdf_attributes_with_managed_reference_uses_provider_runtime() {
    let mut server = Server::new();

    let _bootstrap = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(bootstrap_body(&["protect", "rewrap"]))
        .expect(2)
        .create();
    let _protect_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("protect", 2))
        .expect(1)
        .create();
    let _rewrap_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("rewrap", 2))
        .expect(2)
        .create();
    let _protect_plan = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(protection_plan_body("protect"))
        .expect(1)
        .create();
    let _rewrap_plan = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(protection_plan_body("rewrap"))
        .expect(1)
        .create();
    let _wrap_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"wrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("wrap"))
        .expect(1)
        .create();
    let _rewrap_key_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"rewrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("rewrap"))
        .expect(2)
        .create();
    let _protect_register = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex(
            "\"operation\":\"protect\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(artifact_register_body("protect"))
        .expect(1)
        .create();
    let _rewrap_register = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex(
            "\"operation\":\"rewrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(artifact_register_body("rewrap"))
        .expect(1)
        .create();
    let _protect_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\"".into()))
        .with_status(200)
        .with_body(evidence_body("protect"))
        .expect(1)
        .create();
    let _rewrap_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(evidence_body("rewrap"))
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

    let key_source =
        LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-01");
    let protected = client
        .protect_bytes_with_tdf_using_key_source(&key_source, b"hello world", tdf_request())
        .expect("protect should succeed");

    let edited = client
        .edit_tdf_attributes_using_key_source(
            &key_source,
            &protected.artifact.artifact_bytes,
            LocalAttributeEdit {
                set: BTreeMap::from([("region".to_string(), "eu".to_string())]),
                remove: vec!["legacy".to_string()],
            },
        )
        .expect("edit should succeed");

    assert_eq!(edited.artifact.tdf.meta_version, 2);
    assert_eq!(
        edited.manifest.attributes.get("region"),
        Some(&"eu".to_string())
    );
    assert!(!edited.manifest.attributes.contains_key("legacy"));
}

#[test]
fn rewrap_tdf_with_managed_references_uses_provider_runtime() {
    let mut server = Server::new();

    let _bootstrap = server
        .mock("GET", "/v1/sdk/bootstrap")
        .with_status(200)
        .with_body(bootstrap_body(&["protect", "rewrap", "access"]))
        .expect(2)
        .create();
    let _protect_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("protect", 2))
        .expect(1)
        .create();
    let _rewrap_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("rewrap", 2))
        .expect(2)
        .create();
    let _access_policy = server
        .mock("POST", "/v1/sdk/policy-resolve")
        .match_body(Matcher::Regex("\"operation\":\"access\"".into()))
        .with_status(200)
        .with_body(policy_resolve_body("access", 2))
        .expect(1)
        .create();
    let _protect_plan = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"protect\"".into()))
        .with_status(200)
        .with_body(protection_plan_body("protect"))
        .expect(1)
        .create();
    let _rewrap_plan = server
        .mock("POST", "/v1/sdk/protection-plan")
        .match_body(Matcher::Regex("\"operation\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(protection_plan_body("rewrap"))
        .expect(1)
        .create();
    let _wrap_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"wrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("wrap"))
        .expect(1)
        .create();
    let _rewrap_current_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"rewrap\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("rewrap"))
        .expect(2)
        .create();
    let _unwrap_new_plan = server
        .mock("POST", "/v1/sdk/key-access-plan")
        .match_body(Matcher::Regex(
            "\"operation\":\"unwrap\".*\"key_reference\":\"tenant-key-02\"".into(),
        ))
        .with_status(200)
        .with_body(key_access_plan_body("unwrap"))
        .expect(1)
        .create();
    let _protect_register = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex(
            "\"operation\":\"protect\".*\"key_reference\":\"tenant-key-01\"".into(),
        ))
        .with_status(200)
        .with_body(artifact_register_body("protect"))
        .expect(1)
        .create();
    let _rewrap_register = server
        .mock("POST", "/v1/sdk/artifact-register")
        .match_body(Matcher::Regex(
            "\"operation\":\"rewrap\".*\"key_reference\":\"tenant-key-02\"".into(),
        ))
        .with_status(200)
        .with_body(artifact_register_body("rewrap"))
        .expect(1)
        .create();
    let _protect_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"protect\"".into()))
        .with_status(200)
        .with_body(evidence_body("protect"))
        .expect(1)
        .create();
    let _rewrap_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"rewrap\"".into()))
        .with_status(200)
        .with_body(evidence_body("rewrap"))
        .expect(1)
        .create();
    let _access_evidence = server
        .mock("POST", "/v1/sdk/evidence")
        .match_body(Matcher::Regex("\"event_type\":\"access\"".into()))
        .with_status(200)
        .with_body(evidence_body("access"))
        .expect(1)
        .create();

    let client = Client::builder(server.url())
        .with_managed_symmetric_key_provider(InMemoryManagedSymmetricKeyProvider::new(
            "memory",
            BTreeMap::from([
                (
                    "tenant-key-01".to_string(),
                    LocalSymmetricKey::from([7u8; 32]),
                ),
                (
                    "tenant-key-02".to_string(),
                    LocalSymmetricKey::from([9u8; 32]),
                ),
            ]),
        ))
        .build()
        .expect("client");

    let current_key_source =
        LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-01");
    let new_key_source =
        LocalSymmetricKeySource::managed_reference_with_provider("memory", "tenant-key-02");
    let protected = client
        .protect_bytes_with_tdf_using_key_source(&current_key_source, b"hello world", tdf_request())
        .expect("protect should succeed");

    let rewrapped = client
        .rewrap_bytes_with_tdf_using_key_sources(
            &current_key_source,
            &new_key_source,
            &protected.artifact.artifact_bytes,
        )
        .expect("rewrap should succeed");
    assert_eq!(rewrapped.artifact.tdf.meta_version, 1);

    let accessed = client
        .access_bytes_with_tdf_using_key_source(&new_key_source, &rewrapped.artifact.artifact_bytes)
        .expect("access should succeed after rewrap");
    assert_eq!(accessed.plaintext, b"hello world");
}

#[test]
fn command_managed_provider_resolves_key_material() {
    let key_b64 = BASE64_STANDARD.encode([42u8; 32]);
    let provider = if cfg!(windows) {
        CommandManagedSymmetricKeyProvider::new("command", "powershell").with_args([
            "-NoProfile",
            "-Command",
            &format!("[Console]::Out.Write('{{\"key_b64\":\"{key_b64}\"}}')"),
        ])
    } else {
        CommandManagedSymmetricKeyProvider::new("command", "sh").with_args([
            "-c",
            &format!("printf '%s' '{{\"key_b64\":\"{key_b64}\"}}'"),
        ])
    };

    let resolved = provider
        .resolve_key(&ManagedSymmetricKeyReference::with_provider(
            "command",
            "tenant-key-cmd",
        ))
        .expect("command provider should resolve key");

    assert_eq!(resolved, LocalSymmetricKey::from([42u8; 32]));
}
