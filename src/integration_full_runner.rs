use std::{collections::BTreeMap, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Client, SdkError,
    local::{
        LocalProtectionRequest, LocalSigningKey, LocalSymmetricKey, LocalSymmetricKeySource,
        LocalVerifyingKey,
    },
    models::{
        ArtifactProfile, EvidenceEventType, KeyAccessOperation, KeyTransportGuidance,
        KeyTransportMode, ProtectionOperation, ResourceDescriptor, SdkArtifactRegisterRequest,
        SdkEvidenceIngestRequest, SdkKeyAccessPlanRequest, SdkPolicyResolveRequest,
        SdkProtectionPlanRequest, WorkloadDescriptor,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationFullScenarioStep {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub sdk_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationFullManifest {
    pub name: String,
    pub version: u32,
    pub description: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub subject: String,
    #[serde(default)]
    pub default_required_scopes: Vec<String>,
    pub policy_scope: String,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub purpose: String,
    pub plaintext_utf8: String,
    pub content_digest: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub inline_key_b64: String,
    pub rewrap_key_b64: String,
    pub managed_key_provider_name: String,
    pub managed_key_reference: String,
    pub managed_key_b64: String,
    pub managed_rewrap_key_reference: String,
    pub managed_rewrap_key_b64: String,
    pub signing_key_b64: String,
    pub verifying_key_b64: String,
    #[serde(default)]
    pub steps: Vec<IntegrationFullScenarioStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrationFullRunSummary {
    pub runner: String,
    pub scenario: String,
    pub version: u32,
    pub tenant_id: String,
    pub steps: Vec<Value>,
}

pub fn load_integration_full_manifest(
    path: impl AsRef<Path>,
) -> Result<IntegrationFullManifest, SdkError> {
    let contents = fs::read_to_string(path.as_ref()).map_err(|error| {
        SdkError::InvalidInput(format!(
            "failed to read integration-full manifest {}: {error}",
            path.as_ref().display()
        ))
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        SdkError::Serialization(format!(
            "failed to decode integration-full manifest {}: {error}",
            path.as_ref().display()
        ))
    })
}

fn uses_managed_key_transport(key_transport: Option<&KeyTransportGuidance>) -> bool {
    !matches!(
        key_transport.map(|guidance| guidance.mode),
        None | Some(KeyTransportMode::LocalProvided)
    )
}

fn requires_managed_envelope_key(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::InvalidInput(message)
            if message.contains(
                "local envelope protection requires a managed key reference when key_transport.mode is wrapped_key_reference"
            )
    )
}

pub fn run_integration_full_scenario(
    client: &Client,
    manifest: &IntegrationFullManifest,
) -> Result<IntegrationFullRunSummary, SdkError> {
    let plaintext = manifest.plaintext_utf8.as_bytes();
    let inline_key =
        LocalSymmetricKey::new(decode_fixed_32("inline_key_b64", &manifest.inline_key_b64)?);
    let rewrap_key =
        LocalSymmetricKey::new(decode_fixed_32("rewrap_key_b64", &manifest.rewrap_key_b64)?);
    let signing_key = LocalSigningKey::new(decode_fixed_32(
        "signing_key_b64",
        &manifest.signing_key_b64,
    )?);
    let verifying_key = LocalVerifyingKey::from(decode_fixed_32(
        "verifying_key_b64",
        &manifest.verifying_key_b64,
    )?);

    let workload = manifest.workload.clone();
    let resource = manifest.resource.clone();
    let labels = manifest.labels.clone();
    let attributes = manifest.attributes.clone();

    let envelope_request = LocalProtectionRequest {
        workload: workload.clone(),
        resource: resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::Envelope),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    };
    let tdf_request = LocalProtectionRequest {
        workload: workload.clone(),
        resource: resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    };
    let detached_signature_request = LocalProtectionRequest {
        workload: workload.clone(),
        resource: resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::DetachedSignature),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    };

    let capabilities = client.capabilities()?;
    let bootstrap = client.bootstrap()?;
    let whoami = client.whoami()?;
    let prepared = client.prepare_local_protection(plaintext, envelope_request.clone())?;
    let cid_binding = client.generate_cid_binding(plaintext, envelope_request.clone())?;
    let protection_plan = client.protection_plan(&SdkProtectionPlanRequest {
        operation: ProtectionOperation::Protect,
        workload: workload.clone(),
        resource: resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        content_digest: Some(manifest.content_digest.clone()),
        content_size_bytes: Some(plaintext.len() as u64),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    })?;
    let policy_resolution = client.policy_resolve(&SdkPolicyResolveRequest {
        operation: ProtectionOperation::Protect,
        workload: workload.clone(),
        resource: resource.clone(),
        content_digest: Some(manifest.content_digest.clone()),
        content_size_bytes: Some(plaintext.len() as u64),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    })?;
    let key_access_plan = client.key_access_plan(&SdkKeyAccessPlanRequest {
        operation: KeyAccessOperation::Wrap,
        workload: workload.clone(),
        resource: resource.clone(),
        artifact_profile: Some(ArtifactProfile::Tdf),
        key_reference: Some(manifest.managed_key_reference.clone()),
        content_digest: Some(manifest.content_digest.clone()),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    })?;
    let envelope_key_access_plan = client.key_access_plan(&SdkKeyAccessPlanRequest {
        operation: KeyAccessOperation::Wrap,
        workload: workload.clone(),
        resource: resource.clone(),
        artifact_profile: Some(ArtifactProfile::Envelope),
        key_reference: Some(manifest.managed_key_reference.clone()),
        content_digest: Some(manifest.content_digest.clone()),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    })?;
    let mut use_managed_envelope_keys =
        uses_managed_key_transport(envelope_key_access_plan.execution.key_transport.as_ref());

    let managed_key_source = LocalSymmetricKeySource::managed_reference_with_provider(
        manifest.managed_key_provider_name.clone(),
        manifest.managed_key_reference.clone(),
    );
    let managed_rewrap_key_source = LocalSymmetricKeySource::managed_reference_with_provider(
        manifest.managed_key_provider_name.clone(),
        manifest.managed_rewrap_key_reference.clone(),
    );

    let signed_detached = client.sign_bytes_with_detached_signature(
        &signing_key,
        plaintext,
        detached_signature_request,
    )?;
    let verified_detached = client.verify_bytes_with_detached_signature(
        &verifying_key,
        plaintext,
        &signed_detached.artifact.artifact_bytes,
    )?;

    let protected_envelope = if use_managed_envelope_keys {
        client.protect_bytes_with_envelope_using_key_source(
            &managed_key_source,
            plaintext,
            envelope_request,
        )?
    } else {
        match client.protect_bytes_with_envelope(&inline_key, plaintext, envelope_request.clone()) {
            Ok(result) => result,
            Err(error) if requires_managed_envelope_key(&error) => {
                use_managed_envelope_keys = true;
                client.protect_bytes_with_envelope_using_key_source(
                    &managed_key_source,
                    plaintext,
                    envelope_request,
                )?
            }
            Err(error) => return Err(error),
        }
    };
    let accessed_envelope = if use_managed_envelope_keys {
        client.access_bytes_with_envelope_using_key_source(
            &managed_key_source,
            &protected_envelope.artifact.artifact_bytes,
        )?
    } else {
        client
            .access_bytes_with_envelope(&inline_key, &protected_envelope.artifact.artifact_bytes)?
    };
    let rewrapped_envelope = if use_managed_envelope_keys {
        client.rewrap_bytes_with_envelope_using_key_sources(
            &managed_key_source,
            &managed_rewrap_key_source,
            &protected_envelope.artifact.artifact_bytes,
        )?
    } else {
        client.rewrap_bytes_with_envelope(
            &inline_key,
            &rewrap_key,
            &protected_envelope.artifact.artifact_bytes,
        )?
    };

    let protected_tdf = client.protect_bytes_with_tdf_using_key_source(
        &managed_key_source,
        plaintext,
        tdf_request,
    )?;
    let accessed_tdf = client.access_bytes_with_tdf_using_key_source(
        &managed_key_source,
        &protected_tdf.artifact.artifact_bytes,
    )?;
    let rewrapped_tdf = client.rewrap_bytes_with_tdf_using_key_sources(
        &managed_key_source,
        &managed_rewrap_key_source,
        &protected_tdf.artifact.artifact_bytes,
    )?;
    let direct_artifact_registration = client.artifact_register(&SdkArtifactRegisterRequest {
        operation: ProtectionOperation::Rewrap,
        workload: workload.clone(),
        resource: resource.clone(),
        artifact_profile: ArtifactProfile::Tdf,
        artifact_digest: rewrapped_tdf.artifact.artifact_digest.clone(),
        artifact_locator: None,
        decision_id: None,
        key_reference: Some(manifest.managed_rewrap_key_reference.clone()),
        purpose: Some(manifest.purpose.clone()),
        labels: labels.clone(),
        attributes: attributes.clone(),
    })?;
    let direct_evidence = client.evidence(&SdkEvidenceIngestRequest {
        event_type: EvidenceEventType::Rewrap,
        workload,
        resource,
        artifact_profile: Some(ArtifactProfile::Tdf),
        artifact_digest: Some(rewrapped_tdf.artifact.artifact_digest.clone()),
        decision_id: None,
        outcome: Some("success".to_string()),
        occurred_at: None,
        purpose: Some(manifest.purpose.clone()),
        labels,
        attributes,
    })?;

    Ok(IntegrationFullRunSummary {
        runner: "sdk-rust".to_string(),
        scenario: manifest.name.clone(),
        version: manifest.version,
        tenant_id: manifest.tenant_id.clone(),
        steps: vec![
            integration_full_step(json!({
                "name": "capabilities",
                "tenant_id": capabilities.caller.tenant_id,
                "auth_mode": capabilities.auth_configuration.mode,
            })),
            integration_full_step(json!({
                "name": "bootstrap",
                "supported_operations": bootstrap.supported_operations,
            })),
            integration_full_step(json!({
                "name": "whoami",
                "principal_id": whoami.caller.principal_id,
            })),
            integration_full_step(json!({
                "name": "prepare_local_protection",
                "content_digest": prepared.content_binding.content_digest,
            })),
            integration_full_step(json!({
                "name": "generate_cid_binding",
                "binding_hash": cid_binding.binding_hash,
            })),
            integration_full_step(json!({
                "name": "protection_plan",
                "protect_locally": protection_plan.execution.protect_locally,
            })),
            integration_full_step(json!({
                "name": "policy_resolve",
                "allow": policy_resolution.decision.allow,
            })),
            integration_full_step(json!({
                "name": "key_access_plan",
                "local_cryptographic_operation": key_access_plan.execution.local_cryptographic_operation,
            })),
            integration_full_step(json!({
                "name": "detached_signature_round_trip",
                "artifact_digest": signed_detached.artifact.artifact_digest,
                "signer_key_id": signed_detached.artifact.detached_signature.signer_key_id,
                "verified_content_digest": verified_detached.content_binding.content_digest,
            })),
            integration_full_step(json!({
                "name": "envelope_round_trip",
                "artifact_digest": protected_envelope.artifact.artifact_digest,
                "plaintext_utf8": String::from_utf8_lossy(&accessed_envelope.plaintext).to_string(),
            })),
            integration_full_step(json!({
                "name": "envelope_rewrap",
                "original_artifact_digest": rewrapped_envelope.original_artifact_digest,
                "artifact_digest": rewrapped_envelope.artifact.artifact_digest,
            })),
            integration_full_step(json!({
                "name": "tdf_round_trip",
                "artifact_digest": protected_tdf.artifact.artifact_digest,
                "plaintext_utf8": String::from_utf8_lossy(&accessed_tdf.plaintext).to_string(),
            })),
            integration_full_step(json!({
                "name": "tdf_rewrap",
                "original_artifact_digest": rewrapped_tdf.original_artifact_digest,
                "artifact_digest": rewrapped_tdf.artifact.artifact_digest,
            })),
            integration_full_step(json!({
                "name": "artifact_register_direct",
                "artifact_digest": direct_artifact_registration.request_summary.artifact_digest,
                "accepted": direct_artifact_registration.registration.accepted,
            })),
            integration_full_step(json!({
                "name": "evidence_direct",
                "event_type": direct_evidence.request_summary.event_type,
                "accepted": direct_evidence.ingestion.accepted,
            })),
        ],
    })
}

fn integration_full_step(mut step: Value) -> Value {
    if let Value::Object(ref mut map) = step {
        map.insert("status".to_string(), Value::String("ok".to_string()));
    }
    step
}

fn decode_fixed_32(label: &str, value: &str) -> Result<[u8; 32], SdkError> {
    let bytes = BASE64_STANDARD.decode(value).map_err(|error| {
        SdkError::InvalidInput(format!("failed to decode {label} from base64: {error}"))
    })?;
    if bytes.len() != 32 {
        return Err(SdkError::InvalidInput(format!(
            "{label} must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        env,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use serde_json::Value;
    use serde_json::json;

    use crate::{Client, local::LocalSymmetricKey, providers::InMemoryManagedSymmetricKeyProvider};

    use super::{
        IntegrationFullManifest, load_integration_full_manifest, run_integration_full_scenario,
    };

    struct ContractServer {
        base_url: String,
        address: String,
        running: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for ContractServer {
        fn drop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            let _ = TcpStream::connect(&self.address);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn loads_integration_full_manifest() {
        let manifest =
            load_integration_full_manifest(fixture_manifest_path()).expect("manifest should load");
        assert_eq!(manifest.name, "integration-full");
        assert_eq!(manifest.steps.len(), 15);
    }

    #[test]
    fn runs_integration_full_scenario_against_contract_server() {
        let manifest =
            load_integration_full_manifest(fixture_manifest_path()).expect("manifest should load");
        let server = spawn_contract_server(manifest.clone());

        let managed_key = decode_test_key(&manifest.managed_key_b64);
        let managed_rewrap_key = decode_test_key(&manifest.managed_rewrap_key_b64);
        let mut keys = BTreeMap::new();
        keys.insert(
            manifest.managed_key_reference.clone(),
            LocalSymmetricKey::new(managed_key),
        );
        keys.insert(
            manifest.managed_rewrap_key_reference.clone(),
            LocalSymmetricKey::new(managed_rewrap_key),
        );

        let client = Client::builder(server.base_url.clone())
            .with_managed_symmetric_key_provider(InMemoryManagedSymmetricKeyProvider::new(
                manifest.managed_key_provider_name.clone(),
                keys,
            ))
            .build()
            .expect("client should build");

        let summary =
            run_integration_full_scenario(&client, &manifest).expect("runner should succeed");

        assert_eq!(summary.runner, "sdk-rust");
        assert_eq!(summary.steps.len(), 15);
        assert_eq!(summary.steps[8]["name"], "detached_signature_round_trip");
        assert_eq!(summary.steps[12]["name"], "tdf_rewrap");
        assert_eq!(summary.steps[13]["accepted"], true);
        assert_eq!(summary.steps[14]["accepted"], true);
    }

    fn fixture_manifest_path() -> PathBuf {
        if let Ok(configured) = env::var("SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH") {
            let configured = configured.trim();
            if !configured.is_empty() {
                return PathBuf::from(configured);
            }
        }

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidates = [
            base.join("testdata").join("integration_full_manifest.json"),
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

        panic!(
            "integration-full manifest not found; set SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH"
        )
    }

    fn decode_test_key(value: &str) -> [u8; 32] {
        let bytes = BASE64_STANDARD.decode(value).expect("valid test key");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn spawn_contract_server(manifest: IntegrationFullManifest) -> ContractServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");
        let address = listener.local_addr().expect("listener addr").to_string();
        let base_url = format!("http://{address}");
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let request = match read_http_request(&mut stream) {
                            Ok(request) => request,
                            Err(_) => continue,
                        };
                        let response_body = response_json(&manifest, &request.path, &request.body);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            response_body.len(),
                            response_body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        ContractServer {
            base_url,
            address,
            running,
            handle: Some(handle),
        }
    }

    struct HttpRequest {
        path: String,
        body: String,
    }

    fn read_http_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;

        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];

        loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = find_header_end(&buffer) {
                let content_length = parse_content_length(&buffer[..header_end]);
                let body_len = buffer.len().saturating_sub(header_end + 4);
                if body_len >= content_length {
                    break;
                }
            }
        }

        let request = String::from_utf8_lossy(&buffer).to_string();
        let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
        let request_line = head.lines().next().unwrap_or("");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();
        Ok(HttpRequest {
            path,
            body: body.to_string(),
        })
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn response_json(manifest: &IntegrationFullManifest, path: &str, body: &str) -> String {
        match path {
            "/v1/sdk/capabilities" => json!({
                "service": "lattix-platform-api",
                "status": "ready",
                "auth_mode": "bearer_token",
                "auth_configuration": auth_configuration(),
                "caller": caller(manifest),
                "default_required_scopes": manifest.default_required_scopes,
                "routes": [],
            })
            .to_string(),
            "/v1/sdk/bootstrap" => json!({
                "service": "lattix-platform-api",
                "status": "ready",
                "auth_mode": "bearer_token",
                "auth_configuration": auth_configuration(),
                "caller": caller(manifest),
                "enforcement_model": "embedded_local_library",
                "plaintext_to_platform": false,
                "policy_resolution_mode": "metadata_only_control_plane",
                "supported_operations": ["protect", "access", "rewrap"],
                "supported_artifact_profiles": ["tdf", "envelope", "detached_signature"],
                "platform_domains": [{"domain": "policy", "configured": true, "reason": "metadata-only"}],
            })
            .to_string(),
            "/v1/sdk/whoami" => json!({
                "service": "lattix-platform-api",
                "status": "ok",
                "caller": caller(manifest),
            })
            .to_string(),
            "/v1/sdk/policy-resolve" => json!(policy_response(manifest, request_operation(body)))
                .to_string(),
            "/v1/sdk/protection-plan" => {
                json!(protection_plan_response(manifest, request_operation(body), request_profile(body)))
                    .to_string()
            }
            "/v1/sdk/key-access-plan" => {
                json!(key_access_plan_response(manifest, request_operation(body), request_profile(body)))
                    .to_string()
            }
            "/v1/sdk/artifact-register" => {
                json!(artifact_register_response(manifest, request_operation(body), request_profile(body), request_artifact_digest(body)))
                    .to_string()
            }
            "/v1/sdk/evidence" => {
                json!(evidence_response(manifest, request_event_type(body), request_profile(body)))
                    .to_string()
            }
            _ => json!({"status": "unexpected", "path": path}).to_string(),
        }
    }

    fn auth_configuration() -> Value {
        json!({
            "mode": "oauth_client_credentials",
            "proof_of_possession": "mtls",
            "oidc_issuer": "https://issuer.example",
            "oidc_audience": "lattix-platform-api",
            "oidc_issuer_ready": true,
            "mtls_ready": true,
        })
    }

    fn caller(manifest: &IntegrationFullManifest) -> Value {
        json!({
            "tenant_id": manifest.tenant_id,
            "principal_id": manifest.principal_id,
            "subject": manifest.subject,
            "auth_source": "bearer_token",
            "scopes": manifest.default_required_scopes,
        })
    }

    fn policy_response(manifest: &IntegrationFullManifest, operation: &str) -> Value {
        json!({
            "service": "lattix-platform-api",
            "status": "ready",
            "caller": caller(manifest),
            "request_summary": {
                "operation": operation,
                "workload_application": manifest.workload.application,
                "workload_environment": manifest.workload.environment,
                "workload_component": manifest.workload.component,
                "resource_kind": manifest.resource.kind,
                "resource_id": manifest.resource.id,
                "mime_type": manifest.resource.mime_type,
                "content_digest_present": true,
                "content_size_bytes": manifest.plaintext_utf8.len(),
                "purpose": manifest.purpose,
                "label_count": manifest.labels.len(),
                "attribute_count": manifest.attributes.len(),
            },
            "decision": {
                "allow": true,
                "enforcement_mode": "local_embedded_enforcement",
                "required_scopes": [],
                "policy_inputs": [],
                "required_actions": [],
            },
            "handling": {
                "protect_locally": true,
                "plaintext_transport": "forbidden_by_default",
                "bind_policy_to": ["artifact_digest", "content_digest"],
                "evidence_expected": [],
            },
            "platform_domains": [],
            "warnings": [],
        })
    }

    fn protection_plan_response(
        manifest: &IntegrationFullManifest,
        operation: &str,
        profile: &str,
    ) -> Value {
        let key_transport = if profile == "tdf" {
            json!({
                "mode": "wrapped_key_reference",
                "key_material_origin": "kms",
                "stable_key_reference_preferred": true,
                "raw_key_delivery_forbidden": true,
            })
        } else {
            Value::Null
        };
        json!({
            "service": "lattix-platform-api",
            "status": "ready",
            "caller": caller(manifest),
            "request_summary": {
                "operation": operation,
                "workload_application": manifest.workload.application,
                "workload_environment": manifest.workload.environment,
                "workload_component": manifest.workload.component,
                "resource_kind": manifest.resource.kind,
                "resource_id": manifest.resource.id,
                "mime_type": manifest.resource.mime_type,
                "preferred_artifact_profile": profile,
                "content_digest_present": true,
                "content_size_bytes": manifest.plaintext_utf8.len(),
                "label_count": manifest.labels.len(),
                "attribute_count": manifest.attributes.len(),
                "purpose": manifest.purpose,
            },
            "decision": {
                "allow": true,
                "required_scopes": [],
                "handling_mode": "local_embedded_enforcement",
                "plaintext_transport": "forbidden_by_default",
            },
            "execution": {
                "protect_locally": true,
                "local_enforcement_library": "sdk_embedded_library",
                "send_plaintext_to_platform": false,
                "send_only": ["content digest"],
                "artifact_profile": profile,
                "key_strategy": "local",
                "policy_resolution": "metadata_only",
                "key_transport": key_transport,
            },
            "platform_domains": [],
            "warnings": [],
        })
    }

    fn key_access_plan_response(
        manifest: &IntegrationFullManifest,
        operation: &str,
        profile: &str,
    ) -> Value {
        let key_reference_present = profile == "tdf" || profile == "detached_signature";
        let key_transport = if profile == "tdf" {
            json!({
                "mode": "wrapped_key_reference",
                "key_material_origin": "kms",
                "stable_key_reference_preferred": true,
                "raw_key_delivery_forbidden": true,
            })
        } else {
            Value::Null
        };
        json!({
            "service": "lattix-platform-api",
            "status": "ready",
            "caller": caller(manifest),
            "request_summary": {
                "operation": operation,
                "workload_application": manifest.workload.application,
                "workload_environment": manifest.workload.environment,
                "workload_component": manifest.workload.component,
                "resource_kind": manifest.resource.kind,
                "resource_id": manifest.resource.id,
                "mime_type": manifest.resource.mime_type,
                "artifact_profile": profile,
                "key_reference_present": key_reference_present,
                "content_digest_present": true,
                "purpose": manifest.purpose,
                "label_count": manifest.labels.len(),
                "attribute_count": manifest.attributes.len(),
            },
            "decision": {
                "allow": true,
                "required_scopes": [],
                "operation": operation,
                "key_reference_present": key_reference_present,
            },
            "execution": {
                "local_cryptographic_operation": true,
                "platform_role": "authorize only",
                "send_plaintext_to_platform": false,
                "send_only": ["content digest"],
                "artifact_profile": profile,
                "authorization_strategy": "metadata_only",
                "key_transport": key_transport,
            },
            "platform_domains": [],
            "warnings": [],
        })
    }

    fn artifact_register_response(
        manifest: &IntegrationFullManifest,
        operation: &str,
        profile: &str,
        artifact_digest: &str,
    ) -> Value {
        json!({
            "service": "lattix-platform-api",
            "status": "ready",
            "caller": caller(manifest),
            "request_summary": {
                "operation": operation,
                "workload_application": manifest.workload.application,
                "workload_environment": manifest.workload.environment,
                "workload_component": manifest.workload.component,
                "resource_kind": manifest.resource.kind,
                "resource_id": manifest.resource.id,
                "mime_type": manifest.resource.mime_type,
                "artifact_profile": profile,
                "artifact_digest": artifact_digest,
                "artifact_locator_present": false,
                "decision_id_present": false,
                "key_reference_present": profile == "tdf",
                "purpose": manifest.purpose,
                "label_count": manifest.labels.len(),
                "attribute_count": manifest.attributes.len(),
            },
            "registration": {
                "accepted": true,
                "required_scopes": [],
                "artifact_transport": "metadata_only",
                "send_plaintext_to_platform": false,
                "catalog_actions": [],
                "evidence_expected": [],
            },
            "platform_domains": [],
            "warnings": [],
        })
    }

    fn evidence_response(
        manifest: &IntegrationFullManifest,
        event_type: &str,
        profile: &str,
    ) -> Value {
        json!({
            "service": "lattix-platform-api",
            "status": "ready",
            "caller": caller(manifest),
            "request_summary": {
                "event_type": event_type,
                "workload_application": manifest.workload.application,
                "workload_environment": manifest.workload.environment,
                "workload_component": manifest.workload.component,
                "resource_kind": manifest.resource.kind,
                "resource_id": manifest.resource.id,
                "mime_type": manifest.resource.mime_type,
                "artifact_profile": profile,
                "artifact_digest_present": true,
                "decision_id_present": false,
                "outcome": "success",
                "occurred_at": null,
                "purpose": manifest.purpose,
                "label_count": manifest.labels.len(),
                "attribute_count": manifest.attributes.len(),
            },
            "ingestion": {
                "accepted": true,
                "required_scopes": [],
                "plaintext_transport": "forbidden_by_default",
                "send_only": [],
                "correlate_by": [],
            },
            "platform_domains": [],
            "warnings": [],
        })
    }

    fn request_operation(body: &str) -> &str {
        if body.contains("\"operation\":\"unwrap\"") {
            "unwrap"
        } else if body.contains("\"operation\":\"wrap\"") {
            "wrap"
        } else if body.contains("\"operation\":\"access\"") {
            "access"
        } else if body.contains("\"operation\":\"rewrap\"") {
            "rewrap"
        } else {
            "protect"
        }
    }

    fn request_profile(body: &str) -> &str {
        if body.contains("\"detached_signature\"") {
            "detached_signature"
        } else if body.contains("\"envelope\"") {
            "envelope"
        } else {
            "tdf"
        }
    }

    fn request_artifact_digest(body: &str) -> &str {
        const PREFIX: &str = "\"artifact_digest\":\"";
        extract_json_string(body, PREFIX).unwrap_or("sha256:artifact-tdf-rewrapped")
    }

    fn request_event_type(body: &str) -> &str {
        const PREFIX: &str = "\"event_type\":\"";
        extract_json_string(body, PREFIX).unwrap_or("rewrap")
    }

    fn extract_json_string<'a>(body: &'a str, prefix: &str) -> Option<&'a str> {
        let start = body.find(prefix)? + prefix.len();
        let end = body[start..].find('"')? + start;
        Some(&body[start..end])
    }
}
