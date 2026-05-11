use std::collections::BTreeMap;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Client, SdkError,
    models::{
        ArtifactProfile, EvidenceEventType, KeyAccessOperation, KeyTransportGuidance,
        KeyTransportMode, ProtectionOperation, RequestContext, ResourceDescriptor,
        SdkArtifactRegisterRequest, SdkArtifactRegisterResponse, SdkBootstrapResponse,
        SdkEvidenceIngestRequest, SdkEvidenceIngestResponse, SdkKeyAccessPlanRequest,
        SdkKeyAccessPlanResponse, SdkPolicyResolveRequest, SdkPolicyResolveResponse,
        SdkProtectionPlanRequest, SdkProtectionPlanResponse, WorkloadDescriptor,
    },
};

const LOCAL_ENVELOPE_KEY_REFERENCE: &str = "local-symmetric-key";
const LOCAL_TDF_KEY_REFERENCE: &str = "local-tdf-key";
const LOCAL_DETACHED_SIGNATURE_KEY_REFERENCE: &str = "local-detached-signature-key";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalProtectionRequest {
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub preferred_artifact_profile: Option<ArtifactProfile>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LocalAttributeEdit {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalContentBinding {
    pub tenant_id: String,
    pub content_digest: String,
    pub content_size_bytes: u64,
    pub raw_cid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalArtifactBinding {
    #[serde(default = "default_binding_version")]
    pub version: u8,
    pub tenant_id: String,
    pub raw_cid: String,
    pub content_digest: String,
    pub content_size_bytes: u64,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub binding_targets: Vec<String>,
    #[serde(default)]
    pub binding_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedLocalProtection {
    pub caller: RequestContext,
    pub content_binding: LocalContentBinding,
    pub artifact_binding: LocalArtifactBinding,
    pub bootstrap: SdkBootstrapResponse,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub protection_plan: SdkProtectionPlanResponse,
}

impl PreparedLocalProtection {
    pub fn resolved_artifact_profile(&self) -> ArtifactProfile {
        self.protection_plan.execution.artifact_profile
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalSymmetricKey([u8; 32]);

impl LocalSymmetricKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for LocalSymmetricKey {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedSymmetricKeyReference {
    pub key_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
}

impl ManagedSymmetricKeyReference {
    pub fn new(key_reference: impl Into<String>) -> Self {
        Self {
            key_reference: key_reference.into(),
            provider_name: None,
        }
    }

    pub fn with_provider(
        provider_name: impl Into<String>,
        key_reference: impl Into<String>,
    ) -> Self {
        Self {
            key_reference: key_reference.into(),
            provider_name: Some(provider_name.into()),
        }
    }

    pub fn key_reference(&self) -> &str {
        &self.key_reference
    }

    pub fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalSymmetricKeySource {
    Inline(LocalSymmetricKey),
    ManagedReference(ManagedSymmetricKeyReference),
}

impl LocalSymmetricKeySource {
    pub fn inline(key: impl Into<LocalSymmetricKey>) -> Self {
        Self::Inline(key.into())
    }

    pub fn managed_reference(key_reference: impl Into<String>) -> Self {
        Self::ManagedReference(ManagedSymmetricKeyReference::new(key_reference))
    }

    pub fn managed_reference_with_provider(
        provider_name: impl Into<String>,
        key_reference: impl Into<String>,
    ) -> Self {
        Self::ManagedReference(ManagedSymmetricKeyReference::with_provider(
            provider_name,
            key_reference,
        ))
    }

    pub fn key_reference<'a>(&'a self, default_key_reference: &'a str) -> &'a str {
        match self {
            Self::Inline(_) => default_key_reference,
            Self::ManagedReference(key_reference) => key_reference.key_reference(),
        }
    }

    pub fn provider_name(&self) -> Option<&str> {
        match self {
            Self::Inline(_) => None,
            Self::ManagedReference(key_reference) => key_reference.provider_name(),
        }
    }
}

impl From<LocalSymmetricKey> for LocalSymmetricKeySource {
    fn from(value: LocalSymmetricKey) -> Self {
        Self::Inline(value)
    }
}

impl From<[u8; 32]> for LocalSymmetricKeySource {
    fn from(value: [u8; 32]) -> Self {
        Self::Inline(LocalSymmetricKey::from(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalSigningKey([u8; 32]);

impl LocalSigningKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verifying_key(&self) -> LocalVerifyingKey {
        let signing_key = Ed25519SigningKey::from_bytes(self.as_bytes());
        LocalVerifyingKey::from(signing_key.verifying_key().to_bytes())
    }
}

impl From<[u8; 32]> for LocalSigningKey {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerifyingKey([u8; 32]);

impl LocalVerifyingKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for LocalVerifyingKey {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalEnvelopeAlgorithm {
    Aes256Gcm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalEnvelopeArtifact {
    pub version: u8,
    pub artifact_profile: ArtifactProfile,
    pub algorithm: LocalEnvelopeAlgorithm,
    pub tenant_id: String,
    pub raw_cid: String,
    pub content_digest: String,
    pub content_size_bytes: u64,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub purpose: Option<String>,
    pub labels: Vec<String>,
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub binding_targets: Vec<String>,
    #[serde(default)]
    pub binding_hash: String,
    pub nonce_b64: String,
    pub aad_hash: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedEnvelopeArtifact {
    pub envelope: LocalEnvelopeArtifact,
    pub artifact_bytes: Vec<u8>,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeProtectionResult {
    pub prepared: PreparedLocalProtection,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub artifact: ProtectedEnvelopeArtifact,
    pub artifact_registration: SdkArtifactRegisterResponse,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeAccessResult {
    pub artifact: LocalEnvelopeArtifact,
    pub artifact_digest: String,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub plaintext: Vec<u8>,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalTdfAlgorithm {
    Aes256Gcm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalTdfManifest {
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalTdfArtifact {
    pub version: u8,
    #[serde(default = "default_meta_version")]
    pub meta_version: u64,
    pub artifact_profile: ArtifactProfile,
    pub algorithm: LocalTdfAlgorithm,
    pub tenant_id: String,
    pub raw_cid: String,
    pub content_digest: String,
    pub content_size_bytes: u64,
    pub manifest_digest: String,
    #[serde(default)]
    pub binding_targets: Vec<String>,
    #[serde(default)]
    pub binding_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_context: Option<LocalTdfManifest>,
    pub manifest_nonce_b64: String,
    pub manifest_ciphertext_b64: String,
    pub payload_nonce_b64: String,
    pub payload_ciphertext_b64: String,
    pub aad_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedTdfArtifact {
    pub tdf: LocalTdfArtifact,
    pub artifact_bytes: Vec<u8>,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdfProtectionResult {
    pub prepared: PreparedLocalProtection,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub artifact: ProtectedTdfArtifact,
    pub artifact_registration: SdkArtifactRegisterResponse,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdfAccessResult {
    pub artifact: LocalTdfArtifact,
    pub manifest: LocalTdfManifest,
    pub artifact_digest: String,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub plaintext: Vec<u8>,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeRewrapResult {
    pub content_binding: LocalContentBinding,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub protection_plan: SdkProtectionPlanResponse,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub original_artifact_digest: String,
    pub artifact: ProtectedEnvelopeArtifact,
    pub artifact_registration: SdkArtifactRegisterResponse,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdfRewrapResult {
    pub content_binding: LocalContentBinding,
    pub manifest: LocalTdfManifest,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub protection_plan: SdkProtectionPlanResponse,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub original_artifact_digest: String,
    pub artifact: ProtectedTdfArtifact,
    pub artifact_registration: SdkArtifactRegisterResponse,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalDetachedSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalDetachedSignatureArtifact {
    pub version: u8,
    pub artifact_profile: ArtifactProfile,
    pub algorithm: LocalDetachedSignatureAlgorithm,
    pub tenant_id: String,
    pub raw_cid: String,
    pub content_digest: String,
    pub content_size_bytes: u64,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub binding_targets: Vec<String>,
    pub signer_key_id: String,
    pub signer_public_key_b64: String,
    #[serde(default)]
    pub binding_hash: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedDetachedSignatureArtifact {
    pub detached_signature: LocalDetachedSignatureArtifact,
    pub artifact_bytes: Vec<u8>,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignatureSignResult {
    pub prepared: PreparedLocalProtection,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub artifact: ProtectedDetachedSignatureArtifact,
    pub artifact_registration: SdkArtifactRegisterResponse,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignatureVerifyResult {
    pub artifact: LocalDetachedSignatureArtifact,
    pub artifact_digest: String,
    pub policy_resolution: SdkPolicyResolveResponse,
    pub key_access_plan: SdkKeyAccessPlanResponse,
    pub content_binding: LocalContentBinding,
    pub evidence: SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
struct EnvelopeAadBinding<'a> {
    tenant_id: &'a str,
    raw_cid: &'a str,
    content_digest: &'a str,
    artifact_profile: ArtifactProfile,
    workload: &'a WorkloadDescriptor,
    resource: &'a ResourceDescriptor,
    purpose: &'a Option<String>,
    labels: &'a [String],
    attributes: &'a BTreeMap<String, String>,
    binding_targets: &'a [String],
    binding_hash: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct TdfAadBinding<'a> {
    tenant_id: &'a str,
    raw_cid: &'a str,
    content_digest: &'a str,
    content_size_bytes: u64,
    manifest_digest: &'a str,
    artifact_profile: ArtifactProfile,
    binding_hash: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct LocalArtifactBindingPayload<'a> {
    version: u8,
    tenant_id: &'a str,
    raw_cid: &'a str,
    content_digest: &'a str,
    content_size_bytes: u64,
    workload: &'a WorkloadDescriptor,
    resource: &'a ResourceDescriptor,
    purpose: &'a Option<String>,
    labels: &'a [String],
    attributes: &'a BTreeMap<String, String>,
    binding_targets: &'a [String],
}

impl Client {
    pub fn prepare_local_protection(
        &self,
        content: &[u8],
        request: LocalProtectionRequest,
    ) -> Result<PreparedLocalProtection, SdkError> {
        let digest = sha256_prefixed(content);
        let content_size_bytes = u64::try_from(content.len()).map_err(|_| {
            SdkError::InvalidInput("content length exceeds supported u64 range".to_string())
        })?;

        let bootstrap = self.bootstrap()?;
        ensure_bootstrap_supports_local_protection(&bootstrap, request.preferred_artifact_profile)?;

        let policy_resolution = self.policy_resolve(&SdkPolicyResolveRequest {
            operation: ProtectionOperation::Protect,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            content_digest: Some(digest.clone()),
            content_size_bytes: Some(content_size_bytes),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_policy_resolution_supports_local_protection(&policy_resolution)?;

        let protection_plan = self.protection_plan(&SdkProtectionPlanRequest {
            operation: ProtectionOperation::Protect,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            preferred_artifact_profile: request.preferred_artifact_profile,
            content_digest: Some(digest.clone()),
            content_size_bytes: Some(content_size_bytes),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_protection_plan_supports_local_protection(&protection_plan)?;

        let caller = protection_plan.caller.clone();
        let content_binding = LocalContentBinding {
            tenant_id: caller.tenant_id.clone(),
            content_digest: digest.clone(),
            content_size_bytes,
            raw_cid: digest,
        };
        let artifact_binding = build_local_artifact_binding(
            &content_binding,
            &request,
            &policy_resolution.handling.bind_policy_to,
        )?;

        Ok(PreparedLocalProtection {
            caller,
            content_binding,
            artifact_binding,
            bootstrap,
            policy_resolution,
            protection_plan,
        })
    }

    pub fn generate_cid_binding(
        &self,
        content: &[u8],
        request: LocalProtectionRequest,
    ) -> Result<LocalArtifactBinding, SdkError> {
        Ok(self
            .prepare_local_protection(content, request)?
            .artifact_binding)
    }

    pub fn protect_bytes_with_envelope(
        &self,
        key: &LocalSymmetricKey,
        plaintext: &[u8],
        request: LocalProtectionRequest,
    ) -> Result<EnvelopeProtectionResult, SdkError> {
        self.protect_bytes_with_envelope_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            plaintext,
            request,
        )
    }

    pub fn protect_bytes_with_envelope_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        plaintext: &[u8],
        mut request: LocalProtectionRequest,
    ) -> Result<EnvelopeProtectionResult, SdkError> {
        request.preferred_artifact_profile = Some(ArtifactProfile::Envelope);
        let prepared = self.prepare_local_protection(plaintext, request.clone())?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Wrap,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Envelope),
            key_reference: Some(
                key_source
                    .key_reference(LOCAL_ENVELOPE_KEY_REFERENCE)
                    .to_string(),
            ),
            content_digest: Some(prepared.content_binding.content_digest.clone()),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Wrap,
            ArtifactProfile::Envelope,
        )?;

        let resolved_key = resolve_symmetric_key_for_runtime(
            self,
            key_source,
            key_access_plan.execution.key_transport.as_ref(),
            LOCAL_ENVELOPE_KEY_REFERENCE,
            "local envelope protection",
        )?;

        let envelope =
            encrypt_envelope_artifact(&resolved_key.key, plaintext, &prepared, &request)?;
        let artifact_bytes = serde_json::to_vec(&envelope).map_err(|error| {
            SdkError::Serialization(format!(
                "failed to serialize local envelope artifact: {error}"
            ))
        })?;
        let artifact_digest = sha256_prefixed(&artifact_bytes);

        let artifact_registration = self.artifact_register(&SdkArtifactRegisterRequest {
            operation: ProtectionOperation::Protect,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: ArtifactProfile::Envelope,
            artifact_digest: artifact_digest.clone(),
            artifact_locator: None,
            decision_id: None,
            key_reference: Some(resolved_key.key_reference),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_artifact_registration_supports_local_only(&artifact_registration)?;

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Protect,
            workload: request.workload,
            resource: request.resource,
            artifact_profile: Some(ArtifactProfile::Envelope),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: request.purpose,
            labels: request.labels,
            attributes: request.attributes,
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(EnvelopeProtectionResult {
            prepared,
            key_access_plan,
            artifact: ProtectedEnvelopeArtifact {
                envelope,
                artifact_bytes,
                artifact_digest,
            },
            artifact_registration,
            evidence,
        })
    }

    pub fn access_bytes_with_envelope(
        &self,
        key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
    ) -> Result<EnvelopeAccessResult, SdkError> {
        self.access_bytes_with_envelope_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            artifact_bytes,
        )
    }

    pub fn access_bytes_with_envelope_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
    ) -> Result<EnvelopeAccessResult, SdkError> {
        let artifact: LocalEnvelopeArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!(
                    "failed to decode local envelope artifact: {error}"
                ))
            })?;
        ensure_local_envelope_artifact_valid(&artifact)?;

        let artifact_digest = sha256_prefixed(artifact_bytes);

        let policy_resolution = self.policy_resolve(&SdkPolicyResolveRequest {
            operation: ProtectionOperation::Access,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            content_digest: Some(artifact.content_digest.clone()),
            content_size_bytes: Some(artifact.content_size_bytes),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_access_policy_resolution_supports_local_access(&policy_resolution)?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Unwrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Envelope),
            key_reference: Some(
                key_source
                    .key_reference(LOCAL_ENVELOPE_KEY_REFERENCE)
                    .to_string(),
            ),
            content_digest: Some(artifact.content_digest.clone()),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Unwrap,
            ArtifactProfile::Envelope,
        )?;

        let resolved_key = resolve_symmetric_key_for_runtime(
            self,
            key_source,
            key_access_plan.execution.key_transport.as_ref(),
            LOCAL_ENVELOPE_KEY_REFERENCE,
            "local envelope access",
        )?;

        let plaintext = decrypt_envelope_artifact(&resolved_key.key, &artifact)?;
        let decrypted_digest = sha256_prefixed(&plaintext);
        if decrypted_digest != artifact.content_digest {
            return Err(SdkError::InvalidInput(
                "local envelope decrypted bytes do not match the embedded content digest"
                    .to_string(),
            ));
        }

        let decrypted_size = u64::try_from(plaintext.len()).map_err(|_| {
            SdkError::InvalidInput(
                "decrypted content length exceeds supported u64 range".to_string(),
            )
        })?;
        if decrypted_size != artifact.content_size_bytes {
            return Err(SdkError::InvalidInput(
                "local envelope decrypted bytes do not match the embedded content size".to_string(),
            ));
        }

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Access,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Envelope),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(EnvelopeAccessResult {
            artifact,
            artifact_digest,
            policy_resolution,
            key_access_plan,
            plaintext,
            evidence,
        })
    }

    pub fn rewrap_bytes_with_envelope(
        &self,
        current_key: &LocalSymmetricKey,
        new_key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
    ) -> Result<EnvelopeRewrapResult, SdkError> {
        self.rewrap_bytes_with_envelope_using_key_sources(
            &LocalSymmetricKeySource::from(current_key.clone()),
            &LocalSymmetricKeySource::from(new_key.clone()),
            artifact_bytes,
        )
    }

    pub fn rewrap_bytes_with_envelope_using_key_sources(
        &self,
        current_key_source: &LocalSymmetricKeySource,
        new_key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
    ) -> Result<EnvelopeRewrapResult, SdkError> {
        let artifact: LocalEnvelopeArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!(
                    "failed to decode local envelope artifact: {error}"
                ))
            })?;
        ensure_local_envelope_artifact_valid(&artifact)?;

        let original_artifact_digest = sha256_prefixed(artifact_bytes);
        let bootstrap = self.bootstrap()?;
        ensure_bootstrap_supports_local_rewrap(&bootstrap, ArtifactProfile::Envelope)?;

        let policy_resolution = self.policy_resolve(&SdkPolicyResolveRequest {
            operation: ProtectionOperation::Rewrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            content_digest: Some(artifact.content_digest.clone()),
            content_size_bytes: Some(artifact.content_size_bytes),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_rewrap_policy_resolution_supports_local_only(&policy_resolution)?;

        let protection_plan = self.protection_plan(&SdkProtectionPlanRequest {
            operation: ProtectionOperation::Rewrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            preferred_artifact_profile: Some(ArtifactProfile::Envelope),
            content_digest: Some(artifact.content_digest.clone()),
            content_size_bytes: Some(artifact.content_size_bytes),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_rewrap_protection_plan_supports_local_only(&protection_plan)?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Rewrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Envelope),
            key_reference: Some(
                current_key_source
                    .key_reference(LOCAL_ENVELOPE_KEY_REFERENCE)
                    .to_string(),
            ),
            content_digest: Some(artifact.content_digest.clone()),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Rewrap,
            ArtifactProfile::Envelope,
        )?;

        let current_key = resolve_symmetric_key_for_runtime(
            self,
            current_key_source,
            key_access_plan.execution.key_transport.as_ref(),
            LOCAL_ENVELOPE_KEY_REFERENCE,
            "local envelope rewrap",
        )?;
        let new_key = resolve_symmetric_key_for_runtime(
            self,
            new_key_source,
            key_access_plan.execution.key_transport.as_ref(),
            LOCAL_ENVELOPE_KEY_REFERENCE,
            "local envelope rewrap",
        )?;

        let plaintext = decrypt_envelope_artifact(&current_key.key, &artifact)?;
        let decrypted_digest = sha256_prefixed(&plaintext);
        if decrypted_digest != artifact.content_digest {
            return Err(SdkError::InvalidInput(
                "local envelope decrypted bytes do not match the embedded content digest"
                    .to_string(),
            ));
        }

        let decrypted_size = u64::try_from(plaintext.len()).map_err(|_| {
            SdkError::InvalidInput(
                "decrypted content length exceeds supported u64 range".to_string(),
            )
        })?;
        if decrypted_size != artifact.content_size_bytes {
            return Err(SdkError::InvalidInput(
                "local envelope decrypted bytes do not match the embedded content size".to_string(),
            ));
        }

        let content_binding = LocalContentBinding {
            tenant_id: artifact.tenant_id.clone(),
            content_digest: artifact.content_digest.clone(),
            content_size_bytes: artifact.content_size_bytes,
            raw_cid: artifact.raw_cid.clone(),
        };
        let request = LocalProtectionRequest {
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            preferred_artifact_profile: Some(ArtifactProfile::Envelope),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        };
        let prepared = PreparedLocalProtection {
            caller: protection_plan.caller.clone(),
            content_binding: content_binding.clone(),
            artifact_binding: build_local_artifact_binding(
                &content_binding,
                &request,
                &policy_resolution.handling.bind_policy_to,
            )?,
            bootstrap,
            policy_resolution: policy_resolution.clone(),
            protection_plan: protection_plan.clone(),
        };

        let envelope = encrypt_envelope_artifact(&new_key.key, &plaintext, &prepared, &request)?;
        let new_artifact_bytes = serde_json::to_vec(&envelope).map_err(|error| {
            SdkError::Serialization(format!(
                "failed to serialize local envelope artifact: {error}"
            ))
        })?;
        let artifact_digest = sha256_prefixed(&new_artifact_bytes);

        let artifact_registration = self.artifact_register(&SdkArtifactRegisterRequest {
            operation: ProtectionOperation::Rewrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: ArtifactProfile::Envelope,
            artifact_digest: artifact_digest.clone(),
            artifact_locator: None,
            decision_id: None,
            key_reference: Some(new_key.key_reference),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_artifact_registration_supports_local_only(&artifact_registration)?;

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Rewrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Envelope),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(EnvelopeRewrapResult {
            content_binding,
            policy_resolution,
            protection_plan,
            key_access_plan,
            original_artifact_digest,
            artifact: ProtectedEnvelopeArtifact {
                envelope,
                artifact_bytes: new_artifact_bytes,
                artifact_digest,
            },
            artifact_registration,
            evidence,
        })
    }

    pub fn protect_bytes_with_tdf(
        &self,
        key: &LocalSymmetricKey,
        plaintext: &[u8],
        request: LocalProtectionRequest,
    ) -> Result<TdfProtectionResult, SdkError> {
        self.protect_bytes_with_tdf_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            plaintext,
            request,
        )
    }

    pub fn protect_bytes_with_tdf_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        plaintext: &[u8],
        mut request: LocalProtectionRequest,
    ) -> Result<TdfProtectionResult, SdkError> {
        request.preferred_artifact_profile = Some(ArtifactProfile::Tdf);
        let prepared = self.prepare_local_protection(plaintext, request.clone())?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Wrap,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Tdf),
            key_reference: Some(
                key_source
                    .key_reference(LOCAL_TDF_KEY_REFERENCE)
                    .to_string(),
            ),
            content_digest: Some(prepared.content_binding.content_digest.clone()),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Wrap,
            ArtifactProfile::Tdf,
        )?;

        let resolved_key = resolve_symmetric_key_for_runtime(
            self,
            key_source,
            key_access_plan.execution.key_transport.as_ref(),
            LOCAL_TDF_KEY_REFERENCE,
            "local TDF protection",
        )?;

        let tdf = encrypt_tdf_artifact(&resolved_key.key, plaintext, &prepared, &request, 1)?;
        let artifact_bytes = serde_json::to_vec(&tdf).map_err(|error| {
            SdkError::Serialization(format!("failed to serialize local TDF artifact: {error}"))
        })?;
        let artifact_digest = sha256_prefixed(&artifact_bytes);

        let artifact_registration = self.artifact_register(&SdkArtifactRegisterRequest {
            operation: ProtectionOperation::Protect,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: ArtifactProfile::Tdf,
            artifact_digest: artifact_digest.clone(),
            artifact_locator: None,
            decision_id: None,
            key_reference: Some(resolved_key.key_reference),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_artifact_registration_supports_local_only(&artifact_registration)?;

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Protect,
            workload: request.workload,
            resource: request.resource,
            artifact_profile: Some(ArtifactProfile::Tdf),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: request.purpose,
            labels: request.labels,
            attributes: request.attributes,
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(TdfProtectionResult {
            prepared,
            key_access_plan,
            artifact: ProtectedTdfArtifact {
                tdf,
                artifact_bytes,
                artifact_digest,
            },
            artifact_registration,
            evidence,
        })
    }

    pub fn access_bytes_with_tdf(
        &self,
        key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
    ) -> Result<TdfAccessResult, SdkError> {
        self.access_bytes_with_tdf_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            artifact_bytes,
        )
    }

    pub fn access_bytes_with_tdf_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
    ) -> Result<TdfAccessResult, SdkError> {
        let artifact: LocalTdfArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!("failed to decode local TDF artifact: {error}"))
            })?;
        ensure_local_tdf_artifact_valid(&artifact)?;

        let artifact_digest = sha256_prefixed(artifact_bytes);
        let (manifest, resolved_key) = match artifact.policy_context.as_ref() {
            Some(policy_context) => {
                ensure_local_tdf_binding_matches_manifest(&artifact, policy_context)?;
                let resolved = resolve_tdf_artifact_key_for_operation(
                    self,
                    key_source,
                    &artifact,
                    policy_context,
                    ProtectionOperation::Access,
                    KeyAccessOperation::Unwrap,
                    "local TDF access",
                )?;
                let manifest = decrypt_tdf_manifest(&resolved.key_material.key, &artifact)?;
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                ensure_local_tdf_policy_context_matches_manifest(policy_context, &manifest)?;
                (manifest, resolved)
            }
            None => {
                let key = require_inline_symmetric_key_without_transport_guidance(
                    key_source,
                    "local TDF access",
                )?;
                let manifest = decrypt_tdf_manifest(key, &artifact)?;
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                let resolved = resolve_tdf_artifact_key_for_operation(
                    self,
                    key_source,
                    &artifact,
                    &manifest,
                    ProtectionOperation::Access,
                    KeyAccessOperation::Unwrap,
                    "local TDF access",
                )?;
                (manifest, resolved)
            }
        };

        let plaintext = decrypt_tdf_payload(&resolved_key.key_material.key, &artifact)?;
        let decrypted_digest = sha256_prefixed(&plaintext);
        if decrypted_digest != artifact.content_digest {
            return Err(SdkError::InvalidInput(
                "local TDF decrypted bytes do not match the embedded content digest".to_string(),
            ));
        }

        let decrypted_size = u64::try_from(plaintext.len()).map_err(|_| {
            SdkError::InvalidInput(
                "decrypted content length exceeds supported u64 range".to_string(),
            )
        })?;
        if decrypted_size != artifact.content_size_bytes {
            return Err(SdkError::InvalidInput(
                "local TDF decrypted bytes do not match the embedded content size".to_string(),
            ));
        }

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Access,
            workload: manifest.workload.clone(),
            resource: manifest.resource.clone(),
            artifact_profile: Some(ArtifactProfile::Tdf),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: manifest.purpose.clone(),
            labels: manifest.labels.clone(),
            attributes: manifest.attributes.clone(),
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(TdfAccessResult {
            artifact,
            manifest,
            artifact_digest,
            policy_resolution: resolved_key.policy_resolution,
            key_access_plan: resolved_key.key_access_plan,
            plaintext,
            evidence,
        })
    }

    pub fn rewrap_bytes_with_tdf(
        &self,
        current_key: &LocalSymmetricKey,
        new_key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
    ) -> Result<TdfRewrapResult, SdkError> {
        self.rewrap_bytes_with_tdf_using_key_sources(
            &LocalSymmetricKeySource::from(current_key.clone()),
            &LocalSymmetricKeySource::from(new_key.clone()),
            artifact_bytes,
        )
    }

    pub fn rewrap_bytes_with_tdf_using_key_sources(
        &self,
        current_key_source: &LocalSymmetricKeySource,
        new_key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
    ) -> Result<TdfRewrapResult, SdkError> {
        let artifact: LocalTdfArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!("failed to decode local TDF artifact: {error}"))
            })?;
        ensure_local_tdf_artifact_valid(&artifact)?;

        let manifest = match artifact.policy_context.as_ref() {
            Some(policy_context) => {
                ensure_local_tdf_binding_matches_manifest(&artifact, policy_context)?;
                let manifest = match current_key_source {
                    LocalSymmetricKeySource::Inline(key) => decrypt_tdf_manifest(key, &artifact)?,
                    LocalSymmetricKeySource::ManagedReference(_) => {
                        let resolved = resolve_tdf_artifact_key_for_operation(
                            self,
                            current_key_source,
                            &artifact,
                            policy_context,
                            ProtectionOperation::Rewrap,
                            KeyAccessOperation::Rewrap,
                            "local TDF rewrap",
                        )?;
                        decrypt_tdf_manifest(&resolved.key_material.key, &artifact)?
                    }
                };
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                ensure_local_tdf_policy_context_matches_manifest(policy_context, &manifest)?;
                manifest
            }
            None => {
                let current_key = require_inline_symmetric_key_for_local_runtime(
                    current_key_source,
                    None,
                    "local TDF rewrap",
                )?;
                let manifest = decrypt_tdf_manifest(current_key, &artifact)?;
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                manifest
            }
        };
        let meta_version = artifact.meta_version;

        rewrite_tdf_artifact(
            self,
            current_key_source,
            new_key_source,
            artifact_bytes,
            artifact,
            manifest,
            meta_version,
        )
    }

    pub fn set_tdf_attributes(
        &self,
        key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
        attributes: BTreeMap<String, String>,
    ) -> Result<TdfRewrapResult, SdkError> {
        self.set_tdf_attributes_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            artifact_bytes,
            attributes,
        )
    }

    pub fn set_tdf_attributes_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
        attributes: BTreeMap<String, String>,
    ) -> Result<TdfRewrapResult, SdkError> {
        let artifact: LocalTdfArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!("failed to decode local TDF artifact: {error}"))
            })?;
        ensure_local_tdf_artifact_valid(&artifact)?;

        let mut manifest = match artifact.policy_context.as_ref() {
            Some(policy_context) => {
                ensure_local_tdf_binding_matches_manifest(&artifact, policy_context)?;
                let manifest = match key_source {
                    LocalSymmetricKeySource::Inline(key) => decrypt_tdf_manifest(key, &artifact)?,
                    LocalSymmetricKeySource::ManagedReference(_) => {
                        let resolved = resolve_tdf_artifact_key_for_operation(
                            self,
                            key_source,
                            &artifact,
                            policy_context,
                            ProtectionOperation::Rewrap,
                            KeyAccessOperation::Rewrap,
                            "local TDF attribute rewrite",
                        )?;
                        decrypt_tdf_manifest(&resolved.key_material.key, &artifact)?
                    }
                };
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                ensure_local_tdf_policy_context_matches_manifest(policy_context, &manifest)?;
                manifest
            }
            None => {
                let key = require_inline_symmetric_key_without_transport_guidance(
                    key_source,
                    "local TDF attribute rewrite",
                )?;
                let manifest = decrypt_tdf_manifest(key, &artifact)?;
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                manifest
            }
        };
        manifest.attributes = attributes;
        let meta_version = artifact.meta_version.saturating_add(1);

        rewrite_tdf_artifact(
            self,
            key_source,
            key_source,
            artifact_bytes,
            artifact,
            manifest,
            meta_version,
        )
    }

    pub fn edit_tdf_attributes(
        &self,
        key: &LocalSymmetricKey,
        artifact_bytes: &[u8],
        edit: LocalAttributeEdit,
    ) -> Result<TdfRewrapResult, SdkError> {
        self.edit_tdf_attributes_using_key_source(
            &LocalSymmetricKeySource::from(key.clone()),
            artifact_bytes,
            edit,
        )
    }

    pub fn edit_tdf_attributes_using_key_source(
        &self,
        key_source: &LocalSymmetricKeySource,
        artifact_bytes: &[u8],
        edit: LocalAttributeEdit,
    ) -> Result<TdfRewrapResult, SdkError> {
        let artifact: LocalTdfArtifact =
            serde_json::from_slice(artifact_bytes).map_err(|error| {
                SdkError::Serialization(format!("failed to decode local TDF artifact: {error}"))
            })?;
        ensure_local_tdf_artifact_valid(&artifact)?;

        let mut manifest = match artifact.policy_context.as_ref() {
            Some(policy_context) => {
                ensure_local_tdf_binding_matches_manifest(&artifact, policy_context)?;
                let manifest = match key_source {
                    LocalSymmetricKeySource::Inline(key) => decrypt_tdf_manifest(key, &artifact)?,
                    LocalSymmetricKeySource::ManagedReference(_) => {
                        let resolved = resolve_tdf_artifact_key_for_operation(
                            self,
                            key_source,
                            &artifact,
                            policy_context,
                            ProtectionOperation::Rewrap,
                            KeyAccessOperation::Rewrap,
                            "local TDF attribute rewrite",
                        )?;
                        decrypt_tdf_manifest(&resolved.key_material.key, &artifact)?
                    }
                };
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                ensure_local_tdf_policy_context_matches_manifest(policy_context, &manifest)?;
                manifest
            }
            None => {
                let key = require_inline_symmetric_key_without_transport_guidance(
                    key_source,
                    "local TDF attribute rewrite",
                )?;
                let manifest = decrypt_tdf_manifest(key, &artifact)?;
                ensure_local_tdf_binding_matches_manifest(&artifact, &manifest)?;
                manifest
            }
        };
        apply_attribute_edit(&mut manifest.attributes, &edit);
        let meta_version = artifact.meta_version.saturating_add(1);

        rewrite_tdf_artifact(
            self,
            key_source,
            key_source,
            artifact_bytes,
            artifact,
            manifest,
            meta_version,
        )
    }

    pub fn sign_bytes_with_detached_signature(
        &self,
        signing_key: &LocalSigningKey,
        content: &[u8],
        mut request: LocalProtectionRequest,
    ) -> Result<DetachedSignatureSignResult, SdkError> {
        request.preferred_artifact_profile = Some(ArtifactProfile::DetachedSignature);
        let prepared = self.prepare_local_protection(content, request.clone())?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Wrap,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: Some(ArtifactProfile::DetachedSignature),
            key_reference: Some(LOCAL_DETACHED_SIGNATURE_KEY_REFERENCE.to_string()),
            content_digest: Some(prepared.content_binding.content_digest.clone()),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Wrap,
            ArtifactProfile::DetachedSignature,
        )?;

        let detached_signature =
            sign_detached_signature_artifact(signing_key, &prepared, &request)?;
        let artifact_bytes = serde_json::to_vec(&detached_signature).map_err(|error| {
            SdkError::Serialization(format!(
                "failed to serialize local detached signature artifact: {error}"
            ))
        })?;
        let artifact_digest = sha256_prefixed(&artifact_bytes);

        let artifact_registration = self.artifact_register(&SdkArtifactRegisterRequest {
            operation: ProtectionOperation::Protect,
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            artifact_profile: ArtifactProfile::DetachedSignature,
            artifact_digest: artifact_digest.clone(),
            artifact_locator: None,
            decision_id: None,
            key_reference: Some(LOCAL_DETACHED_SIGNATURE_KEY_REFERENCE.to_string()),
            purpose: request.purpose.clone(),
            labels: request.labels.clone(),
            attributes: request.attributes.clone(),
        })?;
        ensure_artifact_registration_supports_local_only(&artifact_registration)?;

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Protect,
            workload: request.workload,
            resource: request.resource,
            artifact_profile: Some(ArtifactProfile::DetachedSignature),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: request.purpose,
            labels: request.labels,
            attributes: request.attributes,
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(DetachedSignatureSignResult {
            prepared,
            key_access_plan,
            artifact: ProtectedDetachedSignatureArtifact {
                detached_signature,
                artifact_bytes,
                artifact_digest,
            },
            artifact_registration,
            evidence,
        })
    }

    pub fn verify_bytes_with_detached_signature(
        &self,
        verifying_key: &LocalVerifyingKey,
        content: &[u8],
        artifact_bytes: &[u8],
    ) -> Result<DetachedSignatureVerifyResult, SdkError> {
        let artifact: LocalDetachedSignatureArtifact = serde_json::from_slice(artifact_bytes)
            .map_err(|error| {
                SdkError::Serialization(format!(
                    "failed to decode local detached signature artifact: {error}"
                ))
            })?;
        ensure_local_detached_signature_artifact_valid(&artifact)?;

        let artifact_digest = sha256_prefixed(artifact_bytes);
        let content_digest = sha256_prefixed(content);
        if content_digest != artifact.content_digest {
            return Err(SdkError::InvalidInput(
                "detached signature content digest does not match the provided content".to_string(),
            ));
        }

        let content_size_bytes = u64::try_from(content.len()).map_err(|_| {
            SdkError::InvalidInput("content length exceeds supported u64 range".to_string())
        })?;
        if content_size_bytes != artifact.content_size_bytes {
            return Err(SdkError::InvalidInput(
                "detached signature content size does not match the provided content".to_string(),
            ));
        }

        let content_binding = LocalContentBinding {
            tenant_id: artifact.tenant_id.clone(),
            content_digest: artifact.content_digest.clone(),
            content_size_bytes: artifact.content_size_bytes,
            raw_cid: artifact.raw_cid.clone(),
        };

        let policy_resolution = self.policy_resolve(&SdkPolicyResolveRequest {
            operation: ProtectionOperation::Access,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            content_digest: Some(artifact.content_digest.clone()),
            content_size_bytes: Some(artifact.content_size_bytes),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_access_policy_resolution_supports_local_access(&policy_resolution)?;

        let key_access_plan = self.key_access_plan(&SdkKeyAccessPlanRequest {
            operation: KeyAccessOperation::Unwrap,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::DetachedSignature),
            key_reference: Some(LOCAL_DETACHED_SIGNATURE_KEY_REFERENCE.to_string()),
            content_digest: Some(artifact.content_digest.clone()),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_key_access_plan_supports_local_crypto(
            &key_access_plan,
            KeyAccessOperation::Unwrap,
            ArtifactProfile::DetachedSignature,
        )?;

        let expected_public_key_b64 = BASE64_STANDARD.encode(verifying_key.as_bytes());
        if expected_public_key_b64 != artifact.signer_public_key_b64 {
            return Err(SdkError::InvalidInput(
                "provided verifying key does not match the detached signature artifact signer"
                    .to_string(),
            ));
        }

        let expected_signer_key_id = signer_key_id_from_public_key(verifying_key.as_bytes());
        if expected_signer_key_id != artifact.signer_key_id {
            return Err(SdkError::InvalidInput(
                "provided verifying key id does not match the detached signature artifact signer"
                    .to_string(),
            ));
        }

        verify_detached_signature_artifact(verifying_key, &artifact, &content_binding)?;

        let evidence = self.evidence(&SdkEvidenceIngestRequest {
            event_type: EvidenceEventType::Access,
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            artifact_profile: Some(ArtifactProfile::DetachedSignature),
            artifact_digest: Some(artifact_digest.clone()),
            decision_id: None,
            outcome: Some("success".to_string()),
            occurred_at: None,
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        })?;
        ensure_evidence_ingestion_supports_local_only(&evidence)?;

        Ok(DetachedSignatureVerifyResult {
            artifact,
            artifact_digest,
            policy_resolution,
            key_access_plan,
            content_binding,
            evidence,
        })
    }
}

fn sha256_prefixed(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    format!("sha256:{}", hex::encode(digest))
}

fn default_binding_version() -> u8 {
    1
}

fn default_meta_version() -> u64 {
    1
}

fn ensure_bootstrap_supports_local_protection(
    bootstrap: &SdkBootstrapResponse,
    requested_profile: Option<ArtifactProfile>,
) -> Result<(), SdkError> {
    if bootstrap.plaintext_to_platform {
        return Err(SdkError::InvalidInput(
            "bootstrap indicates plaintext may be transported to the platform; refusing local-only workflow"
                .to_string(),
        ));
    }

    if bootstrap.enforcement_model != "embedded_local_library" {
        return Err(SdkError::InvalidInput(format!(
            "bootstrap enforcement model {:?} is incompatible with embedded local protection",
            bootstrap.enforcement_model
        )));
    }

    if !bootstrap
        .supported_operations
        .contains(&ProtectionOperation::Protect)
    {
        return Err(SdkError::InvalidInput(
            "bootstrap does not advertise protect support for local workflows".to_string(),
        ));
    }

    if let Some(profile) = requested_profile
        && !bootstrap.supported_artifact_profiles.is_empty()
        && !bootstrap.supported_artifact_profiles.contains(&profile)
    {
        return Err(SdkError::InvalidInput(format!(
            "requested artifact profile {:?} is not advertised by bootstrap",
            profile
        )));
    }

    Ok(())
}

fn ensure_policy_resolution_supports_local_protection(
    policy_resolution: &SdkPolicyResolveResponse,
) -> Result<(), SdkError> {
    if !policy_resolution.decision.allow {
        return Err(SdkError::InvalidInput(
            "policy resolution denied the protect operation".to_string(),
        ));
    }

    if !policy_resolution.handling.protect_locally {
        return Err(SdkError::InvalidInput(
            "policy resolution did not require local enforcement".to_string(),
        ));
    }

    if policy_resolution.handling.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "policy resolution returned unsupported plaintext transport mode {:?}",
            policy_resolution.handling.plaintext_transport
        )));
    }

    Ok(())
}

fn ensure_access_policy_resolution_supports_local_access(
    policy_resolution: &SdkPolicyResolveResponse,
) -> Result<(), SdkError> {
    if !policy_resolution.decision.allow {
        return Err(SdkError::InvalidInput(
            "policy resolution denied the access operation".to_string(),
        ));
    }

    if !policy_resolution.handling.protect_locally {
        return Err(SdkError::InvalidInput(
            "policy resolution did not preserve local enforcement for access".to_string(),
        ));
    }

    if policy_resolution.handling.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "policy resolution returned unsupported plaintext transport mode {:?}",
            policy_resolution.handling.plaintext_transport
        )));
    }

    Ok(())
}

fn ensure_rewrap_policy_resolution_supports_local_only(
    policy_resolution: &SdkPolicyResolveResponse,
) -> Result<(), SdkError> {
    if !policy_resolution.decision.allow {
        return Err(SdkError::InvalidInput(
            "policy resolution denied the rewrap operation".to_string(),
        ));
    }

    if !policy_resolution.handling.protect_locally {
        return Err(SdkError::InvalidInput(
            "policy resolution did not preserve local enforcement for rewrap".to_string(),
        ));
    }

    if policy_resolution.handling.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "policy resolution returned unsupported plaintext transport mode {:?}",
            policy_resolution.handling.plaintext_transport
        )));
    }

    Ok(())
}

fn ensure_protection_plan_supports_local_protection(
    protection_plan: &SdkProtectionPlanResponse,
) -> Result<(), SdkError> {
    if !protection_plan.decision.allow {
        return Err(SdkError::InvalidInput(
            "protection plan denied the protect operation".to_string(),
        ));
    }

    if !protection_plan.execution.protect_locally {
        return Err(SdkError::InvalidInput(
            "protection plan did not require local enforcement".to_string(),
        ));
    }

    if protection_plan.execution.send_plaintext_to_platform {
        return Err(SdkError::InvalidInput(
            "protection plan requested plaintext transport to the platform; refusing local-only workflow"
                .to_string(),
        ));
    }

    if protection_plan.decision.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "protection plan returned unsupported plaintext transport mode {:?}",
            protection_plan.decision.plaintext_transport
        )));
    }

    ensure_key_transport_guidance_is_fail_closed(protection_plan.execution.key_transport.as_ref())?;

    Ok(())
}

fn ensure_rewrap_protection_plan_supports_local_only(
    protection_plan: &SdkProtectionPlanResponse,
) -> Result<(), SdkError> {
    if !protection_plan.decision.allow {
        return Err(SdkError::InvalidInput(
            "protection plan denied the rewrap operation".to_string(),
        ));
    }

    if !protection_plan.execution.protect_locally {
        return Err(SdkError::InvalidInput(
            "protection plan did not preserve local enforcement for rewrap".to_string(),
        ));
    }

    if protection_plan.execution.send_plaintext_to_platform {
        return Err(SdkError::InvalidInput(
            "protection plan requested plaintext transport to the platform; refusing local-only rewrap workflow"
                .to_string(),
        ));
    }

    if protection_plan.decision.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "protection plan returned unsupported plaintext transport mode {:?}",
            protection_plan.decision.plaintext_transport
        )));
    }

    ensure_key_transport_guidance_is_fail_closed(protection_plan.execution.key_transport.as_ref())?;

    Ok(())
}

fn ensure_bootstrap_supports_local_rewrap(
    bootstrap: &SdkBootstrapResponse,
    requested_profile: ArtifactProfile,
) -> Result<(), SdkError> {
    if bootstrap.plaintext_to_platform {
        return Err(SdkError::InvalidInput(
            "bootstrap indicates plaintext may be transported to the platform; refusing local-only rewrap workflow"
                .to_string(),
        ));
    }

    if bootstrap.enforcement_model != "embedded_local_library" {
        return Err(SdkError::InvalidInput(format!(
            "bootstrap enforcement model {:?} is incompatible with embedded local rewrap",
            bootstrap.enforcement_model
        )));
    }

    if !bootstrap
        .supported_operations
        .contains(&ProtectionOperation::Rewrap)
    {
        return Err(SdkError::InvalidInput(
            "bootstrap does not advertise rewrap support for local workflows".to_string(),
        ));
    }

    if !bootstrap.supported_artifact_profiles.is_empty()
        && !bootstrap
            .supported_artifact_profiles
            .contains(&requested_profile)
    {
        return Err(SdkError::InvalidInput(format!(
            "requested artifact profile {:?} is not advertised by bootstrap",
            requested_profile
        )));
    }

    Ok(())
}

fn ensure_key_access_plan_supports_local_crypto(
    key_access_plan: &SdkKeyAccessPlanResponse,
    expected_operation: KeyAccessOperation,
    expected_profile: ArtifactProfile,
) -> Result<(), SdkError> {
    if !key_access_plan.decision.allow {
        return Err(SdkError::InvalidInput(
            "key access plan denied the local cryptographic operation".to_string(),
        ));
    }

    if key_access_plan.decision.operation != expected_operation {
        return Err(SdkError::InvalidInput(format!(
            "key access plan returned unexpected operation {:?}",
            key_access_plan.decision.operation
        )));
    }

    if !key_access_plan.execution.local_cryptographic_operation {
        return Err(SdkError::InvalidInput(
            "key access plan did not allow local cryptographic execution".to_string(),
        ));
    }

    if key_access_plan.execution.send_plaintext_to_platform {
        return Err(SdkError::InvalidInput(
            "key access plan requested plaintext transport to the platform".to_string(),
        ));
    }

    if key_access_plan.execution.artifact_profile != expected_profile {
        return Err(SdkError::InvalidInput(format!(
            "key access plan returned unexpected artifact profile {:?}",
            key_access_plan.execution.artifact_profile
        )));
    }

    ensure_key_transport_guidance_is_fail_closed(key_access_plan.execution.key_transport.as_ref())?;

    Ok(())
}

fn ensure_key_transport_guidance_is_fail_closed(
    key_transport: Option<&KeyTransportGuidance>,
) -> Result<(), SdkError> {
    if let Some(key_transport) = key_transport
        && !key_transport.raw_key_delivery_forbidden
    {
        return Err(SdkError::InvalidInput(
            "key transport guidance permitted raw key delivery; refusing local-only workflow"
                .to_string(),
        ));
    }

    Ok(())
}

fn ensure_key_transport_guidance_supports_local_only(
    key_transport: Option<&KeyTransportGuidance>,
) -> Result<(), SdkError> {
    ensure_key_transport_guidance_is_fail_closed(key_transport)?;

    if let Some(key_transport) = key_transport
        && key_transport.mode != KeyTransportMode::LocalProvided
    {
        return Err(SdkError::InvalidInput(format!(
            "key transport mode {} requires provider-backed orchestration; current local runtime only supports local_provided",
            key_transport_mode_name(key_transport.mode)
        )));
    }

    Ok(())
}

struct ResolvedSymmetricKeyMaterial {
    key: LocalSymmetricKey,
    key_reference: String,
}

struct ResolvedTdfArtifactKey {
    policy_resolution: SdkPolicyResolveResponse,
    key_access_plan: SdkKeyAccessPlanResponse,
    key_material: ResolvedSymmetricKeyMaterial,
}

fn resolve_symmetric_key_for_runtime(
    client: &Client,
    key_source: &LocalSymmetricKeySource,
    key_transport: Option<&KeyTransportGuidance>,
    default_key_reference: &str,
    context: &str,
) -> Result<ResolvedSymmetricKeyMaterial, SdkError> {
    ensure_key_transport_guidance_is_fail_closed(key_transport)?;

    let transport_mode = key_transport
        .map(|guidance| guidance.mode)
        .unwrap_or(KeyTransportMode::LocalProvided);

    match transport_mode {
        KeyTransportMode::LocalProvided => match key_source {
            LocalSymmetricKeySource::Inline(key) => Ok(ResolvedSymmetricKeyMaterial {
                key: key.clone(),
                key_reference: default_key_reference.to_string(),
            }),
            LocalSymmetricKeySource::ManagedReference(key_reference) => {
                Err(SdkError::InvalidInput(format!(
                    "{context} requires an inline symmetric key when key_transport.mode is local_provided; received managed key reference {:?}",
                    key_reference.key_reference()
                )))
            }
        },
        KeyTransportMode::WrappedKeyReference
        | KeyTransportMode::AuthorizedKeyRelease
        | KeyTransportMode::KemEncapsulatedCek => match key_source {
            LocalSymmetricKeySource::Inline(_) => Err(SdkError::InvalidInput(format!(
                "{context} requires a managed key reference when key_transport.mode is {}",
                key_transport_mode_name(transport_mode)
            ))),
            LocalSymmetricKeySource::ManagedReference(key_reference) => {
                let provider = client
                    .managed_symmetric_key_provider_registry
                    .resolve(key_reference.provider_name())?;

                if !provider.capabilities().supports(transport_mode) {
                    return Err(SdkError::InvalidInput(format!(
                        "managed symmetric key provider {:?} does not support key_transport.mode {}",
                        provider.provider_name(),
                        key_transport_mode_name(transport_mode)
                    )));
                }

                Ok(ResolvedSymmetricKeyMaterial {
                    key: provider.resolve_key(key_reference)?,
                    key_reference: key_reference.key_reference().to_string(),
                })
            }
        },
    }
}

fn resolve_tdf_artifact_key_for_operation(
    client: &Client,
    key_source: &LocalSymmetricKeySource,
    artifact: &LocalTdfArtifact,
    manifest: &LocalTdfManifest,
    policy_operation: ProtectionOperation,
    key_operation: KeyAccessOperation,
    context: &str,
) -> Result<ResolvedTdfArtifactKey, SdkError> {
    let policy_resolution = client.policy_resolve(&SdkPolicyResolveRequest {
        operation: policy_operation,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        content_digest: Some(artifact.content_digest.clone()),
        content_size_bytes: Some(artifact.content_size_bytes),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;

    match policy_operation {
        ProtectionOperation::Access => {
            ensure_access_policy_resolution_supports_local_access(&policy_resolution)?;
        }
        ProtectionOperation::Rewrap => {
            ensure_rewrap_policy_resolution_supports_local_only(&policy_resolution)?;
        }
        ProtectionOperation::Protect => {
            ensure_policy_resolution_supports_local_protection(&policy_resolution)?;
        }
    }

    let key_access_plan = client.key_access_plan(&SdkKeyAccessPlanRequest {
        operation: key_operation,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        artifact_profile: Some(ArtifactProfile::Tdf),
        key_reference: Some(
            key_source
                .key_reference(LOCAL_TDF_KEY_REFERENCE)
                .to_string(),
        ),
        content_digest: Some(artifact.content_digest.clone()),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_key_access_plan_supports_local_crypto(
        &key_access_plan,
        key_operation,
        ArtifactProfile::Tdf,
    )?;

    let key_material = resolve_symmetric_key_for_runtime(
        client,
        key_source,
        key_access_plan.execution.key_transport.as_ref(),
        LOCAL_TDF_KEY_REFERENCE,
        context,
    )?;

    Ok(ResolvedTdfArtifactKey {
        policy_resolution,
        key_access_plan,
        key_material,
    })
}

fn require_inline_symmetric_key_for_local_runtime<'a>(
    key_source: &'a LocalSymmetricKeySource,
    key_transport: Option<&KeyTransportGuidance>,
    context: &str,
) -> Result<&'a LocalSymmetricKey, SdkError> {
    ensure_key_transport_guidance_supports_local_only(key_transport)?;

    match key_source {
        LocalSymmetricKeySource::Inline(key) => Ok(key),
        LocalSymmetricKeySource::ManagedReference(key_reference) => {
            Err(SdkError::InvalidInput(format!(
                "{context} requested managed key reference {key_reference:?}, but provider-backed symmetric key execution is not implemented yet"
            )))
        }
    }
}

fn require_inline_symmetric_key_without_transport_guidance<'a>(
    key_source: &'a LocalSymmetricKeySource,
    context: &str,
) -> Result<&'a LocalSymmetricKey, SdkError> {
    match key_source {
        LocalSymmetricKeySource::Inline(key) => Ok(key),
        LocalSymmetricKeySource::ManagedReference(key_reference) => {
            Err(SdkError::InvalidInput(format!(
                "{context} requested managed key reference {:?}, but this workflow still requires inline symmetric key material before runtime key_transport guidance is available",
                key_reference.key_reference()
            )))
        }
    }
}

fn key_transport_mode_name(mode: KeyTransportMode) -> &'static str {
    match mode {
        KeyTransportMode::LocalProvided => "local_provided",
        KeyTransportMode::WrappedKeyReference => "wrapped_key_reference",
        KeyTransportMode::AuthorizedKeyRelease => "authorized_key_release",
        KeyTransportMode::KemEncapsulatedCek => "kem_encapsulated_cek",
    }
}

fn ensure_artifact_registration_supports_local_only(
    artifact_registration: &SdkArtifactRegisterResponse,
) -> Result<(), SdkError> {
    if !artifact_registration.registration.accepted {
        return Err(SdkError::InvalidInput(
            "artifact registration was not accepted".to_string(),
        ));
    }

    if artifact_registration
        .registration
        .send_plaintext_to_platform
    {
        return Err(SdkError::InvalidInput(
            "artifact registration requested plaintext transport to the platform".to_string(),
        ));
    }

    Ok(())
}

fn ensure_evidence_ingestion_supports_local_only(
    evidence: &SdkEvidenceIngestResponse,
) -> Result<(), SdkError> {
    if !evidence.ingestion.accepted {
        return Err(SdkError::InvalidInput(
            "evidence ingestion was not accepted".to_string(),
        ));
    }

    if evidence.ingestion.plaintext_transport != "forbidden_by_default" {
        return Err(SdkError::InvalidInput(format!(
            "evidence ingestion returned unsupported plaintext transport mode {:?}",
            evidence.ingestion.plaintext_transport
        )));
    }

    Ok(())
}

fn ensure_local_envelope_artifact_valid(artifact: &LocalEnvelopeArtifact) -> Result<(), SdkError> {
    if artifact.version != 1 {
        return Err(SdkError::InvalidInput(format!(
            "unsupported local envelope artifact version {}",
            artifact.version
        )));
    }

    if artifact.artifact_profile != ArtifactProfile::Envelope {
        return Err(SdkError::InvalidInput(format!(
            "unsupported artifact profile {:?} for local envelope access",
            artifact.artifact_profile
        )));
    }

    Ok(())
}

fn ensure_local_envelope_binding_matches_artifact(
    artifact: &LocalEnvelopeArtifact,
) -> Result<(), SdkError> {
    let binding = local_artifact_binding_from_envelope_artifact(artifact)?;
    if binding.binding_hash != artifact.binding_hash {
        return Err(SdkError::InvalidInput(
            "local envelope binding hash does not match the embedded metadata binding".to_string(),
        ));
    }

    Ok(())
}

fn ensure_local_tdf_artifact_valid(artifact: &LocalTdfArtifact) -> Result<(), SdkError> {
    if artifact.version != 1 {
        return Err(SdkError::InvalidInput(format!(
            "unsupported local TDF artifact version {}",
            artifact.version
        )));
    }

    if artifact.artifact_profile != ArtifactProfile::Tdf {
        return Err(SdkError::InvalidInput(format!(
            "unsupported artifact profile {:?} for local TDF access",
            artifact.artifact_profile
        )));
    }

    Ok(())
}

fn ensure_local_tdf_binding_matches_manifest(
    artifact: &LocalTdfArtifact,
    manifest: &LocalTdfManifest,
) -> Result<(), SdkError> {
    let binding = local_artifact_binding_from_tdf_artifact(artifact, manifest)?;
    if binding.binding_hash != artifact.binding_hash {
        return Err(SdkError::InvalidInput(
            "local TDF binding hash does not match the embedded metadata binding".to_string(),
        ));
    }

    Ok(())
}

fn ensure_local_tdf_policy_context_matches_manifest(
    policy_context: &LocalTdfManifest,
    manifest: &LocalTdfManifest,
) -> Result<(), SdkError> {
    if policy_context != manifest {
        return Err(SdkError::InvalidInput(
            "local TDF policy context does not match the decrypted manifest".to_string(),
        ));
    }

    Ok(())
}

fn ensure_local_detached_signature_artifact_valid(
    artifact: &LocalDetachedSignatureArtifact,
) -> Result<(), SdkError> {
    if artifact.version != 1 {
        return Err(SdkError::InvalidInput(format!(
            "unsupported local detached signature artifact version {}",
            artifact.version
        )));
    }

    if artifact.artifact_profile != ArtifactProfile::DetachedSignature {
        return Err(SdkError::InvalidInput(format!(
            "unsupported artifact profile {:?} for detached signature verification",
            artifact.artifact_profile
        )));
    }

    Ok(())
}

fn apply_attribute_edit(attributes: &mut BTreeMap<String, String>, edit: &LocalAttributeEdit) {
    for key in &edit.remove {
        attributes.remove(key);
    }

    for (key, value) in &edit.set {
        attributes.insert(key.clone(), value.clone());
    }
}

fn rewrite_tdf_artifact(
    client: &Client,
    current_key_source: &LocalSymmetricKeySource,
    new_key_source: &LocalSymmetricKeySource,
    artifact_bytes: &[u8],
    artifact: LocalTdfArtifact,
    manifest: LocalTdfManifest,
    meta_version: u64,
) -> Result<TdfRewrapResult, SdkError> {
    let original_artifact_digest = sha256_prefixed(artifact_bytes);

    let bootstrap = client.bootstrap()?;
    ensure_bootstrap_supports_local_rewrap(&bootstrap, ArtifactProfile::Tdf)?;

    let policy_resolution = client.policy_resolve(&SdkPolicyResolveRequest {
        operation: ProtectionOperation::Rewrap,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        content_digest: Some(artifact.content_digest.clone()),
        content_size_bytes: Some(artifact.content_size_bytes),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_rewrap_policy_resolution_supports_local_only(&policy_resolution)?;

    let protection_plan = client.protection_plan(&SdkProtectionPlanRequest {
        operation: ProtectionOperation::Rewrap,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        content_digest: Some(artifact.content_digest.clone()),
        content_size_bytes: Some(artifact.content_size_bytes),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_rewrap_protection_plan_supports_local_only(&protection_plan)?;

    let key_access_plan = client.key_access_plan(&SdkKeyAccessPlanRequest {
        operation: KeyAccessOperation::Rewrap,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        artifact_profile: Some(ArtifactProfile::Tdf),
        key_reference: Some(
            current_key_source
                .key_reference(LOCAL_TDF_KEY_REFERENCE)
                .to_string(),
        ),
        content_digest: Some(artifact.content_digest.clone()),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_key_access_plan_supports_local_crypto(
        &key_access_plan,
        KeyAccessOperation::Rewrap,
        ArtifactProfile::Tdf,
    )?;

    let current_key = resolve_symmetric_key_for_runtime(
        client,
        current_key_source,
        key_access_plan.execution.key_transport.as_ref(),
        LOCAL_TDF_KEY_REFERENCE,
        "local TDF rewrap",
    )?;
    let new_key = resolve_symmetric_key_for_runtime(
        client,
        new_key_source,
        key_access_plan.execution.key_transport.as_ref(),
        LOCAL_TDF_KEY_REFERENCE,
        "local TDF rewrap",
    )?;

    let plaintext = decrypt_tdf_payload(&current_key.key, &artifact)?;
    let decrypted_digest = sha256_prefixed(&plaintext);
    if decrypted_digest != artifact.content_digest {
        return Err(SdkError::InvalidInput(
            "local TDF decrypted bytes do not match the embedded content digest".to_string(),
        ));
    }

    let decrypted_size = u64::try_from(plaintext.len()).map_err(|_| {
        SdkError::InvalidInput("decrypted content length exceeds supported u64 range".to_string())
    })?;
    if decrypted_size != artifact.content_size_bytes {
        return Err(SdkError::InvalidInput(
            "local TDF decrypted bytes do not match the embedded content size".to_string(),
        ));
    }

    let content_binding = LocalContentBinding {
        tenant_id: artifact.tenant_id.clone(),
        content_digest: artifact.content_digest.clone(),
        content_size_bytes: artifact.content_size_bytes,
        raw_cid: artifact.raw_cid.clone(),
    };
    let request = LocalProtectionRequest {
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        preferred_artifact_profile: Some(ArtifactProfile::Tdf),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    };
    let prepared = PreparedLocalProtection {
        caller: protection_plan.caller.clone(),
        content_binding: content_binding.clone(),
        artifact_binding: build_local_artifact_binding(
            &content_binding,
            &request,
            &policy_resolution.handling.bind_policy_to,
        )?,
        bootstrap,
        policy_resolution: policy_resolution.clone(),
        protection_plan: protection_plan.clone(),
    };

    let tdf = encrypt_tdf_artifact(&new_key.key, &plaintext, &prepared, &request, meta_version)?;
    let new_artifact_bytes = serde_json::to_vec(&tdf).map_err(|error| {
        SdkError::Serialization(format!("failed to serialize local TDF artifact: {error}"))
    })?;
    let artifact_digest = sha256_prefixed(&new_artifact_bytes);

    let artifact_registration = client.artifact_register(&SdkArtifactRegisterRequest {
        operation: ProtectionOperation::Rewrap,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        artifact_profile: ArtifactProfile::Tdf,
        artifact_digest: artifact_digest.clone(),
        artifact_locator: None,
        decision_id: None,
        key_reference: Some(new_key.key_reference),
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_artifact_registration_supports_local_only(&artifact_registration)?;

    let evidence = client.evidence(&SdkEvidenceIngestRequest {
        event_type: EvidenceEventType::Rewrap,
        workload: manifest.workload.clone(),
        resource: manifest.resource.clone(),
        artifact_profile: Some(ArtifactProfile::Tdf),
        artifact_digest: Some(artifact_digest.clone()),
        decision_id: None,
        outcome: Some("success".to_string()),
        occurred_at: None,
        purpose: manifest.purpose.clone(),
        labels: manifest.labels.clone(),
        attributes: manifest.attributes.clone(),
    })?;
    ensure_evidence_ingestion_supports_local_only(&evidence)?;

    Ok(TdfRewrapResult {
        content_binding,
        manifest,
        policy_resolution,
        protection_plan,
        key_access_plan,
        original_artifact_digest,
        artifact: ProtectedTdfArtifact {
            tdf,
            artifact_bytes: new_artifact_bytes,
            artifact_digest,
        },
        artifact_registration,
        evidence,
    })
}

fn encrypt_envelope_artifact(
    key: &LocalSymmetricKey,
    plaintext: &[u8],
    prepared: &PreparedLocalProtection,
    request: &LocalProtectionRequest,
) -> Result<LocalEnvelopeArtifact, SdkError> {
    let binding_hash = prepared.artifact_binding.binding_hash.clone();
    let aad = envelope_aad_bytes(&EnvelopeAadBinding {
        tenant_id: &prepared.content_binding.tenant_id,
        raw_cid: &prepared.content_binding.raw_cid,
        content_digest: &prepared.content_binding.content_digest,
        artifact_profile: ArtifactProfile::Envelope,
        workload: &request.workload,
        resource: &request.resource,
        purpose: &request.purpose,
        labels: &request.labels,
        attributes: &request.attributes,
        binding_targets: &prepared.artifact_binding.binding_targets,
        binding_hash: &binding_hash,
    })?;
    let aad_hash = sha256_prefixed(&aad);

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|error| {
        SdkError::InvalidInput(format!("failed to initialize envelope cipher: {error}"))
    })?;
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|error| SdkError::Server(format!("local envelope encryption failed: {error}")))?;

    Ok(LocalEnvelopeArtifact {
        version: 1,
        artifact_profile: ArtifactProfile::Envelope,
        algorithm: LocalEnvelopeAlgorithm::Aes256Gcm,
        tenant_id: prepared.content_binding.tenant_id.clone(),
        raw_cid: prepared.content_binding.raw_cid.clone(),
        content_digest: prepared.content_binding.content_digest.clone(),
        content_size_bytes: prepared.content_binding.content_size_bytes,
        workload: request.workload.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        labels: request.labels.clone(),
        attributes: request.attributes.clone(),
        binding_targets: prepared.artifact_binding.binding_targets.clone(),
        binding_hash,
        nonce_b64: BASE64_STANDARD.encode(nonce_bytes),
        aad_hash,
        ciphertext_b64: BASE64_STANDARD.encode(ciphertext),
    })
}

fn decrypt_envelope_artifact(
    key: &LocalSymmetricKey,
    artifact: &LocalEnvelopeArtifact,
) -> Result<Vec<u8>, SdkError> {
    let aad = envelope_aad_bytes(&EnvelopeAadBinding {
        tenant_id: &artifact.tenant_id,
        raw_cid: &artifact.raw_cid,
        content_digest: &artifact.content_digest,
        artifact_profile: ArtifactProfile::Envelope,
        workload: &artifact.workload,
        resource: &artifact.resource,
        purpose: &artifact.purpose,
        labels: &artifact.labels,
        attributes: &artifact.attributes,
        binding_targets: &artifact.binding_targets,
        binding_hash: &artifact.binding_hash,
    })?;

    let expected_aad_hash = sha256_prefixed(&aad);
    if expected_aad_hash != artifact.aad_hash {
        return Err(SdkError::InvalidInput(
            "local envelope artifact AAD hash does not match the embedded metadata binding"
                .to_string(),
        ));
    }

    ensure_local_envelope_binding_matches_artifact(artifact)?;

    let nonce_bytes = BASE64_STANDARD
        .decode(&artifact.nonce_b64)
        .map_err(|error| {
            SdkError::Serialization(format!("failed to decode local envelope nonce: {error}"))
        })?;
    let ciphertext = BASE64_STANDARD
        .decode(&artifact.ciphertext_b64)
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to decode local envelope ciphertext: {error}"
            ))
        })?;
    let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
        SdkError::Serialization("local envelope nonce must be 12 bytes".to_string())
    })?;

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|error| {
        SdkError::InvalidInput(format!("failed to initialize envelope cipher: {error}"))
    })?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_array),
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|error| SdkError::Server(format!("local envelope decryption failed: {error}")))
}

fn encrypt_tdf_artifact(
    key: &LocalSymmetricKey,
    plaintext: &[u8],
    prepared: &PreparedLocalProtection,
    request: &LocalProtectionRequest,
    meta_version: u64,
) -> Result<LocalTdfArtifact, SdkError> {
    let manifest = LocalTdfManifest {
        workload: request.workload.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        labels: request.labels.clone(),
        attributes: request.attributes.clone(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        SdkError::Serialization(format!("failed to serialize local TDF manifest: {error}"))
    })?;
    let manifest_digest = sha256_prefixed(&manifest_bytes);
    let binding_hash = prepared.artifact_binding.binding_hash.clone();
    let aad = tdf_aad_bytes(
        &prepared.content_binding.tenant_id,
        &prepared.content_binding.raw_cid,
        &prepared.content_binding.content_digest,
        prepared.content_binding.content_size_bytes,
        &manifest_digest,
        &binding_hash,
    )?;
    let aad_hash = sha256_prefixed(&aad);

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|error| {
        SdkError::InvalidInput(format!("failed to initialize TDF cipher: {error}"))
    })?;

    let mut manifest_nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut manifest_nonce_bytes);
    let manifest_nonce = Nonce::from_slice(&manifest_nonce_bytes);
    let manifest_ciphertext = cipher
        .encrypt(
            manifest_nonce,
            aes_gcm::aead::Payload {
                msg: &manifest_bytes,
                aad: &aad,
            },
        )
        .map_err(|error| {
            SdkError::Server(format!("local TDF manifest encryption failed: {error}"))
        })?;

    let mut payload_nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut payload_nonce_bytes);
    let payload_nonce = Nonce::from_slice(&payload_nonce_bytes);
    let payload_ciphertext = cipher
        .encrypt(
            payload_nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|error| {
            SdkError::Server(format!("local TDF payload encryption failed: {error}"))
        })?;

    Ok(LocalTdfArtifact {
        version: 1,
        meta_version,
        artifact_profile: ArtifactProfile::Tdf,
        algorithm: LocalTdfAlgorithm::Aes256Gcm,
        tenant_id: prepared.content_binding.tenant_id.clone(),
        raw_cid: prepared.content_binding.raw_cid.clone(),
        content_digest: prepared.content_binding.content_digest.clone(),
        content_size_bytes: prepared.content_binding.content_size_bytes,
        manifest_digest,
        binding_targets: prepared.artifact_binding.binding_targets.clone(),
        binding_hash,
        policy_context: Some(manifest),
        manifest_nonce_b64: BASE64_STANDARD.encode(manifest_nonce_bytes),
        manifest_ciphertext_b64: BASE64_STANDARD.encode(manifest_ciphertext),
        payload_nonce_b64: BASE64_STANDARD.encode(payload_nonce_bytes),
        payload_ciphertext_b64: BASE64_STANDARD.encode(payload_ciphertext),
        aad_hash,
    })
}

fn decrypt_tdf_manifest(
    key: &LocalSymmetricKey,
    artifact: &LocalTdfArtifact,
) -> Result<LocalTdfManifest, SdkError> {
    let aad = tdf_aad_bytes(
        &artifact.tenant_id,
        &artifact.raw_cid,
        &artifact.content_digest,
        artifact.content_size_bytes,
        &artifact.manifest_digest,
        &artifact.binding_hash,
    )?;
    let expected_aad_hash = sha256_prefixed(&aad);
    if expected_aad_hash != artifact.aad_hash {
        return Err(SdkError::InvalidInput(
            "local TDF artifact AAD hash does not match the embedded metadata binding".to_string(),
        ));
    }

    let nonce_bytes = BASE64_STANDARD
        .decode(&artifact.manifest_nonce_b64)
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to decode local TDF manifest nonce: {error}"
            ))
        })?;
    let ciphertext = BASE64_STANDARD
        .decode(&artifact.manifest_ciphertext_b64)
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to decode local TDF manifest ciphertext: {error}"
            ))
        })?;
    let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
        SdkError::Serialization("local TDF manifest nonce must be 12 bytes".to_string())
    })?;

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|error| {
        SdkError::InvalidInput(format!("failed to initialize TDF cipher: {error}"))
    })?;
    let manifest_bytes = cipher
        .decrypt(
            Nonce::from_slice(&nonce_array),
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|error| {
            SdkError::Server(format!("local TDF manifest decryption failed: {error}"))
        })?;

    let manifest_digest = sha256_prefixed(&manifest_bytes);
    if manifest_digest != artifact.manifest_digest {
        return Err(SdkError::InvalidInput(
            "local TDF manifest digest does not match the embedded metadata binding".to_string(),
        ));
    }

    serde_json::from_slice(&manifest_bytes).map_err(|error| {
        SdkError::Serialization(format!("failed to decode local TDF manifest: {error}"))
    })
}

fn decrypt_tdf_payload(
    key: &LocalSymmetricKey,
    artifact: &LocalTdfArtifact,
) -> Result<Vec<u8>, SdkError> {
    let aad = tdf_aad_bytes(
        &artifact.tenant_id,
        &artifact.raw_cid,
        &artifact.content_digest,
        artifact.content_size_bytes,
        &artifact.manifest_digest,
        &artifact.binding_hash,
    )?;
    let expected_aad_hash = sha256_prefixed(&aad);
    if expected_aad_hash != artifact.aad_hash {
        return Err(SdkError::InvalidInput(
            "local TDF artifact AAD hash does not match the embedded metadata binding".to_string(),
        ));
    }

    let nonce_bytes = BASE64_STANDARD
        .decode(&artifact.payload_nonce_b64)
        .map_err(|error| {
            SdkError::Serialization(format!("failed to decode local TDF payload nonce: {error}"))
        })?;
    let ciphertext = BASE64_STANDARD
        .decode(&artifact.payload_ciphertext_b64)
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to decode local TDF payload ciphertext: {error}"
            ))
        })?;
    let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
        SdkError::Serialization("local TDF payload nonce must be 12 bytes".to_string())
    })?;

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|error| {
        SdkError::InvalidInput(format!("failed to initialize TDF cipher: {error}"))
    })?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_array),
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|error| SdkError::Server(format!("local TDF payload decryption failed: {error}")))
}

fn sign_detached_signature_artifact(
    signing_key: &LocalSigningKey,
    prepared: &PreparedLocalProtection,
    request: &LocalProtectionRequest,
) -> Result<LocalDetachedSignatureArtifact, SdkError> {
    let binding_bytes = local_artifact_binding_bytes(&prepared.artifact_binding)?;
    let binding_hash = prepared.artifact_binding.binding_hash.clone();

    let signer = Ed25519SigningKey::from_bytes(signing_key.as_bytes());
    let verifying_key = signer.verifying_key();
    let signature = signer.sign(&binding_bytes);
    let public_key_bytes = verifying_key.to_bytes();

    Ok(LocalDetachedSignatureArtifact {
        version: 1,
        artifact_profile: ArtifactProfile::DetachedSignature,
        algorithm: LocalDetachedSignatureAlgorithm::Ed25519,
        tenant_id: prepared.content_binding.tenant_id.clone(),
        raw_cid: prepared.content_binding.raw_cid.clone(),
        content_digest: prepared.content_binding.content_digest.clone(),
        content_size_bytes: prepared.content_binding.content_size_bytes,
        workload: request.workload.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        labels: request.labels.clone(),
        attributes: request.attributes.clone(),
        binding_targets: prepared.artifact_binding.binding_targets.clone(),
        signer_key_id: signer_key_id_from_public_key(&public_key_bytes),
        signer_public_key_b64: BASE64_STANDARD.encode(public_key_bytes),
        binding_hash,
        signature_b64: BASE64_STANDARD.encode(signature.to_bytes()),
    })
}

fn verify_detached_signature_artifact(
    verifying_key: &LocalVerifyingKey,
    artifact: &LocalDetachedSignatureArtifact,
    content_binding: &LocalContentBinding,
) -> Result<(), SdkError> {
    let binding =
        local_artifact_binding_from_detached_signature_artifact(artifact, content_binding)?;
    let binding_bytes = local_artifact_binding_bytes(&binding)?;
    let expected_binding_hash = binding.binding_hash;
    if expected_binding_hash != artifact.binding_hash {
        return Err(SdkError::InvalidInput(
            "detached signature binding hash does not match the embedded metadata binding"
                .to_string(),
        ));
    }

    let signature_bytes = BASE64_STANDARD
        .decode(&artifact.signature_b64)
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to decode detached signature bytes: {error}"
            ))
        })?;
    let signature = Ed25519Signature::from_slice(&signature_bytes).map_err(|error| {
        SdkError::Serialization(format!("invalid detached signature bytes: {error}"))
    })?;

    let verifying_key =
        Ed25519VerifyingKey::from_bytes(verifying_key.as_bytes()).map_err(|error| {
            SdkError::InvalidInput(format!("invalid Ed25519 verifying key: {error}"))
        })?;
    verifying_key
        .verify(&binding_bytes, &signature)
        .map_err(|error| {
            SdkError::InvalidInput(format!("detached signature verification failed: {error}"))
        })
}

fn envelope_aad_bytes(binding: &EnvelopeAadBinding<'_>) -> Result<Vec<u8>, SdkError> {
    serde_json::to_vec(binding).map_err(|error| {
        SdkError::Serialization(format!("failed to serialize envelope AAD binding: {error}"))
    })
}

fn tdf_aad_bytes(
    tenant_id: &str,
    raw_cid: &str,
    content_digest: &str,
    content_size_bytes: u64,
    manifest_digest: &str,
    binding_hash: &str,
) -> Result<Vec<u8>, SdkError> {
    serde_json::to_vec(&TdfAadBinding {
        tenant_id,
        raw_cid,
        content_digest,
        content_size_bytes,
        manifest_digest,
        artifact_profile: ArtifactProfile::Tdf,
        binding_hash,
    })
    .map_err(|error| {
        SdkError::Serialization(format!("failed to serialize TDF AAD binding: {error}"))
    })
}

fn build_local_artifact_binding(
    content_binding: &LocalContentBinding,
    request: &LocalProtectionRequest,
    binding_targets: &[String],
) -> Result<LocalArtifactBinding, SdkError> {
    let mut artifact_binding = LocalArtifactBinding {
        version: default_binding_version(),
        tenant_id: content_binding.tenant_id.clone(),
        raw_cid: content_binding.raw_cid.clone(),
        content_digest: content_binding.content_digest.clone(),
        content_size_bytes: content_binding.content_size_bytes,
        workload: request.workload.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        labels: request.labels.clone(),
        attributes: request.attributes.clone(),
        binding_targets: binding_targets.to_vec(),
        binding_hash: String::new(),
    };
    artifact_binding.binding_hash =
        sha256_prefixed(&local_artifact_binding_bytes(&artifact_binding)?);
    Ok(artifact_binding)
}

fn local_artifact_binding_bytes(binding: &LocalArtifactBinding) -> Result<Vec<u8>, SdkError> {
    serde_json::to_vec(&LocalArtifactBindingPayload {
        version: binding.version,
        tenant_id: &binding.tenant_id,
        raw_cid: &binding.raw_cid,
        content_digest: &binding.content_digest,
        content_size_bytes: binding.content_size_bytes,
        workload: &binding.workload,
        resource: &binding.resource,
        purpose: &binding.purpose,
        labels: &binding.labels,
        attributes: &binding.attributes,
        binding_targets: &binding.binding_targets,
    })
    .map_err(|error| {
        SdkError::Serialization(format!(
            "failed to serialize local artifact binding: {error}"
        ))
    })
}

fn local_artifact_binding_from_envelope_artifact(
    artifact: &LocalEnvelopeArtifact,
) -> Result<LocalArtifactBinding, SdkError> {
    build_local_artifact_binding(
        &LocalContentBinding {
            tenant_id: artifact.tenant_id.clone(),
            content_digest: artifact.content_digest.clone(),
            content_size_bytes: artifact.content_size_bytes,
            raw_cid: artifact.raw_cid.clone(),
        },
        &LocalProtectionRequest {
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            preferred_artifact_profile: Some(ArtifactProfile::Envelope),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        },
        &artifact.binding_targets,
    )
}

fn local_artifact_binding_from_tdf_artifact(
    artifact: &LocalTdfArtifact,
    manifest: &LocalTdfManifest,
) -> Result<LocalArtifactBinding, SdkError> {
    build_local_artifact_binding(
        &LocalContentBinding {
            tenant_id: artifact.tenant_id.clone(),
            content_digest: artifact.content_digest.clone(),
            content_size_bytes: artifact.content_size_bytes,
            raw_cid: artifact.raw_cid.clone(),
        },
        &LocalProtectionRequest {
            workload: manifest.workload.clone(),
            resource: manifest.resource.clone(),
            preferred_artifact_profile: Some(ArtifactProfile::Tdf),
            purpose: manifest.purpose.clone(),
            labels: manifest.labels.clone(),
            attributes: manifest.attributes.clone(),
        },
        &artifact.binding_targets,
    )
}

fn local_artifact_binding_from_detached_signature_artifact(
    artifact: &LocalDetachedSignatureArtifact,
    content_binding: &LocalContentBinding,
) -> Result<LocalArtifactBinding, SdkError> {
    build_local_artifact_binding(
        content_binding,
        &LocalProtectionRequest {
            workload: artifact.workload.clone(),
            resource: artifact.resource.clone(),
            preferred_artifact_profile: Some(ArtifactProfile::DetachedSignature),
            purpose: artifact.purpose.clone(),
            labels: artifact.labels.clone(),
            attributes: artifact.attributes.clone(),
        },
        &artifact.binding_targets,
    )
}

fn signer_key_id_from_public_key(public_key_bytes: &[u8]) -> String {
    sha256_prefixed(public_key_bytes)
}
