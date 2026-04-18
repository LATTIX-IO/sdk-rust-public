use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    TrustedHeaders,
    BearerToken,
    BearerTokenOrTrustedHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RequestContext {
    pub tenant_id: String,
    pub principal_id: String,
    pub subject: String,
    pub auth_source: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkRouteCapability {
    pub route: String,
    pub domain: String,
    pub configured: bool,
    #[serde(default)]
    pub required_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkCapabilitiesResponse {
    pub service: String,
    pub status: String,
    pub auth_mode: AuthMode,
    pub caller: RequestContext,
    #[serde(default)]
    pub default_required_scopes: Vec<String>,
    #[serde(default)]
    pub routes: Vec<SdkRouteCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CallerIdentityResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionOperation {
    Protect,
    Access,
    Rewrap,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProfile {
    Tdf,
    Envelope,
    DetachedSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PlatformDomainPlan {
    pub domain: String,
    pub configured: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkBootstrapResponse {
    pub service: String,
    pub status: String,
    pub auth_mode: AuthMode,
    pub caller: RequestContext,
    pub enforcement_model: String,
    pub plaintext_to_platform: bool,
    pub policy_resolution_mode: String,
    #[serde(default)]
    pub supported_operations: Vec<ProtectionOperation>,
    #[serde(default)]
    pub supported_artifact_profiles: Vec<ArtifactProfile>,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkSessionExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    pub tenant_id: String,
    pub client_id: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct WorkloadDescriptor {
    pub application: String,
    pub environment: Option<String>,
    pub component: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ResourceDescriptor {
    pub kind: String,
    pub id: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkProtectionPlanRequest {
    pub operation: ProtectionOperation,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub preferred_artifact_profile: Option<ArtifactProfile>,
    pub content_digest: Option<String>,
    pub content_size_bytes: Option<u64>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ProtectionPlanSummary {
    pub operation: ProtectionOperation,
    pub workload_application: String,
    pub workload_environment: Option<String>,
    pub workload_component: Option<String>,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub mime_type: Option<String>,
    pub preferred_artifact_profile: ArtifactProfile,
    pub content_digest_present: bool,
    pub content_size_bytes: Option<u64>,
    pub label_count: usize,
    pub attribute_count: usize,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ProtectionPlanDecision {
    pub allow: bool,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub handling_mode: String,
    pub plaintext_transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ProtectionExecutionPlan {
    pub protect_locally: bool,
    pub local_enforcement_library: String,
    pub send_plaintext_to_platform: bool,
    #[serde(default)]
    pub send_only: Vec<String>,
    pub artifact_profile: ArtifactProfile,
    pub key_strategy: String,
    pub policy_resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkProtectionPlanResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
    pub request_summary: ProtectionPlanSummary,
    pub decision: ProtectionPlanDecision,
    pub execution: ProtectionExecutionPlan,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkPolicyResolveRequest {
    pub operation: ProtectionOperation,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub content_digest: Option<String>,
    pub content_size_bytes: Option<u64>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PolicyRequestSummary {
    pub operation: ProtectionOperation,
    pub workload_application: String,
    pub workload_environment: Option<String>,
    pub workload_component: Option<String>,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub mime_type: Option<String>,
    pub content_digest_present: bool,
    pub content_size_bytes: Option<u64>,
    pub purpose: Option<String>,
    pub label_count: usize,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PolicyResolutionDecision {
    pub allow: bool,
    pub enforcement_mode: String,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub policy_inputs: Vec<String>,
    #[serde(default)]
    pub required_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PolicyHandlingGuidance {
    pub protect_locally: bool,
    pub plaintext_transport: String,
    #[serde(default)]
    pub bind_policy_to: Vec<String>,
    #[serde(default)]
    pub evidence_expected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkPolicyResolveResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
    pub request_summary: PolicyRequestSummary,
    pub decision: PolicyResolutionDecision,
    pub handling: PolicyHandlingGuidance,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAccessOperation {
    Wrap,
    Unwrap,
    Rewrap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkKeyAccessPlanRequest {
    pub operation: KeyAccessOperation,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub artifact_profile: Option<ArtifactProfile>,
    pub key_reference: Option<String>,
    pub content_digest: Option<String>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct KeyAccessRequestSummary {
    pub operation: KeyAccessOperation,
    pub workload_application: String,
    pub workload_environment: Option<String>,
    pub workload_component: Option<String>,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub mime_type: Option<String>,
    pub artifact_profile: ArtifactProfile,
    pub key_reference_present: bool,
    pub content_digest_present: bool,
    pub purpose: Option<String>,
    pub label_count: usize,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct KeyAccessDecision {
    pub allow: bool,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub operation: KeyAccessOperation,
    pub key_reference_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct KeyAccessExecutionPlan {
    pub local_cryptographic_operation: bool,
    pub platform_role: String,
    pub send_plaintext_to_platform: bool,
    #[serde(default)]
    pub send_only: Vec<String>,
    pub artifact_profile: ArtifactProfile,
    pub authorization_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkKeyAccessPlanResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
    pub request_summary: KeyAccessRequestSummary,
    pub decision: KeyAccessDecision,
    pub execution: KeyAccessExecutionPlan,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkArtifactRegisterRequest {
    pub operation: ProtectionOperation,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub artifact_profile: ArtifactProfile,
    pub artifact_digest: String,
    pub artifact_locator: Option<String>,
    pub decision_id: Option<String>,
    pub key_reference: Option<String>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ArtifactRegistrationSummary {
    pub operation: ProtectionOperation,
    pub workload_application: String,
    pub workload_environment: Option<String>,
    pub workload_component: Option<String>,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub mime_type: Option<String>,
    pub artifact_profile: ArtifactProfile,
    pub artifact_digest: String,
    pub artifact_locator_present: bool,
    pub decision_id_present: bool,
    pub key_reference_present: bool,
    pub purpose: Option<String>,
    pub label_count: usize,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ArtifactRegistrationPlan {
    pub accepted: bool,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub artifact_transport: String,
    pub send_plaintext_to_platform: bool,
    #[serde(default)]
    pub catalog_actions: Vec<String>,
    #[serde(default)]
    pub evidence_expected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkArtifactRegisterResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
    pub request_summary: ArtifactRegistrationSummary,
    pub registration: ArtifactRegistrationPlan,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEventType {
    Protect,
    Access,
    Rewrap,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkEvidenceIngestRequest {
    pub event_type: EvidenceEventType,
    pub workload: WorkloadDescriptor,
    pub resource: ResourceDescriptor,
    pub artifact_profile: Option<ArtifactProfile>,
    pub artifact_digest: Option<String>,
    pub decision_id: Option<String>,
    pub outcome: Option<String>,
    pub occurred_at: Option<String>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EvidenceIngestSummary {
    pub event_type: EvidenceEventType,
    pub workload_application: String,
    pub workload_environment: Option<String>,
    pub workload_component: Option<String>,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub mime_type: Option<String>,
    pub artifact_profile: Option<ArtifactProfile>,
    pub artifact_digest_present: bool,
    pub decision_id_present: bool,
    pub outcome: Option<String>,
    pub occurred_at: Option<String>,
    pub purpose: Option<String>,
    pub label_count: usize,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EvidenceIngestionPlan {
    pub accepted: bool,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub plaintext_transport: String,
    #[serde(default)]
    pub send_only: Vec<String>,
    #[serde(default)]
    pub correlate_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SdkEvidenceIngestResponse {
    pub service: String,
    pub status: String,
    pub caller: RequestContext,
    pub request_summary: EvidenceIngestSummary,
    pub ingestion: EvidenceIngestionPlan,
    #[serde(default)]
    pub platform_domains: Vec<PlatformDomainPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
}
