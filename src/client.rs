use std::collections::BTreeMap;

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    builder::ClientBuilder,
    error::SdkError,
    models::{
        CallerIdentityResponse, SdkArtifactRegisterRequest, SdkArtifactRegisterResponse,
        SdkBootstrapResponse, SdkCapabilitiesResponse, SdkEvidenceIngestRequest,
        SdkEvidenceIngestResponse, SdkKeyAccessPlanRequest, SdkKeyAccessPlanResponse,
        SdkPolicyResolveRequest, SdkPolicyResolveResponse, SdkProtectionPlanRequest, SdkProtectionPlanResponse,
    },
    providers::ManagedSymmetricKeyProviderRegistry,
};

pub(crate) enum ClientAuthStrategy {
    StaticBearer(String),
}

pub struct Client {
    pub(crate) base_url: String,
    pub(crate) agent: ureq::Agent,
    pub(crate) default_headers: BTreeMap<String, String>,
    pub(crate) auth_strategy: Option<ClientAuthStrategy>,
    pub(crate) managed_symmetric_key_provider_registry: ManagedSymmetricKeyProviderRegistry,
}

impl Client {
    pub(crate) fn new(
        base_url: String,
        agent: ureq::Agent,
        default_headers: BTreeMap<String, String>,
        auth_strategy: Option<ClientAuthStrategy>,
        managed_symmetric_key_provider_registry: ManagedSymmetricKeyProviderRegistry,
    ) -> Self {
        Self {
            base_url,
            agent,
            default_headers,
            auth_strategy,
            managed_symmetric_key_provider_registry,
        }
    }

    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn capabilities(&self) -> Result<SdkCapabilitiesResponse, SdkError> {
        self.get_json("/v1/sdk/capabilities")
    }

    pub fn whoami(&self) -> Result<CallerIdentityResponse, SdkError> {
        self.get_json("/v1/sdk/whoami")
    }

    pub fn bootstrap(&self) -> Result<SdkBootstrapResponse, SdkError> {
        self.get_json("/v1/sdk/bootstrap")
    }

    pub fn protection_plan(
        &self,
        request: &SdkProtectionPlanRequest,
    ) -> Result<SdkProtectionPlanResponse, SdkError> {
        self.post_json("/v1/sdk/protection-plan", request)
    }

    pub fn policy_resolve(
        &self,
        request: &SdkPolicyResolveRequest,
    ) -> Result<SdkPolicyResolveResponse, SdkError> {
        self.post_json("/v1/sdk/policy-resolve", request)
    }

    pub fn key_access_plan(
        &self,
        request: &SdkKeyAccessPlanRequest,
    ) -> Result<SdkKeyAccessPlanResponse, SdkError> {
        self.post_json("/v1/sdk/key-access-plan", request)
    }

    pub fn artifact_register(
        &self,
        request: &SdkArtifactRegisterRequest,
    ) -> Result<SdkArtifactRegisterResponse, SdkError> {
        self.post_json("/v1/sdk/artifact-register", request)
    }

    pub fn evidence(
        &self,
        request: &SdkEvidenceIngestRequest,
    ) -> Result<SdkEvidenceIngestResponse, SdkError> {
        self.post_json("/v1/sdk/evidence", request)
    }

    fn get_json<T>(&self, path: &str) -> Result<T, SdkError>
    where
        T: DeserializeOwned,
    {
        let response = self
            .apply_headers(self.agent.get(&self.endpoint(path)))?
            .call()
            .map_err(map_ureq_error)?;
        decode_response(response)
    }

    fn post_json<TReq, TRes>(&self, path: &str, payload: &TReq) -> Result<TRes, SdkError>
    where
        TReq: Serialize,
        TRes: DeserializeOwned,
    {
        let payload_json = serde_json::to_string(payload).map_err(|error| {
            SdkError::Serialization(format!("failed to serialize request payload: {error}"))
        })?;
        let response = self
            .apply_headers(
                self.agent
                    .post(&self.endpoint(path))
                    .set("Content-Type", "application/json"),
            )?
            .send_string(&payload_json)
            .map_err(map_ureq_error)?;
        decode_response(response)
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn apply_headers(&self, mut request: ureq::Request) -> Result<ureq::Request, SdkError> {
        for (name, value) in &self.default_headers {
            request = request.set(name, value);
        }

        if let Some(authorization_header) = self.resolve_authorization_header()? {
            request = request.set("Authorization", &authorization_header);
        }

        Ok(request)
    }

    fn resolve_authorization_header(&self) -> Result<Option<String>, SdkError> {
        match self.auth_strategy.as_ref() {
            Some(ClientAuthStrategy::StaticBearer(header)) => Ok(Some(header.clone())),
            None => Ok(None),
        }
    }
}

fn decode_response<T>(response: ureq::Response) -> Result<T, SdkError>
where
    T: DeserializeOwned,
{
    let body = response.into_string().map_err(|error| {
        SdkError::Connection(format!("failed to read HTTP response body: {error}"))
    })?;
    serde_json::from_str(&body).map_err(|error| {
        SdkError::Serialization(format!("failed to decode JSON response body: {error}"))
    })
}

fn map_ureq_error(error: ureq::Error) -> SdkError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            SdkError::Server(format!("HTTP {status}: {body}"))
        }
        ureq::Error::Transport(transport) => SdkError::Connection(transport.to_string()),
    }
}
