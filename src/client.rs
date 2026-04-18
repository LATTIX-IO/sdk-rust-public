use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    builder::ClientBuilder,
    error::SdkError,
    models::{
        CallerIdentityResponse, SdkArtifactRegisterRequest, SdkArtifactRegisterResponse,
        SdkBootstrapResponse, SdkCapabilitiesResponse, SdkEvidenceIngestRequest,
        SdkEvidenceIngestResponse, SdkKeyAccessPlanRequest, SdkKeyAccessPlanResponse,
        SdkPolicyResolveRequest, SdkPolicyResolveResponse, SdkProtectionPlanRequest,
        SdkProtectionPlanResponse, SdkSessionExchangeResponse,
    },
};

pub(crate) enum ClientAuthStrategy {
    StaticBearer(String),
    SdkClientCredentials(Box<SdkClientCredentialsAuth>),
}

pub(crate) struct SdkClientCredentialsAuth {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_exchange_path: String,
    pub requested_scopes: Vec<String>,
    cached_session: Mutex<Option<CachedSessionToken>>,
}

struct CachedSessionToken {
    response: SdkSessionExchangeResponse,
    refresh_at: Instant,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct SdkSessionExchangeRequest<'a> {
    tenant_id: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    requested_scopes: &'a [String],
}

impl SdkClientCredentialsAuth {
    pub(crate) fn new(
        tenant_id: String,
        client_id: String,
        client_secret: String,
        token_exchange_path: String,
        requested_scopes: Vec<String>,
    ) -> Self {
        Self {
            tenant_id,
            client_id,
            client_secret,
            token_exchange_path,
            requested_scopes,
            cached_session: Mutex::new(None),
        }
    }

    fn resolve_access_token(
        &self,
        agent: &ureq::Agent,
        base_url: &str,
    ) -> Result<SdkSessionExchangeResponse, SdkError> {
        {
            let cache = self.cached_session.lock().map_err(|_| {
                SdkError::Connection("failed to acquire sdk session cache".to_string())
            })?;
            if let Some(cached) = cache.as_ref()
                && Instant::now() < cached.refresh_at
            {
                return Ok(cached.response.clone());
            }
        }

        let endpoint = if self.token_exchange_path.starts_with("http://")
            || self.token_exchange_path.starts_with("https://")
        {
            self.token_exchange_path.clone()
        } else {
            format!("{}{}", base_url, self.token_exchange_path)
        };
        let response = post_json_with_agent::<_, SdkSessionExchangeResponse>(
            agent,
            &endpoint,
            &SdkSessionExchangeRequest {
                tenant_id: &self.tenant_id,
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                requested_scopes: &self.requested_scopes,
            },
            &BTreeMap::new(),
        )?;

        let refresh_after_secs = if response.expires_in > 60 {
            response.expires_in - 60
        } else {
            1
        };

        let mut cache = self
            .cached_session
            .lock()
            .map_err(|_| SdkError::Connection("failed to update sdk session cache".to_string()))?;
        *cache = Some(CachedSessionToken {
            response: response.clone(),
            refresh_at: Instant::now() + Duration::from_secs(refresh_after_secs),
        });

        Ok(response)
    }
}

pub struct Client {
    pub(crate) base_url: String,
    pub(crate) agent: ureq::Agent,
    pub(crate) default_headers: BTreeMap<String, String>,
    pub(crate) auth_strategy: Option<ClientAuthStrategy>,
}

impl Client {
    pub(crate) fn new(
        base_url: String,
        agent: ureq::Agent,
        default_headers: BTreeMap<String, String>,
        auth_strategy: Option<ClientAuthStrategy>,
    ) -> Self {
        Self {
            base_url,
            agent,
            default_headers,
            auth_strategy,
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

    pub fn exchange_session(&self) -> Result<SdkSessionExchangeResponse, SdkError> {
        match self.auth_strategy.as_ref() {
            Some(ClientAuthStrategy::SdkClientCredentials(auth)) => {
                auth.resolve_access_token(&self.agent, &self.base_url)
            }
            Some(ClientAuthStrategy::StaticBearer(_)) => Err(SdkError::InvalidInput(
                "client is configured with a static bearer token; no sdk session exchange is required"
                    .to_string(),
            )),
            None => Err(SdkError::InvalidInput(
                "client is not configured with sdk client credentials".to_string(),
            )),
        }
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
            Some(ClientAuthStrategy::SdkClientCredentials(auth)) => {
                let session = auth.resolve_access_token(&self.agent, &self.base_url)?;
                Ok(Some(format!("Bearer {}", session.access_token)))
            }
            None => Ok(None),
        }
    }
}

fn post_json_with_agent<TReq, TRes>(
    agent: &ureq::Agent,
    endpoint: &str,
    payload: &TReq,
    headers: &BTreeMap<String, String>,
) -> Result<TRes, SdkError>
where
    TReq: Serialize,
    TRes: DeserializeOwned,
{
    let payload_json = serde_json::to_string(payload).map_err(|error| {
        SdkError::Serialization(format!("failed to serialize request payload: {error}"))
    })?;
    let mut request = agent.post(endpoint).set("Content-Type", "application/json");
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = request.send_string(&payload_json).map_err(map_ureq_error)?;
    decode_response(response)
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
