use std::{collections::BTreeMap, time::Duration};

use crate::{
    client::{Client, ClientAuthStrategy, SdkClientCredentialsAuth},
    error::SdkError,
};

pub struct ClientBuilder {
    base_url: String,
    bearer_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    tenant_id: Option<String>,
    user_id: Option<String>,
    timeout_secs: Option<u64>,
    token_exchange_path: Option<String>,
    requested_scopes: Vec<String>,
    headers: BTreeMap<String, String>,
}

impl ClientBuilder {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: None,
            client_id: None,
            client_secret: None,
            tenant_id: None,
            user_id: None,
            timeout_secs: None,
            token_exchange_path: None,
            requested_scopes: Vec::new(),
            headers: BTreeMap::new(),
        }
    }

    pub fn with_bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.bearer_token = Some(bearer_token.into());
        self
    }

    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn with_token_exchange_path(mut self, token_exchange_path: impl Into<String>) -> Self {
        self.token_exchange_path = Some(token_exchange_path.into());
        self
    }

    pub fn with_requested_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requested_scopes = scopes
            .into_iter()
            .map(Into::into)
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect();
        self.requested_scopes.sort();
        self.requested_scopes.dedup();
        self
    }

    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub fn build(self) -> Result<Client, SdkError> {
        let base_url = self.base_url.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(SdkError::InvalidInput(
                "base_url cannot be empty".to_string(),
            ));
        }

        let mut headers = self.headers;
        let tenant_id = self.tenant_id.map(|tenant_id| tenant_id.trim().to_string());
        if let Some(tenant_id) = tenant_id.as_deref()
            && !tenant_id.is_empty()
        {
            headers.insert("x-lattix-tenant-id".to_string(), tenant_id.to_string());
        }
        if let Some(user_id) = self.user_id {
            let user_id = user_id.trim();
            if !user_id.is_empty() {
                headers.insert("x-lattix-user-id".to_string(), user_id.to_string());
            }
        }

        let mut agent_builder = ureq::AgentBuilder::new();
        if let Some(timeout_secs) = self.timeout_secs {
            agent_builder = agent_builder.timeout(Duration::from_secs(timeout_secs));
        }

        let auth_strategy = if let Some(bearer_token) = self.bearer_token {
            let bearer_token = bearer_token.trim().to_string();
            if bearer_token.is_empty() {
                None
            } else {
                Some(ClientAuthStrategy::StaticBearer(format!(
                    "Bearer {bearer_token}"
                )))
            }
        } else {
            match (self.client_id, self.client_secret) {
                (Some(client_id), Some(client_secret)) => {
                    let tenant_id = tenant_id.ok_or_else(|| {
                        SdkError::InvalidInput(
                            "tenant_id is required when sdk client credentials are configured"
                                .to_string(),
                        )
                    })?;
                    let client_id = client_id.trim().to_string();
                    let client_secret = client_secret.trim().to_string();
                    if client_id.is_empty() || client_secret.is_empty() {
                        return Err(SdkError::InvalidInput(
                            "client_id and client_secret cannot be empty".to_string(),
                        ));
                    }

                    Some(ClientAuthStrategy::SdkClientCredentials(Box::new(
                        SdkClientCredentialsAuth::new(
                            tenant_id,
                            client_id,
                            client_secret,
                            self.token_exchange_path
                                .unwrap_or_else(|| "/v1/sdk/session".to_string()),
                            self.requested_scopes,
                        ),
                    )))
                }
                (None, None) => None,
                _ => {
                    return Err(SdkError::InvalidInput(
                        "client_id and client_secret must be provided together".to_string(),
                    ));
                }
            }
        };

        Ok(Client::new(
            base_url,
            agent_builder.build(),
            headers,
            auth_strategy,
        ))
    }
}
