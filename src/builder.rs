use std::{collections::BTreeMap, sync::Arc, time::Duration};

use crate::{
    client::{Client, ClientAuthStrategy},
    error::SdkError,
    providers::{ManagedSymmetricKeyProvider, ManagedSymmetricKeyProviderRegistry},
};

pub struct ClientBuilder {
    base_url: String,
    bearer_token: Option<String>,
    tenant_id: Option<String>,
    user_id: Option<String>,
    timeout_secs: Option<u64>,
    headers: BTreeMap<String, String>,
    managed_symmetric_key_provider_registry: ManagedSymmetricKeyProviderRegistry,
}

impl ClientBuilder {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: None,
            tenant_id: None,
            user_id: None,
            timeout_secs: None,
            headers: BTreeMap::new(),
            managed_symmetric_key_provider_registry: ManagedSymmetricKeyProviderRegistry::new(),
        }
    }

    pub fn with_bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.bearer_token = Some(bearer_token.into());
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

    pub fn with_managed_symmetric_key_provider<P>(mut self, provider: P) -> Self
    where
        P: ManagedSymmetricKeyProvider + 'static,
    {
        self.managed_symmetric_key_provider_registry
            .register(provider);
        self
    }

    pub fn with_managed_symmetric_key_provider_arc(
        mut self,
        provider: Arc<dyn ManagedSymmetricKeyProvider>,
    ) -> Self {
        self.managed_symmetric_key_provider_registry
            .register_arc(provider);
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
            None
        };

        Ok(Client::new(
            base_url,
            agent_builder.build(),
            headers,
            auth_strategy,
            self.managed_symmetric_key_provider_registry,
        ))
    }
}
