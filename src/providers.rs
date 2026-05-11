use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    error::SdkError,
    local::{LocalSymmetricKey, ManagedSymmetricKeyReference},
    models::KeyTransportMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSymmetricKeyProviderCapabilities {
    supported_transport_modes: Vec<KeyTransportMode>,
}

impl ManagedSymmetricKeyProviderCapabilities {
    pub fn new(supported_transport_modes: Vec<KeyTransportMode>) -> Self {
        let mut supported_transport_modes = supported_transport_modes;
        supported_transport_modes.dedup();
        Self {
            supported_transport_modes,
        }
    }

    pub fn supports(&self, mode: KeyTransportMode) -> bool {
        self.supported_transport_modes.contains(&mode)
    }

    pub fn supported_transport_modes(&self) -> &[KeyTransportMode] {
        &self.supported_transport_modes
    }
}

pub trait ManagedSymmetricKeyProvider: Send + Sync {
    fn provider_name(&self) -> &str;

    fn capabilities(&self) -> &ManagedSymmetricKeyProviderCapabilities;

    fn resolve_key(
        &self,
        key_reference: &ManagedSymmetricKeyReference,
    ) -> Result<LocalSymmetricKey, SdkError>;
}

#[derive(Clone, Default)]
pub struct ManagedSymmetricKeyProviderRegistry {
    providers: BTreeMap<String, Arc<dyn ManagedSymmetricKeyProvider>>,
}

impl ManagedSymmetricKeyProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P>(&mut self, provider: P)
    where
        P: ManagedSymmetricKeyProvider + 'static,
    {
        self.register_arc(Arc::new(provider));
    }

    pub fn register_arc(&mut self, provider: Arc<dyn ManagedSymmetricKeyProvider>) {
        self.providers
            .insert(provider.provider_name().to_string(), provider);
    }

    pub fn resolve(
        &self,
        provider_name: Option<&str>,
    ) -> Result<Arc<dyn ManagedSymmetricKeyProvider>, SdkError> {
        match provider_name {
            Some(provider_name) => self.providers.get(provider_name).cloned().ok_or_else(|| {
                SdkError::InvalidInput(format!(
                    "managed symmetric key provider {provider_name:?} is not registered"
                ))
            }),
            None => match self.providers.len() {
                0 => Err(SdkError::InvalidInput(
                    "managed key execution requires a registered symmetric key provider, but none were configured"
                        .to_string(),
                )),
                1 => self
                    .providers
                    .values()
                    .next()
                    .cloned()
                    .ok_or_else(|| {
                        SdkError::InvalidInput(
                            "managed symmetric key provider registry was unexpectedly empty"
                                .to_string(),
                        )
                    }),
                _ => Err(SdkError::InvalidInput(
                    "multiple managed symmetric key providers are registered; specify provider_name in the key source"
                        .to_string(),
                )),
            },
        }
    }
}

#[derive(Clone)]
pub struct InMemoryManagedSymmetricKeyProvider {
    name: String,
    capabilities: ManagedSymmetricKeyProviderCapabilities,
    keys: BTreeMap<String, LocalSymmetricKey>,
}

impl InMemoryManagedSymmetricKeyProvider {
    pub fn new(name: impl Into<String>, keys: BTreeMap<String, LocalSymmetricKey>) -> Self {
        Self {
            name: name.into(),
            capabilities: ManagedSymmetricKeyProviderCapabilities::new(vec![
                KeyTransportMode::WrappedKeyReference,
                KeyTransportMode::AuthorizedKeyRelease,
            ]),
            keys,
        }
    }

    pub fn with_supported_transport_modes<I>(mut self, modes: I) -> Self
    where
        I: IntoIterator<Item = KeyTransportMode>,
    {
        self.capabilities =
            ManagedSymmetricKeyProviderCapabilities::new(modes.into_iter().collect());
        self
    }
}

impl ManagedSymmetricKeyProvider for InMemoryManagedSymmetricKeyProvider {
    fn provider_name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> &ManagedSymmetricKeyProviderCapabilities {
        &self.capabilities
    }

    fn resolve_key(
        &self,
        key_reference: &ManagedSymmetricKeyReference,
    ) -> Result<LocalSymmetricKey, SdkError> {
        self.keys
            .get(key_reference.key_reference())
            .cloned()
            .ok_or_else(|| {
                SdkError::InvalidInput(format!(
                    "managed symmetric key reference {:?} is not available from provider {:?}",
                    key_reference.key_reference(),
                    self.name
                ))
            })
    }
}

#[derive(Clone)]
pub struct CommandManagedSymmetricKeyProvider {
    name: String,
    capabilities: ManagedSymmetricKeyProviderCapabilities,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandManagedSymmetricKeyProviderRequest<'a> {
    provider_name: &'a str,
    key_reference: &'a str,
    requested_provider_name: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandManagedSymmetricKeyProviderResponse {
    key_b64: String,
}

impl CommandManagedSymmetricKeyProvider {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capabilities: ManagedSymmetricKeyProviderCapabilities::new(vec![
                KeyTransportMode::WrappedKeyReference,
                KeyTransportMode::AuthorizedKeyRelease,
            ]),
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
        }
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_envs<I, K, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = envs
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self
    }

    pub fn with_supported_transport_modes<I>(mut self, modes: I) -> Self
    where
        I: IntoIterator<Item = KeyTransportMode>,
    {
        self.capabilities =
            ManagedSymmetricKeyProviderCapabilities::new(modes.into_iter().collect());
        self
    }
}

impl ManagedSymmetricKeyProvider for CommandManagedSymmetricKeyProvider {
    fn provider_name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> &ManagedSymmetricKeyProviderCapabilities {
        &self.capabilities
    }

    fn resolve_key(
        &self,
        key_reference: &ManagedSymmetricKeyReference,
    ) -> Result<LocalSymmetricKey, SdkError> {
        let mut child = Command::new(&self.command)
            .args(&self.args)
            .envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                SdkError::Connection(format!(
                    "failed to launch managed symmetric key provider command {:?}: {error}",
                    self.command
                ))
            })?;

        let request = serde_json::to_vec(&CommandManagedSymmetricKeyProviderRequest {
            provider_name: &self.name,
            key_reference: key_reference.key_reference(),
            requested_provider_name: key_reference.provider_name(),
        })
        .map_err(|error| {
            SdkError::Serialization(format!(
                "failed to serialize managed symmetric key provider command request: {error}"
            ))
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request).map_err(|error| {
                SdkError::Connection(format!(
                    "failed to send key reference to managed symmetric key provider command {:?}: {error}",
                    self.command
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|error| {
            SdkError::Connection(format!(
                "failed waiting for managed symmetric key provider command {:?}: {error}",
                self.command
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(SdkError::Connection(format!(
                "managed symmetric key provider command {:?} failed{}",
                self.command,
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            )));
        }

        let response: CommandManagedSymmetricKeyProviderResponse =
            serde_json::from_slice(&output.stdout).map_err(|error| {
                SdkError::Serialization(format!(
                    "failed to decode managed symmetric key provider command output: {error}"
                ))
            })?;

        let decoded_key = BASE64_STANDARD.decode(&response.key_b64).map_err(|error| {
            SdkError::InvalidInput(format!(
                "managed symmetric key provider command returned invalid base64 key material: {error}"
            ))
        })?;
        let key: [u8; 32] = decoded_key.try_into().map_err(|_| {
            SdkError::InvalidInput(
                "managed symmetric key provider command must return exactly 32 bytes of key material"
                    .to_string(),
            )
        })?;

        Ok(LocalSymmetricKey::from(key))
    }
}
