use std::{
    cell::RefCell,
    ffi::{CStr, CString, c_char},
    ptr,
};

use base64::Engine as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    builder::ClientBuilder,
    client::Client,
    error::SdkError,
    local::{
        DetachedSignatureSignResult, DetachedSignatureVerifyResult, EnvelopeAccessResult,
        EnvelopeProtectionResult, EnvelopeRewrapResult, LocalArtifactBinding, LocalAttributeEdit,
        LocalProtectionRequest, LocalSigningKey, LocalSymmetricKey, LocalSymmetricKeySource,
        LocalVerifyingKey, PreparedLocalProtection, ProtectedDetachedSignatureArtifact,
        ProtectedEnvelopeArtifact, ProtectedTdfArtifact, TdfAccessResult, TdfProtectionResult,
        TdfRewrapResult,
    },
    models::{
        KeyTransportMode, SdkArtifactRegisterRequest, SdkEvidenceIngestRequest,
        SdkKeyAccessPlanRequest, SdkPolicyResolveRequest, SdkProtectionPlanRequest,
    },
    providers::{CommandManagedSymmetricKeyProvider, InMemoryManagedSymmetricKeyProvider},
};

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub struct ClientHandle {
    pub client: Client,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiClientOptions {
    base_url: String,
    bearer_token: Option<String>,
    tenant_id: Option<String>,
    user_id: Option<String>,
    timeout_secs: Option<u64>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    managed_symmetric_key_providers: Vec<FfiManagedSymmetricKeyProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiManagedSymmetricKeyProviderConfig {
    #[serde(default)]
    kind: Option<String>,
    name: String,
    #[serde(default)]
    supported_transport_modes: Vec<KeyTransportMode>,
    #[serde(default)]
    keys: std::collections::BTreeMap<String, String>,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiPrepareLocalProtectionRequest {
    content_b64: String,
    request: LocalProtectionRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeProtectRequest {
    key_b64: Option<String>,
    key_source: Option<FfiSymmetricKeySource>,
    plaintext_b64: String,
    request: LocalProtectionRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeAccessRequest {
    key_b64: Option<String>,
    key_source: Option<FfiSymmetricKeySource>,
    artifact_bytes_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiDetachedSignatureSignRequest {
    signing_key_b64: String,
    content_b64: String,
    request: LocalProtectionRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiDetachedSignatureVerifyRequest {
    verifying_key_b64: String,
    content_b64: String,
    artifact_bytes_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeRewrapRequest {
    current_key_b64: Option<String>,
    current_key_source: Option<FfiSymmetricKeySource>,
    new_key_b64: Option<String>,
    new_key_source: Option<FfiSymmetricKeySource>,
    artifact_bytes_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiTdfSetAttributesRequest {
    key_b64: Option<String>,
    key_source: Option<FfiSymmetricKeySource>,
    artifact_bytes_b64: String,
    #[serde(default)]
    attributes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct FfiTdfEditAttributesRequest {
    key_b64: Option<String>,
    key_source: Option<FfiSymmetricKeySource>,
    artifact_bytes_b64: String,
    #[serde(default)]
    edit: LocalAttributeEdit,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum FfiSymmetricKeySource {
    Inline {
        key_b64: String,
    },
    ManagedReference {
        key_reference: String,
        provider_name: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiProtectedEnvelopeArtifact {
    envelope: crate::local::LocalEnvelopeArtifact,
    artifact_bytes_b64: String,
    artifact_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeProtectionResult {
    prepared: PreparedLocalProtection,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    artifact: FfiProtectedEnvelopeArtifact,
    artifact_registration: crate::models::SdkArtifactRegisterResponse,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeAccessResult {
    artifact: crate::local::LocalEnvelopeArtifact,
    artifact_digest: String,
    policy_resolution: crate::models::SdkPolicyResolveResponse,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    plaintext_b64: String,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiEnvelopeRewrapResult {
    content_binding: crate::local::LocalContentBinding,
    policy_resolution: crate::models::SdkPolicyResolveResponse,
    protection_plan: crate::models::SdkProtectionPlanResponse,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    original_artifact_digest: String,
    artifact: FfiProtectedEnvelopeArtifact,
    artifact_registration: crate::models::SdkArtifactRegisterResponse,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiProtectedDetachedSignatureArtifact {
    detached_signature: crate::local::LocalDetachedSignatureArtifact,
    artifact_bytes_b64: String,
    artifact_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiDetachedSignatureSignResult {
    prepared: PreparedLocalProtection,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    artifact: FfiProtectedDetachedSignatureArtifact,
    artifact_registration: crate::models::SdkArtifactRegisterResponse,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiDetachedSignatureVerifyResult {
    artifact: crate::local::LocalDetachedSignatureArtifact,
    artifact_digest: String,
    policy_resolution: crate::models::SdkPolicyResolveResponse,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    content_binding: crate::local::LocalContentBinding,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiProtectedTdfArtifact {
    tdf: crate::local::LocalTdfArtifact,
    artifact_bytes_b64: String,
    artifact_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiTdfProtectionResult {
    prepared: PreparedLocalProtection,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    artifact: FfiProtectedTdfArtifact,
    artifact_registration: crate::models::SdkArtifactRegisterResponse,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiTdfAccessResult {
    artifact: crate::local::LocalTdfArtifact,
    manifest: crate::local::LocalTdfManifest,
    artifact_digest: String,
    policy_resolution: crate::models::SdkPolicyResolveResponse,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    plaintext_b64: String,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct FfiTdfRewrapResult {
    content_binding: crate::local::LocalContentBinding,
    manifest: crate::local::LocalTdfManifest,
    policy_resolution: crate::models::SdkPolicyResolveResponse,
    protection_plan: crate::models::SdkProtectionPlanResponse,
    key_access_plan: crate::models::SdkKeyAccessPlanResponse,
    original_artifact_digest: String,
    artifact: FfiProtectedTdfArtifact,
    artifact_registration: crate::models::SdkArtifactRegisterResponse,
    evidence: crate::models::SdkEvidenceIngestResponse,
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_version() -> *mut c_char {
    into_c_string(env!("CARGO_PKG_VERSION"))
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_deref() {
        Some(message) => into_c_string(message),
        None => into_c_string(""),
    })
}

/// Frees a string previously allocated by this library and returned over the FFI boundary.
///
/// # Safety
///
/// `value` must either be null or a pointer returned by one of this library's FFI functions
/// that transfer ownership of a `CString` to the caller. Passing any other pointer, or freeing
/// the same pointer more than once, is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lattix_sdk_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    drop(unsafe { CString::from_raw(value) });
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_client_new(options_json: *const c_char) -> *mut ClientHandle {
    match ffi_result(|| {
        let options: FfiClientOptions = parse_json_arg(options_json)?;
        let mut builder = ClientBuilder::new(options.base_url);

        if let Some(bearer_token) = options.bearer_token {
            builder = builder.with_bearer_token(bearer_token);
        }
        if let Some(tenant_id) = options.tenant_id {
            builder = builder.with_tenant_id(tenant_id);
        }
        if let Some(user_id) = options.user_id {
            builder = builder.with_user_id(user_id);
        }
        if let Some(timeout_secs) = options.timeout_secs {
            builder = builder.with_timeout_secs(timeout_secs);
        }
        for (name, value) in options.headers {
            builder = builder.with_header(name, value);
        }
        for provider in options.managed_symmetric_key_providers {
            match provider.kind.as_deref().unwrap_or("in_memory") {
                "in_memory" => {
                    let mut keys = std::collections::BTreeMap::new();
                    for (key_reference, key_b64) in provider.keys {
                        keys.insert(
                            key_reference,
                            decode_base64_key_arg("managed_symmetric_key_provider.keys", &key_b64)?,
                        );
                    }

                    let mut in_memory_provider =
                        InMemoryManagedSymmetricKeyProvider::new(provider.name, keys);
                    if !provider.supported_transport_modes.is_empty() {
                        in_memory_provider = in_memory_provider
                            .with_supported_transport_modes(provider.supported_transport_modes);
                    }
                    builder = builder.with_managed_symmetric_key_provider(in_memory_provider);
                }
                "command" => {
                    let command = provider.command.ok_or_else(|| {
                        SdkError::InvalidInput(
                            "managed symmetric key command provider requires a command".to_string(),
                        )
                    })?;
                    let mut command_provider =
                        CommandManagedSymmetricKeyProvider::new(provider.name, command)
                            .with_args(provider.args)
                            .with_envs(provider.env);
                    if !provider.supported_transport_modes.is_empty() {
                        command_provider = command_provider
                            .with_supported_transport_modes(provider.supported_transport_modes);
                    }
                    builder = builder.with_managed_symmetric_key_provider(command_provider);
                }
                other => {
                    return Err(SdkError::InvalidInput(format!(
                        "unsupported managed symmetric key provider kind {other:?}"
                    )));
                }
            }
        }

        Ok(Box::into_raw(Box::new(ClientHandle {
            client: builder.build()?,
        })))
    }) {
        Ok(handle) => handle,
        Err(_) => ptr::null_mut(),
    }
}

/// Frees a client handle previously allocated by `lattix_sdk_client_new`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `lattix_sdk_client_new` that has not
/// already been freed. Passing any other pointer, or freeing the same pointer more than once,
/// is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lattix_sdk_client_free(handle: *mut ClientHandle) {
    if handle.is_null() {
        return;
    }

    drop(unsafe { Box::from_raw(handle) });
}

macro_rules! ffi_get_method {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(handle: *mut ClientHandle) -> *mut c_char {
            match ffi_result(|| {
                let client = client_from_handle(handle)?;
                let response = client.$method()?;
                serialize_json(&response)
            }) {
                Ok(value) => value,
                Err(_) => ptr::null_mut(),
            }
        }
    };
}

macro_rules! ffi_post_method {
    ($name:ident, $method:ident, $request_ty:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(
            handle: *mut ClientHandle,
            request_json: *const c_char,
        ) -> *mut c_char {
            match ffi_result(|| {
                let client = client_from_handle(handle)?;
                let request: $request_ty = parse_json_arg(request_json)?;
                let response = client.$method(&request)?;
                serialize_json(&response)
            }) {
                Ok(value) => value,
                Err(_) => ptr::null_mut(),
            }
        }
    };
}

ffi_get_method!(lattix_sdk_capabilities, capabilities);
ffi_get_method!(lattix_sdk_whoami, whoami);
ffi_get_method!(lattix_sdk_bootstrap, bootstrap);
ffi_post_method!(
    lattix_sdk_protection_plan,
    protection_plan,
    SdkProtectionPlanRequest
);
ffi_post_method!(
    lattix_sdk_policy_resolve,
    policy_resolve,
    SdkPolicyResolveRequest
);
ffi_post_method!(
    lattix_sdk_key_access_plan,
    key_access_plan,
    SdkKeyAccessPlanRequest
);
ffi_post_method!(
    lattix_sdk_artifact_register,
    artifact_register,
    SdkArtifactRegisterRequest
);
ffi_post_method!(lattix_sdk_evidence, evidence, SdkEvidenceIngestRequest);

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_prepare_local_protection(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiPrepareLocalProtectionRequest = parse_json_arg(request_json)?;
        let content = decode_base64_arg("content_b64", &request.content_b64)?;
        let response = client.prepare_local_protection(&content, request.request)?;
        serialize_json(&response)
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_generate_cid_binding(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiPrepareLocalProtectionRequest = parse_json_arg(request_json)?;
        let content = decode_base64_arg("content_b64", &request.content_b64)?;
        let response: LocalArtifactBinding =
            client.generate_cid_binding(&content, request.request)?;
        serialize_json(&response)
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_sign_bytes_with_detached_signature(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiDetachedSignatureSignRequest = parse_json_arg(request_json)?;
        let signing_key = decode_signing_key(&request.signing_key_b64)?;
        let content = decode_base64_arg("content_b64", &request.content_b64)?;
        let response =
            client.sign_bytes_with_detached_signature(&signing_key, &content, request.request)?;
        serialize_json(&ffi_detached_signature_sign_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_verify_bytes_with_detached_signature(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiDetachedSignatureVerifyRequest = parse_json_arg(request_json)?;
        let verifying_key = decode_verifying_key(&request.verifying_key_b64)?;
        let content = decode_base64_arg("content_b64", &request.content_b64)?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response = client.verify_bytes_with_detached_signature(
            &verifying_key,
            &content,
            &artifact_bytes,
        )?;
        serialize_json(&ffi_detached_signature_verify_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_protect_bytes_with_envelope(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeProtectRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let plaintext = decode_base64_arg("plaintext_b64", &request.plaintext_b64)?;
        let response = client.protect_bytes_with_envelope_using_key_source(
            &key_source,
            &plaintext,
            request.request,
        )?;
        serialize_json(&ffi_envelope_protection_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_protect_bytes_with_tdf(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeProtectRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let plaintext = decode_base64_arg("plaintext_b64", &request.plaintext_b64)?;
        let response = client.protect_bytes_with_tdf_using_key_source(
            &key_source,
            &plaintext,
            request.request,
        )?;
        serialize_json(&ffi_tdf_protection_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_access_bytes_with_envelope(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeAccessRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response =
            client.access_bytes_with_envelope_using_key_source(&key_source, &artifact_bytes)?;
        serialize_json(&ffi_envelope_access_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_rewrap_bytes_with_envelope(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeRewrapRequest = parse_json_arg(request_json)?;
        let current_key_source = decode_symmetric_key_source(
            request.current_key_source,
            request.current_key_b64.as_deref(),
            "current_key_b64",
        )?;
        let new_key_source = decode_symmetric_key_source(
            request.new_key_source,
            request.new_key_b64.as_deref(),
            "new_key_b64",
        )?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response = client.rewrap_bytes_with_envelope_using_key_sources(
            &current_key_source,
            &new_key_source,
            &artifact_bytes,
        )?;
        serialize_json(&ffi_envelope_rewrap_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_access_bytes_with_tdf(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeAccessRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response =
            client.access_bytes_with_tdf_using_key_source(&key_source, &artifact_bytes)?;
        serialize_json(&ffi_tdf_access_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_rewrap_bytes_with_tdf(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiEnvelopeRewrapRequest = parse_json_arg(request_json)?;
        let current_key_source = decode_symmetric_key_source(
            request.current_key_source,
            request.current_key_b64.as_deref(),
            "current_key_b64",
        )?;
        let new_key_source = decode_symmetric_key_source(
            request.new_key_source,
            request.new_key_b64.as_deref(),
            "new_key_b64",
        )?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response = client.rewrap_bytes_with_tdf_using_key_sources(
            &current_key_source,
            &new_key_source,
            &artifact_bytes,
        )?;
        serialize_json(&ffi_tdf_rewrap_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_set_tdf_attributes(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiTdfSetAttributesRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response = client.set_tdf_attributes_using_key_source(
            &key_source,
            &artifact_bytes,
            request.attributes,
        )?;
        serialize_json(&ffi_tdf_rewrap_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lattix_sdk_edit_tdf_attributes(
    handle: *mut ClientHandle,
    request_json: *const c_char,
) -> *mut c_char {
    match ffi_result(|| {
        let client = client_from_handle(handle)?;
        let request: FfiTdfEditAttributesRequest = parse_json_arg(request_json)?;
        let key_source =
            decode_symmetric_key_source(request.key_source, request.key_b64.as_deref(), "key_b64")?;
        let artifact_bytes = decode_base64_arg("artifact_bytes_b64", &request.artifact_bytes_b64)?;
        let response = client.edit_tdf_attributes_using_key_source(
            &key_source,
            &artifact_bytes,
            request.edit,
        )?;
        serialize_json(&ffi_tdf_rewrap_result(response))
    }) {
        Ok(value) => value,
        Err(_) => ptr::null_mut(),
    }
}

fn ffi_result<T>(action: impl FnOnce() -> Result<T, SdkError>) -> Result<T, ()> {
    match action() {
        Ok(value) => {
            clear_last_error();
            Ok(value)
        }
        Err(err) => {
            set_last_error(err.to_string());
            Err(())
        }
    }
}

fn client_from_handle(handle: *mut ClientHandle) -> Result<&'static Client, SdkError> {
    if handle.is_null() {
        return Err(SdkError::InvalidInput(
            "sdk-rust client handle cannot be null".to_string(),
        ));
    }

    let handle = unsafe { &*handle };
    Ok(&handle.client)
}

fn parse_json_arg<T>(value: *const c_char) -> Result<T, SdkError>
where
    T: DeserializeOwned,
{
    if value.is_null() {
        return Err(SdkError::InvalidInput(
            "JSON argument cannot be null".to_string(),
        ));
    }

    let raw = unsafe { CStr::from_ptr(value) };
    let raw = raw
        .to_str()
        .map_err(|err| SdkError::InvalidInput(format!("invalid UTF-8 argument: {err}")))?;
    serde_json::from_str(raw)
        .map_err(|err| SdkError::Serialization(format!("invalid JSON argument: {err}")))
}

fn decode_base64_arg(field_name: &str, value: &str) -> Result<Vec<u8>, SdkError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| SdkError::InvalidInput(format!("invalid base64 for {field_name}: {err}")))
}

fn decode_symmetric_key_source(
    key_source: Option<FfiSymmetricKeySource>,
    legacy_key_b64: Option<&str>,
    legacy_field_name: &str,
) -> Result<LocalSymmetricKeySource, SdkError> {
    if let Some(key_source) = key_source {
        return match key_source {
            FfiSymmetricKeySource::Inline { key_b64 } => Ok(LocalSymmetricKeySource::inline(
                decode_base64_key_arg(legacy_field_name, &key_b64)?,
            )),
            FfiSymmetricKeySource::ManagedReference {
                key_reference,
                provider_name,
            } => Ok(match provider_name {
                Some(provider_name) => LocalSymmetricKeySource::managed_reference_with_provider(
                    provider_name,
                    key_reference,
                ),
                None => LocalSymmetricKeySource::managed_reference(key_reference),
            }),
        };
    }

    let legacy_key_b64 = legacy_key_b64.ok_or_else(|| {
        SdkError::InvalidInput(format!(
            "missing symmetric key input: provide either key_source or {legacy_field_name}"
        ))
    })?;
    Ok(LocalSymmetricKeySource::inline(decode_base64_key_arg(
        legacy_field_name,
        legacy_key_b64,
    )?))
}

fn decode_signing_key(value: &str) -> Result<LocalSigningKey, SdkError> {
    let bytes = decode_base64_arg("signing_key_b64", value)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        SdkError::InvalidInput("signing_key_b64 must decode to exactly 32 bytes".to_string())
    })?;
    Ok(LocalSigningKey::from(key))
}

fn decode_verifying_key(value: &str) -> Result<LocalVerifyingKey, SdkError> {
    let bytes = decode_base64_arg("verifying_key_b64", value)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        SdkError::InvalidInput("verifying_key_b64 must decode to exactly 32 bytes".to_string())
    })?;
    Ok(LocalVerifyingKey::from(key))
}

fn decode_base64_key_arg(field_name: &str, value: &str) -> Result<LocalSymmetricKey, SdkError> {
    let bytes = decode_base64_arg(field_name, value)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        SdkError::InvalidInput(format!("{field_name} must decode to exactly 32 bytes"))
    })?;
    Ok(LocalSymmetricKey::from(key))
}

fn ffi_envelope_protection_result(
    response: EnvelopeProtectionResult,
) -> FfiEnvelopeProtectionResult {
    FfiEnvelopeProtectionResult {
        prepared: response.prepared,
        key_access_plan: response.key_access_plan,
        artifact: ffi_protected_envelope_artifact(response.artifact),
        artifact_registration: response.artifact_registration,
        evidence: response.evidence,
    }
}

fn ffi_detached_signature_sign_result(
    response: DetachedSignatureSignResult,
) -> FfiDetachedSignatureSignResult {
    FfiDetachedSignatureSignResult {
        prepared: response.prepared,
        key_access_plan: response.key_access_plan,
        artifact: ffi_protected_detached_signature_artifact(response.artifact),
        artifact_registration: response.artifact_registration,
        evidence: response.evidence,
    }
}

fn ffi_protected_detached_signature_artifact(
    artifact: ProtectedDetachedSignatureArtifact,
) -> FfiProtectedDetachedSignatureArtifact {
    FfiProtectedDetachedSignatureArtifact {
        detached_signature: artifact.detached_signature,
        artifact_bytes_b64: base64::engine::general_purpose::STANDARD
            .encode(artifact.artifact_bytes),
        artifact_digest: artifact.artifact_digest,
    }
}

fn ffi_detached_signature_verify_result(
    response: DetachedSignatureVerifyResult,
) -> FfiDetachedSignatureVerifyResult {
    FfiDetachedSignatureVerifyResult {
        artifact: response.artifact,
        artifact_digest: response.artifact_digest,
        policy_resolution: response.policy_resolution,
        key_access_plan: response.key_access_plan,
        content_binding: response.content_binding,
        evidence: response.evidence,
    }
}

fn ffi_protected_envelope_artifact(
    artifact: ProtectedEnvelopeArtifact,
) -> FfiProtectedEnvelopeArtifact {
    FfiProtectedEnvelopeArtifact {
        envelope: artifact.envelope,
        artifact_bytes_b64: base64::engine::general_purpose::STANDARD
            .encode(artifact.artifact_bytes),
        artifact_digest: artifact.artifact_digest,
    }
}

fn ffi_envelope_access_result(response: EnvelopeAccessResult) -> FfiEnvelopeAccessResult {
    FfiEnvelopeAccessResult {
        artifact: response.artifact,
        artifact_digest: response.artifact_digest,
        policy_resolution: response.policy_resolution,
        key_access_plan: response.key_access_plan,
        plaintext_b64: base64::engine::general_purpose::STANDARD.encode(response.plaintext),
        evidence: response.evidence,
    }
}

fn ffi_envelope_rewrap_result(response: EnvelopeRewrapResult) -> FfiEnvelopeRewrapResult {
    FfiEnvelopeRewrapResult {
        content_binding: response.content_binding,
        policy_resolution: response.policy_resolution,
        protection_plan: response.protection_plan,
        key_access_plan: response.key_access_plan,
        original_artifact_digest: response.original_artifact_digest,
        artifact: ffi_protected_envelope_artifact(response.artifact),
        artifact_registration: response.artifact_registration,
        evidence: response.evidence,
    }
}

fn ffi_tdf_protection_result(response: TdfProtectionResult) -> FfiTdfProtectionResult {
    FfiTdfProtectionResult {
        prepared: response.prepared,
        key_access_plan: response.key_access_plan,
        artifact: ffi_protected_tdf_artifact(response.artifact),
        artifact_registration: response.artifact_registration,
        evidence: response.evidence,
    }
}

fn ffi_protected_tdf_artifact(artifact: ProtectedTdfArtifact) -> FfiProtectedTdfArtifact {
    FfiProtectedTdfArtifact {
        tdf: artifact.tdf,
        artifact_bytes_b64: base64::engine::general_purpose::STANDARD
            .encode(artifact.artifact_bytes),
        artifact_digest: artifact.artifact_digest,
    }
}

fn ffi_tdf_access_result(response: TdfAccessResult) -> FfiTdfAccessResult {
    FfiTdfAccessResult {
        artifact: response.artifact,
        manifest: response.manifest,
        artifact_digest: response.artifact_digest,
        policy_resolution: response.policy_resolution,
        key_access_plan: response.key_access_plan,
        plaintext_b64: base64::engine::general_purpose::STANDARD.encode(response.plaintext),
        evidence: response.evidence,
    }
}

fn ffi_tdf_rewrap_result(response: TdfRewrapResult) -> FfiTdfRewrapResult {
    FfiTdfRewrapResult {
        content_binding: response.content_binding,
        manifest: response.manifest,
        policy_resolution: response.policy_resolution,
        protection_plan: response.protection_plan,
        key_access_plan: response.key_access_plan,
        original_artifact_digest: response.original_artifact_digest,
        artifact: ffi_protected_tdf_artifact(response.artifact),
        artifact_registration: response.artifact_registration,
        evidence: response.evidence,
    }
}

fn serialize_json<T>(value: &T) -> Result<*mut c_char, SdkError>
where
    T: Serialize,
{
    let payload = serde_json::to_string(value)
        .map_err(|err| SdkError::Serialization(format!("failed to serialize response: {err}")))?;
    Ok(into_c_string(payload))
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(message);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn into_c_string(value: impl AsRef<str>) -> *mut c_char {
    let sanitized = value.as_ref().replace('\0', " ");
    CString::new(sanitized)
        .expect("CString::new should succeed after null sanitization")
        .into_raw()
}
