use std::{
    cell::RefCell,
    ffi::{CStr, CString, c_char},
    ptr,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    builder::ClientBuilder,
    client::Client,
    error::SdkError,
    models::{
        SdkArtifactRegisterRequest, SdkEvidenceIngestRequest, SdkKeyAccessPlanRequest,
        SdkPolicyResolveRequest, SdkProtectionPlanRequest,
    },
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
    client_id: Option<String>,
    client_secret: Option<String>,
    tenant_id: Option<String>,
    user_id: Option<String>,
    timeout_secs: Option<u64>,
    token_exchange_path: Option<String>,
    #[serde(default)]
    requested_scopes: Vec<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
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
        if let Some(client_id) = options.client_id {
            builder = builder.with_client_id(client_id);
        }
        if let Some(client_secret) = options.client_secret {
            builder = builder.with_client_secret(client_secret);
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
        if let Some(token_exchange_path) = options.token_exchange_path {
            builder = builder.with_token_exchange_path(token_exchange_path);
        }
        if !options.requested_scopes.is_empty() {
            builder = builder.with_requested_scopes(options.requested_scopes);
        }
        for (name, value) in options.headers {
            builder = builder.with_header(name, value);
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
ffi_get_method!(lattix_sdk_exchange_session, exchange_session);
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
