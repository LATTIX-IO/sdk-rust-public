/*
 * Canonical C ABI for the Lattix Rust SDK core.
 *
 * Downstream bindings should consume this header directly whenever possible.
 * If a copy is required for build tooling, keep it synchronized from this file
 * instead of maintaining a hand-edited variant.
 */

#ifndef LATTIX_SDK_H
#define LATTIX_SDK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ClientHandle ClientHandle;

char* lattix_sdk_version(void);
char* lattix_sdk_last_error_message(void);
void lattix_sdk_string_free(char* value);

ClientHandle* lattix_sdk_client_new(const char* options_json);
void lattix_sdk_client_free(ClientHandle* handle);

char* lattix_sdk_capabilities(ClientHandle* handle);
char* lattix_sdk_whoami(ClientHandle* handle);
char* lattix_sdk_bootstrap(ClientHandle* handle);
char* lattix_sdk_exchange_session(ClientHandle* handle);
char* lattix_sdk_protection_plan(ClientHandle* handle, const char* request_json);
char* lattix_sdk_policy_resolve(ClientHandle* handle, const char* request_json);
char* lattix_sdk_key_access_plan(ClientHandle* handle, const char* request_json);
char* lattix_sdk_artifact_register(ClientHandle* handle, const char* request_json);
char* lattix_sdk_evidence(ClientHandle* handle, const char* request_json);

#ifdef __cplusplus
}
#endif

#endif
