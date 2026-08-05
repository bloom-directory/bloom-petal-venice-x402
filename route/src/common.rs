//! Shared protocol constants, host abstraction, and utilities.
//!
//! The `Host` trait abstracts store, HTTP, signing, and time so that the
//! business logic shares a single production implementation and test mocks,
//! following the same pattern as the gasless petal.

use base64::Engine;
use petal::{HostStatus, HttpRequest, HttpResponse, SdkError, SignHashOutcome, SignRequest};

pub(crate) use petal::DispatchResponse;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Venice API base URL.
pub(crate) const VENICE_API: &str = "https://api.venice.ai/api/v1";

/// Domain used in the SIWE message and payment resource URL.
pub(crate) const VENICE_DOMAIN: &str = "api.venice.ai";

/// Base mainnet chain ID.
pub(crate) const CHAIN_ID: u64 = 8453;

/// USDC contract on Base (native, EIP-3009 compatible).
pub(crate) const USDC_BASE: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

/// EIP-712 domain name for USDC.
pub(crate) const USDC_NAME: &str = "USD Coin";

/// EIP-712 domain version for USDC.
pub(crate) const USDC_VERSION: &str = "2";

/// x402 protocol version used in payment headers.
pub(crate) const X402_VERSION: u8 = 2;

/// SIWE statement shown to the user in their wallet.
pub(crate) const SIWE_STATEMENT: &str = "Sign in to Venice AI";

/// SIWE session lifetime (5 minutes, matching Venice's expectation).
pub(crate) const SIWE_TTL_SECS: u64 = 300;

/// Renew the SIWE session 30 seconds before it expires.
pub(crate) const SIWE_RENEWAL_SECS: u64 = 270;

/// Maximum HTTP response body (512 KB).
pub(crate) const MAX_BODY: usize = 512 * 1024;

/// Maximum stored value size (32 KB).
pub(crate) const MAX_STORED: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Host trait
// ---------------------------------------------------------------------------

/// Host trait abstracting store, HTTP, signing, and time so the module
/// shares a single production implementation and test mocks.
pub(crate) trait Host {
    fn store_get(&mut self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String>;
    fn store_put(&mut self, key: &str, value: &[u8], secret: bool) -> Result<(), String>;
    fn http_fetch(
        &mut self,
        request: &HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, String>;
    fn sign_hash(&mut self, request: &SignRequest) -> Result<SignHashOutcome, String>;
    fn now_ms(&mut self) -> Result<u64, String>;
    fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, String>;
}

/// Production host backed by Bloom SDK bindings.
pub(crate) struct BloomHost;

impl Host for BloomHost {
    fn store_get(&mut self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        match petal::sdk::store_get(key, max_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(SdkError::Host(HostStatus::NotFound)) => Ok(None),
            Err(error) => Err(error.message()),
        }
    }

    fn store_put(&mut self, key: &str, value: &[u8], secret: bool) -> Result<(), String> {
        petal::sdk::store_put(key, value, secret).map_err(|error| error.message())
    }

    fn http_fetch(
        &mut self,
        request: &HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, String> {
        petal::sdk::http_fetch(request, max_bytes).map_err(|error| error.message())
    }

    fn sign_hash(&mut self, request: &SignRequest) -> Result<SignHashOutcome, String> {
        petal::sdk::sign_hash(request).map_err(|error| error.message())
    }

    fn now_ms(&mut self) -> Result<u64, String> {
        petal::sdk::try_now_ms().map_err(|error| error.message())
    }

    fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
        petal::sdk::random_bytes(len).map_err(|error| error.message())
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

pub(crate) fn invalid(message: impl Into<String>) -> DispatchResponse {
    petal::error(-3, message)
}

pub(crate) fn backend(message: impl Into<String>) -> DispatchResponse {
    petal::error(-4, message)
}

// ---------------------------------------------------------------------------
// Validation utilities
// ---------------------------------------------------------------------------

/// Validate an EVM address (0x-prefixed, 40 hex digits, case-insensitive).
pub(crate) fn is_evm_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Signature helpers
// ---------------------------------------------------------------------------

/// Convert raw 65-byte signature bytes to a `0x`-prefixed hex string with
/// EIP-191 recovery ID normalisation (27/28).
pub(crate) fn signature_hex(mut bytes: Vec<u8>) -> Result<String, String> {
    if bytes.len() != 65 {
        return Err("wallet returned a non-EVM signature".into());
    }
    if bytes[64] < 27 {
        bytes[64] += 27;
    }
    if !matches!(bytes[64], 27 | 28) {
        return Err("wallet returned an invalid EVM recovery ID".into());
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Extract the signing outcome: either a signature hex string, or propagate
/// the `ApprovalRequired` dispatch response.
pub(crate) fn require_signature(
    outcome: SignHashOutcome,
    approval_label: &str,
) -> Result<String, DispatchResponse> {
    match outcome {
        SignHashOutcome::Signature(bytes) => signature_hex(bytes).map_err(backend),
        SignHashOutcome::ApprovalRequired {
            action_id,
            ceremony_url,
            expires_ms,
        } => Err(petal::error(
            -2,
            serde_json::to_string(&serde_json::json!({
                "status": "approval_required",
                "label": approval_label,
                "action_id": action_id,
                "ceremony_url": ceremony_url,
                "expires_ms": expires_ms,
            }))
            .unwrap_or_else(|_| format!("approval required: {approval_label}")),
        )),
    }
}

/// Compact JSON representation of a serde_json::Value, truncated for error messages.
pub(crate) fn compact(value: &serde_json::Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "<invalid>".into())
        .chars()
        .take(4096)
        .collect()
}

/// Parse an HTTP response body as JSON.
pub(crate) fn parse_json_body(response: &HttpResponse) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&response.body)
        .map_err(|e| format!("invalid JSON response from Venice: {e}"))
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    /// Venice's x402 payment receiver address (used in test fixtures).
    pub(crate) const VENICE_PAYEE: &str = "0x2670b922ef37c7df47158725c0cc407b5382293f";

    pub(crate) fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("invalid base64: {e}"))
    }

    #[derive(Default)]
    pub(crate) struct MockHost {
        pub(crate) store: HashMap<String, Vec<u8>>,
        pub(crate) http_results: VecDeque<Result<HttpResponse, String>>,
        pub(crate) sign_results: VecDeque<Result<SignHashOutcome, String>>,
        pub(crate) requests: Vec<HttpRequest>,
        pub(crate) sign_requests: Vec<SignRequest>,
        pub(crate) now_ms: u64,
        pub(crate) random_data: VecDeque<Vec<u8>>,
    }

    impl Host for MockHost {
        fn store_get(&mut self, key: &str, _max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
            Ok(self.store.get(key).cloned())
        }

        fn store_put(&mut self, key: &str, value: &[u8], _secret: bool) -> Result<(), String> {
            self.store.insert(key.into(), value.to_vec());
            Ok(())
        }

        fn http_fetch(
            &mut self,
            request: &HttpRequest,
            _max_bytes: usize,
        ) -> Result<HttpResponse, String> {
            self.requests.push(request.clone());
            self.http_results
                .pop_front()
                .expect("unexpected HTTP request")
        }

        fn sign_hash(&mut self, request: &SignRequest) -> Result<SignHashOutcome, String> {
            self.sign_requests.push(request.clone());
            self.sign_results
                .pop_front()
                .expect("unexpected signing request")
        }

        fn now_ms(&mut self) -> Result<u64, String> {
            Ok(self.now_ms)
        }

        fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
            if let Some(data) = self.random_data.pop_front() {
                Ok(data)
            } else {
                Ok(vec![0x42; len])
            }
        }
    }

    pub(crate) fn signature() -> SignHashOutcome {
        let mut bytes = vec![0xab; 65];
        bytes[64] = 27;
        SignHashOutcome::Signature(bytes)
    }

    pub(crate) fn approval() -> SignHashOutcome {
        SignHashOutcome::ApprovalRequired {
            action_id: "approval-1".into(),
            ceremony_url: "http://127.0.0.1/approve/approval-1".into(),
            expires_ms: 1_500_000,
        }
    }

    /// Deterministic 32-byte nonce for testing.
    pub(crate) fn test_nonce() -> Vec<u8> {
        (0..32).map(|i| i as u8).collect()
    }
}
