//! Shared protocol constants, host abstraction, and utilities.
//!
//! The `Host` trait abstracts store, HTTP, signing, and time so that the
//! business logic shares a single production implementation and test mocks,
//! following the same pattern as the gasless petal.

use base64::Engine;
use petal::{
    HostStatus, HttpRequest, HttpResponse, PayloadSignItem, PayloadSignRequest, SdkError,
    SignOutcome, SignSelector,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

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

/// SIWE statement shown to the user in their wallet.
pub(crate) const SIWE_STATEMENT: &str = "Sign in to Venice AI";

/// SIWE session lifetime (5 minutes, matching Venice's expectation).
pub(crate) const SIWE_TTL_SECS: u64 = 300;

/// Renew the SIWE session 30 seconds before it expires.
pub(crate) const SIWE_RENEWAL_SECS: u64 = 270;

/// Maximum HTTP response body (512 KB).
pub(crate) const MAX_BODY: usize = 512 * 1024;

/// Maximum stored value size (1 MB). Sized so that a chat result — which
/// stores the request messages plus a response that may be up to `MAX_BODY`
/// long — can always be written and read back. The previous 32 KB cap would
/// silently fail the read-back (after the user had already paid for the
/// inference) on any sizable model response.
pub const MAX_STORED: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Host trait
// ---------------------------------------------------------------------------

/// Host trait abstracting store, HTTP, signing, and time so the module
/// shares a single production implementation and test mocks.
pub(crate) trait Host {
    fn store_get(&mut self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String>;
    fn store_put(&mut self, key: &str, value: &[u8], secret: bool) -> Result<(), String>;
    fn store_del(&mut self, key: &str) -> Result<(), String>;
    fn http_fetch(
        &mut self,
        request: &HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, String>;
    fn sign_payload(&mut self, request: &PayloadSignRequest) -> Result<SignOutcome, String>;
    fn package_hash(&self) -> &str;
    fn route_id(&self) -> &str;
    fn now_ms(&mut self) -> Result<u64, String>;
    fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, String>;
}

/// Production host backed by Bloom SDK bindings.
pub(crate) struct BloomHost {
    pub(crate) package_hash: String,
    pub(crate) route_id: String,
}

impl BloomHost {
    pub(crate) fn new(ctx: &petal::Ctx) -> Result<Self, DispatchResponse> {
        let route_id = ctx
            .params
            .iter()
            .find_map(|(name, value)| (name == "bloom.route_id").then_some(value.clone()))
            .ok_or_else(|| backend("trusted Petal route id is unavailable"))?;
        Ok(Self {
            package_hash: ctx.package_hash.clone(),
            route_id,
        })
    }
}

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

    fn store_del(&mut self, key: &str) -> Result<(), String> {
        petal::sdk::store_del(key).map_err(|error| error.message())
    }

    fn http_fetch(
        &mut self,
        request: &HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, String> {
        petal::sdk::http_fetch(request, max_bytes).map_err(|error| error.message())
    }

    fn sign_payload(&mut self, request: &PayloadSignRequest) -> Result<SignOutcome, String> {
        petal::sdk::sign_payload(request).map_err(|error| error.message())
    }

    fn package_hash(&self) -> &str {
        &self.package_hash
    }

    fn route_id(&self) -> &str {
        &self.route_id
    }

    fn now_ms(&mut self) -> Result<u64, String> {
        petal::sdk::try_now_ms().map_err(|error| error.message())
    }

    fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
        petal::sdk::random_bytes(len).map_err(|error| error.message())
    }
}

pub(crate) fn request_payload_signature(
    host: &mut impl Host,
    wallet: &str,
    preimage: Vec<u8>,
    claimed_hash: [u8; 32],
    operation_class: &str,
    approval_hint: Option<String>,
    action: Option<Vec<u8>>,
) -> Result<SignOutcome, String> {
    let payload_digest = petal::payload_batch_digest(&[PayloadSignItem {
        preimage: preimage.clone(),
        claimed_hash,
    }])
    .map_err(|error| error.message())?;
    let nonce = Sha256::digest(
        [
            host.package_hash().as_bytes(),
            host.route_id().as_bytes(),
            operation_class.as_bytes(),
            payload_digest.as_slice(),
        ]
        .concat(),
    );
    let claim = json!({
        "package_hash": host.package_hash(),
        "route": host.route_id(),
        "operation_class": operation_class,
        "crypto_suite": "secp256k1-keccak256-recoverable",
        "payload_digest": hex::encode(payload_digest),
        "ordered_hashes": [hex::encode(claimed_hash)],
        "declared_debits": [],
        "declared_destinations": [],
        "declared_fee": {"kind": "none"},
        "nonce": hex::encode(&nonce[..16]),
        "claim_assurance": {"kind": "machine_asserted"}
    });
    host.sign_payload(&PayloadSignRequest {
        wallet: wallet.to_owned(),
        preimage,
        claimed_hash,
        signature_algorithm: "secp256k1-keccak256-recoverable".into(),
        operation_class: operation_class.into(),
        petal_use_claim_jcs: serde_jcs::to_vec(&claim).map_err(|error| error.to_string())?,
        claim_assurance_evidence: None,
        approval_hint,
        action,
        advisory: None,
        selector: SignSelector::Exact,
        key_ref_jcs: None,
    })
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
pub fn is_evm_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a non-negative USD decimal string (e.g. `"5.00"`, `"0.25"`) into USDC
/// base units (6 decimals). Rejects empty strings, signs, non-digits, and more
/// than 6 fractional digits (USDC cannot represent sub-micro-cent). Use this
/// instead of `f64` parsing: the result drives an on-chain `uint256` transfer
/// value, so it must be exact.
pub(crate) fn parse_usd_to_base_units(amount_usd: &str) -> Result<u64, String> {
    let s = amount_usd.trim();
    if s.is_empty() {
        return Err("amount_usd is empty".into());
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("amount_usd is not a valid number: {amount_usd}"));
    }
    if !frac.is_empty() && !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("amount_usd is not a valid number: {amount_usd}"));
    }
    if frac.len() > 6 {
        return Err(format!(
            "amount_usd has more than 6 decimal places (USDC uses 6 decimals): {amount_usd}"
        ));
    }
    let whole_val: u64 = whole
        .parse()
        .map_err(|_| format!("amount_usd is too large: {amount_usd}"))?;
    let whole_units = whole_val
        .checked_mul(1_000_000)
        .ok_or_else(|| format!("amount_usd is too large: {amount_usd}"))?;
    // Pad the fractional part to exactly 6 digits (USDC decimals).
    let mut frac_padded = [b'0'; 6];
    for (i, b) in frac.bytes().enumerate() {
        frac_padded[i] = b;
    }
    // SAFETY: frac_padded is always 6 ASCII digits.
    let frac_val: u64 = std::str::from_utf8(&frac_padded)
        .unwrap()
        .parse()
        .map_err(|_| format!("amount_usd is not a valid number: {amount_usd}"))?;
    whole_units
        .checked_add(frac_val)
        .ok_or_else(|| format!("amount_usd is too large: {amount_usd}"))
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
        pub(crate) sign_results: VecDeque<Result<SignOutcome, String>>,
        pub(crate) requests: Vec<HttpRequest>,
        pub(crate) sign_requests: Vec<PayloadSignRequest>,
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

        fn store_del(&mut self, key: &str) -> Result<(), String> {
            self.store.remove(key);
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

        fn sign_payload(&mut self, request: &PayloadSignRequest) -> Result<SignOutcome, String> {
            self.sign_requests.push(request.clone());
            self.sign_results
                .pop_front()
                .expect("unexpected signing request")
        }

        fn package_hash(&self) -> &str {
            "test-package-hash"
        }

        fn route_id(&self) -> &str {
            "test/route.json"
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

    pub(crate) fn signature() -> SignOutcome {
        let mut bytes = vec![0xab; 65];
        bytes[64] = 27;
        SignOutcome::Signature(bytes)
    }

    pub(crate) fn approval() -> SignOutcome {
        SignOutcome::ApprovalPending {
            action_id: "approval-1".into(),
            expires_ms: 1_500_000,
        }
    }

    /// Deterministic 32-byte nonce for testing.
    pub(crate) fn test_nonce() -> Vec<u8> {
        (0..32).map(|i| i as u8).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_usd_to_base_units;

    #[test]
    fn parses_whole_and_fractional_usd() {
        assert_eq!(parse_usd_to_base_units("5.00").unwrap(), 5_000_000);
        assert_eq!(parse_usd_to_base_units("0.25").unwrap(), 250_000);
        assert_eq!(parse_usd_to_base_units("10").unwrap(), 10_000_000);
        assert_eq!(parse_usd_to_base_units("0.000001").unwrap(), 1);
    }

    #[test]
    fn pads_short_fractional_part() {
        assert_eq!(parse_usd_to_base_units("5.1").unwrap(), 5_100_000);
        assert_eq!(parse_usd_to_base_units("5.123").unwrap(), 5_123_000);
    }

    #[test]
    fn rejects_non_positive_and_garbage() {
        assert!(parse_usd_to_base_units("0").is_ok_and(|v| v == 0));
        assert!(parse_usd_to_base_units("").is_err());
        assert!(parse_usd_to_base_units("-5.00").is_err());
        assert!(parse_usd_to_base_units("five").is_err());
        assert!(parse_usd_to_base_units("5.abc").is_err());
    }

    #[test]
    fn rejects_more_than_six_decimals() {
        assert!(parse_usd_to_base_units("5.0000001").is_err());
        assert!(parse_usd_to_base_units("0.1234567").is_err());
    }
}
