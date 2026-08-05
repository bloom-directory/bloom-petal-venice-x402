//! Sign-In-With-Ethereum (EIP-4361) message construction and EIP-191 hashing.
//!
//! Venice expects a Base64-encoded JSON payload in the `X-Sign-In-With-X`
//! header containing a signed SIWE message. The message follows EIP-4361
//! with a fixed statement and 5-minute expiry.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::common::{
    self, CHAIN_ID, DispatchResponse, Host, MAX_STORED, SIWE_RENEWAL_SECS, SIWE_STATEMENT,
    SIWE_TTL_SECS, VENICE_API, VENICE_DOMAIN,
};

/// Parameters for constructing a SIWE message.
pub(crate) struct SiweParams {
    pub address: String,
    pub nonce: String,
    pub issued_at_iso: String,
    pub expiration_iso: String,
}

/// The persisted SIWE session (stored in secrets namespace).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SiweSession {
    /// EVM address of the wallet.
    pub address: String,
    /// The EIP-4361 message string that was signed.
    pub message: String,
    /// `0x`-prefixed hex signature.
    pub signature: String,
    /// Unix milliseconds when the session was created.
    pub created_ms: u64,
    /// Base64-encoded `X-Sign-In-With-X` header value.
    pub header_b64: String,
}

/// The decoded SIWE header payload (Base64-decoded JSON).
#[derive(Clone, Debug, Serialize)]
struct SiweHeaderPayload {
    address: String,
    message: String,
    signature: String,
    timestamp: u64,
    chain_id: u64,
}

/// Construct an EIP-4361 SIWE message string for Venice.
///
/// Format:
/// ```text
/// api.venice.ai wants you to sign in with your Ethereum account:
/// 0x...
///
/// Sign in to Venice AI
///
/// URI: https://api.venice.ai/api/v1/chat/completions
/// Version: 1
/// Chain ID: 8453
/// Nonce: <hex>
/// Issued At: <ISO 8601>
/// Expiration Time: <ISO 8601>
/// ```
pub(crate) fn format_message(params: &SiweParams) -> String {
    let uri = format!("{VENICE_API}/chat/completions");
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\
         \n\
         {statement}\n\
         \n\
         URI: {uri}\n\
         Version: 1\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration}",
        domain = VENICE_DOMAIN,
        address = params.address,
        statement = SIWE_STATEMENT,
        uri = uri,
        chain_id = CHAIN_ID,
        nonce = params.nonce,
        issued_at = params.issued_at_iso,
        expiration = params.expiration_iso,
    )
}

/// Compute the EIP-191 personal-message signing hash:
/// `keccak256("\x19Ethereum Signed Message:\n" + len + message)`.
pub(crate) fn eip191_signing_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

/// Convert Unix milliseconds to an ISO-8601 UTC timestamp string.
fn ms_to_iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    let dt = chrono_like_utc(secs, nanos);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.millis
    )
}

/// Minimal UTC datetime struct (avoids pulling in chrono for WASM targets).
struct UtcDateTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
}

/// Convert a Unix timestamp (seconds + nanos) to a broken-down UTC datetime.
///
/// This implements the standard civil-from-days algorithm (Howard Hinnant).
fn chrono_like_utc(secs: i64, nanos: u32) -> UtcDateTime {
    let days = secs.div_euclid(86_400);
    let remainder = secs.rem_euclid(86_400);
    let hour = (remainder / 3600) as u32;
    let minute = ((remainder % 3600) / 60) as u32;
    let second = (remainder % 60) as u32;
    let millis = nanos / 1_000_000;

    // Civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    UtcDateTime {
        year,
        month: m as u32,
        day: d as u32,
        hour,
        minute,
        second,
        millis,
    }
}

/// Generate a random hex nonce (32 bytes → 64 hex chars, 0x-prefixed).
fn generate_nonce(host: &mut impl Host) -> Result<String, String> {
    let bytes = host.random_bytes(32)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Get a valid SIWE session for the wallet, creating a new one if needed.
///
/// Sessions are cached in the secrets store. A session is reused if it has
/// more than `SIWE_RENEWAL_SECS` seconds of validity remaining.
pub(crate) fn get_or_create_session(
    host: &mut impl Host,
    wallet: &str,
    address: &str,
) -> Result<SiweSession, DispatchResponse> {
    let key = session_key(wallet);

    // Try to load and validate an existing session.
    if let Some(session) = load_cached_session(host, &key)? {
        return Ok(session);
    }

    // Create new session.
    let now_ms = host.now_ms().map_err(common::backend)?;
    let nonce = generate_nonce(host).map_err(common::backend)?;
    let issued_iso = ms_to_iso(now_ms);
    let expiry_ms = now_ms + SIWE_TTL_SECS * 1000;
    let expiration_iso = ms_to_iso(expiry_ms);

    let message = format_message(&SiweParams {
        address: address.to_owned(),
        nonce: nonce.clone(),
        issued_at_iso: issued_iso,
        expiration_iso: expiration_iso.clone(),
    });

    let hash = eip191_signing_hash(&message);
    let outcome = host
        .sign_hash(&petal::SignRequest {
            wallet: wallet.to_owned(),
            hash32: hash,
            purpose: "venice.siwe".into(),
        })
        .map_err(common::backend)?;

    let signature = common::require_signature(outcome, "SIWE authentication")?;

    let payload = SiweHeaderPayload {
        address: address.to_owned(),
        message: message.clone(),
        signature: signature.clone(),
        timestamp: now_ms,
        chain_id: CHAIN_ID,
    };
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| common::backend(format!("serialize SIWE payload: {e}")))?;
    let header_b64 = common::encode_base64(&payload_json);

    let session = SiweSession {
        address: address.to_owned(),
        message,
        signature,
        created_ms: now_ms,
        header_b64,
    };

    let session_bytes = serde_json::to_vec(&session)
        .map_err(|e| common::backend(format!("serialize session: {e}")))?;
    host.store_put(&key, &session_bytes, true)
        .map_err(common::backend)?;

    Ok(session)
}

/// Try to load a cached SIWE session from the store.
///
/// Returns `Ok(None)` if there is no session, the stored data is corrupt,
/// or the session is past its renewal threshold.
fn load_cached_session(
    host: &mut impl Host,
    key: &str,
) -> Result<Option<SiweSession>, DispatchResponse> {
    let Some(bytes) = host.store_get(key, MAX_STORED).map_err(common::backend)? else {
        return Ok(None);
    };
    let Ok(session) = serde_json::from_slice::<SiweSession>(&bytes) else {
        return Ok(None); // Corrupt session — create a new one.
    };
    let now_ms = host.now_ms().map_err(common::backend)?;
    let age_secs = now_ms.saturating_sub(session.created_ms) / 1000;
    Ok((age_secs < SIWE_RENEWAL_SECS).then_some(session))
}

fn session_key(wallet: &str) -> String {
    format!("venice-x402/sessions/{wallet}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::*;

    #[test]
    fn siwe_message_format() {
        let params = SiweParams {
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            nonce: "0xabc123".into(),
            issued_at_iso: "2024-01-01T00:00:00.000Z".into(),
            expiration_iso: "2024-01-01T00:05:00.000Z".into(),
        };
        let msg = format_message(&params);
        assert!(msg.starts_with("api.venice.ai wants you to sign in with your Ethereum account:"));
        assert!(msg.contains("0x1234567890abcdef1234567890abcdef12345678"));
        assert!(msg.contains("Sign in to Venice AI"));
        assert!(msg.contains("URI: https://api.venice.ai/api/v1/chat/completions"));
        assert!(msg.contains("Version: 1"));
        assert!(msg.contains("Chain ID: 8453"));
        assert!(msg.contains("Nonce: 0xabc123"));
        assert!(msg.contains("Issued At: 2024-01-01T00:00:00.000Z"));
        assert!(msg.contains("Expiration Time: 2024-01-01T00:05:00.000Z"));
    }

    #[test]
    fn eip191_hash_is_deterministic() {
        let h1 = eip191_signing_hash("");
        let h2 = eip191_signing_hash("");
        assert_eq!(h1, h2);
    }

    #[test]
    fn eip191_hash_is_deterministic_and_varies_by_input() {
        let h1 = eip191_signing_hash("hello");
        let h2 = eip191_signing_hash("hello");
        let h3 = eip191_signing_hash("world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn iso_timestamp_format() {
        // 2024-01-01T00:00:00.000Z = 1704067200000 ms
        let iso = ms_to_iso(1_704_067_200_000);
        assert_eq!(iso, "2024-01-01T00:00:00.000Z");
    }

    #[test]
    fn iso_timestamp_with_fractional() {
        // 2024-06-15T12:30:45.123Z = 1718454645123 ms
        let iso = ms_to_iso(1_718_454_645_123);
        assert_eq!(iso, "2024-06-15T12:30:45.123Z");
    }

    #[test]
    fn session_creation_and_caching() {
        let mut host = MockHost {
            now_ms: 1_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature()));

        let wallet = "0xwallet1";
        let address = "0x1234567890abcdef1234567890abcdef12345678";

        // First call creates a session.
        let session = get_or_create_session(&mut host, wallet, address).unwrap();
        assert_eq!(session.address, address);
        assert!(!session.header_b64.is_empty());
        assert_eq!(host.sign_requests.len(), 1);

        // Second call (same time) reuses cached session — no new sign.
        let session2 = get_or_create_session(&mut host, wallet, address).unwrap();
        assert_eq!(session2.header_b64, session.header_b64);
        assert_eq!(host.sign_requests.len(), 1);
    }

    #[test]
    fn session_expires_after_ttl() {
        let mut host = MockHost {
            now_ms: 1_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature()));
        host.sign_results.push_back(Ok(signature()));

        let wallet = "0xwallet2";
        let address = "0x1234567890abcdef1234567890abcdef12345678";

        // Create session.
        let _ = get_or_create_session(&mut host, wallet, address).unwrap();
        assert_eq!(host.sign_requests.len(), 1);

        // Advance past renewal threshold.
        host.now_ms = 1_000_000 + (SIWE_RENEWAL_SECS + 1) * 1000;

        // Should create new session.
        let _ = get_or_create_session(&mut host, wallet, address).unwrap();
        assert_eq!(host.sign_requests.len(), 2);
    }
}
