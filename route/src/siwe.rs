//! Sign-In-With-Ethereum (EIP-4361) message construction and EIP-191 hashing.
//!
//! Venice expects a Base64-encoded JSON payload in the `X-Sign-In-With-X`
//! header containing a signed SIWE message. The message follows EIP-4361
//! with a fixed statement and 5-minute expiry.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::common::{
    self, CHAIN_ID, DispatchResponse, Host, MAX_STORED, SIWE_RENEWAL_SECS, SIWE_STATEMENT,
    SIWE_TTL_SECS, VENICE_DOMAIN,
};

/// Parameters for constructing a SIWE message.
pub(crate) struct SiweParams {
    pub address: String,
    pub uri: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingSiwe {
    address: String,
    resource_url: String,
    message: String,
    created_ms: u64,
    approval_action_id: Option<String>,
    approval_expires_ms: Option<u64>,
}

/// The decoded SIWE header payload (Base64-decoded JSON).
///
/// Field names match Venice's canonical x402 client wire format
/// (`chainId`, camelCase); `message` and `signature` are the EIP-191 pair
/// Venice verifies, the remaining fields are advisory.
#[derive(Clone, Debug, Serialize)]
struct SiweHeaderPayload {
    address: String,
    message: String,
    signature: String,
    timestamp: u64,
    #[serde(rename = "chainId")]
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
/// URI: <resource URL the session is bound to>
/// Version: 1
/// Chain ID: 8453
/// Nonce: <hex>
/// Issued At: <ISO 8601>
/// Expiration Time: <ISO 8601>
/// ```
pub(crate) fn format_message(params: &SiweParams) -> String {
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
        uri = params.uri,
        chain_id = CHAIN_ID,
        nonce = params.nonce,
        issued_at = params.issued_at_iso,
        expiration = params.expiration_iso,
    )
}

/// Compute the EIP-191 personal-message signing hash:
/// `keccak256("\x19Ethereum Signed Message:\n" + len + message)`.
#[cfg(test)]
pub(crate) fn eip191_signing_hash(message: &str) -> [u8; 32] {
    let preimage = eip191_signing_preimage(message);
    Keccak256::digest(preimage).into()
}

pub(crate) fn eip191_signing_preimage(message: &str) -> Vec<u8> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut preimage = Vec::with_capacity(prefix.len() + message.len());
    preimage.extend_from_slice(prefix.as_bytes());
    preimage.extend_from_slice(message.as_bytes());
    preimage
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

/// Get a valid SIWE session for `wallet` bound to `resource_url`, creating a
/// new one if needed.
///
/// The SIWE `URI` is bound to the resource URL (matching Venice's canonical
/// x402 client, which signs per-request with the actual endpoint URL).
/// Sessions are cached per `(wallet, resource_url)` in the secrets store and
/// reused while they have more than `SIWE_RENEWAL_SECS` seconds of validity
/// remaining. This keeps the URI correct per endpoint without forcing a fresh
/// wallet signature on every request.
pub(crate) fn get_or_create_session(
    host: &mut impl Host,
    wallet: &str,
    address: &str,
    resource_url: &str,
    operation_class: &str,
) -> Result<SiweSession, DispatchResponse> {
    let key = session_key(wallet, resource_url);

    // Try to load and validate an existing session.
    if let Some(session) = load_cached_session(host, &key)? {
        return Ok(session);
    }

    let now_ms = host.now_ms().map_err(common::backend)?;
    let pending_key = pending_session_key(wallet, resource_url);
    let existing_pending = load_pending_session(host, &pending_key)?;
    let mut pending = match existing_pending {
        Some(pending)
            if pending.address.eq_ignore_ascii_case(address)
                && pending.resource_url == resource_url
                && now_ms.saturating_sub(pending.created_ms) < SIWE_RENEWAL_SECS * 1000 =>
        {
            pending
        }
        _ => {
            let nonce = generate_nonce(host).map_err(common::backend)?;
            let message = format_message(&SiweParams {
                address: address.to_owned(),
                uri: resource_url.to_owned(),
                nonce,
                issued_at_iso: ms_to_iso(now_ms),
                expiration_iso: ms_to_iso(now_ms + SIWE_TTL_SECS * 1000),
            });
            let pending = PendingSiwe {
                address: address.to_owned(),
                resource_url: resource_url.to_owned(),
                message,
                created_ms: now_ms,
                approval_action_id: None,
                approval_expires_ms: None,
            };
            save_pending_session(host, &pending_key, &pending)?;
            pending
        }
    };
    let message = pending.message.clone();

    let preimage = eip191_signing_preimage(&message);
    let hash = Keccak256::digest(&preimage).into();
    let outcome = common::request_payload_signature(
        host,
        wallet,
        preimage,
        hash,
        operation_class,
        pending
            .approval_expires_ms
            .is_some_and(|expires_ms| expires_ms > now_ms)
            .then(|| pending.approval_action_id.clone())
            .flatten(),
        Some(message.as_bytes().to_vec()),
    )
    .map_err(common::backend)?;

    let signature = match outcome {
        petal::SignOutcome::Signature(bytes) => {
            common::signature_hex(bytes).map_err(common::backend)?
        }
        petal::SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        } => {
            pending.approval_action_id = Some(action_id.clone());
            pending.approval_expires_ms = Some(expires_ms);
            save_pending_session(host, &pending_key, &pending)?;
            return Err(petal::error(
                -2,
                format!(
                    "SIWE approval required for action {action_id}; open the owner-visible Bloom signing request, approve it, then retry the exact write"
                ),
            ));
        }
    };

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
    host.store_del(&pending_key).map_err(common::backend)?;

    Ok(session)
}

fn load_pending_session(
    host: &mut impl Host,
    key: &str,
) -> Result<Option<PendingSiwe>, DispatchResponse> {
    let Some(bytes) = host.store_get(key, MAX_STORED).map_err(common::backend)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        common::backend(format!("stored pending SIWE request is invalid: {error}"))
    })
}

fn save_pending_session(
    host: &mut impl Host,
    key: &str,
    pending: &PendingSiwe,
) -> Result<(), DispatchResponse> {
    let bytes = serde_json::to_vec(pending)
        .map_err(|error| common::backend(format!("serialize pending SIWE request: {error}")))?;
    host.store_put(key, &bytes, true).map_err(common::backend)
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

fn session_key(wallet: &str, resource_url: &str) -> String {
    // Bucket the cached session by resource URL so each endpoint (balance,
    // chat, ...) gets its own correctly URI-bound session. Keccak256 is
    // available in-module; a short digest is plenty for endpoint bucketing.
    let mut hasher = Keccak256::new();
    hasher.update(resource_url.as_bytes());
    let slug = hex::encode(&hasher.finalize()[..8]);
    format!("venice-x402/sessions/{wallet}/{slug}")
}

fn pending_session_key(wallet: &str, resource_url: &str) -> String {
    format!("{}.pending", session_key(wallet, resource_url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::*;

    #[test]
    fn siwe_message_format() {
        let params = SiweParams {
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            uri: "https://api.venice.ai/api/v1/chat/completions".into(),
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
    fn format_message_matches_canonical_siwe_library() {
        // Byte-identical to what the `siwe` npm library (which Venice's x402
        // client imports) produces via `prepareMessage()` for the same inputs.
        let petal = format_message(&SiweParams {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            uri: "https://api.venice.ai/api/v1/chat/completions".into(),
            nonce: "0xabc123".into(),
            issued_at_iso: "2024-01-01T00:00:00.000Z".into(),
            expiration_iso: "2024-01-01T00:05:00.000Z".into(),
        });
        let canonical = "api.venice.ai wants you to sign in with your Ethereum account:\n\
             0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n\
             \n\
             Sign in to Venice AI\n\
             \n\
             URI: https://api.venice.ai/api/v1/chat/completions\n\
             Version: 1\n\
             Chain ID: 8453\n\
             Nonce: 0xabc123\n\
             Issued At: 2024-01-01T00:00:00.000Z\n\
             Expiration Time: 2024-01-01T00:05:00.000Z";
        assert_eq!(petal, canonical);
    }

    #[test]
    fn eip191_hash_matches_viem_reference_vector() {
        // viem `hashMessage` for the canonical SIWE string above. Venice
        // verifies the SIWE signature by ecrecover over this prehash; equality
        // here ⟹ the petal signs exactly the prehash Venice will reconstruct.
        let message = "api.venice.ai wants you to sign in with your Ethereum account:\n\
             0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n\
             \n\
             Sign in to Venice AI\n\
             \n\
             URI: https://api.venice.ai/api/v1/chat/completions\n\
             Version: 1\n\
             Chain ID: 8453\n\
             Nonce: 0xabc123\n\
             Issued At: 2024-01-01T00:00:00.000Z\n\
             Expiration Time: 2024-01-01T00:05:00.000Z";
        let hash = eip191_signing_hash(message);
        let expected =
            hex::decode("768958987d01dfcfab498d155bebf322a44bcf1f85ede5e2f0a2f6894e252624")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
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
        let url = "https://api.venice.ai/api/v1/chat/completions";

        // First call creates a session.
        let session =
            get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").unwrap();
        assert_eq!(session.address, address);
        assert!(!session.header_b64.is_empty());
        assert_eq!(host.sign_requests.len(), 1);

        // Second call (same time) reuses cached session — no new sign.
        let session2 =
            get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").unwrap();
        assert_eq!(session2.header_b64, session.header_b64);
        assert_eq!(host.sign_requests.len(), 1);
    }

    #[test]
    fn approval_retry_reuses_identical_siwe_payload_and_hint() {
        let mut host = MockHost {
            now_ms: 1_000_000,
            ..Default::default()
        };
        host.random_data.push_back(test_nonce());
        host.sign_results.push_back(Ok(approval()));
        host.sign_results.push_back(Ok(signature()));

        let wallet = "minnow-passkey";
        let address = "0x1234567890abcdef1234567890abcdef12345678";
        let url = "https://api.venice.ai/api/v1/chat/completions";
        assert!(
            get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").is_err()
        );
        let session =
            get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").unwrap();

        assert!(!session.header_b64.is_empty());
        assert_eq!(host.sign_requests.len(), 2);
        assert_eq!(
            host.sign_requests[0].preimage,
            host.sign_requests[1].preimage
        );
        assert_eq!(
            host.sign_requests[0].claimed_hash,
            host.sign_requests[1].claimed_hash
        );
        assert_eq!(
            host.sign_requests[1].approval_hint.as_deref(),
            Some("approval-1")
        );
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
        let url = "https://api.venice.ai/api/v1/chat/completions";

        // Create session.
        let _ = get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").unwrap();
        assert_eq!(host.sign_requests.len(), 1);

        // Advance past renewal threshold.
        host.now_ms = 1_000_000 + (SIWE_RENEWAL_SECS + 1) * 1000;

        // Should create new session.
        let _ = get_or_create_session(&mut host, wallet, address, url, "venice-x402.chat").unwrap();
        assert_eq!(host.sign_requests.len(), 2);
    }

    #[test]
    fn session_is_cached_per_resource_url() {
        // Each endpoint must get its own URI-bound session: a balance URL and
        // a chat URL produce separate sessions (separate signs), and each is
        // then reused. This matches Venice's per-request URI binding.
        let mut host = MockHost {
            now_ms: 1_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature()));
        host.sign_results.push_back(Ok(signature()));

        let wallet = "0xwallet3";
        let address = "0x1234567890abcdef1234567890abcdef12345678";
        let chat_url = "https://api.venice.ai/api/v1/chat/completions";
        let balance_url = "https://api.venice.ai/api/v1/x402/balance/0x1234";

        let chat_session =
            get_or_create_session(&mut host, wallet, address, chat_url, "venice-x402.chat")
                .unwrap();
        let balance_session = get_or_create_session(
            &mut host,
            wallet,
            address,
            balance_url,
            "venice-x402.balance",
        )
        .unwrap();

        // Different endpoints => different sessions (different messages/URIs).
        assert_ne!(chat_session.header_b64, balance_session.header_b64);
        assert!(chat_session.message.contains("/chat/completions"));
        assert!(balance_session.message.contains("/x402/balance/"));
        assert_eq!(host.sign_requests.len(), 2);

        // Reusing the same endpoint does not re-sign.
        let _ = get_or_create_session(&mut host, wallet, address, chat_url, "venice-x402.chat")
            .unwrap();
        assert_eq!(host.sign_requests.len(), 2);
    }

    #[test]
    fn siwe_header_payload_uses_camel_case_chainid() {
        // Wire-format check: Venice's canonical x402 client serializes the
        // SIWE header payload with `chainId` (camelCase), not `chain_id`.
        let payload = SiweHeaderPayload {
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            message: "m".into(),
            signature: "0x...".into(),
            timestamp: 1,
            chain_id: CHAIN_ID,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"chainId\":8453"), "got: {json}");
        assert!(!json.contains("chain_id"), "got: {json}");
    }
}
