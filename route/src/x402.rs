//! x402 payment header construction using EIP-3009 `TransferWithAuthorization`.
//!
//! When Venice returns HTTP 402, the response body contains an `accepts` array
//! with payment requirements (asset, payTo, amount, etc.). We build an
//! EIP-3009 authorization, sign it via EIP-712, and encode the result as a
//! Base64 JSON string for the `X-402-Payment` header.

use alloy_dyn_abi::eip712::TypedData;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::common::{
    self, CHAIN_ID, DispatchResponse, Host, USDC_BASE, USDC_NAME, USDC_VERSION, X402_VERSION,
};

/// One accepted payment option from a 402 response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PaymentRequirement {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    pub amount: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: serde_json::Value,
}

/// The 402 response body from Venice.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default)]
    pub error: Option<String>,
    pub accepts: Vec<PaymentRequirement>,
}

/// The EIP-3009 authorization struct.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

/// The complete payment payload (pre-encoding).
#[derive(Clone, Debug, Serialize)]
struct PaymentPayload {
    x402_version: u64,
    scheme: String,
    network: String,
    payload: PaymentPayloadInner,
}

#[derive(Clone, Debug, Serialize)]
struct PaymentPayloadInner {
    signature: String,
    authorization: Eip3009Authorization,
}

/// EIP-712 type definitions for `TransferWithAuthorization`.
fn authorization_types() -> Value {
    json!({
        "TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"}
        ]
    })
}

/// Compute the EIP-712 signing hash for an EIP-3009 authorization.
///
/// Uses `alloy_dyn_abi::eip712::TypedData` to ensure the hash matches what
/// EVM wallets produce with `signTypedData`.
pub(crate) fn eip712_signing_hash(
    auth: &Eip3009Authorization,
    chain_id: u64,
    verifying_contract: &str,
    token_name: &str,
    token_version: &str,
) -> Result<[u8; 32], String> {
    let mut types = Map::new();
    types.insert(
        "EIP712Domain".into(),
        json!([
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
        ]),
    );
    types.insert(
        "TransferWithAuthorization".into(),
        authorization_types()["TransferWithAuthorization"].clone(),
    );

    let typed: TypedData = serde_json::from_value(json!({
        "types": types,
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id.to_string(),
            "verifyingContract": verifying_contract
        },
        "message": {
            "from": auth.from,
            "to": auth.to,
            "value": auth.value,
            "validAfter": auth.valid_after,
            "validBefore": auth.valid_before,
            "nonce": auth.nonce
        }
    }))
    .map_err(|e| format!("invalid EIP-712 typed data: {e}"))?;

    let hash: B256 = typed
        .eip712_signing_hash()
        .map_err(|e| format!("cannot hash EIP-712 typed data: {e}"))?;

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    Ok(result)
}

/// Extract a USDC-on-Base payment requirement from a 402 response.
///
/// Venice supports multiple payment options (Base, Solana). We only support
/// USDC on Base (EIP-3009).
pub(crate) fn extract_base_requirement(
    required: &PaymentRequired,
) -> Result<&PaymentRequirement, DispatchResponse> {
    required
        .accepts
        .iter()
        .find(|req| req.network == "base" && req.asset.eq_ignore_ascii_case(USDC_BASE))
        .ok_or_else(|| {
            common::backend(
                "Venice 402 response did not include a USDC-on-Base payment option; \
                 only EIP-3009 USDC on Base is supported",
            )
        })
}

/// Build and sign an x402 payment header for a top-up.
///
/// Returns the Base64-encoded `X-402-Payment` header value.
pub(crate) fn build_payment_header(
    host: &mut impl Host,
    wallet: &str,
    from_address: &str,
    requirement: &PaymentRequirement,
    now_secs: u64,
) -> Result<String, DispatchResponse> {
    // Generate a random 32-byte nonce.
    let nonce_bytes = host.random_bytes(32).map_err(common::backend)?;
    let nonce = format!("0x{}", hex::encode(&nonce_bytes));

    // Build the authorization.
    // valid_after: 10 minutes in the past (tolerate clock skew).
    // valid_before: now + max_timeout_seconds from the requirement.
    let valid_after = now_secs.saturating_sub(600);
    let valid_before = now_secs + requirement.max_timeout_seconds;

    let auth = Eip3009Authorization {
        from: from_address.to_owned(),
        to: requirement.pay_to.clone(),
        value: requirement.amount.clone(),
        valid_after: valid_after.to_string(),
        valid_before: valid_before.to_string(),
        nonce,
    };

    // Extract token name/version from the requirement's extra field.
    let token_name = requirement
        .extra
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(USDC_NAME);
    let token_version = requirement
        .extra
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or(USDC_VERSION);

    // Compute the EIP-712 signing hash.
    let hash = eip712_signing_hash(
        &auth,
        CHAIN_ID,
        &requirement.asset,
        token_name,
        token_version,
    )
    .map_err(common::backend)?;

    // Sign via Bloom.
    let outcome = host
        .sign_hash(&petal::SignRequest {
            wallet: wallet.to_owned(),
            hash32: hash,
            purpose: "venice.x402".into(),
        })
        .map_err(common::backend)?;

    let signature = common::require_signature(outcome, "x402 payment authorization")?;

    // Build and encode the payment payload.
    let payload = PaymentPayload {
        x402_version: u64::from(X402_VERSION),
        scheme: requirement.scheme.clone(),
        network: requirement.network.clone(),
        payload: PaymentPayloadInner {
            signature,
            authorization: auth,
        },
    };

    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| common::backend(format!("serialize payment: {e}")))?;

    Ok(common::encode_base64(&payload_json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::VENICE_PAYEE;
    use crate::common::test_helpers::decode_base64;
    use crate::common::test_helpers::*;

    const WALLET: &str = "0xwallet1";
    const ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";

    fn base_requirement() -> PaymentRequirement {
        PaymentRequirement {
            scheme: "exact".into(),
            network: "base".into(),
            asset: USDC_BASE.into(),
            amount: "5000000".into(),
            pay_to: VENICE_PAYEE.into(),
            max_timeout_seconds: 300,
            extra: json!({"name": "USD Coin", "version": "2"}),
        }
    }

    #[test]
    fn eip712_hash_is_deterministic() {
        let auth = Eip3009Authorization {
            from: ADDRESS.into(),
            to: VENICE_PAYEE.into(),
            value: "5000000".into(),
            valid_after: "1000".into(),
            valid_before: "2000".into(),
            nonce: format!("0x{}", hex::encode(test_nonce())),
        };

        let h1 = eip712_signing_hash(&auth, CHAIN_ID, USDC_BASE, USDC_NAME, USDC_VERSION).unwrap();
        let h2 = eip712_signing_hash(&auth, CHAIN_ID, USDC_BASE, USDC_NAME, USDC_VERSION).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn eip712_hash_varies_by_nonce() {
        let auth1 = Eip3009Authorization {
            from: ADDRESS.into(),
            to: VENICE_PAYEE.into(),
            value: "5000000".into(),
            valid_after: "1000".into(),
            valid_before: "2000".into(),
            nonce: format!("0x{}", hex::encode(test_nonce())),
        };
        let auth2 = Eip3009Authorization {
            nonce: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            from: auth1.from.clone(),
            to: auth1.to.clone(),
            value: auth1.value.clone(),
            valid_after: auth1.valid_after.clone(),
            valid_before: auth1.valid_before.clone(),
        };

        let h1 = eip712_signing_hash(&auth1, CHAIN_ID, USDC_BASE, USDC_NAME, USDC_VERSION).unwrap();
        let h2 = eip712_signing_hash(&auth2, CHAIN_ID, USDC_BASE, USDC_NAME, USDC_VERSION).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn extract_base_requirement_succeeds() {
        let required = PaymentRequired {
            x402_version: 2,
            error: Some("Payment required".into()),
            accepts: vec![
                PaymentRequirement {
                    scheme: "exact".into(),
                    network: "solana".into(),
                    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                    amount: "5000000".into(),
                    pay_to: "solana_address".into(),
                    max_timeout_seconds: 300,
                    extra: json!({}),
                },
                base_requirement(),
            ],
        };

        let result = extract_base_requirement(&required);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().network, "base");
    }

    #[test]
    fn extract_base_requirement_fails_without_base() {
        let required = PaymentRequired {
            x402_version: 2,
            error: None,
            accepts: vec![],
        };
        assert!(extract_base_requirement(&required).is_err());
    }

    #[test]
    fn payment_header_builds_and_signs() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        let header =
            build_payment_header(&mut host, WALLET, ADDRESS, &requirement, 1_000_000).unwrap();

        // Should be valid base64.
        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(payload["x402_version"], 2);
        assert_eq!(payload["scheme"], "exact");
        assert_eq!(payload["network"], "base");
        assert_eq!(payload["payload"]["authorization"]["from"], ADDRESS);
        assert_eq!(payload["payload"]["authorization"]["to"], VENICE_PAYEE);
        assert_eq!(payload["payload"]["authorization"]["value"], "5000000");
        assert!(
            payload["payload"]["signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );

        // Should have signed exactly once.
        assert_eq!(host.sign_requests.len(), 1);
        assert_eq!(host.sign_requests[0].purpose, "venice.x402");
    }

    #[test]
    fn payment_header_propagates_approval() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(approval()));

        let requirement = base_requirement();
        let result = build_payment_header(&mut host, WALLET, ADDRESS, &requirement, 1_000_000);

        assert!(result.is_err());
    }

    #[test]
    fn valid_before_includes_timeout() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        let now = 1_000_000_u64;
        let header = build_payment_header(&mut host, WALLET, ADDRESS, &requirement, now).unwrap();

        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();

        let valid_before: u64 = payload["payload"]["authorization"]["valid_before"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(valid_before, now + 300); // max_timeout_seconds = 300

        let valid_after: u64 = payload["payload"]["authorization"]["valid_after"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(valid_after, now - 600); // 10 min before
    }
}
