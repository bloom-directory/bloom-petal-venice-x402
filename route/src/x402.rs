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

use crate::common::{self, CHAIN_ID, DispatchResponse, Host, USDC_BASE, USDC_NAME, USDC_VERSION};

/// One accepted payment option from a 402 response.
///
/// Field names deserialize from the x402 `accepts` entries (camelCase per
/// spec): `payTo`, `maxTimeoutSeconds`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PaymentRequirement {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    pub amount: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    #[serde(default = "empty_object")]
    pub extra: serde_json::Value,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

/// The 402 response body from Venice.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PaymentRequired {
    #[serde(rename = "x402Version")]
    pub x402_version: u64,
    #[serde(default)]
    pub error: Option<String>,
    pub accepts: Vec<PaymentRequirement>,
}

/// The EIP-3009 authorization struct.
///
/// Field names serialize to the x402 wire format (camelCase) per the
/// `exact`/EVM scheme spec — the facilitator validates against a strict
/// schema that requires `validAfter` / `validBefore`.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    #[serde(rename = "validAfter")]
    pub valid_after: String,
    #[serde(rename = "validBefore")]
    pub valid_before: String,
    pub nonce: String,
}

/// The complete payment payload (pre-encoding).
///
/// Wire field names match the x402 `PaymentPayload` schema (`x402Version`,
/// camelCase). `scheme` and `network` live at the top level alongside
/// `x402Version` and `payload`, matching the canonical client.
#[derive(Clone, Debug, Serialize)]
struct PaymentPayload {
    #[serde(rename = "x402Version")]
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
        // `chainId` is a JSON number (EIP-712 domain types it as uint256).
        // Passing a string risks an encoding mismatch with the contract's own
        // domain separator, which would make the signature fail ecrecover.
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
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
/// USDC on Base (EIP-3009). Venice sends networks as CAIP-2 IDs
/// (`eip155:8453` for Base mainnet); `is_base_mainnet` mirrors the canonical
/// Venice x402 client's `normalizePaymentNetwork`, and the `asset` check
/// pins native USDC on Base.
pub(crate) fn extract_base_requirement(
    required: &PaymentRequired,
) -> Result<&PaymentRequirement, DispatchResponse> {
    required
        .accepts
        .iter()
        .find(|req| is_base_mainnet(&req.network) && req.asset.eq_ignore_ascii_case(USDC_BASE))
        .ok_or_else(|| {
            common::backend(
                "Venice 402 response did not include a USDC-on-Base payment option; \
                 only EIP-3009 USDC on Base is supported",
            )
        })
}

/// Returns true for a Base mainnet network identifier. Mirrors Venice's
/// canonical x402 client (`normalizePaymentNetwork`): Sepolia variants are
/// excluded, everything else is treated as Base mainnet. The asset check in
/// the caller pins native USDC, so Solana/Sepolia options are filtered there.
fn is_base_mainnet(network: &str) -> bool {
    let n = network.trim().to_ascii_lowercase();
    !(n == "base-sepolia" || n == "eip155:84532")
}

/// Build and sign an x402 payment header for a top-up.
///
/// `amount_base_units` is the caller-chosen USDC amount in base units (6
/// decimals) — this is the value actually transferred on-chain. It must be at
/// least the minimum Venice quoted in the 402 response
/// (`requirement.amount`). `x402_version` is the protocol version negotiated
/// in the 402 response, not a hardcoded constant.
///
/// Returns the Base64-encoded `X-402-Payment` header value.
pub(crate) fn build_payment_header(
    host: &mut impl Host,
    wallet: &str,
    from_address: &str,
    requirement: &PaymentRequirement,
    amount_base_units: &str,
    x402_version: u64,
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
        value: amount_base_units.to_owned(),
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
            purpose: "venice-x402.topup".into(),
        })
        .map_err(common::backend)?;

    let signature = common::require_signature(outcome, "x402 payment authorization")?;

    // Build and encode the payment payload.
    let payload = PaymentPayload {
        x402_version,
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
            // Venice sends CAIP-2 mainnet IDs; Base is `eip155:8453`.
            network: "eip155:8453".into(),
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
    fn eip712_hash_matches_viem_reference_vector() {
        // Known vector produced by viem (`hashTypedData`) — the same library
        // Venice's x402 client uses to build the signature the USDC contract
        // accepts via `transferWithAuthorization`. The facilitator passes the
        //authorization to the contract, which recomputes this exact hash and
        // runs ecrecover. Equality here ⟹ the petal's hash == the contract's
        // hash ⟹ any signature over it (including one from bloom:sign) is
        // accepted.
        let auth = Eip3009Authorization {
            from: "0x857b06519E91e3A54538791bDbb0E22373e36b66".into(),
            to: "0x2670B922ef37C7Df47158725C0CC407b5382293F".into(),
            value: "5000000".into(),
            valid_after: "1700000000".into(),
            valid_before: "1700000300".into(),
            nonce: "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480".into(),
        };
        let hash =
            eip712_signing_hash(&auth, CHAIN_ID, USDC_BASE, USDC_NAME, USDC_VERSION).unwrap();
        let expected =
            hex::decode("0ec54d91e69b70ffed5015f83301ca356cc3763c6572e1ce8f5cb6a2dce7d5fd")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn extract_base_requirement_succeeds() {
        let required = PaymentRequired {
            x402_version: 2,
            error: Some("Payment required".into()),
            accepts: vec![
                PaymentRequirement {
                    scheme: "exact".into(),
                    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
                    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                    amount: "5000000".into(),
                    pay_to: "8qUL23aSj7mDWdoLMXGHFvnVCT9wd7jXcysiekroADEL".into(),
                    max_timeout_seconds: 300,
                    extra: json!({"name": "USD Coin", "version": "2", "feePayer": "..."}),
                },
                base_requirement(),
            ],
        };

        let result = extract_base_requirement(&required);
        assert!(result.is_ok());
        // Returns the Base mainnet option (CAIP-2 eip155:8453), not Solana.
        assert_eq!(result.unwrap().network, "eip155:8453");
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
    fn parses_realistic_venice_402_body() {
        // The EXACT shape Venice returns live (captured via curl against
        // api.venice.ai): camelCase keys, CAIP-2 networks (`eip155:8453` for
        // Base mainnet, `solana:5eykt4...` for Solana), Solana carrying an
        // optional `feePayer`. A regression to snake_case or to matching
        // `network == "base"` would silently break the whole top-up flow.
        let body = serde_json::to_vec(&json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "amount": "5000000",
                "payTo": "0x2670b922ef37c7df47158725c0cc407b5382293f",
                "maxTimeoutSeconds": 300,
                "extra": {"name": "USD Coin", "version": "2"}
            }, {
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "amount": "5000000",
                "payTo": "8qUL23aSj7mDWdoLMXGHFvnVCT9wd7jXcysiekroADEL",
                "maxTimeoutSeconds": 300,
                "extra": {"name": "USD Coin", "version": "2", "feePayer": "BFK9TLC3edb13K6v4YyH3DwPb5DSUpkWvb7XnqCL9b4F"}
            }]
        }))
        .unwrap();
        let required: PaymentRequired = serde_json::from_slice(&body).unwrap();
        assert_eq!(required.x402_version, 2);
        assert_eq!(required.accepts.len(), 2);
        let base = extract_base_requirement(&required).unwrap();
        assert_eq!(base.network, "eip155:8453");
        assert_eq!(base.pay_to, "0x2670b922ef37c7df47158725c0cc407b5382293f");
        assert_eq!(base.max_timeout_seconds, 300);
    }

    #[test]
    fn payment_header_builds_and_signs() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        // The caller pays $10 (10,000,000 base units), above Venice's $5 minimum.
        let header = build_payment_header(
            &mut host,
            WALLET,
            ADDRESS,
            &requirement,
            "10000000",
            2,
            1_000_000,
        )
        .unwrap();

        // Should be valid base64.
        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(payload["x402Version"], 2);
        assert_eq!(payload["scheme"], "exact");
        assert_eq!(payload["network"], "eip155:8453");
        assert_eq!(payload["payload"]["authorization"]["from"], ADDRESS);
        assert_eq!(payload["payload"]["authorization"]["to"], VENICE_PAYEE);
        // The paid value is the CALLER's amount, not the requirement minimum.
        assert_eq!(payload["payload"]["authorization"]["value"], "10000000");
        assert!(
            payload["payload"]["signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );

        // Should have signed exactly once.
        assert_eq!(host.sign_requests.len(), 1);
        assert_eq!(host.sign_requests[0].purpose, "venice-x402.topup");
    }

    #[test]
    fn payment_header_uses_caller_amount_not_requirement_minimum() {
        // Lock in the Venice x402 semantics: requirement.amount is the MINIMUM
        // (here $1 = 1,000,000 base units); the caller may pay more (here $7).
        // The EIP-3009 `value` and on-chain transfer must equal the caller's
        // amount, and `to`/`asset` must come from the requirement.
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let mut requirement = base_requirement();
        requirement.amount = "1000000".into(); // $1 minimum

        let header = build_payment_header(
            &mut host,
            WALLET,
            ADDRESS,
            &requirement,
            "7000000",
            2,
            1_000_000,
        )
        .unwrap();

        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(payload["payload"]["authorization"]["value"], "7000000");
        assert_eq!(payload["payload"]["authorization"]["to"], VENICE_PAYEE);
    }

    #[test]
    fn payment_header_passes_through_negotiated_version() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        let header = build_payment_header(
            &mut host,
            WALLET,
            ADDRESS,
            &requirement,
            "5000000",
            3,
            1_000_000,
        )
        .unwrap();

        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(payload["x402Version"], 3);
    }

    #[test]
    fn payment_header_propagates_approval() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(approval()));

        let requirement = base_requirement();
        let result = build_payment_header(
            &mut host,
            WALLET,
            ADDRESS,
            &requirement,
            "5000000",
            2,
            1_000_000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn valid_before_includes_timeout() {
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        let now = 1_000_000_u64;
        let header =
            build_payment_header(&mut host, WALLET, ADDRESS, &requirement, "5000000", 2, now)
                .unwrap();

        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();

        let valid_before: u64 = payload["payload"]["authorization"]["validBefore"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(valid_before, now + 300); // max_timeout_seconds = 300

        let valid_after: u64 = payload["payload"]["authorization"]["validAfter"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(valid_after, now - 600); // 10 min before
    }

    #[test]
    fn payment_header_wire_keys_match_x402_spec() {
        // The facilitator validates the X-402-Payment header against a strict
        // zod schema requiring camelCase keys: x402Version / validAfter /
        // validBefore. Snake_case would be silently rejected. This test pins
        // the exact on-the-wire object shape.
        let mut host = MockHost::default();
        host.sign_results.push_back(Ok(signature()));

        let requirement = base_requirement();
        let header = build_payment_header(
            &mut host,
            WALLET,
            ADDRESS,
            &requirement,
            "5000000",
            2,
            1_000_000,
        )
        .unwrap();

        let decoded = decode_base64(&header).unwrap();
        let payload: Value = serde_json::from_slice(&decoded).unwrap();

        // Top-level canonical keys.
        assert_eq!(payload["x402Version"], 2);
        assert_eq!(payload["scheme"], "exact");
        assert_eq!(payload["network"], "eip155:8453");
        // No snake_case leakage anywhere in the wire object.
        let wire = serde_json::to_string(&payload).unwrap();
        assert!(
            !wire.contains("x402_version"),
            "wire leaked x402_version: {wire}"
        );
        assert!(
            !wire.contains("valid_after"),
            "wire leaked valid_after: {wire}"
        );
        assert!(
            !wire.contains("valid_before"),
            "wire leaked valid_before: {wire}"
        );

        // Authorization keys.
        let auth = &payload["payload"]["authorization"];
        assert_eq!(auth["from"], ADDRESS);
        assert_eq!(auth["to"], VENICE_PAYEE);
        assert_eq!(auth["value"], "5000000");
        assert!(auth["validAfter"].is_string());
        assert!(auth["validBefore"].is_string());
        assert!(auth["nonce"].as_str().unwrap().starts_with("0x"));
        assert!(
            payload["payload"]["signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }
}
