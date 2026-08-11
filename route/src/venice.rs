//! Venice HTTP API client: models, balance, chat completions, top-up.
//!
//! All HTTP calls go through the `Host` trait so tests can inject mocks.
//! SIWE auth and x402 payment headers are added per-request.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::common::{self, DispatchResponse, Host, MAX_BODY, VENICE_API};
use crate::siwe;
use crate::types::{BalanceView, ChatRequest};
use crate::x402;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingTopUp {
    wallet: String,
    address: String,
    amount_base_units: String,
    prepared: x402::PreparedPayment,
    approval_action_id: Option<String>,
    approval_expires_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Low-level HTTP helpers
// ---------------------------------------------------------------------------

/// Build and execute an authenticated GET request to Venice.
fn authed_get<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
    path: &str,
) -> Result<Value, DispatchResponse> {
    let url = format!("{VENICE_API}{path}");
    let session = siwe::get_or_create_session(host, wallet, address, &url, "venice-x402.balance")?;
    let request = petal::HttpRequest {
        method: "GET".into(),
        url,
        headers: vec![
            ("accept".into(), "application/json".into()),
            ("X-Sign-In-With-X".into(), session.header_b64.clone()),
        ],
        body: Vec::new(),
    };
    let response = host
        .http_fetch(&request, MAX_BODY)
        .map_err(common::backend)?;
    interpret_response(response)
}

/// Extract the `X-Balance-Remaining` header from a response.
pub(crate) fn extract_balance_remaining(response: &petal::HttpResponse) -> Option<String> {
    response.headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("x-balance-remaining") {
            Some(v.clone())
        } else {
            None
        }
    })
}

/// Interpret an HTTP response: 2xx → parsed JSON value, 402 → special handling,
/// other → error.
fn interpret_response(response: petal::HttpResponse) -> Result<Value, DispatchResponse> {
    let status = response.status;
    if (200..300).contains(&status) {
        return common::parse_json_body(&response).map_err(common::backend);
    }
    if status == 402 {
        let body = common::parse_json_body(&response).unwrap_or(Value::Null);
        return Err(common::backend(
            serde_json::to_string(&json!({
                "status": "insufficient_balance",
                "message": "Venice returned 402 Payment Required. Top up balance first.",
                "venice_response": body,
            }))
            .unwrap_or_else(|_| "insufficient balance".into()),
        ));
    }
    if status == 401 {
        return Err(common::backend(
            "Venice returned 401: SIWE session is invalid or expired. Retry the request.",
        ));
    }
    let body = common::parse_json_body(&response).unwrap_or(Value::Null);
    Err(common::backend(
        serde_json::to_string(&json!({
            "status": "venice_error",
            "status_code": status,
            "body": body,
        }))
        .unwrap_or_else(|_| format!("Venice API error: HTTP {status}")),
    ))
}

// ---------------------------------------------------------------------------
// Public API operations
// ---------------------------------------------------------------------------

/// Fetch the list of available Venice models (no auth required).
pub(crate) fn list_models<H: Host>(host: &mut H) -> Result<Value, DispatchResponse> {
    let request = petal::HttpRequest {
        method: "GET".into(),
        url: format!("{VENICE_API}/models"),
        headers: vec![("accept".into(), "application/json".into())],
        body: Vec::new(),
    };
    let response = host
        .http_fetch(&request, MAX_BODY)
        .map_err(common::backend)?;
    interpret_response(response)
}

/// Check the x402 wallet balance.
pub(crate) fn check_balance<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
) -> Result<BalanceView, DispatchResponse> {
    let value = authed_get(host, wallet, address, &format!("/x402/balance/{address}"))?;
    let view = BalanceView {
        wallet: wallet.to_string(),
        address: address.to_string(),
        can_consume: field_bool(&value, "canConsume").unwrap_or(false),
        balance_usd: field_string(&value, "balanceUsd").unwrap_or_else(|| "0".into()),
        diem_balance_usd: field_string(&value, "diemBalanceUsd"),
        minimum_top_up_usd: field_string(&value, "minimumTopUpUsd"),
        suggested_top_up_usd: field_string(&value, "suggestedTopUpUsd"),
    };
    Ok(view)
}

/// Read a field from a Venice response, tolerating both a top-level placement
/// and a `{data: {...}}` envelope. The Venice docs describe top-level fields
/// while the canonical x402 client reads from `data`; accepting both makes the
/// petal robust to either shape without a live probe.
fn field_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .get(key)
        .or_else(|| value.get("data").and_then(|d| d.get(key)))
}

/// Read a boolean field (top-level or under `data`).
fn field_bool(value: &Value, key: &str) -> Option<bool> {
    field_value(value, key).and_then(Value::as_bool)
}

/// Read a field as a string, coercing numbers (Venice sometimes returns
/// balances as JSON numbers). Top-level or under `data`.
fn field_string(value: &Value, key: &str) -> Option<String> {
    let v = field_value(value, key)?;
    v.as_str()
        .map(str::to_string)
        .or_else(|| v.as_f64().map(format_balance_number))
}

/// Format a JSON-number balance as a tidy decimal string (e.g. 9.87, 10, 0.5).
fn format_balance_number(n: f64) -> String {
    if n == n.trunc() {
        format!("{n:.0}")
    } else {
        // Trim trailing zeros from a fixed 6-decimal render.
        format!("{n:.6}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

/// Perform an x402 top-up with USDC on Base.
///
/// Flow:
/// 1. POST /x402/top-up (no payment header) → 402 with payment requirements.
///    The `amount` in each requirement is the *minimum* top-up.
/// 2. Validate the requested amount is >= that minimum.
/// 3. Build and sign an EIP-3009 `TransferWithAuthorization` for the
///    *requested* amount (the value actually transferred on-chain).
/// 4. POST /x402/top-up with `X-402-Payment` header → 200 with balance.
pub(crate) fn top_up<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
    amount_usd: &str,
) -> Result<(String, Option<String>), DispatchResponse> {
    // Parse the requested amount into USDC base units. This value drives the
    // on-chain transfer, so it is computed with exact integer math, not f64.
    let amount_base_units = common::parse_usd_to_base_units(amount_usd)
        .map_err(|e| common::invalid(format!("{e}; amount_usd must be a decimal USD value")))?;
    if amount_base_units == 0 {
        return Err(common::invalid("amount_usd must be positive"));
    }
    let amount_base_units_str = amount_base_units.to_string();

    let now_ms = host.now_ms().map_err(common::backend)?;
    let now_secs = now_ms / 1000;
    let pending_key = format!("state/topups/{wallet}.pending.json");
    let stored_pending =
        match host
            .store_get(&pending_key, crate::common::MAX_STORED)
            .map_err(common::backend)?
        {
            Some(bytes) => Some(serde_json::from_slice::<PendingTopUp>(&bytes).map_err(
                |error| common::backend(format!("stored pending top-up is invalid: {error}")),
            )?),
            None => None,
        };
    let mut pending = match stored_pending {
        Some(pending) => {
            let valid_before = pending
                .prepared
                .authorization
                .valid_before
                .parse::<u64>()
                .map_err(|_| common::backend("stored top-up validity is invalid"))?;
            if valid_before <= now_secs.saturating_add(30) {
                host.store_del(&pending_key).map_err(common::backend)?;
                prepare_top_up(
                    host,
                    wallet,
                    address,
                    &amount_base_units_str,
                    amount_base_units,
                    now_secs,
                )?
            } else {
                if pending.wallet != wallet
                    || !pending.address.eq_ignore_ascii_case(address)
                    || pending.amount_base_units != amount_base_units_str
                {
                    return Err(common::invalid(
                        "a different top-up is already awaiting completion for this wallet",
                    ));
                }
                pending
            }
        }
        None => prepare_top_up(
            host,
            wallet,
            address,
            &amount_base_units_str,
            amount_base_units,
            now_secs,
        )?,
    };
    let pending_bytes = serde_json::to_vec(&pending)
        .map_err(|error| common::backend(format!("serialize pending top-up: {error}")))?;
    host.store_put(&pending_key, &pending_bytes, false)
        .map_err(common::backend)?;

    let approval_hint = pending
        .approval_expires_ms
        .is_some_and(|expires_ms| expires_ms > now_ms)
        .then(|| pending.approval_action_id.clone())
        .flatten();
    let payment_header = match x402::sign_payment_header(
        host,
        wallet,
        &pending.prepared,
        approval_hint,
    )? {
        x402::PaymentSignOutcome::Header(header) => header,
        x402::PaymentSignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        } => {
            pending.approval_action_id = Some(action_id.clone());
            pending.approval_expires_ms = Some(expires_ms);
            let bytes = serde_json::to_vec(&pending)
                .map_err(|error| common::backend(format!("serialize pending top-up: {error}")))?;
            host.store_put(&pending_key, &bytes, false)
                .map_err(common::backend)?;
            return Err(petal::error(
                -2,
                format!(
                    "x402 payment approval required for action {action_id}; open the owner-visible Bloom signing request, approve it, then retry the exact write"
                ),
            ));
        }
    };

    // Step 4: retry top-up with payment header.
    let retry_request = petal::HttpRequest {
        method: "POST".into(),
        url: format!("{VENICE_API}/x402/top-up"),
        headers: vec![("X-402-Payment".into(), payment_header)],
        body: serde_json::to_vec(&json!({}))
            .map_err(|e| common::backend(format!("serialize retry body: {e}")))?,
    };
    let retry_response = host
        .http_fetch(&retry_request, MAX_BODY)
        .map_err(common::backend)?;

    if !(200..300).contains(&retry_response.status) {
        let body = common::parse_json_body(&retry_response).unwrap_or(Value::Null);
        return Err(common::backend(format!(
            "Venice top-up payment failed: HTTP {}: {}",
            retry_response.status,
            common::compact(&body)
        )));
    }

    let result = common::parse_json_body(&retry_response).map_err(common::backend)?;
    // Venice's canonical client reads `data.newBalance` (number); some response
    // shapes use a top-level `balanceUsd` string. Accept either so the recorded
    // balance reflects reality regardless of the exact envelope.
    let balance_usd =
        field_string(&result, "balanceUsd").or_else(|| field_string(&result, "newBalance"));
    host.store_del(&pending_key).map_err(common::backend)?;

    Ok((amount_base_units_str, balance_usd))
}

fn prepare_top_up<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
    amount_base_units_str: &str,
    amount_base_units: u64,
    now_secs: u64,
) -> Result<PendingTopUp, DispatchResponse> {
    let init_request = petal::HttpRequest {
        method: "POST".into(),
        url: format!("{VENICE_API}/x402/top-up"),
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!({}))
            .map_err(|error| common::backend(format!("serialize top-up body: {error}")))?,
    };
    let init_response = host
        .http_fetch(&init_request, MAX_BODY)
        .map_err(common::backend)?;
    if init_response.status != 402 {
        let body = common::parse_json_body(&init_response).unwrap_or(Value::Null);
        if (200..300).contains(&init_response.status) {
            return Err(common::invalid(
                "Venice did not require payment for top-up — balance may already be sufficient",
            ));
        }
        return Err(common::backend(format!(
            "Venice top-up initiation returned HTTP {}: {}",
            init_response.status,
            common::compact(&body)
        )));
    }
    let required: x402::PaymentRequired = serde_json::from_slice(&init_response.body)
        .map_err(|error| common::backend(format!("parse 402 payment requirements: {error}")))?;
    let requirement = x402::extract_base_requirement(&required)?;
    let minimum_base_units: u64 = requirement.amount.parse().map_err(|_| {
        common::backend(format!(
            "Venice 402 requirement has a non-numeric amount: {}",
            requirement.amount
        ))
    })?;
    if amount_base_units < minimum_base_units {
        let minimum_usd = (minimum_base_units as f64) / 1_000_000.0;
        return Err(common::invalid(format!(
            "amount_usd must be at least ${minimum_usd:.2}"
        )));
    }
    let prepared = x402::prepare_payment(
        host,
        address,
        requirement,
        amount_base_units_str,
        required.x402_version,
        now_secs,
    )?;
    Ok(PendingTopUp {
        wallet: wallet.to_owned(),
        address: address.to_owned(),
        amount_base_units: amount_base_units_str.to_owned(),
        prepared,
        approval_action_id: None,
        approval_expires_ms: None,
    })
}

/// Send a chat completion request.
///
/// Returns the raw Venice response value.
pub(crate) fn chat_completion_raw<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
    request: &ChatRequest,
) -> Result<(Value, Option<String>), DispatchResponse> {
    if request.stream {
        return Err(common::invalid(
            "streaming is not yet supported; set stream to false",
        ));
    }

    let url = format!("{VENICE_API}/chat/completions");
    let session = siwe::get_or_create_session(host, wallet, address, &url, "venice-x402.chat")?;

    // Venice's chat API is OpenAI-compatible: system context goes in the
    // messages array as a {role:"system"} message, not a top-level field.
    let mut messages: Vec<Value> = Vec::with_capacity(request.messages.len() + 1);
    if let Some(system) = &request.system_prompt {
        messages.push(json!({"role": "system", "content": system}));
    }
    for m in &request.messages {
        messages.push(json!({"role": m.role, "content": m.content}));
    }

    let mut body = json!({
        "model": request.model,
        "messages": messages,
    });

    if let Some(temp) = request.temperature {
        body["temperature"] = json!(temp);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_tokens"] = json!(max_tokens);
    }

    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| common::backend(format!("serialize chat body: {e}")))?;

    let http_request = petal::HttpRequest {
        method: "POST".into(),
        url,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("accept".into(), "application/json".into()),
            ("X-Sign-In-With-X".into(), session.header_b64.clone()),
        ],
        body: body_bytes,
    };

    let response = host
        .http_fetch(&http_request, MAX_BODY)
        .map_err(common::backend)?;

    let balance = extract_balance_remaining(&response);
    let value = interpret_response(response)?;

    Ok((value, balance))
}

/// Extract the assistant's response text and model from a Venice chat response.
pub(crate) fn extract_chat_response(value: &Value) -> (String, Option<String>) {
    let content = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let model = value.get("model").and_then(Value::as_str).map(String::from);
    (content, model)
}

/// Extract token usage from a Venice chat response.
pub(crate) fn extract_usage(value: &Value) -> Option<crate::types::TokenUsage> {
    value.get("usage").map(|u| crate::types::TokenUsage {
        prompt_tokens: u.get("prompt_tokens").and_then(Value::as_u64),
        completion_tokens: u.get("completion_tokens").and_then(Value::as_u64),
        total_tokens: u.get("total_tokens").and_then(Value::as_u64),
    })
}

/// Parse and validate a chat request body.
pub fn parse_chat_request(body: &[u8]) -> Result<ChatRequest, DispatchResponse> {
    if body.len() > 64 * 1024 {
        return Err(common::invalid("request body is too large (max 64 KB)"));
    }
    let request: ChatRequest = serde_json::from_slice(body)
        .map_err(|e| common::invalid(format!("invalid request JSON: {e}")))?;
    if request.address.is_empty() {
        return Err(common::invalid("address is required"));
    }
    if !common::is_evm_address(&request.address) {
        return Err(common::invalid(
            "address must be a valid EVM address (0x-prefixed, 40 hex digits)",
        ));
    }
    if request.model.is_empty() {
        return Err(common::invalid("model is required"));
    }
    if request.messages.is_empty() {
        return Err(common::invalid("at least one message is required"));
    }
    for msg in &request.messages {
        if msg.role.is_empty() {
            return Err(common::invalid("message role cannot be empty"));
        }
        if msg.content.is_empty() {
            return Err(common::invalid("message content cannot be empty"));
        }
    }
    if request
        .temperature
        .is_some_and(|temp| !(0.0..=2.0).contains(&temp))
    {
        return Err(common::invalid("temperature must be between 0.0 and 2.0"));
    }
    if request.max_tokens.is_some_and(|max| max == 0) {
        return Err(common::invalid("max_tokens must be greater than 0"));
    }
    Ok(request)
}

/// Validate a top-up request body and return the parsed request.
pub fn parse_topup_request(body: &[u8]) -> Result<crate::types::TopUpRequest, DispatchResponse> {
    if body.len() > 4 * 1024 {
        return Err(common::invalid("request body is too large (max 4 KB)"));
    }
    let request: crate::types::TopUpRequest = serde_json::from_slice(body)
        .map_err(|e| common::invalid(format!("invalid request JSON: {e}")))?;
    if !common::is_evm_address(&request.address) {
        return Err(common::invalid(
            "address must be a valid EVM address (0x-prefixed, 40 hex digits)",
        ));
    }
    if request.amount_usd.is_empty() {
        return Err(common::invalid("amount_usd is required"));
    }
    let base_units = common::parse_usd_to_base_units(&request.amount_usd)
        .map_err(|e| common::invalid(format!("{e}; amount_usd must be a decimal USD value")))?;
    if base_units == 0 {
        return Err(common::invalid("amount_usd must be positive"));
    }
    Ok(request)
}

/// Store key for a chat result in the state namespace.
pub fn chat_store_key(wallet: &str, id: &str) -> String {
    format!("state/venice-x402/chat/{wallet}/{id}")
}

/// Store key for a top-up result in the state namespace.
pub fn topup_store_key(wallet: &str) -> String {
    format!("state/venice-x402/topup/{wallet}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::test_nonce;
    use crate::common::test_helpers::{MockHost, signature};
    use crate::types::{ChatMessage, ChatRequest};
    use petal::HttpResponse;

    const ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";

    #[test]
    fn extract_chat_response_extracts_content_and_model() {
        let value = json!({
            "model": "kimi-k2-5",
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });
        let (content, model) = extract_chat_response(&value);
        assert_eq!(content, "Hello!");
        assert_eq!(model.as_deref(), Some("kimi-k2-5"));
    }

    #[test]
    fn extract_chat_response_handles_missing_choices() {
        let value = json!({});
        let (content, model) = extract_chat_response(&value);
        assert!(content.is_empty());
        assert!(model.is_none());
    }

    #[test]
    fn extract_usage_extracts_all_fields() {
        let value =
            json!({"usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}});
        let usage = extract_usage(&value).unwrap();
        assert_eq!(usage.prompt_tokens, Some(100));
        assert_eq!(usage.completion_tokens, Some(50));
        assert_eq!(usage.total_tokens, Some(150));
    }

    #[test]
    fn extract_usage_returns_none_when_absent() {
        let value = json!({});
        assert!(extract_usage(&value).is_none());
    }

    #[test]
    fn parse_chat_request_valid() {
        let body = serde_json::to_vec(&json!({
            "address": ADDRESS,
            "model": "kimi-k2-5",
            "messages": [{"role": "user", "content": "Hi"}]
        }))
        .unwrap();
        let request = parse_chat_request(&body).unwrap();
        assert_eq!(request.address, ADDRESS);
        assert_eq!(request.model, "kimi-k2-5");
        assert_eq!(request.messages.len(), 1);
    }

    #[test]
    fn parse_chat_request_rejects_empty_messages() {
        let body = serde_json::to_vec(&json!({
            "address": ADDRESS,
            "model": "kimi-k2-5",
            "messages": []
        }))
        .unwrap();
        assert!(parse_chat_request(&body).is_err());
    }

    #[test]
    fn parse_chat_request_rejects_invalid_address() {
        let body = serde_json::to_vec(&json!({
            "address": "0xshort",
            "model": "kimi-k2-5",
            "messages": [{"role": "user", "content": "Hi"}]
        }))
        .unwrap();
        assert!(parse_chat_request(&body).is_err());
    }

    #[test]
    fn parse_chat_request_rejects_invalid_temperature() {
        let body = serde_json::to_vec(&json!({
            "address": ADDRESS,
            "model": "kimi-k2-5",
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 5.0
        }))
        .unwrap();
        assert!(parse_chat_request(&body).is_err());
    }

    #[test]
    fn parse_topup_request_valid() {
        let body = serde_json::to_vec(&json!({
            "address": ADDRESS,
            "amount_usd": "5.00"
        }))
        .unwrap();
        let request = parse_topup_request(&body).unwrap();
        assert_eq!(request.address, ADDRESS);
        assert_eq!(request.amount_usd, "5.00");
    }

    #[test]
    fn parse_topup_request_rejects_negative() {
        let body = serde_json::to_vec(&json!({
            "address": ADDRESS,
            "amount_usd": "-5.00"
        }))
        .unwrap();
        assert!(parse_topup_request(&body).is_err());
    }

    #[test]
    fn interpret_response_2xx_parses_json() {
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({"ok": true})).unwrap(),
        };
        let value = interpret_response(response).unwrap();
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn interpret_response_402_returns_insufficient_balance_error() {
        let response = HttpResponse {
            status: 402,
            headers: vec![],
            body: serde_json::to_vec(&json!({"error": "no balance"})).unwrap(),
        };
        let result = interpret_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should contain the DispatchResponse::Error from backend
        if let petal::DispatchResponse::Error { message, .. } = err {
            assert!(message.contains("insufficient_balance"));
        } else {
            panic!("expected error dispatch");
        }
    }

    #[test]
    fn interpret_response_401_returns_auth_error() {
        let response = HttpResponse {
            status: 401,
            headers: vec![],
            body: vec![],
        };
        let result = interpret_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn interpret_response_500_returns_error() {
        let response = HttpResponse {
            status: 500,
            headers: vec![],
            body: serde_json::to_vec(&json!({"error": "internal"})).unwrap(),
        };
        let result = interpret_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn extract_balance_remaining_finds_header() {
        let response = HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("X-Balance-Remaining".into(), "3.50".into()),
            ],
            body: vec![],
        };
        assert_eq!(extract_balance_remaining(&response), Some("3.50".into()));
    }

    #[test]
    fn extract_balance_remaining_returns_none_if_absent() {
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        };
        assert!(extract_balance_remaining(&response).is_none());
    }

    #[test]
    fn check_balance_parses_top_level_string_fields() {
        // Shape described by the Venice x402 docs.
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature())); // SIWE session
        host.http_results.push_back(Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({
                "canConsume": true,
                "balanceUsd": "12.50",
                "diemBalanceUsd": "0",
                "minimumTopUpUsd": "5.00",
                "suggestedTopUpUsd": "10.00"
            }))
            .unwrap(),
        }));
        let view = check_balance(&mut host, "0xw", ADDRESS).unwrap();
        assert!(view.can_consume);
        assert_eq!(view.balance_usd, "12.50");
        assert_eq!(view.suggested_top_up_usd.as_deref(), Some("10.00"));
    }

    #[test]
    fn check_balance_parses_nested_data_envelope_and_numbers() {
        // Shape the canonical Venice x402 client reads (`data.data.<field>`
        // with numeric balances). The petal must tolerate this too.
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature()));
        host.http_results.push_back(Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({
                "data": {
                    "canConsume": false,
                    "balanceUsd": 9.87,
                    "minimumTopUpUsd": 5.0
                }
            }))
            .unwrap(),
        }));
        let view = check_balance(&mut host, "0xw", ADDRESS).unwrap();
        assert!(!view.can_consume);
        assert_eq!(view.balance_usd, "9.87");
        assert_eq!(view.minimum_top_up_usd.as_deref(), Some("5"));
        assert!(view.suggested_top_up_usd.is_none());
    }

    // -----------------------------------------------------------------------
    // Capstone end-to-end flows (mocked Venice). These prove the integrated
    // wiring of the payment + chat paths after the amount-semantics, SIWE
    // URI-binding, system_prompt, and x402 wire-format fixes.
    // -----------------------------------------------------------------------

    #[test]
    fn top_up_full_flow_pays_caller_amount_and_records_balance() {
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        // Only one signature is needed: the EIP-3009 payment. The init POST
        // takes no SIWE auth (matches the canonical Venice client).
        host.sign_results.push_back(Ok(signature()));

        // Step 1 response: 402 with a USDC-on-Base requirement (minimum $5).
        host.http_results.push_back(Ok(HttpResponse {
            status: 402,
            headers: vec![],
            body: serde_json::to_vec(&json!({
                "x402Version": 2,
                "accepts": [{
                    "scheme": "exact",
                    "network": "base",
                    "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                    "amount": "5000000",
                    "payTo": "0x2670b922ef37c7df47158725c0cc407b5382293f",
                    "maxTimeoutSeconds": 300,
                    "extra": {"name": "USD Coin", "version": "2"}
                }]
            }))
            .unwrap(),
        }));
        // Step 2 response: 200 with the new balance.
        host.http_results.push_back(Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({"balanceUsd": "15.00"})).unwrap(),
        }));

        let (amount_base_units, balance_usd) =
            top_up(&mut host, "0xwallet1", ADDRESS, "10.00").unwrap();

        // Records the CALLER's amount ($10), not Venice's $5 minimum.
        assert_eq!(amount_base_units, "10000000");
        assert_eq!(balance_usd.as_deref(), Some("15.00"));
        assert_eq!(host.sign_requests.len(), 1);
        assert_eq!(host.sign_requests[0].operation_class, "venice-x402.topup");

        // The retry carried the X-402-Payment header; the init did not.
        assert_eq!(host.requests.len(), 2);
        let init = &host.requests[0];
        let retry = &host.requests[1];
        assert!(
            !init
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-402-payment")),
            "init must not carry a payment header"
        );
        let payment = retry
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-402-payment"))
            .expect("retry must carry X-402-Payment");
        assert!(!payment.1.is_empty());
    }

    #[test]
    fn top_up_approval_retry_reuses_prepared_authorization_and_hint() {
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        host.random_data.push_back(test_nonce());
        host.sign_results
            .push_back(Ok(petal::SignOutcome::ApprovalPending {
                action_id: "approval-1".into(),
                expires_ms: 1_700_000_060_000,
            }));
        host.sign_results.push_back(Ok(signature()));
        host.http_results.push_back(Ok(HttpResponse {
            status: 402,
            headers: vec![],
            body: serde_json::to_vec(&json!({
                "x402Version": 2,
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                    "amount": "5000000",
                    "payTo": "0x2670b922ef37c7df47158725c0cc407b5382293f",
                    "maxTimeoutSeconds": 300,
                    "extra": {"name": "USD Coin", "version": "2"}
                }]
            }))
            .unwrap(),
        }));
        host.http_results.push_back(Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({"balanceUsd": "15.00"})).unwrap(),
        }));

        assert!(top_up(&mut host, "minnow-passkey", ADDRESS, "10.00").is_err());
        let completed = top_up(&mut host, "minnow-passkey", ADDRESS, "10.00").unwrap();

        assert_eq!(completed.0, "10000000");
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
        assert_eq!(host.requests.len(), 2, "retry must not fetch a fresh quote");
    }

    #[test]
    fn top_up_rejects_amount_below_minimum() {
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        host.http_results.push_back(Ok(HttpResponse {
            status: 402,
            headers: vec![],
            body: serde_json::to_vec(&json!({
                "x402Version": 2,
                "accepts": [{
                    "scheme": "exact",
                    "network": "base",
                    "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                    "amount": "5000000",
                    "payTo": "0x2670b922ef37c7df47158725c0cc407b5382293f",
                    "maxTimeoutSeconds": 300,
                    "extra": {"name": "USD Coin", "version": "2"}
                }]
            }))
            .unwrap(),
        }));

        let err = top_up(&mut host, "0xwallet1", ADDRESS, "1.00").unwrap_err();
        if let petal::DispatchResponse::Error { message, .. } = err {
            assert!(message.contains("at least $5.00"), "got: {message}");
        } else {
            panic!("expected error dispatch");
        }
        // No signing happened (validation short-circuited before payment).
        assert!(host.sign_requests.is_empty());
    }

    #[test]
    fn chat_full_flow_sends_system_prompt_as_message_and_reads_balance_header() {
        let mut host = MockHost {
            now_ms: 1_700_000_000_000,
            ..Default::default()
        };
        host.sign_results.push_back(Ok(signature())); // SIWE session
        host.http_results.push_back(Ok(HttpResponse {
            status: 200,
            headers: vec![("X-Balance-Remaining".into(), "9.87".into())],
            body: serde_json::to_vec(&json!({
                "model": "kimi-k2-5",
                "choices": [{"message": {"role": "assistant", "content": "Hi!"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
            }))
            .unwrap(),
        }));

        let request = ChatRequest {
            address: ADDRESS.into(),
            model: "kimi-k2-5".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            system_prompt: Some("Be concise.".into()),
            temperature: Some(0.7),
            max_tokens: Some(128),
            stream: false,
        };

        let (value, balance) =
            chat_completion_raw(&mut host, "0xwallet1", ADDRESS, &request).unwrap();
        assert_eq!(value["choices"][0]["message"]["content"], "Hi!");
        assert_eq!(balance.as_deref(), Some("9.87"));

        // The single Venice request carried the SIWE header...
        assert_eq!(host.requests.len(), 1);
        let req = &host.requests[0];
        assert!(
            req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-sign-in-with-x"))
        );
        // ...and the body injected the system prompt as a system message,
        // NOT as a top-level `system_prompt` field.
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "Be concise.");
        assert_eq!(body["messages"][1]["role"], "user");
        assert!(body.get("system_prompt").is_none(), "got: {body}");
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["max_tokens"], 128);
    }
}
