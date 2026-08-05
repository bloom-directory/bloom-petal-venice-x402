//! Venice HTTP API client: models, balance, chat completions, top-up.
//!
//! All HTTP calls go through the `Host` trait so tests can inject mocks.
//! SIWE auth and x402 payment headers are added per-request.

use serde_json::{Value, json};

use crate::common::{self, DispatchResponse, Host, MAX_BODY, VENICE_API};
use crate::siwe;
use crate::types::{BalanceView, ChatRequest};
use crate::x402;

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
    let session = siwe::get_or_create_session(host, wallet, address)?;
    let request = petal::HttpRequest {
        method: "GET".into(),
        url: format!("{VENICE_API}{path}"),
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
        can_consume: value
            .get("canConsume")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        balance_usd: value
            .get("balanceUsd")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string(),
        diem_balance_usd: value
            .get("diemBalanceUsd")
            .and_then(Value::as_str)
            .map(String::from),
        minimum_top_up_usd: value
            .get("minimumTopUpUsd")
            .and_then(Value::as_str)
            .map(String::from),
        suggested_top_up_usd: value
            .get("suggestedTopUpUsd")
            .and_then(Value::as_str)
            .map(String::from),
    };
    Ok(view)
}

/// Perform an x402 top-up with USDC on Base.
///
/// Flow:
/// 1. POST /x402/top-up (no payment header) → 402 with payment requirements.
/// 2. Build and sign EIP-3009 `TransferWithAuthorization`.
/// 3. POST /x402/top-up with `X-402-Payment` header → 200 with balance.
pub(crate) fn top_up<H: Host>(
    host: &mut H,
    wallet: &str,
    address: &str,
    amount_usd: &str,
) -> Result<(String, Option<String>), DispatchResponse> {
    // Parse amount and convert to USDC base units (6 decimals).
    let amount_f: f64 = amount_usd
        .parse()
        .map_err(|_| common::invalid(format!("amount_usd is not a valid number: {amount_usd}")))?;
    if amount_f <= 0.0 {
        return Err(common::invalid("amount_usd must be positive"));
    }
    let amount_base_units = format!("{}", (amount_f * 1e6).round() as u64);

    // Step 1: initiate top-up to get payment requirements.
    let session = siwe::get_or_create_session(host, wallet, address)?;
    let init_request = petal::HttpRequest {
        method: "POST".into(),
        url: format!("{VENICE_API}/x402/top-up"),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("X-Sign-In-With-X".into(), session.header_b64.clone()),
        ],
        body: serde_json::to_vec(&json!({}))
            .map_err(|e| common::backend(format!("serialize top-up body: {e}")))?,
    };
    let init_response = host
        .http_fetch(&init_request, MAX_BODY)
        .map_err(common::backend)?;

    if init_response.status != 402 {
        // Unexpected — could be already sufficient or an error.
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

    // Parse the 402 payment requirements.
    let required: x402::PaymentRequired = serde_json::from_slice(&init_response.body)
        .map_err(|e| common::backend(format!("parse 402 payment requirements: {e}")))?;
    let requirement = x402::extract_base_requirement(&required)?;

    // Step 2: build and sign the x402 payment header.
    let now_ms = host.now_ms().map_err(common::backend)?;
    let now_secs = now_ms / 1000;
    let payment_header = x402::build_payment_header(host, wallet, address, requirement, now_secs)?;

    // Step 3: retry top-up with payment header.
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
    let balance_usd = result
        .get("balanceUsd")
        .and_then(Value::as_str)
        .map(String::from);

    Ok((amount_base_units, balance_usd))
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

    let session = siwe::get_or_create_session(host, wallet, address)?;

    let mut body = json!({
        "model": request.model,
        "messages": request.messages.iter().map(|m| {
            json!({"role": m.role, "content": m.content})
        }).collect::<Vec<_>>(),
    });

    if let Some(system) = &request.system_prompt {
        body["system_prompt"] = json!(system);
    }
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
        url: format!("{VENICE_API}/chat/completions"),
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
    let amount: f64 = request.amount_usd.parse().map_err(|_| {
        common::invalid(format!(
            "amount_usd is not a valid number: {}",
            request.amount_usd
        ))
    })?;
    if amount <= 0.0 {
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
}
