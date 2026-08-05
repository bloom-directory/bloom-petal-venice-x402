//! Integration tests for the Venice x402 petal public API.
//!
//! These tests validate request parsing and type serialization using only
//! the crate's public interface. Host-mocked flow tests (SIWE session,
//! x402 payment header, balance, top-up, chat) live as unit tests in each
//! source module.

use venice_x402_route::{ChatMessage, ChatRequest, StoredChat};
use venice_x402_route::{parse_chat_request, parse_topup_request};

use serde_json::json;

const ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";

// ---------------------------------------------------------------------------
// Chat request validation
// ---------------------------------------------------------------------------

#[test]
fn parse_chat_request_full() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "kimi-k2-5",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello!"}
        ],
        "system_prompt": "Be concise.",
        "temperature": 0.7,
        "max_tokens": 1024
    }))
    .unwrap();

    let request = parse_chat_request(&body).unwrap();
    assert_eq!(request.address, ADDRESS);
    assert_eq!(request.model, "kimi-k2-5");
    assert_eq!(request.messages.len(), 2);
    assert_eq!(request.messages[0].role, "system");
    assert_eq!(request.system_prompt.as_deref(), Some("Be concise."));
    assert_eq!(request.temperature, Some(0.7));
    assert_eq!(request.max_tokens, Some(1024));
}

#[test]
fn parse_chat_request_minimal() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "llama-3.3-70b",
        "messages": [{"role": "user", "content": "Hi"}]
    }))
    .unwrap();

    let request = parse_chat_request(&body).unwrap();
    assert_eq!(request.model, "llama-3.3-70b");
    assert_eq!(request.system_prompt, None);
    assert_eq!(request.temperature, None);
    assert_eq!(request.max_tokens, None);
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
fn parse_chat_request_rejects_bad_address() {
    let body = serde_json::to_vec(&json!({
        "address": "0xshort",
        "model": "kimi-k2-5",
        "messages": [{"role": "user", "content": "Hi"}]
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

#[test]
fn parse_chat_request_rejects_temperature_out_of_range() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "kimi-k2-5",
        "messages": [{"role": "user", "content": "Hi"}],
        "temperature": 3.0
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

#[test]
fn parse_chat_request_rejects_zero_max_tokens() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "kimi-k2-5",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 0
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

#[test]
fn parse_chat_request_rejects_missing_model() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "messages": [{"role": "user", "content": "Hi"}]
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

#[test]
fn parse_chat_request_rejects_empty_content() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "kimi-k2-5",
        "messages": [{"role": "user", "content": ""}]
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

#[test]
fn parse_chat_request_rejects_unknown_field() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "model": "kimi-k2-5",
        "messages": [{"role": "user", "content": "Hi"}],
        "unknown_field": "oops"
    }))
    .unwrap();
    assert!(parse_chat_request(&body).is_err());
}

// ---------------------------------------------------------------------------
// Top-up request validation
// ---------------------------------------------------------------------------

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
fn parse_topup_request_rejects_zero() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "amount_usd": "0"
    }))
    .unwrap();
    assert!(parse_topup_request(&body).is_err());
}

#[test]
fn parse_topup_request_rejects_non_numeric() {
    let body = serde_json::to_vec(&json!({
        "address": ADDRESS,
        "amount_usd": "five"
    }))
    .unwrap();
    assert!(parse_topup_request(&body).is_err());
}

#[test]
fn parse_topup_request_rejects_bad_address() {
    let body = serde_json::to_vec(&json!({
        "address": "0xnope",
        "amount_usd": "5.00"
    }))
    .unwrap();
    assert!(parse_topup_request(&body).is_err());
}

// ---------------------------------------------------------------------------
// Type serialization
// ---------------------------------------------------------------------------

#[test]
fn stored_chat_round_trips() {
    let chat = StoredChat {
        wallet: "test-wallet".into(),
        model: "kimi-k2-5".into(),
        request: vec![ChatMessage {
            role: "user".into(),
            content: "Hello".into(),
        }],
        response: "Hi there!".into(),
        actual_model: Some("kimi-k2-5".into()),
        usage: Some(venice_x402_route::TokenUsage {
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
            total_tokens: Some(15),
        }),
        created_ms: 1_000_000,
        balance_remaining: Some("4.99".into()),
    };

    let json = serde_json::to_vec(&chat).unwrap();
    let deserialized: StoredChat = serde_json::from_slice(&json).unwrap();
    assert_eq!(deserialized.response, "Hi there!");
    assert_eq!(deserialized.usage.unwrap().total_tokens, Some(15));
}

#[test]
fn chat_request_serializes_without_optionals() {
    let request = ChatRequest {
        address: ADDRESS.into(),
        model: "kimi-k2-5".into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "Hello".into(),
        }],
        system_prompt: None,
        temperature: None,
        max_tokens: None,
        stream: false,
    };

    let json = serde_json::to_vec(&request).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert!(value.get("system_prompt").is_none());
    assert!(value.get("temperature").is_none());
    assert!(value.get("max_tokens").is_none());
}
