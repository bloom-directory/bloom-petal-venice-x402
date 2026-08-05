//! Wire types for the venice-x402 petal: chat requests, chat responses,
//! balance views, and top-up status objects.

use serde::{Deserialize, Serialize};

/// Write body for `POST /petals/venice-x402/chat/<wallet>/<id>.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChatRequest {
    /// EVM address of the wallet (used for SIWE + payment).
    pub address: String,
    /// Venice model identifier (e.g. `"kimi-k2-5"`).
    pub model: String,
    /// Chat messages in OpenAI-compatible format.
    pub messages: Vec<ChatMessage>,
    /// Optional system prompt prepended to the messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Sampling temperature (0.0–2.0). Defaults to the model default if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Maximum tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Whether to stream the response. Currently only `false` is supported.
    #[serde(default)]
    pub stream: bool,
}

/// A single chat message (OpenAI-compatible).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Persisted chat completion result (stored in state namespace).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredChat {
    pub wallet: String,
    pub model: String,
    /// The request messages (for reference).
    pub request: Vec<ChatMessage>,
    /// The response content from the assistant.
    pub response: String,
    /// Venice model used (may differ from request if Venice remaps).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_model: Option<String>,
    /// Token usage statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
    /// Unix milliseconds when the chat was created.
    pub created_ms: u64,
    /// Venice balance remaining after this request (from response header).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_remaining: Option<String>,
}

/// Token usage breakdown.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

/// Write body for `POST /petals/venice-x402/topup/<wallet>.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopUpRequest {
    /// EVM address of the wallet.
    pub address: String,
    /// Amount to top up in USD (e.g. `"5.00"`). Converted to USDC base units.
    pub amount_usd: String,
}

/// Persisted top-up result (stored in state namespace).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredTopUp {
    pub wallet: String,
    /// Amount topped up in USD.
    pub amount_usd: String,
    /// USDC base units paid.
    pub amount_base_units: String,
    /// Top-up status.
    pub status: String,
    /// Unix milliseconds when the top-up was initiated.
    pub created_ms: u64,
    /// Balance after top-up (if returned by Venice).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_usd: Option<String>,
}

/// Balance view returned at `GET /petals/venice-x402/balance/<wallet>.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BalanceView {
    pub wallet: String,
    pub address: String,
    /// Whether the wallet can make paid requests.
    pub can_consume: bool,
    /// Current spendable balance in USD.
    #[serde(default)]
    pub balance_usd: String,
    /// DIEM-backed balance in USD (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diem_balance_usd: Option<String>,
    /// Minimum top-up amount in USD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_top_up_usd: Option<String>,
    /// Suggested top-up amount in USD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_top_up_usd: Option<String>,
}
