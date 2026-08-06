//! Venice x402 petal — private AI inference via Venice's x402 payment protocol.
//!
//! Pay-per-request AI inference using Venice's x402 protocol: authenticate
//! with SIWE, top up with USDC on Base via EIP-3009, and call any Venice
//! inference endpoint.

pub mod common;
mod siwe;
mod types;
pub mod venice;
mod x402;

pub use common::{MAX_STORED, is_evm_address};
pub use serde_json;
pub use types::{
    BalanceView, ChatMessage, ChatRequest, StoredChat, StoredTopUp, TokenUsage, TopUpRequest,
};
pub use venice::{chat_store_key, parse_chat_request, parse_topup_request, topup_store_key};

/// Resolve a wallet alias to its EVM address via VFS.
pub fn wallet_address(wallet: &str) -> Result<String, petal::DispatchResponse> {
    let path = format!("wallets/{wallet}/address");
    let bytes =
        petal::sdk::vfs_read(&path, 128).map_err(|error| petal::error(-4, error.message()))?;
    let address = core::str::from_utf8(&bytes)
        .map_err(|_| petal::error(-4, "wallet address is not UTF-8"))?
        .trim();
    let lower = address.to_ascii_lowercase();
    if common::is_evm_address(&lower) {
        Ok(lower)
    } else {
        Err(petal::error(-4, "wallet must be a 20-byte EVM address"))
    }
}

/// Execute a chat completion request and persist the result.
pub fn venice_chat(
    wallet: &str,
    address: &str,
    chat_id: &str,
    request: ChatRequest,
) -> petal::DispatchResponse {
    use common::Host;

    let mut host = common::BloomHost;
    let (value, balance_remaining) =
        match venice::chat_completion_raw(&mut host, wallet, address, &request) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let (content, actual_model) = venice::extract_chat_response(&value);
    let usage = venice::extract_usage(&value);
    let now_ms = host.now_ms().unwrap_or(0);

    let stored = StoredChat {
        wallet: wallet.to_string(),
        model: request.model.clone(),
        request: request.messages,
        response: content,
        actual_model,
        usage,
        created_ms: now_ms,
        balance_remaining,
    };

    let key = venice::chat_store_key(wallet, chat_id);
    let bytes = match serde_json::to_vec_pretty(&stored) {
        Ok(bytes) => bytes,
        Err(e) => return common::backend(format!("serialize chat result: {e}")),
    };

    if let Err(e) = host.store_put(&key, &bytes, false) {
        return common::backend(e);
    }

    petal::read_store(&key, common::MAX_STORED)
}

/// Execute an x402 top-up and persist the result.
pub fn venice_topup(wallet: &str, address: &str, request: TopUpRequest) -> petal::DispatchResponse {
    use common::Host;

    let mut host = common::BloomHost;
    let (amount_base_units, balance_usd) =
        match venice::top_up(&mut host, wallet, address, &request.amount_usd) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let now_ms = host.now_ms().unwrap_or(0);
    let stored = StoredTopUp {
        wallet: wallet.to_string(),
        amount_usd: request.amount_usd.clone(),
        amount_base_units,
        status: "completed".to_string(),
        created_ms: now_ms,
        balance_usd,
    };

    let key = venice::topup_store_key(wallet);
    let bytes = match serde_json::to_vec_pretty(&stored) {
        Ok(bytes) => bytes,
        Err(e) => return common::backend(format!("serialize top-up result: {e}")),
    };

    if let Err(e) = host.store_put(&key, &bytes, false) {
        return common::backend(e);
    }

    petal::read_store(&key, common::MAX_STORED)
}

/// Fetch balance view for the wallet.
pub fn venice_balance(wallet: &str, address: &str) -> petal::DispatchResponse {
    let mut host = common::BloomHost;
    match venice::check_balance(&mut host, wallet, address) {
        Ok(view) => petal::read_json_value(&view),
        Err(response) => response,
    }
}

/// Fetch Venice models list (no auth required).
pub fn venice_models() -> petal::DispatchResponse {
    let mut host = common::BloomHost;
    match venice::list_models(&mut host) {
        Ok(value) => petal::read_json_value(&value),
        Err(response) => response,
    }
}
