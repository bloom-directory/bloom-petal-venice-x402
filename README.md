# bloom-petal-venice-x402

Pay-per-request private AI inference via Venice's [x402 payment protocol](https://docs.venice.ai/docs/x402).

## How It Works

```
User → Bloom VFS wallet → SIWE auth → Venice x402 balance → chat completions
                          ↓                       ↑
                     bloom:sign              EIP-3009 USDC
                     (EIP-191)              on Base (L2)
```

1. **SIWE Authentication**: The wallet signs an EIP-4361 message (hashed via EIP-191). The signature is sent as a Base64-encoded JSON payload in the `X-Sign-In-With-X` header.

2. **x402 Top-Up**: When Venice returns HTTP 402, the response contains payment requirements. The petal constructs an EIP-3009 `TransferWithAuthorization`, signs it via EIP-712, and retries with the `X-402-Payment` header. USDC is transferred on Base (chainId 8453).

3. **Chat Completions**: Standard OpenAI-compatible `POST /chat/completions` with SIWE auth. If the response includes a `X-Balance-Remaining` header, it's persisted with the chat result.

## Architecture

```
route/
├── src/
│   ├── lib.rs          — Public API: venice_chat, venice_topup, venice_balance, venice_models
│   ├── common.rs       — Host trait, BloomHost impl, constants, error/validation helpers
│   ├── siwe.rs         — EIP-4361 SIWE message construction, EIP-191 hashing, session caching
│   ├── x402.rs         — EIP-3009 authorization, EIP-712 signing, 402 response parsing
│   ├── venice.rs       — Venice HTTP client: models, balance, top-up, chat completions
│   └── types.rs        — Wire types: ChatRequest, BalanceView, StoredChat, StoredTopUp
├── files/
│   ├── status.json.rs              — Static petal health endpoint
│   ├── models.json.rs              — Proxy to Venice's public models list
│   ├── balance/[wallet].json.rs    — Explicit refresh write + cached balance read
│   ├── topup/[wallet].json.rs      — Top-up handler (SIWE + EIP-3009 payment)
│   ├── chat/[wallet]/[id].json.rs  — Chat completion handler (SIWE auth)
│   └── $index.rs                   — Directory listing
└── tests/
    └── integration.rs              — 16 public API tests
```

### Design Principles

- **Host trait abstraction**: All I/O (store, HTTP, signing, time, randomness) goes through the `Host` trait in `common.rs`. Production uses `BloomHost`; tests inject `MockHost`. This makes the entire business logic unit-testable without network access.

- **Session caching**: SIWE sessions are cached in the secrets store with a 270-second renewal threshold (5-minute lifetime). Sessions survive across route dispatches.

- **No API keys**: Authentication is purely cryptographic — the wallet signs messages and payments. No Venice API key or secret is stored.

- **Route files are thin**: The `.rs` files in `files/` only parse parameters, call `lib.rs` functions, and return `DispatchResponse`. All business logic lives in `src/`.

## API Reference

### `GET /models.json`
Public proxy to Venice's model list. Cached for 60 seconds. No auth required.

### `GET /status.json`
Static health check endpoint. Returns petal name and version.

### `GET /balance/{wallet}.json`
Reads the last known balance from the state store. Wallet alias is validated as a safe path segment.
On a fresh install this returns not found until the balance has been refreshed.

### `POST /balance/{wallet}.json`
Refreshes the cached balance. Write either an empty body or `{}`. The wallet signs
the `venice-x402.balance` SIWE intent through Bloom's owner-visible approval flow;
after approval, retry the identical write and then read the route with `GET`.

### `POST /topup/{wallet}.json`
Initiates an x402 top-up. Requires a signed request with:
```json
{
  "address": "0x...",
  "amount_usd": "5.00"
}
```
The wallet signs the `venice-x402.topup` intent. The petal constructs and signs an EIP-3009 payment authorization.

### `POST /chat/{wallet}/{id}.json`
Sends a chat completion request. Requires a signed request with:
```json
{
  "address": "0x...",
  "model": "llama-3.3-70b",
  "messages": [{"role": "user", "content": "Hello!"}],
  "system_prompt": "Be concise.",
  "temperature": 0.7,
  "max_tokens": 1024,
  "stream": false
}
```
The wallet signs the `venice-x402.chat` intent. Results are persisted to `state/venice-x402/chat/{wallet}/{id}`.

## Capabilities

| Capability | Usage |
|---|---|
| `bloom:http` | Fetch Venice API endpoints |
| `bloom:store` | Persist chat results, top-up records, balance views |
| `bloom:sign` | Sign SIWE messages and EIP-3009 authorizations |
| `bloom:vfs.read` | Resolve wallet aliases to EVM addresses |

## Network Policy

Only `api.venice.ai` is allowed, restricted to:
- `GET /api/v1/models`
- `POST /api/v1/chat/completions`
- `GET /api/v1/x402/balance/*`
- `POST /api/v1/x402/top-up`
- `GET /api/v1/x402/transactions`

## Cross-Petal Narrative

This petal pairs with [bloom-petal-privacy-pools](https://github.com/bloom-directory/bloom-petal-privacy-pools):

1. Deposit ETH into a privacy pool to anonymize funds
2. Withdraw to a fresh wallet address
3. Fund the fresh wallet with USDC on Base
4. Top up the Venice x402 balance via this petal
5. Run private AI inference — privacy pools anonymize the *money*, Venice TEE/E2EE anonymizes the *inference*

## Building

```bash
cargo fmt --manifest-path route/Cargo.toml --check
cargo clippy --all-targets --manifest-path route/Cargo.toml -- -D warnings
cargo test --manifest-path route/Cargo.toml
bash scripts/check-route-architecture.sh
```

## License

MIT
