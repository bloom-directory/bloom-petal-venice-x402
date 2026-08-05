# AGENTS.md

Build and contribute to the Venice x402 petal.

## Quick Start

```bash
cargo test --manifest-path route/Cargo.toml         # 46 tests (30 unit + 16 integration)
cargo clippy --all-targets --manifest-path route/Cargo.toml -- -D warnings
cargo fmt --manifest-path route/Cargo.toml --check
bash scripts/check-route-architecture.sh
```

All four must pass before pushing. CI runs them on every PR.

## Architecture Rules

1. **Route files in `route/files/` must be thin** — they parse params, call functions from `src/lib.rs`, and return `DispatchResponse`. No business logic in route files.

2. **Route files must never access the `secret:` store namespace.** The architecture check script enforces this. Route files may only use `state/` prefixed keys.

3. **All I/O goes through the `Host` trait** in `common.rs`. Never call `petal::sdk::*` directly from `siwe.rs`, `x402.rs`, `venice.rs`, or `types.rs`. Use `host.store_get()`, `host.http_fetch()`, `host.sign_hash()`, etc.

4. **`lib.rs` is the only place that constructs `BloomHost`** and calls `petal::sdk` directly (for `vfs_read`, `read_store`, `read_json_value`).

5. **Secrets never leave the secrets namespace.** SIWE sessions are stored under `venice-x402/sessions/{wallet}` (secret=true). Chat results and balance views go to `state/venice-x402/...` (secret=false).

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `common.rs` | Host trait + BloomHost impl, constants, error helpers, validation, base64, signature normalization |
| `siwe.rs` | EIP-4361 SIWE message format, EIP-191 hashing, session caching with 270s renewal |
| `x402.rs` | EIP-3009 TransferWithAuthorization, EIP-712 signing hash, 402 response parsing, payment header encoding |
| `venice.rs` | Venice HTTP client: authed_get, list_models, check_balance, top_up, chat_completion_raw, response interpretation |
| `types.rs` | Serde wire types with skip_serializing_if for optional fields |
| `lib.rs` | Public API wrappers + wallet address resolver via VFS |

## Testing

- **Unit tests** (30): In each module's `#[cfg(test)] mod tests`. Use `MockHost` from `common::test_helpers`. Test message formats, hashing, parsing, session caching, payment header construction.
- **Integration tests** (16): In `route/tests/integration.rs`. Test only the public API (`parse_chat_request`, `parse_topup_request`, type serialization).
- **No network tests**: All tests are hermetic. Venice API calls are mocked via `MockHost.http_results`.

## Key Constants

| Constant | Value | Notes |
|---|---|---|
| `VENICE_API` | `https://api.venice.ai/api/v1` | API base URL |
| `CHAIN_ID` | `8453` | Base L2 |
| `USDC_BASE` | `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` | Native USDC on Base |
| `SIWE_TTL_SECS` | `300` | 5-minute session lifetime |
| `SIWE_RENEWAL_SECS` | `270` | Renew 30s before expiry |
| `MAX_BODY` | `512 * 1024` | Max HTTP response body |
| `MAX_STORED` | `32 * 1024` | Max stored value size |

## Dependency Pinning

`petal-build.toml` pins `alloy-dyn-abi = "=1.6"` to prevent ABI-encoding-breaking patch releases. Do not bump without verifying EIP-712 hash compatibility.
