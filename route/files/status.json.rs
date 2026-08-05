petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "petal": "venice-x402",
        "status": "ok",
        "description": "Private AI inference via Venice's x402 payment protocol. Authenticate with SIWE, top up with USDC on Base via EIP-3009, and call Venice inference endpoints.",
        "canonical_routes": {
            "models": "models.json",
            "balance": "balance/<wallet>.json",
            "topup": "topup/<wallet>.json",
            "chat": "chat/<wallet>/<id>.json"
        },
        "provider": "venice",
        "auth": "siwe-eip4361",
        "payment": "x402-eip3009",
        "chain": "base",
        "chain_id": 8453,
        "currency": {
            "symbol": "USDC",
            "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "decimals": 6
        },
        "cross_petal_reference": {
            "privacy_pools": "bloom-petal-privacy-pools",
            "flow": "deposit ETH → withdraw to fresh wallet → fund with USDC on Base → top up x402 → private inference"
        },
        "docs": ["README.md", "AGENTS.md"]
    }))
);
