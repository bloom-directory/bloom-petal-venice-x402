petal::route_file!(
    spec: petal::signing_write_spec("venice-x402.topup").caps(&[
        "bloom:http",
        "bloom:store",
        "bloom:sign",
        "bloom:vfs.read",
    ]),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet").and_then(|value| {
            if petal::is_safe_segment(value) && value.len() <= 128 {
                Ok(value)
            } else {
                Err(petal::error(-3, "wallet alias is unsafe"))
            }
        }) {
            Ok(wallet) => wallet,
            Err(response) => return response,
        };
        let key = crate::topup_store_key(wallet);
        petal::read_store(&key, crate::MAX_STORED)
    },
    write: |ctx: &petal::Ctx, body: &[u8]| {
        if body.len() > 4 * 1024 {
            return petal::error(-3, "request body is too large");
        }
        let wallet = match petal::param(ctx, "wallet").and_then(|value| {
            if petal::is_safe_segment(value) && value.len() <= 128 {
                Ok(value.to_owned())
            } else {
                Err(petal::error(-3, "wallet alias is unsafe"))
            }
        }) {
            Ok(wallet) => wallet,
            Err(response) => return response,
        };
        let address = match crate::wallet_address(&wallet) {
            Ok(address) => address,
            Err(response) => return response,
        };
        let request: crate::TopUpRequest = match crate::serde_json::from_slice(body) {
            Ok(request) => request,
            Err(error) => return petal::error(-3, format!("invalid request JSON: {error}")),
        };
        if !crate::is_evm_address(&request.address) {
            return petal::error(-3, "address must be a valid EVM address");
        }
        crate::venice_topup(ctx, &wallet, &address, request)
    },
);
