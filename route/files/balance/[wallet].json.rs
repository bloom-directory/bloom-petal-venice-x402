petal::route_file!(
    spec: petal::signing_write_spec("venice-x402.balance").caps(&[
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
        let key = format!("state/balance/{wallet}.json");
        petal::read_store(&key, crate::MAX_STORED)
    },
    write: |ctx: &petal::Ctx, body: &[u8]| {
        if !body.is_empty() && body != b"{}" {
            return petal::error(-3, "balance refresh body must be empty or {}");
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
        crate::venice_balance(ctx, &wallet, &address)
    },
);
