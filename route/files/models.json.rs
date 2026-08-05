petal::route_file!(
    spec: petal::http_read_spec(60_000),
    read: |_ctx: &petal::Ctx| crate::venice_models()
);
