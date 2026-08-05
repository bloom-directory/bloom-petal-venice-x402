petal::route_file!(
    spec: petal::static_dir_spec(),
    read: |_ctx: &petal::Ctx| {
        petal::framework_fallible_list(_ctx, Ok(petal::dir_names(&["models.json", "status.json"])))
    }
);
