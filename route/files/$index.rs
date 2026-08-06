petal::route_file!(
    spec: petal::static_dir_spec(),
    list: vec![
        petal::dir("balance"),
        petal::dir("chat"),
        petal::dir("topup"),
        petal::file("models.json"),
        petal::file("status.json"),
    ]
);
