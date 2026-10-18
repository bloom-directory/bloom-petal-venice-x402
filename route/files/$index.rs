petal::route_file!(
    spec: petal::static_dir_spec(),
    list: vec![
        petal::dir("accounts"),
        petal::file("models.json"),
        petal::file("status.json"),
    ]
);
