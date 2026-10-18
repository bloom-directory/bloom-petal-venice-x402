petal::route_file!(
    spec: petal::static_dir_spec(),
    list: vec![
        petal::writable("balance.json"),
        petal::writable("topup.json"),
        petal::dir("chat"),
    ]
);
