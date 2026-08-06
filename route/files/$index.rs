petal::route_file!(
    spec: petal::static_dir_spec(),
    fallible_list: Ok(petal::dir_names(&["models.json", "status.json"]))
);
