use std::path::Path;

fn check_routes(root: &Path, path: &Path, count: &mut usize) {
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            check_routes(root, &path, count);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(root).unwrap().to_string_lossy();
            let parts: Vec<_> = relative.split('/').collect();
            if let Some(wallet) = parts.iter().position(|part| *part == "[wallet]") {
                if parts.get(wallet + 1) == Some(&"$index.rs") {
                    continue; // Host-owned account inventory, not an action.
                }
                // Bloom validates whole path segments, not an index captured
                // inside a filename. The latter builds but is refused at runtime.
                assert_eq!(parts.get(wallet + 1), Some(&"[index]"), "{relative}");
                *count += 1;
            }
        }
    }
}

#[test]
fn every_account_route_uses_blooms_authenticated_directory_pair() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("files");
    let mut count = 0;
    check_routes(&root, &root, &mut count);
    assert!(count >= 4, "account routes were not inspected");
}
