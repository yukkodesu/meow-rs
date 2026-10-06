#[test]
fn ordinary_cli_reads_without_installing_a_product_home_policy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("nodes.yaml");
    std::fs::write(&file, b"proxies: []").unwrap();
    assert_eq!(
        meow_common::managed_files::read(&file).unwrap(),
        b"proxies: []"
    );
}
