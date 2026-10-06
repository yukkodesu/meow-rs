#[path = "support/macos_routes.rs"]
mod routes;

#[test]
fn macos_native_observer_preserves_routes_across_neighbor_cache_expiry() {
    let before = include_str!("fixtures/macos_routes_before.txt");
    let after = include_str!("fixtures/macos_routes_after.txt");
    let baseline = routes::persistent_routes(before);
    assert_eq!(baseline, routes::persistent_routes(after));
    assert!(baseline.contains(&"default 192.168.64.1 UGScg en0".to_owned()));
    assert!(baseline.contains(&"192.168.64 link#5 UCS en0".to_owned()));
    let owned = format!("{after}\n198.18.0/16 link#10 USc utun4\n");
    let leaked = routes::persistent_routes(&owned);
    assert!(leaked.contains(&"198.18.0/16 link#10 USc utun4".to_owned()));
    assert_ne!(baseline, leaked, "An owned route leak must remain visible");
    let foreign = format!("{after}\n203.0.113/24 192.168.64.1 UGS en0\n");
    assert_ne!(baseline, routes::persistent_routes(&foreign));
    let missing = after.replace("default 192.168.64.1 UGScg en0", "");
    assert_ne!(baseline, routes::persistent_routes(&missing));
}
