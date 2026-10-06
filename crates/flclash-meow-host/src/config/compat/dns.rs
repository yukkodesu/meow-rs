use crate::config::{warning, Diagnostic};
use meow_config::raw::RawConfig;

pub(super) fn filter_system_bootstrap(raw: &mut RawConfig, diagnostics: &mut Vec<Diagnostic>) {
    let Some(servers) = raw
        .dns
        .as_mut()
        .filter(|dns| dns.enable == Some(true))
        .and_then(|dns| dns.default_nameserver.as_mut())
    else {
        return;
    };
    if !servers.iter().any(|server| !is_system(server)) {
        return;
    }
    let original_count = servers.len();
    servers.retain(|server| !is_system(server));
    if servers.len() != original_count {
        diagnostics.push(warning(
            "dns.default-nameserver",
            "system/system:// is unsupported by meow-rs and was ignored; using the remaining bootstrap DNS entries",
        ));
    }
}

fn is_system(server: &str) -> bool {
    matches!(server.trim(), "system" | "system://")
}
