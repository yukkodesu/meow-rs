use crate::config::{warning, Diagnostic};
use meow_config::raw::{RawConfig, RawNspValue};

pub(super) fn filter_system_nameservers(raw: &mut RawConfig, diagnostics: &mut Vec<Diagnostic>) {
    let Some(dns) = raw.dns.as_mut().filter(|dns| dns.enable == Some(true)) else {
        return;
    };
    for (field, servers) in [
        ("nameserver", dns.nameserver.as_mut()),
        ("fallback", dns.fallback.as_mut()),
        ("default-nameserver", dns.default_nameserver.as_mut()),
        (
            "proxy-server-nameserver",
            dns.proxy_server_nameserver.as_mut(),
        ),
    ] {
        if let Some(servers) = servers {
            filter_system(servers, &format!("dns.{field}"), diagnostics);
        }
    }
    if let Some(policy) = dns.nameserver_policy.as_mut() {
        for (domain, servers) in policy {
            if let RawNspValue::Many(servers) = servers {
                filter_system(
                    servers,
                    &format!("dns.nameserver-policy.{domain}"),
                    diagnostics,
                );
            }
        }
    }
}

fn filter_system(servers: &mut Vec<String>, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    if !servers.iter().any(|server| !is_system(server)) {
        return;
    }
    let original_count = servers.len();
    servers.retain(|server| !is_system(server));
    if servers.len() != original_count {
        diagnostics.push(warning(
            path,
            "System DNS entries are unsupported by meow-rs and were ignored; using the remaining DNS entries",
        ));
    }
}

fn is_system(server: &str) -> bool {
    let server = server.trim();
    matches!(server, "system" | "dhcp://system") || server.starts_with("system://")
}
