use crate::protocol::RpcError;
use meow_config::raw::RawConfig;
use serde::Serialize;
use serde_yaml::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub severity: &'static str,
    pub path: String,
    pub reason: String,
    pub suggestion: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub valid: bool,
    pub diagnostics: Vec<Diagnostic>,
}

fn problem(path: impl Into<String>, reason: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: "error",
        path: path.into(),
        reason: reason.into(),
        suggestion: "Remove or replace the unsupported configuration before applying it.",
    }
}

pub fn parse(content: &str, home: Option<&Path>) -> Result<(RawConfig, CheckResult), RpcError> {
    let raw = meow_config::parse_raw_yaml(content)
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    let mut document: Value = serde_yaml::from_str(content)
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    document
        .apply_merge()
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    let mut diagnostics = Vec::new();
    let _: RawConfig = serde_ignored::deserialize(document.clone(), |path| {
        diagnostics.push(problem(path.to_string(), "Unknown configuration field"));
    })
    .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    if let Some(map) = document.as_mapping() {
        for key in [
            "firewall",
            "udp",
            "udp-timeout",
            "external-ui-url",
            "subscriptions",
        ] {
            if map
                .get(Value::String(key.into()))
                .is_some_and(|v| !v.is_null())
            {
                diagnostics.push(problem(
                    key,
                    "This field is not supported by the embedded desktop host",
                ));
            }
        }
        if let Some(tun) = document.get("tun").and_then(Value::as_mapping) {
            for key in [
                "stack",
                "strict-route",
                "auto-detect-interface",
                "auto-redirect",
                "endpoint-independent-nat",
                "mtu-v6",
                "route-address",
                "route-exclude-address",
                "include-uid",
                "exclude-uid",
            ] {
                if tun
                    .get(Value::String(key.into()))
                    .is_some_and(|v| !v.is_null())
                {
                    diagnostics.push(problem(
                        format!("tun.{key}"),
                        "meow-rs ignores this capture setting",
                    ));
                }
            }
        }
        if let Some(geo) = document.get("geodata").and_then(Value::as_mapping) {
            for key in ["geodata-mode", "geodata-loader", "geoip-matcher"] {
                if geo
                    .get(Value::String(key.into()))
                    .is_some_and(|v| !v.is_null())
                {
                    diagnostics.push(Diagnostic {
                        severity: "warning",
                        path: format!("geodata.{key}"),
                        reason: "The meow-rs resource loader ignores this performance setting"
                            .into(),
                        suggestion: "Remove this setting; the meow-rs loader is used.",
                    });
                }
            }
        }
    }
    for (index, node) in document
        .get("proxies")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
    {
        check_proxy(node, &format!("proxies[{index}]"), &mut diagnostics);
    }
    for (index, listener) in document
        .get("listeners")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if let Some(map) = listener.as_mapping() {
            let path = format!("listeners[{index}]");
            check_keys(
                map,
                "name type listen port max-connections",
                &path,
                &mut diagnostics,
            );
            if !matches!(
                listener.get("type").and_then(Value::as_str),
                Some("mixed" | "http" | "socks5")
            ) {
                diagnostics.push(problem(
                    format!("{path}.type"),
                    "This desktop host only embeds HTTP, SOCKS5 and mixed listeners",
                ));
            }
        }
    }
    if let Some(sniffer) = document.get("sniffer") {
        if sniffer
            .get("force-dns-mapping")
            .is_some_and(|v| !v.is_null())
        {
            diagnostics.push(problem(
                "sniffer.force-dns-mapping",
                "meow-rs ignores this DNS behavior setting",
            ));
        }
        if let Some(sniff) = sniffer.get("sniff").and_then(Value::as_mapping) {
            for protocol in sniff.keys() {
                if !matches!(protocol.as_str(), Some("TLS" | "HTTP")) {
                    diagnostics.push(problem(
                        format!("sniffer.sniff.{}", protocol.as_str().unwrap_or("?")),
                        "Unsupported sniff protocol",
                    ));
                }
            }
        }
    }
    for (kind, providers) in [
        ("proxy-providers", document.get("proxy-providers")),
        ("rule-providers", document.get("rule-providers")),
    ] {
        if let Some(providers) = providers.and_then(Value::as_mapping) {
            for (name, provider) in providers {
                let name = name.as_str().unwrap_or("?");
                if let Some(overrides) = provider.get("override").and_then(Value::as_mapping) {
                    check_keys(
                        overrides,
                        "dialer-proxy",
                        &format!("{kind}.{name}.override"),
                        &mut diagnostics,
                    );
                }
                if provider
                    .get("allow-external-plugin")
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    diagnostics.push(problem(
                        format!("{kind}.{name}.allow-external-plugin"),
                        "External executable plugins are disabled in the privileged host",
                    ));
                }
            }
        }
    }
    if let Some(home) = home {
        if let Some(geodata) = raw.geodata.as_ref() {
            for (key, path) in [
                ("mmdb-path", &geodata.mmdb_path),
                ("asn-path", &geodata.asn_path),
                ("geosite-path", &geodata.geosite_path),
            ] {
                if let Some(path) = path {
                    if let Err(e) = contained_path(home, path) {
                        diagnostics.push(problem(format!("geodata.{key}"), e.message));
                    }
                }
            }
        }
        if let Some(path) = raw.external_ui.as_ref() {
            if let Err(e) = contained_path(home, path) {
                diagnostics.push(problem("external-ui", e.message));
            }
        }
    }
    let mut raw = raw;
    raw.strict = Some(true);
    let valid = !diagnostics.iter().any(|d| d.severity == "error");
    Ok((raw, CheckResult { valid, diagnostics }))
}

fn check_keys(
    map: &serde_yaml::Mapping,
    allowed: &str,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for key in map.keys() {
        let key = key.as_str().unwrap_or("?");
        if !allowed.split_whitespace().any(|a| a == key) {
            diagnostics.push(problem(
                format!("{path}.{key}"),
                "Unknown or unsupported option",
            ));
        }
    }
}

pub fn validate_provider_node(
    node: &std::collections::HashMap<String, Value>,
) -> Result<(), String> {
    let value = serde_yaml::to_value(node).map_err(|e| e.to_string())?;
    let mut diagnostics = Vec::new();
    check_proxy(&value, "proxy", &mut diagnostics);
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics
            .iter()
            .map(|d| format!("{}: {}", d.path, d.reason))
            .collect::<Vec<_>>()
            .join("; "))
    }
}

fn check_proxy(node: &Value, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let Some(map) = node.as_mapping() else {
        return;
    };
    let common = "name type dialer-proxy";
    let fields = match node.get("type").and_then(Value::as_str).unwrap_or("") {
        "direct" => "dns connect-timeout",
        "ss" => "server port udp password cipher plugin plugin-opts client-fingerprint smux mux",
        "trojan" => "server port udp password sni skip-cert-verify smux mux",
        "vless" => "server port udp uuid tls servername skip-cert-verify flow encryption client-fingerprint reality-opts ech-opts network ws-opts grpc-opts h2-opts http-upgrade-opts xhttp-opts smux mux alpn",
        "vmess" => "server port udp uuid alterId cipher tls servername skip-cert-verify client-fingerprint network ws-opts grpc-opts h2-opts http-upgrade-opts smux mux alpn",
        "http" => "server port username password tls skip-cert-verify headers",
        "socks5" => "server port udp username password tls skip-cert-verify",
        "anytls" => "server port udp password sni skip-cert-verify",
        "hysteria2" => "server port udp password sni skip-cert-verify alpn obfs obfs-password up down ports hop-interval fingerprint",
        "snell" => "server port udp psk version mode obfs-opts reuse",
        unknown => {diagnostics.push(problem(format!("{path}.type"),format!("Unsupported proxy protocol: {unknown}"))); ""},
    };
    check_keys(map, &format!("{common} {fields}"), path, diagnostics);
    for (key, fields) in [
        ("reality-opts", "public-key short-id support-x25519mlkem768"),
        ("ech-opts", "enable config dns"),
        ("ws-opts", "path headers max-early-data early-data-header-name"),
        ("grpc-opts", "grpc-service-name no-grpc-header"),
        ("h2-opts", "host path headers"),
        ("http-upgrade-opts", "path headers host"),
        ("xhttp-opts", "path mode headers host x-padding-bytes"),
        ("obfs-opts", "mode host"),
        ("smux", "enabled protocol max-connections min-streams max-streams padding-only-brutal brutal-opts"),
        ("mux", "enable enabled protocol max-connections min-streams max-streams padding concurrency"),
    ] {
        if let Some(opts) = node.get(key).and_then(Value::as_mapping) {
            check_keys(opts, fields, &format!("{path}.{key}"), diagnostics);
            if let Some(brutal) = opts.get(Value::String("brutal-opts".into())).and_then(Value::as_mapping) {
                check_keys(brutal,"enabled up down",&format!("{path}.{key}.brutal-opts"),diagnostics);
            }
        }
    }
    if let Some(plugin) = node.get("plugin").and_then(Value::as_str) {
        if !meow_proxy::shadowsocks_adapter::is_builtin_sip003_plugin(plugin) {
            diagnostics.push(problem(
                format!("{path}.plugin"),
                "External executable plugins are disabled",
            ));
        }
        if let Some(opts) = node.get("plugin-opts").and_then(Value::as_mapping) {
            let fields = match plugin {
                "obfs" | "obfs-local" => "mode host",
                "v2ray-plugin" => "mode host path tls skip-cert-verify mux headers",
                "shadow-tls" => "host password version strict",
                "kcptun" => "key crypt mode mtu sndwnd rcvwnd datashard parityshard dscp nocomp acknodelay nodelay interval resend nc sockbuf smuxver smuxbuf streambuf keepalive",
                "ech-tls-tunnel" => "host password ech servername alpn",
                _ => "",
            };
            check_keys(opts, fields, &format!("{path}.plugin-opts"), diagnostics);
        }
    }
}

pub fn contained_path(home: &Path, relative: &str) -> Result<PathBuf, RpcError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(RpcError::new(
            "invalid_path",
            "Managed paths must be relative and remain inside the product home",
        ));
    }
    let joined = home.join(path);
    let mut existing = joined.as_path();
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| RpcError::new("invalid_path", "Invalid managed path"))?;
    }
    let base = home
        .canonicalize()
        .map_err(|e| RpcError::new("invalid_path", e.to_string()))?;
    let resolved = existing
        .canonicalize()
        .map_err(|e| RpcError::new("invalid_path", e.to_string()))?;
    if !resolved.starts_with(base) {
        return Err(RpcError::new(
            "invalid_path",
            "Managed path resolves outside the product home",
        ));
    }
    Ok(joined)
}
