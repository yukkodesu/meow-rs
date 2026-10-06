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

pub fn validation_path(reason: &str) -> String {
    reason.split_once(':').map_or_else(
        || "$".into(),
        |(field, _)| {
            if !field.is_empty()
                && field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-_[]".contains(c))
            {
                field.into()
            } else {
                "$".into()
            }
        },
    )
}

fn problem(path: impl Into<String>, reason: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: "error",
        path: path.into(),
        reason: reason.into(),
        suggestion: "Remove or replace the unsupported configuration before applying it.",
    }
}

fn warning(path: impl Into<String>, reason: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: "warning",
        path: path.into(),
        reason: reason.into(),
        suggestion: "",
    }
}

pub fn parse(content: &str, home: Option<&Path>) -> Result<(RawConfig, CheckResult), RpcError> {
    let mut raw = meow_config::parse_raw_yaml(content)
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    let mut document: Value = serde_yaml::from_str(content)
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    document
        .apply_merge()
        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    let mut diagnostics = Vec::new();
    if raw
        .authentication
        .as_ref()
        .is_some_and(|entries| !entries.is_empty())
    {
        diagnostics.push(Diagnostic {
            severity: "warning",
            path: "authentication".into(),
            reason: "meow-rs always bypasses proxy authentication for 127.0.0.1/32 and ::1/128. skip-auth-prefixes only adds bypasses; it cannot disable these defaults.".into(),
            suggestion: "Do not rely on proxy authentication to restrict these local callers.",
        });
    }
    if let Some(level) = raw.log_level.as_deref() {
        if !meow_api::log_stream::is_valid_log_level(level) {
            diagnostics.push(problem("log-level", "Unsupported log level"));
        }
    }
    let _: RawConfig = serde_ignored::deserialize(document.clone(), |path| {
        diagnostics.push(warning(
            path.to_string(),
            "Unknown configuration field ignored by meow-rs",
        ));
    })
    .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
    for (index, node) in document
        .get("proxies")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
    {
        check_proxy(node, &format!("proxies[{index}]"), &mut diagnostics);
    }
    for (kind, providers) in [
        ("proxy-providers", document.get("proxy-providers")),
        ("rule-providers", document.get("rule-providers")),
    ] {
        if let Some(providers) = providers.and_then(Value::as_mapping) {
            for (name, provider) in providers {
                let name = name.as_str().unwrap_or("?");
                if let (Some(home), Some(path)) =
                    (home, provider.get("path").and_then(Value::as_str))
                {
                    if let Err(error) = contained_path(home, path) {
                        diagnostics.push(problem(format!("{kind}.{name}.path"), error.message));
                    }
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
        if raw.external_ui.is_some() && crate::native::privileged() {
            diagnostics.push(problem("external-ui", "An elevated host cannot securely serve caller-supplied static files; use the built-in dashboard"));
        }
        let geodata = raw.geodata.get_or_insert_with(Default::default);
        for (key, path, default) in [
            ("mmdb-path", &mut geodata.mmdb_path, "Country.mmdb"),
            ("asn-path", &mut geodata.asn_path, "GeoLite2-ASN.mmdb"),
            ("geosite-path", &mut geodata.geosite_path, "geosite.dat"),
        ] {
            match contained_path(home, path.as_deref().unwrap_or(default)) {
                Ok(resolved) => *path = Some(resolved.to_string_lossy().into_owned()),
                Err(e) => diagnostics.push(problem(format!("geodata.{key}"), e.message)),
            }
        }
        if let Some(path) = raw.external_ui.as_mut() {
            match contained_path(home, path) {
                Ok(resolved) => *path = resolved.to_string_lossy().into_owned(),
                Err(e) => diagnostics.push(problem("external-ui", e.message)),
            }
        }
    }
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
            diagnostics.push(warning(
                format!("{path}.{key}"),
                "Unknown or unsupported option ignored by meow-rs",
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
    for diagnostic in diagnostics.iter().filter(|d| d.severity == "warning") {
        tracing::warn!("{}: {}", diagnostic.path, diagnostic.reason);
    }
    if diagnostics.iter().any(|d| d.severity == "error") {
        Err(diagnostics
            .iter()
            .filter(|d| d.severity == "error")
            .map(|d| format!("{}: {}", d.path, d.reason))
            .collect::<Vec<_>>()
            .join("; "))
    } else {
        Ok(())
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
        _ => return,
    };
    check_keys(map, &format!("{common} {fields}"), path, diagnostics);
    for (key, fields) in [
        ("reality-opts", "public-key short-id support-x25519mlkem768"),
        ("ech-opts", "enable config dns"),
        (
            "ws-opts",
            "path headers max-early-data early-data-header-name",
        ),
        ("grpc-opts", "grpc-service-name no-grpc-header"),
        ("h2-opts", "host path headers"),
        ("http-upgrade-opts", "path headers host"),
        ("xhttp-opts", "path mode headers host x-padding-bytes"),
        ("obfs-opts", "mode host"),
        (
            "smux",
            "enabled protocol max-connections min-streams max-streams padding only-tcp",
        ),
        (
            "mux",
            "enabled protocol max-connections min-streams max-streams padding only-tcp",
        ),
    ] {
        if let Some(value) = node.get(key) {
            let Some(opts) = value.as_mapping() else {
                continue;
            };
            check_keys(opts, fields, &format!("{path}.{key}"), diagnostics);
            if let Some(brutal) = opts
                .get(Value::String("brutal-opts".into()))
                .and_then(Value::as_mapping)
            {
                check_keys(
                    brutal,
                    "enabled up down",
                    &format!("{path}.{key}.brutal-opts"),
                    diagnostics,
                );
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
        if let Some(opts) = node.get("plugin-opts") {
            check_plugin_files(opts, &format!("{path}.plugin-opts"), diagnostics);
        }
    }
}

fn check_plugin_files(opts: &Value, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let check = |key: &str, value: &str, diagnostics: &mut Vec<Diagnostic>| {
        let key = key.trim().to_ascii_lowercase();
        if matches!(key.as_str(), "certificate" | "private-key") && !value.contains("-----BEGIN") {
            diagnostics.push(problem(format!("{path}.{key}"), "File-backed plugin certificates and keys are unsupported in the host; use inline PEM to avoid unconfined file reads"));
        }
    };
    match opts {
        Value::String(opts) => {
            for token in opts.split(';') {
                if let Some((key, value)) = token.split_once('=') {
                    check(key, value, diagnostics);
                }
            }
        }
        Value::Mapping(opts) => {
            for (key, value) in opts {
                if let (Some(key), Some(value)) = (key.as_str(), value.as_str()) {
                    check(key, value, diagnostics);
                }
            }
        }
        _ => {}
    }
}

pub fn contained_path(home: &Path, relative: &str) -> Result<PathBuf, RpcError> {
    let path = Path::new(relative);
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
        || (!path.is_absolute()
            && path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::Prefix(_) | std::path::Component::RootDir
                )
            }))
    {
        return Err(RpcError::new(
            "invalid_path",
            "Managed paths must remain inside the product home without parent traversal",
        ));
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        home.join(path)
    };
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
