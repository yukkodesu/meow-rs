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
                if let (Some(home), Some(path)) =
                    (home, provider.get("path").and_then(Value::as_str))
                {
                    if let Err(error) = contained_path(home, path) {
                        diagnostics.push(problem(format!("{kind}.{name}.path"), error.message));
                    }
                }
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
        diagnostics.push(problem(path, "Expected a proxy mapping"));
        return;
    };
    let common = "name type dialer-proxy";
    if node.get("type").and_then(Value::as_str) == Some("direct")
        && node.get("name").and_then(Value::as_str) != Some("DIRECT")
    {
        diagnostics.push(Diagnostic {
            severity: "error",
            path: format!("{path}.name"),
            reason: "meow-rs direct adapters always expose the name DIRECT; aliases cannot be selected or referenced reliably".into(),
            suggestion: "Use the built-in DIRECT target instead of a named direct alias.",
        });
    }
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
    check_option_types(map, path, diagnostics, false);
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
                diagnostics.push(problem(
                    format!("{path}.{key}"),
                    "Expected an options mapping",
                ));
                continue;
            };
            check_keys(opts, fields, &format!("{path}.{key}"), diagnostics);
            check_option_types(
                opts,
                &format!("{path}.{key}"),
                diagnostics,
                key == "h2-opts",
            );
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
            check_plugin_options(plugin, opts, &format!("{path}.plugin-opts"), diagnostics);
        }
    } else if node.get("plugin-opts").is_some() {
        diagnostics.push(problem(
            format!("{path}.plugin-opts"),
            "Plugin options require a supported plugin",
        ));
    }
}

fn check_plugin_options(plugin: &str, opts: &Value, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let (text, boolean, integer) = match plugin {
        "obfs" | "simple-obfs" => ("mode host obfs obfs-host", "", ""),
        "v2ray-plugin" => ("mode host path header", "tls skip-cert-verify mux", ""),
        "gost-plugin" => ("mode host path header name-cert-verify fingerprint certificate private-key ech-config ech-opts.config", "tls skip-cert-verify mux ech-enable ech-opts.enable", ""),
        "shadow-tls" => ("host password alpn name-cert-verify fingerprint certificate private-key", "skip-cert-verify strict-mode", "version"),
        "restls" => ("host password version-hint restls-script name-cert-verify fingerprint", "skip-cert-verify force-tls12", ""),
        "jls" => ("host username password alpn", "", ""),
        "kcptun" => ("key crypt mode", "nocomp acknodelay", "conn autoexpire scavengettl mtu ratelimit sndwnd rcvwnd datashard parityshard dscp nodelay interval resend nc sockbuf smuxver smuxbuf framesize streambuf keepalive"),
        "ech-tls-tunnel" => ("mode sni path ech_config ech-config fingerprint client-fingerprint client_fingerprint", "", ""),
        _ => ("", "", ""),
    };
    let includes = |fields: &str, key: &str| fields.split_whitespace().any(|field| field == key);
    let check = |key: &str, value: &Value, field: String, diagnostics: &mut Vec<Diagnostic>| {
        let key = if matches!(plugin, "obfs" | "simple-obfs") {
            key.to_string()
        } else {
            key.trim().to_ascii_lowercase()
        };
        let scalar = match value {
            Value::String(s) => Some(s.trim().to_string()),
            Value::Bool(v) => Some(v.to_string()),
            Value::Number(v) => Some(v.to_string()),
            _ => None,
        };
        let valid = if includes(boolean, &key) {
            scalar.as_deref().is_some_and(|s| {
                matches!(
                    s.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off"
                ) || (s.is_empty()
                    && (plugin == "v2ray-plugin" || (plugin == "kcptun" && key == "acknodelay")))
            })
        } else if includes(integer, &key) {
            scalar.as_deref().is_some_and(|s| s.parse::<u64>().is_ok())
        } else if includes(text, &key) {
            value.as_str().is_some_and(|s| {
                !s.contains(';')
                    && (key != "header"
                        || s.split_once(':')
                            .is_some_and(|(name, _)| !name.trim().is_empty()))
            })
        } else {
            diagnostics.push(problem(field, "Unknown or unsupported plugin option"));
            return;
        };
        if matches!(key.as_str(), "certificate" | "private-key")
            && !value.as_str().is_some_and(|s| s.contains("-----BEGIN"))
        {
            diagnostics.push(problem(field, "File-backed plugin certificates and keys are unsupported in the host; use inline PEM to avoid unconfined file reads"));
            return;
        }
        let recognized = if plugin == "kcptun" && key == "crypt" {
            scalar.as_deref().is_some_and(|s| {
                matches!(
                    s.to_ascii_lowercase().as_str(),
                    "aes"
                        | "aes-256"
                        | "aes-128"
                        | "aes-192"
                        | "aes-128-gcm"
                        | "salsa20"
                        | "none"
                        | "null"
                        | "xor"
                        | "tea"
                        | "xtea"
                        | "blowfish"
                        | "twofish"
                        | "cast5"
                        | "3des"
                        | "sm4"
                )
            })
        } else if plugin == "kcptun" && key == "mode" {
            scalar.as_deref().is_some_and(|s| {
                matches!(
                    s.to_ascii_lowercase().as_str(),
                    "normal" | "fast" | "fast2" | "fast3" | "manual"
                )
            })
        } else {
            true
        };
        if !valid || !recognized {
            diagnostics.push(problem(field, "Invalid plugin option value; coercion, flattening or discarded values are not allowed"));
        }
    };
    match opts {
        Value::String(opts) => {
            for token in opts
                .split(';')
                .map(str::trim)
                .filter(|token| !token.is_empty())
            {
                let (key, value) = token.split_once('=').unwrap_or((token, "true"));
                check(
                    key,
                    &Value::String(value.trim().to_string()),
                    format!("{path}.{}", key.trim()),
                    diagnostics,
                );
            }
        }
        Value::Mapping(opts) => {
            for (key, value) in opts {
                let Some(name) = key.as_str().filter(|s| !s.contains([';', '='])) else {
                    diagnostics.push(problem(
                        format!("{path}.?"),
                        "Expected a plugin option name without separators",
                    ));
                    continue;
                };
                let field = format!("{path}.{name}");
                if name.eq_ignore_ascii_case("headers")
                    && matches!(plugin, "v2ray-plugin" | "gost-plugin")
                {
                    if let Some(headers) = value.as_mapping() {
                        for (name, value) in headers {
                            if !name.as_str().is_some_and(|s| {
                                !s.trim().is_empty() && !s.contains([';', '=', ':'])
                            }) || !value.as_str().is_some_and(|s| !s.contains(';'))
                            {
                                diagnostics.push(problem(format!("{field}.{}", name.as_str().unwrap_or("?")), "Expected a string header name and value without SIP003 separators"));
                            }
                        }
                    } else {
                        diagnostics.push(problem(field, "Expected a headers mapping"));
                    }
                } else if name.eq_ignore_ascii_case("alpn")
                    && includes(text, "alpn")
                    && value.is_sequence()
                {
                    if !value
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .all(|v| v.as_str().is_some_and(|s| !s.contains([',', ';'])))
                    {
                        diagnostics
                            .push(problem(field, "Expected ALPN strings without separators"));
                    }
                } else if name == "ech-opts" && plugin == "gost-plugin" && value.is_mapping() {
                    for (key, value) in value.as_mapping().unwrap() {
                        let key = key.as_str().unwrap_or("?");
                        check(
                            &format!("ech-opts.{key}"),
                            value,
                            format!("{field}.{key}"),
                            diagnostics,
                        );
                    }
                } else {
                    check(name, value, field, diagnostics);
                }
            }
        }
        _ => diagnostics.push(problem(
            path,
            "Expected a plugin options mapping or SIP003 string",
        )),
    }
}

fn check_option_types(
    map: &serde_yaml::Mapping,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
    h2_hosts: bool,
) {
    for (key, value) in map {
        let Some(key) = key.as_str() else { continue };
        let strings = |v: &Value| {
            v.as_sequence()
                .is_some_and(|seq| seq.iter().all(Value::is_string))
        };
        let valid = match key {
            "udp"
            | "tls"
            | "skip-cert-verify"
            | "enabled"
            | "enable"
            | "padding"
            | "only-tcp"
            | "support-x25519mlkem768"
            | "no-grpc-header"
            | "reuse" => value.is_bool(),
            "host" if h2_hosts => strings(value),
            "name"
            | "type"
            | "server"
            | "username"
            | "password"
            | "cipher"
            | "psk"
            | "uuid"
            | "sni"
            | "servername"
            | "dialer-proxy"
            | "plugin"
            | "client-fingerprint"
            | "flow"
            | "encryption"
            | "network"
            | "public-key"
            | "short-id"
            | "config"
            | "path"
            | "mode"
            | "protocol"
            | "grpc-service-name"
            | "early-data-header-name"
            | "obfs"
            | "obfs-password"
            | "fingerprint"
            | "host" => value.is_string(),
            "port" | "alterId" | "connect-timeout" | "max-connections" | "min-streams"
            | "max-streams" | "max-early-data" => value.as_u64().is_some(),
            "alpn" => {
                strings(value)
                    || (path.ends_with("plugin-opts") && value.is_string())
                    || (map
                        .get(Value::String("type".into()))
                        .and_then(Value::as_str)
                        == Some("hysteria2")
                        && value.is_string())
            }
            "headers" => {
                if let Some(headers) = value.as_mapping() {
                    for (name, header) in headers {
                        if !name.is_string() || !header.is_string() {
                            diagnostics.push(problem(
                                format!("{path}.headers.{}", name.as_str().unwrap_or("?")),
                                "Expected a string header name and value",
                            ));
                        }
                    }
                    true
                } else {
                    false
                }
            }
            _ => true,
        };
        if !valid {
            diagnostics.push(problem(
                format!("{path}.{key}"),
                "Invalid value type for this supported option",
            ));
        }
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
