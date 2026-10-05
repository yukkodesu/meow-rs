use super::ownership::{OwnedResources, ResourceBackend};
use meow_tunnel::Tunnel;
use std::{io, net::IpAddr, path::PathBuf};

pub(super) struct DnsGuard {
    resources: OwnedResources<NativeDns>,
    tunnel: Tunnel,
}

impl DnsGuard {
    pub(super) fn setup(
        dns_addr: IpAddr,
        journal: Option<PathBuf>,
        tunnel: Tunnel,
    ) -> io::Result<Self> {
        let mut backend = NativeDns;
        if let Some(path) = journal.as_ref() {
            OwnedResources::recover(&mut backend, path)?;
        }
        let plan = backend.plan(dns_addr)?;
        let resources = OwnedResources::install(backend, journal, plan, true)?;
        Ok(Self { resources, tunnel })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Err(error) = self.resources.cleanup() {
            self.tunnel
                .report_tun_cleanup_failure(format!("DNS restoration: {error}"));
            tracing::error!("TUN DNS restoration failed: {error}");
        }
    }
}

struct NativeDns;

pub(super) fn recover(path: &std::path::Path) -> io::Result<()> {
    OwnedResources::recover(&mut NativeDns, path)
}

impl ResourceBackend for NativeDns {
    fn read(&mut self, resource: &str) -> io::Result<Option<String>> {
        native::read(resource)
    }
    fn write(&mut self, resource: &str, value: Option<&str>) -> io::Result<()> {
        native::write(
            resource,
            value.ok_or_else(|| io::Error::other("DNS backup is absent"))?,
        )
    }
    fn owner_alive(&self, pid: u32) -> io::Result<bool> {
        super::ownership::owner_alive(pid)
    }
    fn create_journal(&self, path: &std::path::Path) -> io::Result<std::fs::File> {
        super::ownership::create_privileged_journal(path)
    }
}

impl NativeDns {
    fn plan(&self, address: IpAddr) -> io::Result<Vec<(String, String)>> {
        native::plan(address)
    }
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;

    fn run(script: &str) -> io::Result<String> {
        super::super::ownership::powershell(script)
    }

    pub(super) fn plan(_: IpAddr) -> io::Result<Vec<(String, String)>> {
        let output = run(include_str!("windows_dns_plan.ps1"))?;
        let ids: Vec<String> = serde_json::from_str(&output).map_err(io::Error::other)?;
        ids.into_iter()
            .map(|id| {
                let (_, family) = decode(&id)?;
                let address = if family == "IPv4" { "127.0.0.1" } else { "::1" };
                Ok((
                    id,
                    serde_json::to_string(&[address]).map_err(io::Error::other)?,
                ))
            })
            .collect()
    }

    fn decode(resource: &str) -> io::Result<(&str, &str)> {
        let (guid, family) = resource
            .split_once('|')
            .ok_or_else(|| io::Error::other("Invalid DNS resource"))?;
        if guid.len() != 36
            || !guid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
            || !matches!(family, "IPv4" | "IPv6")
        {
            return Err(io::Error::other("Invalid DNS adapter identity"));
        }
        Ok((guid, family))
    }

    pub(super) fn read(resource: &str) -> io::Result<Option<String>> {
        let (guid, family) = decode(resource)?;
        let service = if family == "IPv4" { "Tcpip" } else { "Tcpip6" };
        let output = run(&format!(
            r#"$guid = '{guid}'; {adapter_lookup}; $key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{{{guid}}}'; $value = $key.GetValue('NameServer', ''); $servers = @($value -split '[,;\s]+' | Where-Object {{ $_ }}); ConvertTo-Json -InputObject $servers -Compress"#,
            adapter_lookup = include_str!("windows_dns_adapter.ps1"),
        ))?;
        let addresses: Vec<IpAddr> = serde_json::from_str(&output).map_err(io::Error::other)?;
        serde_json::to_string(&addresses)
            .map(Some)
            .map_err(io::Error::other)
    }

    pub(super) fn write(resource: &str, value: &str) -> io::Result<()> {
        let (guid, family) = decode(resource)?;
        let addresses: Vec<IpAddr> = serde_json::from_str(value).map_err(io::Error::other)?;
        if addresses
            .iter()
            .any(|address| address.is_ipv4() != (family == "IPv4"))
        {
            return Err(io::Error::other("DNS backup address family mismatch"));
        }
        let action = if addresses.is_empty() {
            "-ResetServerAddresses".into()
        } else {
            format!(
                "-ServerAddresses @({})",
                addresses
                    .iter()
                    .map(|address| format!("'{address}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        run(&format!(
            r#"$guid = '{guid}'; {adapter_lookup}; Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily {family} | Set-DnsClientServerAddress {action}"#,
            adapter_lookup = include_str!("windows_dns_adapter.ps1"),
        ))?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::process::Command;

    fn run(args: &[&str]) -> io::Result<String> {
        let mut command = Command::new("/usr/sbin/networksetup");
        command.args(args);
        let output = super::super::ownership::owned_command_output(
            &mut command,
            std::time::Duration::from_secs(20),
        )?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        super::networksetup::check_exit(
            args[0],
            output.status.code(),
            &stdout,
            &String::from_utf8_lossy(&output.stderr),
        )?;
        Ok(stdout)
    }

    pub(super) fn plan(address: IpAddr) -> io::Result<Vec<(String, String)>> {
        let services = super::networksetup::parse_services(&run(&["-listallnetworkservices"])?);
        let installed = serde_json::to_string(&[address]).map_err(io::Error::other)?;
        Ok(services
            .into_iter()
            .map(|service| (service, installed.clone()))
            .collect())
    }

    pub(super) fn read(resource: &str) -> io::Result<Option<String>> {
        if resource.starts_with('-') || resource.is_empty() {
            return Err(io::Error::other("Invalid DNS service"));
        }
        let output = run(&["-getdnsservers", resource])?;
        let addresses = super::networksetup::configured_dns_servers(&output);
        serde_json::to_string(&addresses)
            .map(Some)
            .map_err(io::Error::other)
    }

    pub(super) fn write(resource: &str, value: &str) -> io::Result<()> {
        read(resource)?;
        let addresses: Vec<IpAddr> = serde_json::from_str(value).map_err(io::Error::other)?;
        let values = super::networksetup::dns_server_args(&addresses);
        let mut args = vec!["-setdnsservers", resource];
        args.extend(values.iter().map(String::as_str));
        run(&args)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::fs;
    const RESOLV: &str = "/etc/resolv.conf";
    pub(super) fn plan(address: IpAddr) -> io::Result<Vec<(String, String)>> {
        Ok(vec![(
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = fs::metadata(RESOLV)?;
                serde_json::to_string(&(RESOLV, metadata.dev(), metadata.ino()))
                    .map_err(io::Error::other)?
            },
            format!("# Generated by meow-rs TUN\nnameserver {address}\n"),
        )])
    }
    fn identity(resource: &str) -> io::Result<(u64, u64)> {
        let (path, dev, ino): (String, u64, u64) =
            serde_json::from_str(resource).map_err(io::Error::other)?;
        if path != RESOLV {
            return Err(io::Error::other("Invalid resolver resource"));
        }
        Ok((dev, ino))
    }
    pub(super) fn read(resource: &str) -> io::Result<Option<String>> {
        use std::{io::Read, os::unix::fs::MetadataExt};
        let expected = identity(resource)?;
        let mut file = match fs::File::open(RESOLV) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            result => result?,
        };
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != expected {
            return Ok(None);
        }
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(Some(content))
    }
    pub(super) fn write(resource: &str, value: &str) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let expected = identity(resource)?;
        let mut file = fs::OpenOptions::new().write(true).open(RESOLV)?;
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != expected {
            return Err(io::Error::other("Resolver file identity changed"));
        }
        file.set_len(0)?;
        use std::io::Write;
        file.write_all(value.as_bytes())?;
        file.sync_all()
    }
}
#[cfg(any(target_os = "macos", test))]
mod networksetup {
    use std::io;
    use std::net::IpAddr;

    /// `-setdnsservers` keyword that clears a service's manual DNS list.
    const EMPTY: &str = "Empty";

    /// Classify one `networksetup` run. Exit 0 is success; any other exit
    /// — or death by signal (`code == None`) — is an error carrying the
    /// diagnostic, which networksetup prints on stdout (stderr is appended
    /// in case that ever changes), folded onto one line for the log.
    pub(super) fn check_exit(
        subcmd: &str,
        code: Option<i32>,
        stdout: &str,
        stderr: &str,
    ) -> io::Result<()> {
        if code == Some(0) {
            return Ok(());
        }
        let status = code.map_or_else(
            || "terminated by a signal".to_owned(),
            |c| format!("exit status {c}"),
        );
        let lines: Vec<&str> = stdout
            .lines()
            .chain(stderr.lines())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let detail = if lines.is_empty() {
            "no output".to_owned()
        } else {
            lines.join(" ")
        };
        Err(io::Error::other(format!(
            "networksetup {subcmd} failed ({status}): {detail}"
        )))
    }

    /// Enabled network services from `-listallnetworkservices` stdout.
    /// Line 1 is the "An asterisk (*) denotes that a network service is
    /// disabled." legend; disabled services carry a leading `*`.
    pub(super) fn parse_services(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('*'))
            .map(str::to_owned)
            .collect()
    }

    /// Configured addresses do not establish ownership; only the journal does.
    pub(super) fn configured_dns_servers(stdout: &str) -> Vec<IpAddr> {
        stdout
            .lines()
            .filter_map(|l| l.trim().parse::<IpAddr>().ok())
            .collect()
    }

    /// `-setdnsservers <svc>` arguments for `servers`; an empty list
    /// becomes `Empty`.
    pub(super) fn dns_server_args(servers: &[IpAddr]) -> Vec<String> {
        if servers.is_empty() {
            vec![EMPTY.to_owned()]
        } else {
            servers.iter().map(ToString::to_string).collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// networksetup's trailer on every parameter error.
        const PARAMS_INVALID: &str = "** Error: The parameters were not valid.";

        fn ips(list: &[&str]) -> Vec<IpAddr> {
            list.iter().map(|s| s.parse().unwrap()).collect()
        }

        #[test]
        fn no_servers_sentence_names_the_service() {
            // Real macOS 26 output (#695): the sentence names the service,
            // so the old exact match against "...on this device." missed it
            // and backed the sentence up as the server list.
            for svc in ["Ethernet", "Wi-Fi", "USB 10/100/1000 LAN"] {
                let out = format!("There aren't any DNS Servers set on {svc}.\n");
                assert!(configured_dns_servers(&out).is_empty(), "{out:?}");
            }
        }

        #[test]
        fn legacy_this_device_sentence_is_empty() {
            let out = "There aren't any DNS Servers set on this device.\n";
            assert!(configured_dns_servers(out).is_empty());
        }

        #[test]
        fn ipv4_and_ipv6_lists_are_kept_in_order() {
            assert_eq!(configured_dns_servers("9.9.9.9\n"), ips(&["9.9.9.9"]));
            assert_eq!(
                configured_dns_servers("1.1.1.1\n2606:4700:4700::1111\n8.8.8.8\n"),
                ips(&["1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"]),
            );
        }

        #[test]
        fn tolerates_crlf_padding_and_blank_lines() {
            assert_eq!(
                configured_dns_servers("  8.8.8.8 \r\n\r\n2001:4860:4860::8888\t\r\n"),
                ips(&["8.8.8.8", "2001:4860:4860::8888"]),
            );
            assert!(
                configured_dns_servers("There aren't any DNS Servers set on Ethernet. \r\n")
                    .is_empty()
            );
            assert!(configured_dns_servers("").is_empty());
        }

        #[test]
        fn configured_gateway_is_preserved_without_an_ownership_record() {
            assert_eq!(configured_dns_servers("198.18.0.1\n"), ips(&["198.18.0.1"]));
            assert_eq!(
                configured_dns_servers("198.18.0.1\n1.1.1.1\n"),
                ips(&["198.18.0.1", "1.1.1.1"])
            );
        }

        #[test]
        fn scoped_ipv6_is_not_a_server() {
            // `-setdnsservers` rejects it (exit 4), so it can never be a
            // configured server — and could never be restored.
            assert_eq!(
                configured_dns_servers("1.1.1.1\nfe80::1%en0\n"),
                ips(&["1.1.1.1"])
            );
        }

        #[test]
        fn error_text_never_parses_as_servers() {
            let out =
                format!("No Such Service is not a recognized network service.\n{PARAMS_INVALID}\n");
            assert!(configured_dns_servers(&out).is_empty());
            let err = check_exit("-getdnsservers", Some(4), &out, "").unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "networksetup -getdnsservers failed (exit status 4): \
                     No Such Service is not a recognized network service. {PARAMS_INVALID}"
                ),
            );
        }

        #[test]
        fn check_exit_accepts_only_exit_zero() {
            assert!(check_exit("-setdnsservers", Some(0), "", "").is_ok());
            assert!(check_exit("-getdnsservers", Some(0), "9.9.9.9\n", "").is_ok());
            assert!(check_exit(
                "-getdnsservers",
                Some(0),
                "There aren't any DNS Servers set on Ethernet.\n",
                ""
            )
            .is_ok());
        }

        #[test]
        fn check_exit_surfaces_rejected_set() {
            // The exact failure #695 hid: restoring the backed-up sentence.
            let out = format!(
                "There aren't any DNS Servers set on Ethernet. is not a valid IP address. \
                 No changes were saved...\n{PARAMS_INVALID}\n"
            );
            let err = check_exit("-setdnsservers", Some(4), &out, "").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.starts_with("networksetup -setdnsservers failed (exit status 4): "),
                "{msg}"
            );
            assert!(
                msg.contains("is not a valid IP address. No changes were saved..."),
                "{msg}"
            );
            assert!(msg.ends_with(PARAMS_INVALID), "{msg}");
            assert!(!msg.contains('\n'), "folded onto one line: {msg}");

            let out = format!(
                "bogus is not a valid IP address. No changes were saved...\n{PARAMS_INVALID}\n"
            );
            assert!(check_exit("-setdnsservers", Some(4), &out, "").is_err());
        }

        #[test]
        fn check_exit_without_output() {
            let err = check_exit("-setdnsservers", None, "", "").unwrap_err();
            assert_eq!(
                err.to_string(),
                "networksetup -setdnsservers failed (terminated by a signal): no output"
            );
            let err = check_exit("-listallnetworkservices", Some(1), "", "boom\n").unwrap_err();
            assert!(err.to_string().ends_with("(exit status 1): boom"), "{err}");
        }

        #[test]
        fn empty_list_restores_as_empty_keyword() {
            assert_eq!(dns_server_args(&[]), ["Empty"]);
            // The full #695 path for a DHCP service: snapshot the
            // no-servers sentence, restore with `Empty` (exit 0, no
            // output) — never the sentence itself.
            let saved = configured_dns_servers("There aren't any DNS Servers set on Ethernet.\n");
            assert_eq!(dns_server_args(&saved), ["Empty"]);
        }

        #[test]
        fn server_args_round_trip() {
            let servers = ips(&["1.1.1.1", "2606:4700:4700::1111"]);
            assert_eq!(
                dns_server_args(&servers),
                ["1.1.1.1", "2606:4700:4700::1111"]
            );
            let out = "1.1.1.1\n2606:4700:4700::1111\n";
            assert_eq!(configured_dns_servers(out), servers);
        }

        #[test]
        fn services_skip_legend_and_disabled() {
            let out = "An asterisk (*) denotes that a network service is disabled.\n\
                       Ethernet\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\r\n\n";
            assert_eq!(
                parse_services(out),
                ["Ethernet", "Wi-Fi", "USB 10/100/1000 LAN"]
            );
            assert!(parse_services("").is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Linux backend — /etc/resolv.conf
// ---------------------------------------------------------------------------
