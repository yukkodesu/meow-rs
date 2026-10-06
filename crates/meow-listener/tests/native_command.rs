#![cfg(feature = "listener-tun")]
use meow_listener::tun::ownership::owned_command_output;
use std::{process::Command, time::Duration};

#[test]
fn native_child_fixture() {
    match std::env::var("MEOW_NATIVE_CHILD_FIXTURE").as_deref() {
        Ok("wait") => std::thread::sleep(Duration::from_secs(30)),
        Ok("flood") => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&vec![b'x'; 2 * 1024 * 1024]);
        }
        #[cfg(windows)]
        Ok("acl") => {
            let output = meow_listener::tun::ownership::powershell(
                r#"$acl = Get-Acl -LiteralPath $env:MEOW_NATIVE_ACL_PATH;
                   foreach ($name in 'Get-Acl','Get-NetAdapter','Get-DnsClientServerAddress') {
                       $command = Get-Command $name;
                       if (!$command.Module.Path.StartsWith($PSHOME, [StringComparison]::OrdinalIgnoreCase)) {
                           throw "Native command loaded outside the system PowerShell directory: $name"
                       }
                   }
                   $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value"#,
            )
            .unwrap();
            assert!(
                output.starts_with("S-1-"),
                "ACL owner was not read: {output}"
            );
        }
        #[cfg(windows)]
        Ok("slow-powershell") => {
            let output = meow_listener::tun::ownership::powershell(
                "Start-Sleep -Seconds 21; 'native command completed'",
            )
            .unwrap();
            assert_eq!(output, "native command completed");
        }
        #[cfg(windows)]
        Ok("dns-plan-excludes-owned-tun") => {
            let fixture = include_str!("fixtures/windows_dns_commands.ps1");
            let plan = include_str!("../src/tun/windows_dns_plan.ps1");
            let output = meow_listener::tun::ownership::powershell(&format!(
                "{fixture}\n$excludedInterfaceIndex = 2\n{plan}"
            ))
            .unwrap();
            let resources: Vec<String> = serde_json::from_str(&output).unwrap();
            assert_eq!(
                resources,
                [
                    "11111111-1111-1111-1111-111111111111|IPv4",
                    "11111111-1111-1111-1111-111111111111|IPv6",
                ]
            );
            let lookup = include_str!("../src/tun/windows_dns_adapter.ps1");
            let error = meow_listener::tun::ownership::powershell(&format!(
                "{fixture}\n$guid = '33333333-3333-3333-3333-333333333333'\n{lookup}"
            ))
            .unwrap_err();
            assert!(error
                .to_string()
                .contains("restoration cannot be confirmed"));
        }
        #[cfg(windows)]
        Ok("dns-plan") => {
            let fixture = include_str!("fixtures/windows_dns_commands.ps1");
            let plan = include_str!("../src/tun/windows_dns_plan.ps1");
            let output =
                meow_listener::tun::ownership::powershell(&format!("{fixture}\n{plan}")).unwrap();
            let mut resources: Vec<String> = serde_json::from_str(&output).unwrap();
            resources.sort();
            assert_eq!(
                resources,
                [
                    "11111111-1111-1111-1111-111111111111|IPv4",
                    "11111111-1111-1111-1111-111111111111|IPv6",
                    "22222222-2222-2222-2222-222222222222|IPv6",
                ]
            );
            let error = meow_listener::tun::ownership::powershell(&format!(
                "{fixture}\n$script:queryFailure = $true\n{plan}"
            ))
            .unwrap_err();
            assert!(error.to_string().contains("DNS provider query failed"));
            for guid in [
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ] {
                let lookup = include_str!("../src/tun/windows_dns_adapter.ps1");
                let output = meow_listener::tun::ownership::powershell(&format!(
                    "{fixture}\n$guid = '{guid}'\n{lookup}\n([guid]$adapter[0].InterfaceGuid).ToString('D')"
                )).unwrap();
                assert_eq!(output, guid);
            }
            let error = meow_listener::tun::ownership::powershell(&format!(
                "{fixture}\n$script:adapterQueryFailure = $true\n{plan}"
            ))
            .unwrap_err();
            assert!(error.to_string().contains("Adapter provider query failed"));
            let error = meow_listener::tun::ownership::powershell(&format!(
                "{fixture}\n$script:invalidGuid = $true\n{plan}"
            ))
            .unwrap_err();
            assert!(error.to_string().contains("not-a-guid"));
        }
        _ => {}
    }
}

#[cfg(windows)]
#[test]
fn windows_dns_plan_excludes_owned_tun_and_missing_external_adapter_still_fails() {
    let output = owned_command_output(
        &mut child("dns-plan-excludes-owned-tun"),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn windows_dns_plan_handles_missing_family_records_but_reports_query_failures() {
    let output = owned_command_output(&mut child("dns-plan"), Duration::from_secs(125)).unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn powershell_allows_slow_windows_native_command_completion() {
    let output =
        owned_command_output(&mut child("slow-powershell"), Duration::from_secs(65)).unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn acl_module_loads_with_a_parent_powershell_core_module_path() {
    let directory = tempfile::tempdir().unwrap();
    let module = directory.path().join("Microsoft.PowerShell.Security");
    std::fs::create_dir(&module).unwrap();
    std::fs::write(
        module.join("Microsoft.PowerShell.Security.psd1"),
        "@{ ModuleVersion='7.0.0'; RootModule='incompatible.psm1'; \
         PowerShellVersion='3.0'; CompatiblePSEditions=@('Core'); \
         FunctionsToExport=@('Get-Acl') }",
    )
    .unwrap();
    std::fs::write(
        module.join("incompatible.psm1"),
        "throw 'Core module must not load in Windows PowerShell'",
    )
    .unwrap();
    let mut command = child("acl");
    command.env("PSModulePath", directory.path());
    command.env("MEOW_NATIVE_ACL_PATH", directory.path());
    let output = owned_command_output(&mut command, Duration::from_secs(30)).unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "native_child_fixture", "--nocapture"]);
    command.env("MEOW_NATIVE_CHILD_FIXTURE", mode);
    command
}

#[test]
fn cleanup_commands_own_and_reap_their_children() {
    let output = owned_command_output(&mut child("success"), Duration::from_secs(5)).unwrap();
    assert!(output.status.success());
    let error = owned_command_output(&mut child("wait"), Duration::from_millis(100)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let error = owned_command_output(&mut child("flood"), Duration::from_secs(5)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
}

#[cfg(windows)]
#[test]
#[ignore = "read-only inspection of actual Windows adapters; opt in explicitly"]
fn windows_dns_plan_readonly_inspection() {
    assert_eq!(
        std::env::var("MEOW_NATIVE_READ_ONLY_INSPECTION").as_deref(),
        Ok("1")
    );
    let output =
        meow_listener::tun::ownership::powershell(include_str!("../src/tun/windows_dns_plan.ps1"))
            .unwrap();
    let resources: Vec<String> = serde_json::from_str(&output).unwrap();
    for resource in &resources {
        let (guid, family) = resource.split_once('|').unwrap();
        assert_eq!(guid.len(), 36);
        assert!(matches!(family, "IPv4" | "IPv6"));
        let lookup = include_str!("../src/tun/windows_dns_adapter.ps1");
        let selected = meow_listener::tun::ownership::powershell(&format!(
            "$guid = '{guid}'\n{lookup}\n([guid]$adapter[0].InterfaceGuid).ToString('D')"
        ))
        .unwrap();
        assert_eq!(selected, guid);
    }
    println!(
        "Read-only production DNS plan and adapter lookup inspected: {} resources",
        resources.len()
    );
}
