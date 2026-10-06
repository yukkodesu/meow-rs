use anyhow::Context;
use flclash_meow_host::protocol::{read_frame, write_frame};
use serde_json::{json, Value};
use std::{io, path::Path, process::ExitStatus, time::Duration};
use tokio::process::{Child, Command};

#[cfg(windows)]
type Peer = tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
type Peer = tokio::net::UnixStream;

#[path = "support/native_traffic.rs"]
mod traffic;

#[path = "support/native_child.rs"]
mod native_child;

#[cfg(target_os = "macos")]
#[path = "support/macos_routes.rs"]
mod macos_routes;

struct Session {
    peer: Option<Peer>,
    child: Child,
}

impl Session {
    async fn spawn(directory: &Path) -> anyhow::Result<Self> {
        #[cfg(windows)]
        let address = format!(
            r"\\.\pipe\FlClashMeowCore_native_{}_{}",
            std::process::id(),
            directory.file_name().unwrap().to_string_lossy()
        );
        #[cfg(unix)]
        let address = directory.join("FlClashMeowSocket_native");
        #[cfg(windows)]
        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&address)?;
        #[cfg(unix)]
        let server = {
            use std::os::unix::fs::PermissionsExt;
            if address.exists() {
                std::fs::remove_file(&address)?;
            }
            let server = tokio::net::UnixListener::bind(&address)?;
            std::fs::set_permissions(&address, std::fs::Permissions::from_mode(0o600))?;
            server
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_flclash-meow-host"));
        command.arg(&address).kill_on_drop(true);
        let mut child = command.spawn()?;
        let accept = async {
            #[cfg(windows)]
            {
                server.connect().await?;
                Ok::<Peer, io::Error>(server)
            }
            #[cfg(unix)]
            {
                Ok::<Peer, io::Error>(server.accept().await?.0)
            }
        };
        let peer = match tokio::time::timeout(Duration::from_secs(15), accept).await {
            Ok(Ok(peer)) => peer,
            result => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                anyhow::bail!("Host IPC connection failed: {result:?}");
            }
        };
        Ok(Self {
            peer: Some(peer),
            child,
        })
    }

    async fn call(&mut self, method: &str, arguments: Value) -> anyhow::Result<Value> {
        let deadline = if method == "startListener" { 360 } else { 90 };
        let result = tokio::time::timeout(Duration::from_secs(deadline), async {
            let peer = self.peer.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "IPC session has closed")
            })?;
            write_frame(
                peer,
                &serde_json::to_vec(&json!({
                    "id":"native", "method":method, "arguments":arguments
                }))?,
            )
            .await?;
            loop {
                let frame = read_frame(peer).await?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Host IPC closed before its native response",
                    )
                })?;
                let response: Value = serde_json::from_slice(&frame)?;
                if response["id"] != "native" {
                    continue;
                }
                anyhow::ensure!(response.get("error").is_none(), "{method}: {response}");
                return Ok(response["result"].clone());
            }
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|value| value);
        if let Err(error) = &result {
            let child = native_child::observe_exit(&mut self.child, Duration::from_secs(2)).await;
            println!(
                "{}",
                json!({
                    "phase":"rpcFailure",
                    "method":method,
                    "error":format!("{error:#}"),
                    "child":child.as_ref().ok(),
                    "childObservationError":child.as_ref().err().map(ToString::to_string),
                })
            );
        }
        result.with_context(|| format!("Native request {method} failed"))
    }

    async fn initialize(&mut self, home: &Path) -> anyhow::Result<Value> {
        self.call("initClash", json!({"home-dir":home,"version":1}))
            .await?;
        self.call("getRuntimeState", Value::Null).await
    }

    async fn start(&mut self) -> anyhow::Result<Value> {
        self.call(
            "setupConfig",
            json!({"selected-map":{},"test-url":"http://127.0.0.1/"}),
        )
        .await?;
        anyhow::ensure!(
            self.call("startListener", Value::Null).await? == true,
            "TUN startup was not acknowledged"
        );
        self.call("getRuntimeState", Value::Null).await
    }

    async fn reap(&mut self) -> anyhow::Result<ExitStatus> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        Ok(self.child.wait().await?)
    }
}

fn snapshot() -> anyhow::Result<Value> {
    #[cfg(windows)]
    {
        let dns = meow_listener::tun::ownership::powershell(include_str!(
            "fixtures/windows_dns_snapshot.ps1"
        ))?;
        let routes = meow_listener::tun::ownership::powershell(
            r#"$result=@(Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric | Sort-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric); ConvertTo-Json -InputObject $result -Compress"#,
        )?;
        Ok(
            json!({"dns":serde_json::from_str::<Value>(&dns)?,"routes":serde_json::from_str::<Value>(&routes)?}),
        )
    }
    #[cfg(target_os = "linux")]
    {
        let mut command = std::process::Command::new("ip");
        command.args(["-json", "route", "show", "table", "all"]);
        let output = meow_listener::tun::ownership::owned_command_output(
            &mut command,
            Duration::from_secs(20),
        )?;
        anyhow::ensure!(output.status.success(), "ip route snapshot failed");
        let mut routes: Vec<Value> = serde_json::from_slice(&output.stdout)?;
        for route in &mut routes {
            if let Some(fields) = route.as_object_mut() {
                fields.remove("expires");
                fields.remove("cache");
            }
        }
        routes.sort_by_cached_key(Value::to_string);
        Ok(json!({"dns":std::fs::read_to_string("/etc/resolv.conf")?,"routes":routes}))
    }
    #[cfg(target_os = "macos")]
    {
        let run = |args: &[&str]| -> anyhow::Result<String> {
            let mut command = std::process::Command::new("/usr/sbin/networksetup");
            command.args(args);
            let output = meow_listener::tun::ownership::owned_command_output(
                &mut command,
                Duration::from_secs(20),
            )?;
            anyhow::ensure!(output.status.success(), "networksetup snapshot failed");
            Ok(String::from_utf8(output.stdout)?)
        };
        let mut dns = Vec::new();
        for service in run(&["-listallnetworkservices"])?.lines().skip(1) {
            if service.starts_with('*') || service.is_empty() {
                continue;
            }
            dns.push(json!({"service":service,"servers":run(&["-getdnsservers",service])?}));
        }
        let mut command = std::process::Command::new("/usr/sbin/netstat");
        command.args(["-rn", "-f", "inet"]);
        let output = meow_listener::tun::ownership::owned_command_output(
            &mut command,
            Duration::from_secs(20),
        )?;
        anyhow::ensure!(output.status.success(), "route snapshot failed");
        let routes = macos_routes::persistent_routes(&String::from_utf8(output.stdout)?);
        Ok(json!({"dns":dns,"routes":routes}))
    }
}

async fn exercise(
    session: &mut Session,
    home: &Path,
    evidence: &mut Vec<Value>,
    fixtures: &traffic::Fixtures,
) -> anyhow::Result<()> {
    let idle = session.initialize(home).await?;
    anyhow::ensure!(
        idle["recovery"]["state"] == "clean",
        "Runner must begin without previous product residue: {idle}"
    );
    let before = snapshot()?;
    let running = session.start().await?;
    anyhow::ensure!(running["running"] == true, "{running}");
    evidence.push(json!({"phase":"nativeTraffic","results":fixtures.verify().await?}));
    let directory = flclash_meow_host::native::recovery_directory()?;
    let journal = |name: &str| -> anyhow::Result<Value> {
        Ok(serde_json::from_slice(&std::fs::read(
            directory.join(name),
        )?)?)
    };
    let leases = json!({"dns":journal("dns.json")?,"routes":journal("routes.json")?});
    anyhow::ensure!(
        !leases["routes"]["changes"].as_array().unwrap().is_empty(),
        "No owned native route was installed"
    );
    evidence.push(json!({"phase":"ready","runtime":running,"before":before,"installed":snapshot()?,"leases":leases}));
    session.call("stopListener", Value::Null).await?;
    anyhow::ensure!(
        snapshot()? == before,
        "Normal stop did not restore native DNS/routes"
    );
    anyhow::ensure!(
        !directory.join("dns.json").exists() && !directory.join("routes.json").exists(),
        "Normal stop left journals"
    );
    evidence.push(json!({"phase":"stop","restored":snapshot()?}));
    session.call("startListener", Value::Null).await?;
    session.call("shutdown", Value::Null).await?;
    let exit = tokio::time::timeout(Duration::from_secs(10), session.child.wait()).await??;
    anyhow::ensure!(
        exit.success() && snapshot()? == before,
        "Shutdown did not confirm native restoration"
    );
    evidence.push(json!({"phase":"shutdown","restored":snapshot()?}));
    drop(session.peer.take());
    *session = Session::spawn(home).await?;
    session.initialize(home).await?;
    session.start().await?;
    drop(session.peer.take());
    let exit = tokio::time::timeout(Duration::from_secs(45), session.child.wait()).await??;
    let restored = snapshot()?;
    evidence.push(json!({
        "phase":"ipcEof",
        "exitSuccess":exit.success(),
        "exitStatus":exit.to_string(),
        "restored":&restored,
    }));
    anyhow::ensure!(exit.success(), "IPC EOF host exited unsuccessfully: {exit}");
    anyhow::ensure!(
        restored == before,
        "IPC EOF did not confirm native restoration"
    );
    *session = Session::spawn(home).await?;
    session.initialize(home).await?;
    session.start().await?;
    #[cfg(unix)]
    {
        let pid = session
            .child
            .id()
            .ok_or_else(|| io::Error::other("Host already exited"))?;
        anyhow::ensure!(
            unsafe { libc::kill(pid.try_into()?, libc::SIGTERM) } == 0,
            "Unable to signal owned host"
        );
        let exit = tokio::time::timeout(Duration::from_secs(45), session.child.wait()).await??;
        anyhow::ensure!(
            exit.success() && snapshot()? == before,
            "SIGTERM did not confirm native restoration"
        );
        evidence.push(json!({"phase":"sigterm","restored":snapshot()?}));
        drop(session.peer.take());
        *session = Session::spawn(home).await?;
        session.initialize(home).await?;
        session.start().await?;
    }
    session.reap().await?;
    let residue = json!({"dns":journal("dns.json")?,"routes":journal("routes.json")?});
    evidence.push(json!({"phase":"forcedExit","residue":residue,"remaining":snapshot()?}));
    drop(session.peer.take());
    *session = Session::spawn(home).await?;
    let recovered = session.initialize(home).await?;
    anyhow::ensure!(
        recovered["recovery"]["state"] == "recovered",
        "Crash recovery was not reported: {recovered}"
    );
    anyhow::ensure!(
        snapshot()? == before,
        "Crash recovery did not restore native DNS/routes"
    );
    evidence.push(json!({"phase":"recovered","runtime":recovered,"restored":snapshot()?}));
    session.start().await?;
    session.call("shutdown", Value::Null).await?;
    tokio::time::timeout(Duration::from_secs(10), session.child.wait()).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "Changes native DNS/routes: disposable privileged desktop runner only"]
async fn native_tun_stop_exit_and_crash_recovery() {
    assert_eq!(
        std::env::var("MEOW_DISPOSABLE_NATIVE_RUNNER").as_deref(),
        Ok("1"),
        "Explicit disposable-runner opt-in is required"
    );
    let global = std::env::var("MEOW_NATIVE_ROUTE_MODE").as_deref() == Ok("global");
    let home = tempfile::tempdir().unwrap();
    let fixtures = traffic::Fixtures::start().await.unwrap();
    let geo = "geodata:\n  mmdb-path: Country.mmdb\n  asn-path: ASN.mmdb\n  geosite-path: geosite.mrs\n  auto-update: false\n";
    for file in ["Country.mmdb", "ASN.mmdb", "geosite.mrs"] {
        std::fs::write(home.path().join(file), []).unwrap();
    }
    std::fs::write(home.path().join("config.yaml"), format!("{geo}mode: rule\nhosts: {{ test.example: 127.0.0.42 }}\nrules: ['MATCH,DIRECT']\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: [{}]\ntun:\n  enable: true\n  auto-route: {}\n  dns-hijack: [any:53]\n", fixtures.dns, if global {"global"} else {"fake-ip"})).unwrap();
    let before = snapshot().unwrap();
    println!("{}", json!({"phase":"before","snapshot":&before}));
    let mut session = Session::spawn(home.path()).await.unwrap();
    let mut evidence = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(900),
        exercise(&mut session, home.path(), &mut evidence, &fixtures),
    )
    .await;
    let pre_reap = session.child.try_wait();
    let reaped = session.reap().await;
    let recovery = flclash_meow_host::native::recover_existing_product_resources();
    let restored = snapshot();
    println!(
        "{}",
        json!({"platform":std::env::consts::OS,"arch":std::env::consts::ARCH,"mode":if global {"global"} else {"fake-ip"},"evidence":evidence,"before":before,"preReapChild":format!("{pre_reap:?}"),"reapedChild":reaped.as_ref().ok().map(ToString::to_string),"finallyRecovery":recovery,"finallyState":restored.as_ref().ok(),"scenarioResult":format!("{result:?}")})
    );
    reaped.unwrap();
    assert!(
        matches!(
            recovery.state,
            meow_listener::tun::RecoveryState::Clean | meow_listener::tun::RecoveryState::Recovered
        ),
        "Finally recovery failed: {recovery:?}"
    );
    assert_eq!(
        restored.unwrap(),
        before,
        "Finally DNS/routes restoration failed"
    );
    result.unwrap().unwrap();
}
