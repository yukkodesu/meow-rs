use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MEOW_HOST_COMMIT");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    let manifest = std::fs::read_to_string("../../Cargo.toml").expect("workspace manifest");
    let workspace: toml::Value = toml::from_str(&manifest).expect("workspace TOML");
    let version = workspace["workspace"]["package"]["version"]
        .as_str()
        .expect("meow workspace version");
    println!("cargo:rustc-env=MEOW_CORE_VERSION={version}");
    for refname in [
        Some("HEAD".to_string()),
        git(&["symbolic-ref", "--quiet", "HEAD"]),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = git(&["rev-parse", "--git-path", &refname]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let commit = std::env::var("MEOW_HOST_COMMIT")
        .ok()
        .or_else(|| {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        })
        .expect("MEOW_HOST_COMMIT must identify the pinned meow-rs source commit");
    assert!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid MEOW_HOST_COMMIT"
    );
    println!("cargo:rustc-env=MEOW_HOST_COMMIT={commit}");
}

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
