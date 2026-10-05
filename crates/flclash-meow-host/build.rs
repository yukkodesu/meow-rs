use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MEOW_HOST_COMMIT");
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
