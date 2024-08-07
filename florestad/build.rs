fn main() {
    let git_description = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .map(|output| {
            assert!(
                output.status.success(),
                "Failed to run git describe. Is git installed?"
            );
            let mut git_description = String::from_utf8(output.stdout).unwrap();
            git_description.pop(); // remove the trailing newline
            git_description
        })
        .expect("Failed to run git describe. Is git installed?");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let runtime = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();

    let rustc = std::process::Command::new("rustc")
        .args(["--version"])
        .output()
        .map(|output| {
            assert!(
                output.status.success(),
                "Failed to run rustc --version. Is rustc installed?"
            );
            String::from_utf8(output.stdout).expect("Failed to parse rustc version")
        })
        .expect("Failed to run rustc --version. Is rustc installed?");

    let version =
        format!("version {git_description} compiled for {arch}-{os}-{runtime} with {rustc}");
    println!("cargo:rustc-env=LONG_VERSION={}", version);
    println!("cargo:rustc-env=GIT_DESCRIBE={}", git_description);

    // re-run if either the build script or the git HEAD changes
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
}
