use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TARGET: &str = "thumbv7em-none-eabi";

type DynError = Box<dyn Error>;

fn main() -> Result<(), DynError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build-fae") => build_fae_command(),
        Some("-h") | Some("--help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'").into()),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo build-fae");
    eprintln!("  cargo run --manifest-path xtask/Cargo.toml -- build-fae");
}

fn build_fae_command() -> Result<(), DynError> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rustlet_dir = xtask_dir
        .parent()
        .ok_or("xtask directory has no Rustlet parent")?;
    let rustlet_manifest = rustlet_dir.join("Cargo.toml");
    let repo_root = find_repo_root(&xtask_dir)?;
    let tool_manifest = repo_root.join("tooling/build-fae/Cargo.toml");
    let target = env::var("RUSTLET_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_owned());

    run_checked(
        Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&tool_manifest)
            .arg("--bin")
            .arg("build_fae_rust")
            .arg("--")
            .arg("--manifest-path")
            .arg(&rustlet_manifest)
            .arg("--target")
            .arg(&target)
            .arg("--align_payload")
            .arg("0")
            .arg("--align_size")
            .arg("2048")
            .arg("--securitydomain")
            .arg("--fae"),
        "cargo run build-fae-rust --fae",
    )?;

    Ok(())
}

fn find_repo_root(start: &Path) -> Result<PathBuf, DynError> {
    for ancestor in start.ancestors() {
        if ancestor.join("tooling/build-fae/crates/build-fae-rust/Cargo.toml").is_file() {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err(format!("cannot locate repository root from {}", start.display()).into())
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), DynError> {
    let status = cmd.status().map_err(|err| format!("failed to run {label}: {err}"))?;
    if !status.success() {
        return Err(format!("{label} failed with status {status}").into());
    }
    Ok(())
}
