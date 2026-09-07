use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const DEFAULT_TARGET: &str = "thumbv7em-none-eabi";

type DynError = Box<dyn Error>;

fn main() -> Result<(), DynError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build-fae") => build_fae_command(args.collect()),
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
    eprintln!("  cargo build-fae <test-name> [<test-name> ...]");
    eprintln!("  cargo run -p rustlet_tests_xtask -- build-fae");
}

fn build_fae_command(requested_names: Vec<String>) -> Result<(), DynError> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = xtask_dir
        .parent()
        .ok_or("xtask directory has no tests parent")?;
    let repo_root = find_repo_root(&xtask_dir)?;
    let tool_manifest = repo_root.join("tooling/build-fae/Cargo.toml");
    let target = env::var("RUSTLET_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.to_owned());

    for crate_dir in test_crate_dirs(tests_dir, &requested_names)? {
        build_one_rustlet(&repo_root, &tool_manifest, &target, &crate_dir)?;
    }

    Ok(())
}

fn build_one_rustlet(
    repo_root: &Path,
    tool_manifest: &Path,
    target: &str,
    crate_dir: &Path,
) -> Result<(), DynError> {
    let rustlet_manifest = crate_dir.join("Cargo.toml");
    let package_name = parse_package_name(&rustlet_manifest)?;
    let fae_path = crate_dir.join("build").join(format!("{package_name}.fae"));
    let stamp_path = crate_dir
        .join("build")
        .join(format!("{package_name}.fae.stamp"));

    if fae_is_fresh(repo_root, crate_dir, &fae_path, &stamp_path, target)? {
        println!("Up to date: {}", fae_path.display());
        return Ok(());
    }

    println!("Building {}", crate_dir.display());
    run_checked(
        Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(tool_manifest)
            .arg("--bin")
            .arg("build_fae_rust")
            .arg("--")
            .arg("--manifest-path")
            .arg(&rustlet_manifest)
            .arg("--target")
            .arg(target)
            .arg("--align_payload")
            .arg("0")
            .arg("--align_size")
            .arg("2048")
            .arg("--rustlet")
            .arg("--fae"),
        "cargo run build-fae-rust --fae",
    )?;
    write_fae_stamp(&stamp_path, target)?;

    Ok(())
}

fn fae_is_fresh(
    repo_root: &Path,
    crate_dir: &Path,
    fae_path: &Path,
    stamp_path: &Path,
    target: &str,
) -> Result<bool, DynError> {
    if !fae_path.is_file() || !stamp_path.is_file() {
        return Ok(false);
    }

    let expected_stamp = fae_stamp_content(target);
    let stamp = fs::read_to_string(stamp_path)
        .map_err(|err| format!("cannot read {}: {err}", stamp_path.display()))?;
    if stamp != expected_stamp {
        return Ok(false);
    }

    let fae_mtime = fs::metadata(fae_path)
        .and_then(|metadata| metadata.modified())
        .map_err(|err| format!("cannot stat {}: {err}", fae_path.display()))?;
    let newest_input = newest_fae_input_mtime(repo_root, crate_dir)?;

    Ok(newest_input <= fae_mtime)
}

fn write_fae_stamp(stamp_path: &Path, target: &str) -> Result<(), DynError> {
    if let Some(parent) = stamp_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    fs::write(stamp_path, fae_stamp_content(target))
        .map_err(|err| format!("cannot write {}: {err}", stamp_path.display()))?;
    Ok(())
}

fn fae_stamp_content(target: &str) -> String {
    format!(
        "target={target}\nstartup={}\nabi=rustlet\n",
        runtime_startup_for_target(target)
    )
}

fn runtime_startup_for_target(target: &str) -> &'static str {
    if target.starts_with("thumbv6m") {
        "thumbv6m-v2"
    } else {
        "default"
    }
}

fn newest_fae_input_mtime(repo_root: &Path, crate_dir: &Path) -> Result<SystemTime, DynError> {
    let mut newest = newest_input_mtime(crate_dir)?;
    let runtime_dir = repo_root.join("rustlets/rustlet_runtime");
    visit_input_mtimes(&runtime_dir, &mut newest)?;
    Ok(newest)
}

fn newest_input_mtime(crate_dir: &Path) -> Result<SystemTime, DynError> {
    let mut newest = SystemTime::UNIX_EPOCH;
    visit_input_mtimes(crate_dir, &mut newest)?;
    Ok(newest)
}

fn visit_input_mtimes(dir: &Path, newest: &mut SystemTime) -> Result<(), DynError> {
    for entry in fs::read_dir(dir).map_err(|err| format!("cannot list {}: {err}", dir.display()))? {
        let entry = entry.map_err(|err| format!("cannot read dir entry: {err}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("cannot stat {}: {err}", path.display()))?;

        if file_type.is_dir() {
            if is_ignored_input_dir(&path) {
                continue;
            }
            visit_input_mtimes(&path, newest)?;
            continue;
        }

        if file_type.is_file() && is_build_input_file(&path) {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map_err(|err| format!("cannot stat {}: {err}", path.display()))?;
            if modified > *newest {
                *newest = modified;
            }
        }
    }
    Ok(())
}

fn is_ignored_input_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("build" | "target" | ".git")
    )
}

fn is_build_input_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("Cargo.toml" | "Cargo.lock" | "build.rs")
    ) || path.extension().and_then(|extension| extension.to_str()) == Some("rs")
}

fn test_crate_dirs(tests_dir: &Path, requested_names: &[String]) -> Result<Vec<PathBuf>, DynError> {
    let mut dirs = Vec::new();
    let requested: Vec<&str> = requested_names.iter().map(String::as_str).collect();
    for entry in fs::read_dir(tests_dir)
        .map_err(|err| format!("cannot list {}: {err}", tests_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("cannot read dir entry: {err}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("xtask") {
            continue;
        }
        if path.join("Cargo.toml").is_file()
            && is_single_bin_rustlet(&path)?
            && matches_requested_test(&path, &requested)?
        {
            dirs.push(path);
        }
    }
    dirs.sort();
    if !requested.is_empty() && dirs.is_empty() {
        return Err(format!(
            "no single-bin rustlet test matched: {}",
            requested.join(", ")
        )
        .into());
    }
    Ok(dirs)
}

fn matches_requested_test(crate_dir: &Path, requested: &[&str]) -> Result<bool, DynError> {
    if requested.is_empty() {
        return Ok(true);
    }

    let manifest_path = crate_dir.join("Cargo.toml");
    let package_name = parse_package_name(&manifest_path)?;
    let dir_name = crate_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("crate directory has no valid UTF-8 basename")?;

    Ok(requested
        .iter()
        .any(|name| *name == dir_name || *name == package_name))
}

fn is_single_bin_rustlet(crate_dir: &Path) -> Result<bool, DynError> {
    let manifest_path = crate_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
    let bin_count = manifest
        .lines()
        .filter(|line| line.trim() == "[[bin]]")
        .count();

    if bin_count > 1 {
        println!(
            "Skipping {}: multi-bin crate handled outside grouped build-fae",
            crate_dir.display()
        );
        return Ok(false);
    }

    Ok(true)
}

fn find_repo_root(start: &Path) -> Result<PathBuf, DynError> {
    for ancestor in start.ancestors() {
        if ancestor.join("tooling/build-fae/crates/build-fae-rust/Cargo.toml").is_file() {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err(format!("cannot locate repository root from {}", start.display()).into())
}

fn parse_package_name(manifest_path: &Path) -> Result<String, DynError> {
    let manifest = fs::read_to_string(manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;

    let mut in_package = false;
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let value = rest.trim().trim_matches('"');
                if !value.is_empty() {
                    return Ok(value.to_owned());
                }
            }
        }
    }

    Err(format!(
        "failed to find [package].name in {}",
        manifest_path.display()
    )
    .into())
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), DynError> {
    let status = cmd
        .status()
        .map_err(|err| format!("failed to run {label}: {err}"))?;
    if !status.success() {
        return Err(format!("{label} failed with status {status}").into());
    }
    Ok(())
}
