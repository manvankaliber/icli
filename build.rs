use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("could not read Cargo.toml for release metadata");
    let release_date = package_release_date(&manifest)
        .expect("Cargo.toml must define package.metadata.icli.release-date");

    println!("cargo:rustc-env=ICLI_RELEASE_DATE={release_date}");
}

fn package_release_date(manifest: &str) -> Option<&str> {
    let mut in_icli_metadata = false;

    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_icli_metadata = line == "[package.metadata.icli]";
            continue;
        }
        if !in_icli_metadata {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "release-date" {
            return Some(value.trim().trim_matches('"'));
        }
    }

    None
}
