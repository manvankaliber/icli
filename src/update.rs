use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::Path,
    time::Duration,
};

const REPOSITORY: &str = "https://github.com/manvankaliber/icli";
const LATEST: &str = "https://api.github.com/repos/manvankaliber/icli/releases/latest";
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_BINARY: u64 = 128 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

pub fn run(check: bool) -> Result<()> {
    let client = Client::builder()
        .user_agent(concat!("icli/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .https_only(true)
        .build()?;
    let metadata = download(&client, LATEST, 2 * 1024 * 1024)
        .context("Could not check the latest iCLI release")?;
    let release: Release = serde_json::from_slice(&metadata)
        .context("GitHub returned invalid iCLI release metadata")?;
    let latest = stable_version(&release)?;
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let available = latest.cmp_precedence(&current).is_gt();
    let target = release_target()?;
    let executable = std::env::current_exe()?;
    let mut updated = false;

    if available && !check {
        let extension = if cfg!(windows) { "zip" } else { "tar.gz" };
        let asset = format!("icli-{}-{target}.{extension}", release.tag_name);
        for required in [asset.clone(), format!("{asset}.sha256")] {
            if !release.assets.iter().any(|entry| entry.name == required) {
                bail!(
                    "The latest release has no {required}; this platform's release may still be uploading"
                );
            }
        }
        let base = format!("{REPOSITORY}/releases/download/{}", release.tag_name);
        let checksum = download(&client, &format!("{base}/{asset}.sha256"), 4096)
            .context("Could not download the iCLI release checksum")?;
        let archive = download(&client, &format!("{base}/{asset}"), MAX_ARCHIVE)
            .context("Could not download the iCLI release archive")?;
        verify_checksum(&archive, &checksum)?;
        let staging =
            tempfile::tempdir().context("Could not create the update staging directory")?;
        let binary = staging
            .path()
            .join(if cfg!(windows) { "icli.exe" } else { "icli" });
        extract_binary(&archive, extension, &binary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        }
        replace_with_backup(&executable, &binary, |path| self_replace::self_replace(path))
            .context("Could not replace the iCLI executable; check directory permissions or use the original installation method")?;
        updated = true;
    }

    crate::response::next(if available && check {
        "icli update"
    } else {
        "icli --help"
    });
    crate::response::selected(
        &serde_json::json!({
            "current_version": current.to_string(),
            "latest_version": latest.to_string(),
            "update_available": available,
            "updated": updated,
            "check_only": check,
            "target": target,
            "executable": executable,
            "release_url": format!("{REPOSITORY}/releases/tag/{}", release.tag_name)
        }),
        if updated {
            "Updated iCLI; the next invocation uses the new version"
        } else if available {
            "An iCLI update is available"
        } else {
            "iCLI is current or newer than the latest stable release"
        },
    )?;
    Ok(())
}

fn stable_version(release: &Release) -> Result<Version> {
    let version = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name),
    )
    .context("Release tag is not a semantic version")?;
    if release.draft || release.prerelease || !version.pre.is_empty() {
        bail!("The latest-release endpoint did not return a stable release");
    }
    Ok(version)
}

fn replace_with_backup(
    executable: &Path,
    binary: &Path,
    replace: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let directory = executable
        .parent()
        .context("Executable has no parent directory")?;
    let mut backup = tempfile::Builder::new()
        .prefix(".icli-update-backup-")
        .tempfile_in(directory)?;
    std::io::copy(&mut fs::File::open(executable)?, backup.as_file_mut())?;
    backup.as_file().sync_all()?;
    fs::set_permissions(backup.path(), fs::metadata(executable)?.permissions())?;
    if let Err(error) = replace(binary) {
        // Windows replacement renames the running file before installing the new
        // one. Restore that path if a subsequent copy/rename fails.
        if !executable.is_file() {
            if let Err(restore_error) = fs::copy(backup.path(), executable) {
                let (_, saved) = backup
                    .keep()
                    .context("Could not retain the update recovery copy")?;
                bail!(
                    "Update failed ({error}) and restoration failed ({restore_error}); the original binary is preserved at {}",
                    saved.display()
                );
            }
        }
        return Err(error)
            .context("Executable replacement failed; the original executable is available");
    }
    Ok(())
}

fn release_target() -> Result<String> {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        architecture => bail!("No iCLI release binary is published for {architecture}"),
    };
    let platform = match std::env::consts::OS {
        "windows" if cfg!(target_env = "msvc") => "pc-windows-msvc",
        "macos" => "apple-darwin",
        "linux" if cfg!(target_env = "gnu") => "unknown-linux-gnu",
        platform => bail!(
            "No compatible iCLI release binary is published for {platform}; update using the original installation method"
        ),
    };
    Ok(format!("{architecture}-{platform}"))
}

fn download(client: &Client, url: &str, limit: u64) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            if url == LATEST {
                "application/vnd.github+json"
            } else {
                "application/octet-stream"
            },
        )
        .send()?
        .error_for_status()?;
    read_limited(response, limit)
}

fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("Update download or archive entry exceeds the permitted size");
    }
    Ok(bytes)
}

fn verify_checksum(archive: &[u8], checksum: &[u8]) -> Result<()> {
    let expected = std::str::from_utf8(checksum)?.trim();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Invalid SHA-256 release checksum");
    }
    let actual = format!("{:x}", Sha256::digest(archive));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("Release checksum did not match; the installed executable was not replaced");
    }
    Ok(())
}

fn extract_binary(archive: &[u8], extension: &str, destination: &Path) -> Result<()> {
    let bytes = match extension {
        "zip" => {
            let mut archive = zip::ZipArchive::new(Cursor::new(archive))?;
            let binary = archive
                .by_name("icli.exe")
                .context("Release archive has no icli.exe")?;
            if binary.is_dir()
                || binary
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                bail!("Release binary is not a regular file");
            }
            read_limited(binary, MAX_BINARY)?
        }
        "tar.gz" => {
            let decoder = flate2::read::GzDecoder::new(archive);
            let mut archive = tar::Archive::new(decoder);
            let mut found = None;
            for entry in archive.entries()? {
                let entry = entry?;
                if entry.path()?.as_ref() == Path::new("icli") {
                    if !entry.header().entry_type().is_file() {
                        bail!("Release binary is not a regular file");
                    }
                    found = Some(read_limited(entry, MAX_BINARY)?);
                    break;
                }
            }
            found.context("Release archive has no icli")?
        }
        _ => bail!("Unsupported release archive format"),
    };
    if bytes.is_empty() {
        bail!("Release binary is empty");
    }
    let mut output = fs::File::create(destination)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_replacement_restores_the_original_executable() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("icli");
        let candidate = directory.path().join("candidate");
        fs::write(&current, b"old executable").unwrap();
        fs::write(&candidate, b"new executable").unwrap();
        let failure = replace_with_backup(&current, &candidate, |_| {
            fs::remove_file(&current)?;
            Err(std::io::Error::other(
                "simulated failure after moving the original",
            ))
        });
        assert!(failure.is_err());
        assert_eq!(fs::read(&current).unwrap(), b"old executable");
        assert_eq!(fs::read(&candidate).unwrap(), b"new executable");
    }

    #[test]
    fn checksum_and_limits_reject_incomplete_or_changed_downloads() {
        let bytes = b"release archive";
        let checksum = format!("{:x}\n", Sha256::digest(bytes));
        assert!(verify_checksum(bytes, checksum.as_bytes()).is_ok());
        assert!(verify_checksum(b"changed archive", checksum.as_bytes()).is_err());
        assert!(verify_checksum(bytes, b"invalid").is_err());
        assert!(read_limited(&b"four"[..], 3).is_err());
        assert_eq!(read_limited(&b"four"[..], 4).unwrap(), b"four");
    }

    #[test]
    fn stable_release_ordering_does_not_downgrade_or_accept_prereleases() {
        let release = |tag: &str| Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let current = Version::parse("1.10.0").unwrap();
        assert!(
            stable_version(&release("v1.9.9"))
                .unwrap()
                .cmp_precedence(&current)
                .is_lt()
        );
        assert!(
            stable_version(&release("v1.11.0"))
                .unwrap()
                .cmp_precedence(&current)
                .is_gt()
        );
        assert!(stable_version(&release("v1.11.0-rc.1")).is_err());
        assert!(stable_version(&release("../../bad")).is_err());
    }

    #[test]
    fn archives_extract_only_the_expected_regular_binary() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("binary");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "icli", &b"binary"[..])
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();
        extract_binary(&archive, "tar.gz", &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"binary");

        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("icli.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"windows binary").unwrap();
        let archive = zip.finish().unwrap().into_inner();
        extract_binary(&archive, "zip", &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"windows binary");

        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("other").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "icli", std::io::empty())
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();
        assert!(extract_binary(&archive, "tar.gz", &destination).is_err());
    }
}
