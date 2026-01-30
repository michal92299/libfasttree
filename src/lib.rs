//! libfasttree: A Rust library analogous to libostree but for distribution repositories (APT, RPM, Pacman).
//!
//! This library aims to provide immutable system snapshots based on package managers.
//! It uses content-addressable storage (CAS) for files, builds trees from packages,
//! and handles deployments atomically.

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use sqlx::{Connection, SqliteConnection};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use walkdir::WalkDir;
use zstd::stream::Decoder;
use ar::Archive as ArArchive;  // For .deb
use xz2::read::XzDecoder;  // For .xz in .deb

/// Configuration for the library.
#[derive(Debug, Clone)]
pub struct Config {
    pub repo_url: String,  // e.g., "http://deb.debian.org/debian"
    pub distro_type: DistroType,
    pub cas_dir: PathBuf,  // e.g., "/fasttree/objects/"
    pub db_path: PathBuf,  // SQLite DB for state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroType {
    Apt,  // Debian-like
    Rpm,  // Fedora-like
    Pacman,  // Arch-like
}

/// Main struct for libfasttree operations.
pub struct FastTree {
    config: Config,
    rt: Runtime,
    db: SqliteConnection,
}

impl FastTree {
    /// Initialize a new FastTree instance.
    pub async fn new(config: Config) -> Result<Self> {
        let rt = Runtime::new()?;
        let mut db = SqliteConnection::connect(&config.db_path.to_string_lossy())
            .await
            .context("Failed to connect to DB")?;
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
                hash TEXT PRIMARY KEY,
                path TEXT NOT NULL
            )
            "#
        )
        .execute(&mut db)
        .await?;
        Ok(Self { config, rt, db })
    }

    /// Download a package from the repository.
    pub fn download_package(&self, package_name: &str, version: &str) -> Result<PathBuf> {
        let url = match self.config.distro_type {
            DistroType::Apt => format!("{}/pool/main/{}/{}_{}.deb", self.config.repo_url, package_name.chars().next().unwrap_or(' '), package_name, version),
            DistroType::Rpm => format!("{}/{}-{}.rpm", self.config.repo_url, package_name, version),
            DistroType::Pacman => format!("{}/{}-{}.pkg.tar.zst", self.config.repo_url, package_name, version),
        };
        let client = Client::new();
        let response = client.get(&url).send()?.error_for_status()?;
        let mut file = BufWriter::new(File::create(format!("{}.pkg", package_name))?);
        response.copy_to(&mut file)?;
        Ok(PathBuf::from(format!("{}.pkg", package_name)))
    }

    /// Decompress and extract package to CAS.
    pub fn extract_to_cas(&mut self, pkg_path: &Path) -> Result<Vec<(String, PathBuf)>> {  // Returns (file_path_in_pkg, cas_path)
        let temp_dir = TempDir::new()?;
        match self.config.distro_type {
            DistroType::Apt => self.extract_deb(pkg_path, temp_dir.path())?,
            DistroType::Rpm => self.extract_rpm(pkg_path, temp_dir.path())?,
            DistroType::Pacman => self.extract_pacman(pkg_path, temp_dir.path())?,
        };
        let mut entries = Vec::new();
        for entry in WalkDir::new(temp_dir.path()).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                let rel_path = entry.path().strip_prefix(temp_dir.path())?.to_path_buf();
                let cas_path = self.store_in_cas(entry.path())?;
                entries.push((rel_path.to_string_lossy().to_string(), cas_path));
            }
        }
        Ok(entries)
    }

    fn extract_deb(&self, pkg_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(pkg_path)?;
        let mut ar = ArArchive::new(file);
        while let Some(entry) = ar.next_entry() {
            let mut entry = entry?;
            let header = entry.header();
            let ident = std::str::from_utf8(header.identifier())?;
            if ident.starts_with("data.tar") {
                let decoder = if ident.ends_with(".xz") {
                    Box::new(XzDecoder::new(entry)) as Box<dyn Read>
                } else if ident.ends_with(".zst") {
                    Box::new(Decoder::new(entry)?) as Box<dyn Read>
                } else {
                    Box::new(entry) as Box<dyn Read>
                };
                let mut tar = tar::Archive::new(decoder);
                tar.unpack(dest)?;
                break;
            }
        }
        Ok(())
    }

    fn extract_rpm(&self, pkg_path: &Path, dest: &Path) -> Result<()> {
        // Using rpm crate (assuming it has extraction)
        let pkg = rpm::Package::open(pkg_path)?;
        for file in pkg.files()? {
            let path = dest.join(file.path());
            fs::create_dir_all(path.parent().unwrap())?;
            let mut f = File::create(&path)?;
            f.write_all(&file.content()?)?;
        }
        Ok(())
    }

    fn extract_pacman(&self, pkg_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(pkg_path)?;
        let decoder = Decoder::new(file)?;
        let mut tar = tar::Archive::new(decoder);
        tar.unpack(dest)?;
        Ok(())
    }

    /// Store a file in CAS using SHA256 hash.
    fn store_in_cas(&mut self, file_path: &Path) -> Result<PathBuf> {
        let mut hasher = Sha256::new();
        let mut file = BufReader::new(File::open(file_path)?);
        io::copy(&mut file, &mut hasher)?;
        let hash = hex::encode(hasher.finalize());
        let obj_dir = self.config.cas_dir.join(&hash[0..2]);
        fs::create_dir_all(&obj_dir)?;
        let obj_path = obj_dir.join(&hash);
        if !obj_path.exists() {
            fs::hard_link(file_path, &obj_path)?;
        }
        sqlx::query!("INSERT OR IGNORE INTO objects (hash, path) VALUES (?, ?)", hash, obj_path.to_string_lossy())
            .execute(&mut self.db)
            .await?;
        Ok(obj_path)
    }

    /// Build a tree from extracted files.
    pub fn build_tree(&self, entries: &[(String, PathBuf)], tree_root: &Path) -> Result<()> {
        fs::create_dir_all(tree_root)?;
        for (rel_path, cas_path) in entries {
            let dest = tree_root.join(rel_path);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::hard_link(cas_path, &dest)?;
        }
        Ok(())
    }

    /// Deploy the tree atomically (simplified; real impl would use mounts or symlinks).
    pub fn deploy(&self, tree_root: &Path, system_root: &Path) -> Result<()> {
        // Simplified: copy or link tree to system_root
        // In real: use overlayfs or atomic symlink swap for A/B
        for entry in WalkDir::new(tree_root).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(tree_root)?;
                let dest = system_root.join(rel);
                fs::create_dir_all(dest.parent().unwrap())?;
                fs::hard_link(entry.path(), &dest)?;
            }
        }
        // Handle /etc and /var merge (TODO: implement 3-way merge)
        Ok(())
    }

    // TODO: Implement dependency solver using libsolv-rs or custom.
    // For now, placeholder.
    pub fn resolve_dependencies(&self, _package: &str) -> Result<Vec<(String, String)>> {
        // Use libsolv or similar to resolve deps.
        unimplemented!("Dependency resolution not implemented yet.");
    }
}

// Example usage
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_fasttree() -> Result<()> {
        let config = Config {
            repo_url: "http://example.com".to_string(),
            distro_type: DistroType::Apt,
            cas_dir: PathBuf::from("/tmp/fasttree/objects"),
            db_path: PathBuf::from("/tmp/fasttree.db"),
        };
        let mut ft = FastTree::new(config).await?;
        // Further tests...
        Ok(())
    }
                  }
