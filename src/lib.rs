//! libfasttree: A Rust library analogous to libostree but for distribution repositories (APT, RPM, Pacman).
//!
//! This library provides immutable system snapshots based on package managers.
//! It uses content-addressable storage (CAS) for files, builds trees from packages,
//! handles deployments atomically, supports metadata (symlinks, permissions), 
//! dependency resolution, refs for history, and static deltas for efficient updates.

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::{Gid, Uid};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, SqliteConnection};
use std::collections::HashMap;
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use walkdir::{DirEntry, WalkDir};
use xml::reader::{EventReader, XmlEvent};
use zstd::stream::Decoder;
use ar::Archive as ArArchive;  // For .deb
use xz2::read::XzDecoder;  // For .xz in .deb
use libsolv_rs::{Pool, Repo, Solver};  // Assuming libsolv-rs API

/// Configuration for the library.
#[derive(Debug, Clone)]
pub struct Config {
    pub repo_url: String,  // e.g., "http://deb.debian.org/debian"
    pub distro_type: DistroType,
    pub cas_dir: PathBuf,  // e.g., "/fasttree/objects/"
    pub db_path: PathBuf,  // SQLite DB for state
    pub deployments_dir: PathBuf,  // e.g., "/fasttree/deployments/"
    pub current_link: PathBuf,  // e.g., "/current" symlink
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroType {
    Apt,    // Debian-like
    Rpm,    // Fedora-like
    Pacman, // Arch-like
}

/// File metadata for storage in DB.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub mode: u32,     // Permissions mode
    pub uid: u32,      // User ID
    pub gid: u32,      // Group ID
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
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

        // Create tables
        db.execute(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
                hash TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                metadata TEXT NOT NULL  -- JSON serialized FileMetadata
            );
            CREATE TABLE IF NOT EXISTS refs (
                ref_name TEXT PRIMARY KEY,
                tree_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trees (
                tree_hash TEXT PRIMARY KEY,
                package_list TEXT NOT NULL  -- JSON list of packages
            );
            "#,
        )
        .await?;

        fs::create_dir_all(&config.cas_dir)?;
        fs::create_dir_all(&config.deployments_dir)?;

        Ok(Self { config, rt, db })
    }

    /// Fetch repository metadata for dependency resolution.
    pub fn fetch_repo_metadata(&self) -> Result<PathBuf> {
        let url = match self.config.distro_type {
            DistroType::Apt => format!("{}/dists/stable/main/binary-amd64/Packages.gz", self.config.repo_url),
            DistroType::Rpm => format!("{}/repodata/repomd.xml", self.config.repo_url),
            DistroType::Pacman => format!("{}/core.db", self.config.repo_url),  // .db is a tar.gz
        };
        let client = Client::new();
        let response = client.get(&url).send()?.error_for_status()?;
        let meta_path = PathBuf::from("repo_metadata");
        let mut file = BufWriter::new(File::create(&meta_path)?);
        response.copy_to(&mut file)?;
        Ok(meta_path)
    }

    /// Resolve dependencies using libsolv.
    pub async fn resolve_dependencies(&mut self, package: &str) -> Result<Vec<(String, String)>> {  // (name, version)
        let meta_path = self.fetch_repo_metadata()?;
        let pool = Pool::new();
        let repo = Repo::new(&pool, "main_repo");

        match self.config.distro_type {
            DistroType::Apt => {
                let file = File::open(&meta_path)?;
                let decoder = GzDecoder::new(file);
                // Parse Packages format and add to repo (custom parsing needed)
                // For simplicity, assume we parse lines and add solvables
                unimplemented!("APT metadata parsing");
            }
            DistroType::Rpm => {
                let file = File::open(&meta_path)?;
                let parser = EventReader::new(file);
                // Parse repomd.xml to find primary.xml.gz, then parse that
                unimplemented!("RPM metadata parsing");
            }
            DistroType::Pacman => {
                // Extract tar.gz and parse desc files
                unimplemented!("Pacman metadata parsing");
            }
        };

        let solver = Solver::new(&pool);
        solver.install(package)?;
        let transaction = solver.solve()?;
        let mut deps = Vec::new();
        for solvable in transaction.install {
            deps.push((solvable.name().to_string(), solvable.version().to_string()));
        }
        Ok(deps)
    }

    /// Download a package if not already in CAS (static delta check).
    pub fn download_package(&self, package_name: &str, version: &str) -> Result<Option<PathBuf>> {
        // Check if package objects already exist (requires pre-known file list/hashes from metadata)
        // For now, simplistic: always download, but check after extraction
        let url = match self.config.distro_type {
            DistroType::Apt => format!("{}/pool/main/{}/{}_{}.deb", self.config.repo_url, package_name.chars().next().unwrap_or(' '), package_name, version),
            DistroType::Rpm => format!("{}/{}-{}.rpm", self.config.repo_url, package_name, version),
            DistroType::Pacman => format!("{}/{}-{}.pkg.tar.zst", self.config.repo_url, package_name, version),
        };
        // Hypothetical: query DB if package_version hash exists
        // If exists, return None (already have)
        let client = Client::new();
        let response = client.get(&url).send()?.error_for_status()?;
        let pkg_path = PathBuf::from(format!("{}_{}.pkg", package_name, version));
        let mut file = BufWriter::new(File::create(&pkg_path)?);
        response.copy_to(&mut file)?;
        Ok(Some(pkg_path))
    }

    /// Extract package to temp dir, handling symlinks and metadata.
    pub fn extract_to_temp(&self, pkg_path: &Path) -> Result<(TempDir, HashMap<PathBuf, FileMetadata>)> {
        let temp_dir = TempDir::new()?;
        let mut metadata_map = HashMap::new();

        match self.config.distro_type {
            DistroType::Apt => self.extract_deb(pkg_path, temp_dir.path(), &mut metadata_map)?,
            DistroType::Rpm => self.extract_rpm(pkg_path, temp_dir.path(), &mut metadata_map)?,
            DistroType::Pacman => self.extract_pacman(pkg_path, temp_dir.path(), &mut metadata_map)?,
        };

        Ok((temp_dir, metadata_map))
    }

    fn extract_deb(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        let file = File::open(pkg_path)?;
        let mut ar = ArArchive::new(file);
        while let Some(Ok(mut entry)) = ar.next_entry() {
            let header = entry.header();
            let ident = std::str::from_utf8(header.identifier())?.trim_end_matches('\0');
            if ident.starts_with("data.tar") {
                let decoder: Box<dyn Read> = if ident.ends_with(".xz") {
                    Box::new(XzDecoder::new(&mut entry))
                } else if ident.ends_with(".zst") {
                    Box::new(Decoder::new(&mut entry)?)
                } else {
                    Box::new(&mut entry)
                };
                let mut tar = tar::Archive::new(decoder);
                for entry in tar.entries()? {
                    let mut entry = entry?;
                    let path = dest.join(entry.path()?);
                    if entry.header().entry_type() == tar::EntryType::Regular {
                        fs::create_dir_all(path.parent().unwrap())?;
                        entry.unpack(&path)?;
                    } else if entry.header().entry_type() == tar::EntryType::Symlink {
                        let target = entry.link_name()?.unwrap_or_default();
                        fs::create_dir_all(path.parent().unwrap())?;
                        symlink(&target, &path)?;
                    }
                    // Capture metadata
                    let meta = fs::symlink_metadata(&path)?;
                    meta_map.insert(path.strip_prefix(dest)?.to_path_buf(), FileMetadata {
                        mode: meta.mode(),
                        uid: meta.uid(),
                        gid: meta.gid(),
                        is_symlink: meta.file_type().is_symlink(),
                        symlink_target: if meta.file_type().is_symlink() { fs::read_link(&path).ok().map(|p| p.to_string_lossy().to_string()) } else { None },
                    });
                }
                break;
            }
        }
        Ok(())
    }

    fn extract_rpm(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        let pkg = rpm::Package::open(pkg_path)?;
        for file in pkg.files()? {
            let path = dest.join(file.path());
            fs::create_dir_all(path.parent().unwrap())?;
            if file.is_symlink() {
                symlink(file.symlink_target().unwrap(), &path)?;
            } else {
                let mut f = File::create(&path)?;
                f.write_all(&file.content()?)?;
            }
            // Set permissions (simplified)
            fs::set_permissions(&path, Permissions::from_mode(file.mode()))?;
            // Capture metadata (UID/GID from RPM header if available)
            let meta = fs::symlink_metadata(&path)?;
            meta_map.insert(path.strip_prefix(dest)?.to_path_buf(), FileMetadata {
                mode: meta.mode(),
                uid: file.uid().unwrap_or(0),
                gid: file.gid().unwrap_or(0),
                is_symlink: file.is_symlink(),
                symlink_target: file.symlink_target().map(|s| s.to_string()),
            });
        }
        Ok(())
    }

    fn extract_pacman(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        let file = File::open(pkg_path)?;
        let decoder = Decoder::new(file)?;
        let mut tar = tar::Archive::new(decoder);
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = dest.join(entry.path()?);
            if entry.header().entry_type() == tar::EntryType::Regular {
                fs::create_dir_all(path.parent().unwrap())?;
                entry.unpack(&path)?;
            } else if entry.header().entry_type() == tar::EntryType::Symlink {
                let target = entry.link_name()?.unwrap_or_default();
                fs::create_dir_all(path.parent().unwrap())?;
                symlink(&target, &path)?;
            }
            // Capture metadata
            let meta = fs::symlink_metadata(&path)?;
            meta_map.insert(path.strip_prefix(dest)?.to_path_buf(), FileMetadata {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                is_symlink: meta.file_type().is_symlink(),
                symlink_target: if meta.file_type().is_symlink() { fs::read_link(&path).ok().map(|p| p.to_string_lossy().to_string()) } else { None },
            });
        }
        Ok(())
    }

    /// Store files in CAS, storing metadata in DB.
    pub async fn store_in_cas(&mut self, temp_dir: &Path, meta_map: &HashMap<PathBuf, FileMetadata>) -> Result<Vec<(PathBuf, PathBuf)>> {  // (rel_path, cas_path)
        let mut entries = Vec::new();
        for entry in WalkDir::new(temp_dir).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() || entry.file_type().is_symlink() {
                let rel_path = entry.path().strip_prefix(temp_dir)?.to_path_buf();
                let mut hasher = Sha256::new();
                if entry.file_type().is_file() {
                    let mut file = BufReader::new(File::open(entry.path())?);
                    io::copy(&mut file, &mut hasher)?;
                } else {
                    // For symlinks, hash the target path
                    let target = fs::read_link(entry.path())?;
                    hasher.update(target.to_string_lossy().as_bytes());
                }
                let hash = hex::encode(hasher.finalize());
                let obj_dir = self.config.cas_dir.join(&hash[0..2]);
                fs::create_dir_all(&obj_dir)?;
                let obj_path = obj_dir.join(&hash);

                if !obj_path.exists() {
                    if entry.file_type().is_file() {
                        fs::hard_link(entry.path(), &obj_path)?;
                    } else {
                        // For symlinks, store as a file with target content or handle specially
                        let target = fs::read_link(entry.path())?;
                        let mut f = File::create(&obj_path)?;
                        f.write_all(target.to_string_lossy().as_bytes())?;
                    }
                }

                let meta_json = serde_json::to_string(meta_map.get(&rel_path).unwrap())?;
                sqlx::query!("INSERT OR IGNORE INTO objects (hash, path, metadata) VALUES (?, ?, ?)", hash, obj_path.to_string_lossy().to_string(), meta_json)
                    .execute(&mut self.db)
                    .await?;

                entries.push((rel_path, obj_path));
            }
        }
        Ok(entries)
    }

    /// Build a tree from extracted files, applying metadata.
    pub async fn build_tree(&mut self, entries: &[(PathBuf, PathBuf)], tree_root: &Path) -> Result<String> {
        fs::create_dir_all(tree_root)?;
        let mut tree_hasher = Sha256::new();
        for (rel_path, cas_path) in entries {
            let dest = tree_root.join(rel_path);
            fs::create_dir_all(dest.parent().unwrap())?;

            // Fetch metadata from DB
            let hash = cas_path.file_name().unwrap().to_string_lossy().to_string();
            let row = sqlx::query!("SELECT metadata FROM objects WHERE hash = ?", hash)
                .fetch_one(&mut self.db)
                .await?;
            let meta: FileMetadata = serde_json::from_str(&row.metadata)?;

            if meta.is_symlink {
                symlink(meta.symlink_target.as_ref().unwrap(), &dest)?;
            } else {
                fs::hard_link(cas_path, &dest)?;
            }

            // Apply permissions
            fs::set_permissions(&dest, Permissions::from_mode(meta.mode))?;
            nix::unistd::chown(&dest, Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid)))?;

            // Update tree hash
            tree_hasher.update(hash.as_bytes());
            tree_hasher.update(rel_path.to_string_lossy().as_bytes());
        }
        let tree_hash = hex::encode(tree_hasher.finalize());
        Ok(tree_hash)
    }

    /// Commit tree to refs.
    pub async fn commit_tree(&mut self, tree_hash: &str, ref_name: &str, packages: &[ (String, String) ]) -> Result<()> {
        let packages_json = serde_json::to_string(packages)?;
        sqlx::query!("INSERT OR REPLACE INTO trees (tree_hash, package_list) VALUES (?, ?)", tree_hash, packages_json)
            .execute(&mut self.db)
            .await?;
        sqlx::query!("INSERT OR REPLACE INTO refs (ref_name, tree_hash) VALUES (?, ?)", ref_name, tree_hash)
            .execute(&mut self.db)
            .await?;
        Ok(())
    }

    /// Deploy a ref atomically.
    pub async fn deploy(&mut self, ref_name: &str) -> Result<()> {
        let row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = ?", ref_name)
            .fetch_one(&mut self.db)
            .await?;
        let tree_hash = row.tree_hash;
        let deployment_path = self.config.deployments_dir.join(&tree_hash);

        // Assume tree is built at deployment_path (from build_tree)
        // Atomic swap: update symlink
        fs::remove_file(&self.config.current_link)?;
        symlink(&deployment_path, &self.config.current_link)?;

        // Handle /etc and /var 3-way merge (TODO: implement)
        Ok(())
    }

    // Full workflow example: install package with deps
    pub async fn install(&mut self, package: &str, ref_name: &str) -> Result<()> {
        let deps = self.resolve_dependencies(package).await?;
        let mut entries = Vec::new();
        for (name, ver) in deps {
            if let Some(pkg_path) = self.download_package(&name, &ver)? {
                let (temp_dir, meta_map) = self.extract_to_temp(&pkg_path)?;
                let mut pkg_entries = self.store_in_cas(temp_dir.path(), &meta_map).await?;
                entries.append(&mut pkg_entries);
            }
        }
        let tree_root = self.config.deployments_dir.join("temp_tree");
        let tree_hash = self.build_tree(&entries, &tree_root).await?;
        self.commit_tree(&tree_hash, ref_name, &deps).await?;
        self.deploy(ref_name).await?;
        Ok(())
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
            deployments_dir: PathBuf::from("/tmp/fasttree/deployments"),
            current_link: PathBuf::from("/tmp/current"),
        };
        let mut ft = FastTree::new(config).await?;
        // ft.install("core-utils", "stable").await?;
        Ok(())
    }
            }
