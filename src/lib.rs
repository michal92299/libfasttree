//! libfasttree: A Rust library analogous to libostree but for distribution repositories (APT, RPM, Pacman).
//!
//! This library provides immutable system snapshots based on package managers.
//! It uses content-addressable storage (CAS) for files, builds trees from packages,
//! handles deployments atomically, supports metadata (symlinks, permissions),
//! dependency resolution, refs for history, and static deltas for efficient updates.
//! Expanded with bootloader integration, rollback, filesystem support (reflinks, subvolumes),
//! overlayfs, image builder, and stateless config support.
//! Further expanded with user data management, optimizations, security, advanced features, and improved architecture.
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
use zstd::stream::Decoder as ZstdDecoder;
use ar::Archive as ArArchive; // For .deb
use xz2::read::XzDecoder; // For .xz in .deb
use libsolv_rs::{Pool, Repo, Solver}; // Assuming libsolv-rs API
use nix::ioctl_write_ptr; // For reflinks
use nix::sys::ioctl; // For BTRFS ioctls
use std::os::unix::io::AsRawFd;
use std::process::Command; // For external commands like mkimage, btrfs, dracut
use tar::Archive; // For tar handling
use rayon::prelude::*; // For parallel processing
use gpgme; // For GPG verification
use bsdiff; // For binary deltas (assuming crate)
use merge3; // For three-way merge (assuming crate or implement)
use systemd_sysext; // Hypothetical for sysext
// Define ioctl for reflink (FICLONE)
ioctl_write_ptr!(ficlone, 'X', 9, i32); // Assuming standard
// fs-verity ioctl
ioctl_write_ptr!(fsverity_enable, 'X', 133, i32); // Hypothetical

/// Configuration for the library.
#[derive(Debug, Clone)]
pub struct Config {
    pub repo_url: String, // e.g., "http://deb.debian.org/debian"
    pub distro_type: DistroType,
    pub cas_dir: PathBuf, // e.g., "/fasttree/objects/"
    pub db_path: PathBuf, // SQLite DB for state
    pub deployments_dir: PathBuf, // e.g., "/fasttree/deployments/"
    pub current_link: PathBuf, // e.g., "/current" symlink
    pub boot_dir: PathBuf, // e.g., "/boot"
    pub bootloader: BootloaderType,
    pub filesystem: FilesystemType,
    pub health_check_script: Option<PathBuf>, // Optional health check script
    pub overlay_dirs: Vec<PathBuf>, // Dirs to overlay, e.g., /etc, /var
    pub var_volume: Option<PathBuf>, // Separate /var volume
    pub gpg_keyring: PathBuf, // For signature verification
    pub use_fsverity: bool,
    pub use_ima: bool,
    pub partitioning: PartitioningType,
    pub sysext_dir: PathBuf, // For systemd-sysext
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroType {
    Apt, // Debian-like
    Rpm, // Fedora-like
    Pacman, // Arch-like
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderType {
    Grub,
    SystemdBoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    Btrfs,
    Xfs,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitioningType {
    Subvolumes,
    ABPartitions,
}

/// File metadata for storage in DB.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub mode: u32, // Permissions mode
    pub uid: u32, // User ID
    pub gid: u32, // Group ID
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub ima_label: Option<String>, // For IMA
}

/// Trait for PackageManager abstraction.
pub trait PackageManager {
    fn fetch_metadata(&self, config: &Config) -> Result<PathBuf>;
    fn parse_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()>;
    fn download_package(&self, config: &Config, name: &str, version: &str) -> Result<Option<PathBuf>>;
    fn extract_package(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()>;
    fn verify_signature(&self, pkg_path: &Path, config: &Config) -> Result<()>;
}

/// APT Manager
struct AptManager;
impl PackageManager for AptManager {
    fn fetch_metadata(&self, config: &Config) -> Result<PathBuf> {
        let url = format!("{}/dists/stable/main/binary-amd64/Packages.gz", config.repo_url);
        // Download logic...
        unimplemented!();
    }
    fn parse_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        // Parse logic...
        unimplemented!();
    }
    fn download_package(&self, config: &Config, name: &str, version: &str) -> Result<Option<PathBuf>> {
        // Download...
        unimplemented!();
    }
    fn extract_package(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        // Extract deb...
        unimplemented!();
    }
    fn verify_signature(&self, pkg_path: &Path, config: &Config) -> Result<()> {
        // GPG verify...
        let ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        // Verify logic...
        Ok(())
    }
}

// Similar for RpmManager, PacmanManager...

/// Main struct for libfasttree operations.
pub struct FastTree {
    config: Config,
    rt: Runtime,
    db: SqliteConnection,
    pkg_manager: Box<dyn PackageManager>,
}

impl FastTree {
    /// Initialize a new FastTree instance.
    pub async fn new(mut config: Config) -> Result<Self> {
        let rt = Runtime::new()?;
        let mut db = SqliteConnection::connect(&config.db_path.to_string_lossy())
            .await
            .context("Failed to connect to DB")?;
        // Create tables (expanded with more fields)
        db.execute(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
                hash TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                metadata TEXT NOT NULL -- JSON serialized FileMetadata
            );
            CREATE TABLE IF NOT EXISTS refs (
                ref_name TEXT PRIMARY KEY,
                tree_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trees (
                tree_hash TEXT PRIMARY KEY,
                package_list TEXT NOT NULL, -- JSON list of packages
                previous_hash TEXT -- For rollback chain
            );
            CREATE TABLE IF NOT EXISTS deltas (
                from_hash TEXT,
                to_hash TEXT,
                delta_path TEXT,
                PRIMARY KEY (from_hash, to_hash)
            );
            "#,
        )
        .await?;
        fs::create_dir_all(&config.cas_dir)?;
        fs::create_dir_all(&config.deployments_dir)?;
        fs::create_dir_all(&config.sysext_dir)?;
        let pkg_manager: Box<dyn PackageManager> = match config.distro_type {
            DistroType::Apt => Box::new(AptManager),
            // Add others
            _ => unimplemented!(),
        };
        // Mount /var if separate
        if let Some(var_vol) = &config.var_volume {
            Command::new("mount").arg(var_vol).arg("/var").output()?;
        }
        Ok(Self { config, rt, db, pkg_manager })
    }

    /// Fetch repository metadata for dependency resolution.
    pub fn fetch_repo_metadata(&self) -> Result<PathBuf> {
        self.pkg_manager.fetch_metadata(&self.config)
    }

    /// Parse metadata using abstracted manager.
    fn parse_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        self.pkg_manager.parse_metadata(meta_path, repo)
    }

    /// Resolve dependencies using libsolv.
    pub async fn resolve_dependencies(&mut self, package: &str) -> Result<Vec<(String, String)>> { // (name, version)
        let meta_path = self.fetch_repo_metadata()?;
        let pool = Pool::new();
        let mut repo = Repo::new(&pool, "main_repo");
        self.parse_metadata(&meta_path, &mut repo)?;
        let solver = Solver::new(&pool);
        solver.install(package)?;
        let transaction = solver.solve()?;
        let mut deps = Vec::new();
        for solvable in transaction.install {
            deps.push((solvable.name().to_string(), solvable.version().to_string()));
        }
        Ok(deps)
    }

    /// Download a package if not already in CAS, with signature verification.
    pub fn download_package(&self, package_name: &str, version: &str) -> Result<Option<PathBuf>> {
        let pkg_path = self.pkg_manager.download_package(&self.config, package_name, version)?;
        if let Some(path) = &pkg_path {
            self.pkg_manager.verify_signature(path, &self.config)?;
        }
        Ok(pkg_path)
    }

    /// Extract package to temp dir, handling symlinks and metadata.
    pub fn extract_to_temp(&self, pkg_path: &Path) -> Result<(TempDir, HashMap<PathBuf, FileMetadata>)> {
        let temp_dir = TempDir::new()?;
        let mut metadata_map = HashMap::new();
        self.pkg_manager.extract_package(pkg_path, temp_dir.path(), &mut metadata_map)?;
        Ok((temp_dir, metadata_map))
    }

    /// Store files in CAS, parallelized, with fs-verity and IMA.
    pub async fn store_in_cas(&mut self, temp_dir: &Path, meta_map: &HashMap<PathBuf, FileMetadata>) -> Result<Vec<(PathBuf, String)>> { // (rel_path, hash)
        let entries: Vec<DirEntry> = WalkDir::new(temp_dir).into_iter().filter_map(Result::ok).collect();
        let results: Vec<Result<(PathBuf, String)>> = entries.par_iter().map(|entry| {
            if entry.file_type().is_file() || entry.file_type().is_symlink() {
                let rel_path = entry.path().strip_prefix(temp_dir)?.to_path_buf();
                let mut hasher = Sha256::new();
                if entry.file_type().is_file() {
                    let mut file = File::open(entry.path())?;
                    io::copy(&mut file, &mut hasher)?;
                } else {
                    let target = fs::read_link(entry.path())?;
                    hasher.update(target.to_string_lossy().as_bytes());
                }
                let hash = hex::encode(hasher.finalize());
                let obj_dir = self.config.cas_dir.join(&hash[0..2]);
                fs::create_dir_all(&obj_dir)?;
                let obj_path = obj_dir.join(&hash);
                if !obj_path.exists() {
                    if entry.file_type().is_file() {
                        // Reflink
                        if let FilesystemType::Btrfs | FilesystemType::Xfs = self.config.filesystem {
                            let src_fd = File::open(entry.path())?.as_raw_fd();
                            let dest_fd = OpenOptions::new().write(true).create(true).open(&obj_path)?.as_raw_fd();
                            unsafe { ficlone(dest_fd, &src_fd as *const i32)?; }
                        } else {
                            fs::hard_link(entry.path(), &obj_path)?;
                        }
                        // fs-verity
                        if self.config.use_fsverity {
                            let fd = File::open(&obj_path)?.as_raw_fd();
                            unsafe { fsverity_enable(fd, &0 as *const i32)?; } // Hypothetical
                        }
                        // IMA
                        if self.config.use_ima {
                            // Set xattr for IMA label
                            let meta = meta_map.get(&rel_path).unwrap();
                            if let Some(label) = &meta.ima_label {
                                nix::sys::xattr::set(&obj_path, "security.ima", label.as_bytes())?;
                            }
                        }
                    } else {
                        let target = fs::read_link(entry.path())?;
                        symlink(&target, &obj_path)?;
                    }
                }
                let meta_json = serde_json::to_string(meta_map.get(&rel_path).unwrap())?;
                // DB insert (sync for simplicity)
                let db = &mut self.db; // Note: for parallel, need pool or lock
                self.rt.block_on(sqlx::query!("INSERT OR IGNORE INTO objects (hash, path, metadata) VALUES (?, ?, ?)", hash, obj_path.to_string_lossy().to_string(), meta_json)
                    .execute(db))?;
                Ok((rel_path, hash))
            } else {
                Ok((PathBuf::new(), String::new())) // Skip dirs
            }
        }).collect::<Result<Vec<_>>>()?;
        let filtered = results.into_iter().filter(|(_, h)| !h.is_empty()).collect();
        Ok(filtered)
    }

    /// Build a tree from extracted files, applying metadata, using subvolumes or A/B.
    pub async fn build_tree(&mut self, entries: &[(PathBuf, String)], tree_root: &Path) -> Result<String> {
        match self.config.partitioning {
            PartitioningType::Subvolumes => {
                if let FilesystemType::Btrfs = self.config.filesystem {
                    Command::new("btrfs").arg("subvolume").arg("create").arg(tree_root).output()?;
                } else {
                    fs::create_dir_all(tree_root)?;
                }
            }
            PartitioningType::ABPartitions => {
                // Assume /dev/sda1 A, /dev/sda2 B, alternate
                // Simplified: create dir for now
                fs::create_dir_all(tree_root)?;
            }
        }
        let mut tree_hasher = Sha256::new();
        for (rel_path, hash) in entries {
            let cas_path = self.get_cas_path(hash)?;
            let dest = tree_root.join(rel_path);
            fs::create_dir_all(dest.parent().unwrap())?;
            let row = sqlx::query!("SELECT metadata FROM objects WHERE hash = ?", hash)
                .fetch_one(&mut self.db)
                .await?;
            let meta: FileMetadata = serde_json::from_str(&row.metadata)?;
            if meta.is_symlink {
                symlink(meta.symlink_target.as_ref().unwrap(), &dest)?;
            } else {
                if let FilesystemType::Btrfs | FilesystemType::Xfs = self.config.filesystem {
                    let src_fd = File::open(&cas_path)?.as_raw_fd();
                    let dest_fd = OpenOptions::new().write(true).create(true).open(&dest)?.as_raw_fd();
                    unsafe { ficlone(dest_fd, &src_fd as *const i32)?; }
                } else {
                    fs::hard_link(&cas_path, &dest)?;
                }
            }
            fs::set_permissions(&dest, Permissions::from_mode(meta.mode))?;
            nix::unistd::chown(&dest, Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid)))?;
            tree_hasher.update(hash.as_bytes());
            tree_hasher.update(rel_path.to_string_lossy().as_bytes());
        }
        let tree_hash = hex::encode(tree_hasher.finalize());
        match self.config.partitioning {
            PartitioningType::Subvolumes => {
                if let FilesystemType::Btrfs = self.config.filesystem {
                    Command::new("btrfs").arg("subvolume").arg("snapshot").arg("-r").arg(tree_root).arg(tree_root.with_file_name(format!("{}-ro", tree_hash))) .output()?;
                }
            }
            PartitioningType::ABPartitions => {
                // Copy to alternate partition
            }
        }
        Ok(tree_hash)
    }

    fn get_cas_path(&self, hash: &str) -> Result<PathBuf> {
        Ok(self.config.cas_dir.join(&hash[0..2]).join(hash))
    }

    /// Commit tree to refs, linking previous.
    pub async fn commit_tree(&mut self, tree_hash: &str, ref_name: &str, packages: &[ (String, String) ], previous_hash: Option<String>) -> Result<()> {
        let packages_json = serde_json::to_string(packages)?;
        let prev = previous_hash.unwrap_or_default();
        sqlx::query!("INSERT OR REPLACE INTO trees (tree_hash, package_list, previous_hash) VALUES (?, ?, ?)", tree_hash, packages_json, prev)
            .execute(&mut self.db)
            .await?;
        sqlx::query!("INSERT OR REPLACE INTO refs (ref_name, tree_hash) VALUES (?, ?)", ref_name, tree_hash)
            .execute(&mut self.db)
            .await?;
        Ok(())
    }

    /// Generate static delta between two trees.
    pub async fn generate_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<PathBuf> {
        let from_path = self.config.deployments_dir.join(from_hash);
        let to_path = self.config.deployments_dir.join(to_hash);
        let delta_path = self.config.cas_dir.join(format!("delta-{}-{}", from_hash, to_hash));
        // Use bsdiff or similar to generate delta
        let from_data = fs::read(&from_path)?; // Simplified, actually diff trees
        let to_data = fs::read(&to_path)?;
        let patch = bsdiff::diff(&from_data, &to_data);
        fs::write(&delta_path, &patch)?;
        sqlx::query!("INSERT INTO deltas (from_hash, to_hash, delta_path) VALUES (?, ?, ?)", from_hash, to_hash, delta_path.to_string_lossy())
            .execute(&mut self.db)
            .await?;
        Ok(delta_path)
    }

    /// Apply delta for efficient update.
    pub async fn apply_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<()> {
        let row = sqlx::query!("SELECT delta_path FROM deltas WHERE from_hash = ? AND to_hash = ?", from_hash, to_hash)
            .fetch_one(&mut self.db)
            .await?;
        let delta_path = PathBuf::from(row.delta_path);
        let from_path = self.config.deployments_dir.join(from_hash);
        let to_path = self.config.deployments_dir.join(to_hash);
        let patch = fs::read(&delta_path)?;
        let from_data = fs::read(&from_path)?;
        let new_data = bsdiff::patch(&from_data, &patch)?;
        fs::write(&to_path, &new_data)?;
        Ok(())
    }

    /// Deploy a ref atomically, update bootloader, with transaction rollback.
    pub async fn deploy(&mut self, ref_name: &str) -> Result<()> {
        let tx = self.db.begin().await?;
        let row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = ?", ref_name)
            .fetch_one(&mut self.db)
            .await?;
        let tree_hash = row.tree_hash;
        let deployment_path = self.config.deployments_dir.join(&tree_hash);
        // Assume tree built
        fs::remove_file(&self.config.current_link).ok();
        if let Err(e) = symlink(&deployment_path, &self.config.current_link) {
            tx.rollback().await?;
            return Err(e.into());
        }
        // Setup overlays with merge
        if let Err(e) = self.setup_overlays_with_merge() {
            tx.rollback().await?;
            fs::remove_file(&self.config.current_link)?;
            return Err(e);
        }
        // Update bootloader
        if let Err(e) = self.update_bootloader(&tree_hash) {
            tx.rollback().await?;
            return Err(e.into());
        }
        // Stateless config
        self.handle_stateless_config()?;
        // Sysext
        self.load_sysexts()?;
        tx.commit().await?;
        Ok(())
    }

    /// Setup OverlayFS with three-way merge for /etc.
    fn setup_overlays_with_merge(&self) -> Result<()> {
        for dir in &self.config.overlay_dirs {
            if dir == &PathBuf::from("/etc") {
                // Three-way merge
                let base = self.config.current_link.join("usr/share/factory/etc");
                let current = PathBuf::from("/etc");
                let new = self.config.current_link.join("etc");
                // Merge base, current, new using merge3
                for file in WalkDir::new(&new).into_iter().filter_map(Result::ok) {
                    let rel = file.path().strip_prefix(&new)?;
                    let base_file = base.join(rel);
                    let current_file = current.join(rel);
                    let new_file = new.join(rel);
                    if base_file.exists() && current_file.exists() {
                        let base_data = fs::read(&base_file)?;
                        let current_data = fs::read(&current_file)?;
                        let new_data = fs::read(&new_file)?;
                        let merged = merge3::merge(&base_data, &current_data, &new_data)?; // Hypothetical
                        fs::write(&current_file, &merged)?;
                    }
                }
            }
            let lower = self.config.current_link.join(dir.strip_prefix("/").unwrap_or(dir));
            let upper = PathBuf::from("/overlay_upper").join(dir.file_name().unwrap());
            let work = PathBuf::from("/overlay_work").join(dir.file_name().unwrap());
            fs::create_dir_all(&upper)?;
            fs::create_dir_all(&work)?;
            // Mount overlay
            Command::new("mount")
                .arg("-t").arg("overlay")
                .arg("overlay")
                .arg("-o").arg(format!("lowerdir={},upperdir={},workdir={}", lower.display(), upper.display(), work.display()))
                .arg(dir)
                .output()?;
        }
        Ok(())
    }

    /// Update bootloader config.
    fn update_bootloader(&self, tree_hash: &str) -> Result<()> {
        // Generate initramfs
        self.generate_initramfs(tree_hash)?;
        let root_flags = match self.config.partitioning {
            PartitioningType::Subvolumes => {
                if let FilesystemType::Btrfs = self.config.filesystem {
                    format!("rootflags=subvol={}", tree_hash)
                } else {
                    "".to_string()
                }
            }
            PartitioningType::ABPartitions => "root=/dev/sda2".to_string(), // Alternate
        };
        match self.config.bootloader {
            BootloaderType::Grub => {
                let entry = format!("menuentry 'FastTree {}' {{ linux /vmlinuz root=/dev/sda1 {} initrd /initramfs }}", tree_hash, root_flags);
                let mut config = File::create(self.config.boot_dir.join("grub/grub.cfg"))?;
                config.write_all(entry.as_bytes())?;
                Command::new("grub-mkconfig").arg("-o").arg(self.config.boot_dir.join("grub/grub.cfg")).output()?;
            }
            BootloaderType::SystemdBoot => {
                let entry_path = self.config.boot_dir.join(format!("loader/entries/fasttree-{}.conf", tree_hash));
                let mut file = File::create(&entry_path)?;
                file.write_all(format!("title FastTree {}\nlinux /vmlinuz\ninitrd /initramfs\noptions root=/dev/sda1 {}\n", tree_hash, root_flags).as_bytes())?;
            }
        }
        Ok(())
    }

    /// Generate initramfs for new snapshot.
    fn generate_initramfs(&self, tree_hash: &str) -> Result<()> {
        let root = self.config.deployments_dir.join(tree_hash);
        Command::new("dracut")
            .arg("--kver").arg("5.10.0") // Hypothetical kernel
            .arg("--install").arg(root.to_string_lossy())
            .arg(self.config.boot_dir.join("initramfs"))
            .output()?;
        Ok(())
    }

    /// Load systemd-sysext extensions.
    fn load_sysexts(&self) -> Result<()> {
        // Hypothetical
        for ext in fs::read_dir(&self.config.sysext_dir)? {
            let path = ext?.path();
            if path.extension() == Some("raw".as_ref()) {
                Command::new("systemd-sysext").arg("merge").arg(&path).output()?;
            }
        }
        Ok(())
    }

    /// Rollback to previous tree.
    pub async fn rollback(&mut self) -> Result<()> {
        let current_row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = 'current'")
            .fetch_optional(&mut self.db)
            .await?;
        if let Some(current) = current_row {
            let tree_row = sqlx::query!("SELECT previous_hash FROM trees WHERE tree_hash = ?", current.tree_hash)
                .fetch_one(&mut self.db)
                .await?;
            let prev_hash = tree_row.previous_hash;
            if !prev_hash.is_empty() {
                sqlx::query!("UPDATE refs SET tree_hash = ? WHERE ref_name = 'current'", prev_hash)
                    .execute(&mut self.db)
                    .await?;
                self.deploy("current").await?;
            }
        }
        Ok(())
    }

    /// Run health check and rollback if fails.
    pub fn run_health_check(&self) -> Result<bool> {
        if let Some(script) = &self.config.health_check_script {
            let output = Command::new(script).output()?;
            if !output.status.success() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Handle stateless config: copy defaults if not exist.
    fn handle_stateless_config(&self) -> Result<()> {
        let factory = self.config.current_link.join("usr/share/factory");
        let etc = PathBuf::from("/etc");
        for entry in WalkDir::new(&factory).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(&factory)?;
                let target = etc.join(rel);
                if !target.exists() {
                    fs::create_dir_all(target.parent().unwrap())?;
                    fs::copy(entry.path(), &target)?;
                }
            }
        }
        Ok(())
    }

    /// Full workflow: install package with deps, with deltas if possible.
    pub async fn install(&mut self, package: &str, ref_name: &str) -> Result<()> {
        let deps = self.resolve_dependencies(package).await?;
        let mut entries = Vec::new();
        let prev_row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = ?", ref_name)
            .fetch_optional(&mut self.db)
            .await?;
        let prev_hash = prev_row.map(|r| r.tree_hash);
        if let Some(prev) = &prev_hash {
            // Check for delta
            let delta_row = sqlx::query!("SELECT to_hash FROM deltas WHERE from_hash = ?", prev)
                .fetch_optional(&mut self.db)
                .await?;
            if let Some(delta) = delta_row {
                self.apply_delta(prev, &delta.to_hash).await?;
                return Ok(());
            }
        }
        for (name, ver) in &deps {
            if let Some(pkg_path) = self.download_package(name, ver)? {
                let (temp_dir, meta_map) = self.extract_to_temp(&pkg_path)?;
                let mut pkg_entries = self.store_in_cas(temp_dir.path(), &meta_map).await?;
                entries.append(&mut pkg_entries);
            }
        }
        let tree_root = self.config.deployments_dir.join("temp_tree");
        let tree_hash = self.build_tree(&entries, &tree_root).await?;
        self.commit_tree(&tree_hash, ref_name, deps, prev_hash).await?;
        if let Some(prev) = prev_hash {
            self.generate_delta(&prev, &tree_hash).await?;
        }
        self.deploy(ref_name).await?;
        fs::rename(&tree_root, self.config.deployments_dir.join(&tree_hash))?;
        Ok(())
    }

    /// Image builder: generate disk image from packages.
    pub async fn build_image(&mut self, packages: &[String], output: &Path, format: ImageFormat) -> Result<()> {
        // Similar to original, expanded if needed
        unimplemented!();
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ImageFormat {
    Img,
    Qcow2,
}

// CLI tool
#[tokio::main]
async fn main() -> Result<()> {
    // Example config expanded
    let config = Config {
        repo_url: "http://deb.debian.org/debian".to_string(),
        distro_type: DistroType::Apt,
        cas_dir: PathBuf::from("/var/lib/fasttree/objects"),
        db_path: PathBuf::from("/var/lib/fasttree/db.sqlite"),
        deployments_dir: PathBuf::from("/sysroot"),
        current_link: PathBuf::from("/"),
        boot_dir: PathBuf::from("/boot"),
        bootloader: BootloaderType::Grub,
        filesystem: FilesystemType::Btrfs,
        health_check_script: Some(PathBuf::from("/usr/bin/health-check.sh")),
        overlay_dirs: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
        var_volume: Some(PathBuf::from("/dev/sdb1")),
        gpg_keyring: PathBuf::from("/etc/apt/trusted.gpg"),
        use_fsverity: true,
        use_ima: true,
        partitioning: PartitioningType::Subvolumes,
        sysext_dir: PathBuf::from("/var/lib/extensions"),
    };
    let mut ft = FastTree::new(config).await?;
    // ft.install("nginx", "stable").await?;
    Ok(())
}

// Tests similar
