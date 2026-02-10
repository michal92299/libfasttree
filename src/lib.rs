//! libfasttree: A Rust library analogous to libostree but for distribution repositories.
use anyhow::{Context, Result};
// use nix::sys::stat::Mode; // Unused
use nix::unistd::{Gid, Uid};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, Row, SqliteConnection};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Cursor, Write}; // Removed unused Read
use std::os::unix::fs::{PermissionsExt, symlink}; // Removed MetadataExt (unused)
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use walkdir::{DirEntry, WalkDir};
use rayon::prelude::*;
// Fixed import for nix 0.28 macro
use nix::ioctl_write_int;

// --- Mocks for missing crates (libsolv_rs, systemd_sysext) ---
pub mod libsolv_mock {
    use anyhow::Result;
    pub struct Pool;
    impl Pool { pub fn new() -> Self { Self } }
    pub struct Repo<'a> { _p: &'a Pool }
    impl<'a> Repo<'a> { pub fn new(_p: &'a Pool, _n: &str) -> Self { Self { _p } } }
    pub struct Solver<'a> { _p: &'a Pool }
    impl<'a> Solver<'a> {
        pub fn new(_p: &'a Pool) -> Self { Self { _p } }
        pub fn install(&self, _pkg: &str) -> Result<()> { Ok(()) }
        pub fn solve(&self) -> Result<Transaction> { Ok(Transaction { install: vec![Solvable] }) }
    }
    pub struct Transaction { pub install: Vec<Solvable> }
    pub struct Solvable;
    impl Solvable {
        pub fn name(&self) -> &str { "dummy-package" }
        pub fn version(&self) -> &str { "1.0.0" }
    }
}
use libsolv_mock::{Pool, Repo, Solver};

// --- Ioctl Definitions ---
// FICLONE is _IOW(0x94, 9, int) on Linux.
ioctl_write_int!(ficlone, 0x94, 9);
// FS_VERITY_ENABLE is _IOW('f', 133, struct fsverity_enable_arg).
// Simplified here to int for compilation.
ioctl_write_int!(fsverity_enable, b'f', 133);

/// Configuration for the library.
#[derive(Debug, Clone)]
pub struct Config {
    pub repo_url: String,
    pub distro_type: DistroType,
    pub cas_dir: PathBuf,
    pub db_path: PathBuf,
    pub deployments_dir: PathBuf,
    pub current_link: PathBuf,
    pub boot_dir: PathBuf,
    pub bootloader: BootloaderType,
    pub filesystem: FilesystemType,
    pub health_check_script: Option<PathBuf>,
    pub overlay_dirs: Vec<PathBuf>,
    pub var_volume: Option<PathBuf>,
    pub gpg_keyring: PathBuf,
    pub use_fsverity: bool,
    pub use_ima: bool,
    pub partitioning: PartitioningType,
    pub sysext_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroType {
    Apt,
    Rpm,
    Pacman,
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
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub ima_label: Option<String>,
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
        let _url = format!("{}/dists/stable/main/binary-amd64/Packages.gz", config.repo_url);
        // Mock implementation
        Ok(PathBuf::from("/tmp/Packages.gz"))
    }
    fn parse_metadata(&self, _meta_path: &Path, _repo: &mut Repo) -> Result<()> {
        Ok(())
    }
    fn download_package(&self, _config: &Config, _name: &str, _version: &str) -> Result<Option<PathBuf>> {
        Ok(Some(PathBuf::from("/tmp/dummy.deb")))
    }
    fn extract_package(&self, _pkg_path: &Path, _dest: &Path, _meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        Ok(())
    }
    fn verify_signature(&self, _pkg_path: &Path, _config: &Config) -> Result<()> {
        // Mock GPG
        let _ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        Ok(())
    }
}

/// Main struct for libfasttree operations.
pub struct FastTree {
    config: Config,
    rt: Runtime,
    db: SqliteConnection,
    pkg_manager: Box<dyn PackageManager>,
}

// Helper function for 3-way merge
fn three_way_merge(base: &[u8], _current: &[u8], new: &[u8]) -> Vec<u8> {
    // A simplified merge implementation for compilation.
    // In a real scenario, this would use diff3 logic.
    // Prefer 'new' content if base matches, otherwise logic is needed.
    // Here we simply return 'new' to simulate a successful merge/overwrite.
    if base == new {
        // No change in new, check current... (omitted for brevity)
    }
    new.to_vec()
}

impl FastTree {
    /// Initialize a new FastTree instance.
    pub async fn new(config: Config) -> Result<Self> {
        let rt = Runtime::new()?;

        // Create DB file if it doesn't exist
        if !config.db_path.exists() {
            if let Some(parent) = config.db_path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(&config.db_path)?;
        }

        let mut db = SqliteConnection::connect(&format!("sqlite:{}", config.db_path.to_string_lossy()))
        .await
        .context("Failed to connect to DB")?;

        // Create tables. Added target_size to deltas for bsdiff patch.
        db.execute(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
                hash TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                metadata TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refs (
            ref_name TEXT PRIMARY KEY,
            tree_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trees (
            tree_hash TEXT PRIMARY KEY,
            package_list TEXT NOT NULL,
            previous_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS deltas (
            from_hash TEXT,
            to_hash TEXT,
            delta_path TEXT,
            target_size INTEGER,
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
            _ => Box::new(AptManager), // Fallback/Mock
        };

        if let Some(var_vol) = &config.var_volume {
            // Check if running as root/capability before mounting, usually skipped in lib tests
            if Uid::effective().is_root() {
                Command::new("mount").arg(var_vol).arg("/var").output()?;
            }
        }
        Ok(Self { config, rt, db, pkg_manager })
    }

    pub fn fetch_repo_metadata(&self) -> Result<PathBuf> {
        self.pkg_manager.fetch_metadata(&self.config)
    }

    fn parse_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        self.pkg_manager.parse_metadata(meta_path, repo)
    }

    pub async fn resolve_dependencies(&mut self, package: &str) -> Result<Vec<(String, String)>> {
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

    pub fn download_package(&self, package_name: &str, version: &str) -> Result<Option<PathBuf>> {
        let pkg_path = self.pkg_manager.download_package(&self.config, package_name, version)?;
        if let Some(path) = &pkg_path {
            self.pkg_manager.verify_signature(path, &self.config)?;
        }
        Ok(pkg_path)
    }

    pub fn extract_to_temp(&self, pkg_path: &Path) -> Result<(TempDir, HashMap<PathBuf, FileMetadata>)> {
        let temp_dir = TempDir::new()?;
        let mut metadata_map = HashMap::new();
        self.pkg_manager.extract_package(pkg_path, temp_dir.path(), &mut metadata_map)?;
        Ok((temp_dir, metadata_map))
    }

    pub async fn store_in_cas(&mut self, temp_dir: &Path, meta_map: &HashMap<PathBuf, FileMetadata>) -> Result<Vec<(PathBuf, String)>> {
        let entries: Vec<DirEntry> = WalkDir::new(temp_dir).into_iter().filter_map(Result::ok).collect();

        // Parallel processing of files to compute hashes and prepare CAS paths
        let results: Vec<Result<(PathBuf, String)>> = entries.par_iter().map(|entry| {
            if entry.file_type().is_file() || entry.file_type().is_symlink() {
                let rel_path = entry.path().strip_prefix(temp_dir)?.to_path_buf();

                // If metadata is missing for a file (e.g. created during extraction but not tracked), skip or handle error
                if !meta_map.contains_key(&rel_path) {
                    return Ok((PathBuf::new(), String::new()));
                }

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
                        if matches!(self.config.filesystem, FilesystemType::Btrfs | FilesystemType::Xfs) {
                            let src_file = File::open(entry.path())?;
                            let dest_file = OpenOptions::new().write(true).create(true).open(&obj_path)?;
                            // SAFETY: calling ioctl with valid FDs. ficlone defined by macro.
                            // Cast as_raw_fd() (i32) to u64 for ioctl macro argument
                            unsafe { ficlone(dest_file.as_raw_fd(), src_file.as_raw_fd() as u64)?; }
                        } else {
                            fs::hard_link(entry.path(), &obj_path)?;
                        }

                        // fs-verity
                        if self.config.use_fsverity {
                            let file = File::open(&obj_path)?;
                            // SAFETY: hypothetical implementation, simplified
                            unsafe { fsverity_enable(file.as_raw_fd(), 0)?; }
                        }

                        // IMA
                        if self.config.use_ima {
                            if let Some(meta) = meta_map.get(&rel_path) {
                                if let Some(label) = &meta.ima_label {
                                    // Set xattr: requires 'xattr' crate or nix::sys::xattr (if enabled)
                                    let _ = Command::new("setfattr").arg("-n").arg("security.ima").arg("-v").arg(label).arg(&obj_path).output();
                                }
                            }
                        }
                    } else {
                        let target = fs::read_link(entry.path())?;
                        symlink(&target, &obj_path)?;
                    }
                }

                Ok((rel_path, hash))
            } else {
                Ok((PathBuf::new(), String::new()))
            }
        }).collect();

        let mut successful_entries = Vec::new();

        for res in results {
            let (rel_path, hash) = res?;
            if !hash.is_empty() {
                let meta_json = serde_json::to_string(meta_map.get(&rel_path).unwrap())?;
                // Use sqlx::query (function) instead of macro
                sqlx::query("INSERT OR IGNORE INTO objects (hash, path, metadata) VALUES (?, ?, ?)")
                .bind(&hash)
                .bind(self.config.cas_dir.join(&hash[0..2]).join(&hash).to_string_lossy())
                .bind(meta_json)
                .execute(&mut self.db)
                .await?;
                successful_entries.push((rel_path, hash));
            }
        }

        Ok(successful_entries)
    }

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
                fs::create_dir_all(tree_root)?;
            }
        }

        let mut tree_hasher = Sha256::new();
        for (rel_path, hash) in entries {
            let cas_path = self.get_cas_path(hash)?;
            let dest = tree_root.join(rel_path);

            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Using sqlx::query function
            let row = sqlx::query("SELECT metadata FROM objects WHERE hash = ?")
            .bind(hash)
            .fetch_one(&mut self.db)
            .await?;

            let meta_str: String = row.try_get("metadata")?;
            let meta: FileMetadata = serde_json::from_str(&meta_str)?;

            if meta.is_symlink {
                symlink(meta.symlink_target.as_ref().unwrap(), &dest)?;
            } else {
                if matches!(self.config.filesystem, FilesystemType::Btrfs | FilesystemType::Xfs) {
                    let src_file = File::open(&cas_path)?;
                    let dest_file = OpenOptions::new().write(true).create(true).open(&dest)?;
                    // SAFETY: Cast as_raw_fd() (i32) to u64 for ioctl
                    unsafe { ficlone(dest_file.as_raw_fd(), src_file.as_raw_fd() as u64)?; }
                } else {
                    fs::hard_link(&cas_path, &dest)?;
                }
            }

            // Set permissions
            fs::set_permissions(&dest, Permissions::from_mode(meta.mode))?;

            // Set ownership
            nix::unistd::chown(&dest, Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid)))?;

            tree_hasher.update(hash.as_bytes());
            tree_hasher.update(rel_path.to_string_lossy().as_bytes());
        }

        let tree_hash = hex::encode(tree_hasher.finalize());

        if self.config.partitioning == PartitioningType::Subvolumes && self.config.filesystem == FilesystemType::Btrfs {
            Command::new("btrfs").arg("subvolume").arg("snapshot").arg("-r").arg(tree_root).arg(tree_root.with_file_name(format!("{}-ro", tree_hash))) .output()?;
        }

        Ok(tree_hash)
    }

    fn get_cas_path(&self, hash: &str) -> Result<PathBuf> {
        Ok(self.config.cas_dir.join(&hash[0..2]).join(hash))
    }

    pub async fn commit_tree(&mut self, tree_hash: &str, ref_name: &str, packages: &[(String, String)], previous_hash: Option<String>) -> Result<()> {
        let packages_json = serde_json::to_string(packages)?;
        let prev = previous_hash.unwrap_or_default();

        sqlx::query("INSERT OR REPLACE INTO trees (tree_hash, package_list, previous_hash) VALUES (?, ?, ?)")
        .bind(tree_hash)
        .bind(packages_json)
        .bind(prev)
        .execute(&mut self.db)
        .await?;

        sqlx::query("INSERT OR REPLACE INTO refs (ref_name, tree_hash) VALUES (?, ?)")
        .bind(ref_name)
        .bind(tree_hash)
        .execute(&mut self.db)
        .await?;

        Ok(())
    }

    pub async fn generate_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<PathBuf> {
        // let from_path = self.config.deployments_dir.join(from_hash);
        // let to_path = self.config.deployments_dir.join(to_hash);
        let delta_path = self.config.cas_dir.join(format!("delta-{}-{}", from_hash, to_hash));

        // Mock data read for compilation - real impl needs files
        let from_data = vec![0u8]; // fs::read(&from_path)?;
        let to_data = vec![1u8]; // fs::read(&to_path)?;
        let target_size = to_data.len() as i64;

        // Use bsdiff crate function. It writes to a writer.
        let mut patch_buffer = Vec::new();
        bsdiff::diff::diff(&from_data, &to_data, &mut patch_buffer)
        .map_err(|e| anyhow::anyhow!("Bsdiff error: {:?}", e))?;

        fs::write(&delta_path, &patch_buffer)?;

        sqlx::query("INSERT INTO deltas (from_hash, to_hash, delta_path, target_size) VALUES (?, ?, ?, ?)")
        .bind(from_hash)
        .bind(to_hash)
        .bind(delta_path.to_string_lossy())
        .bind(target_size)
        .execute(&mut self.db)
        .await?;

        Ok(delta_path)
    }

    pub async fn apply_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<()> {
        let row = sqlx::query("SELECT delta_path, target_size FROM deltas WHERE from_hash = ? AND to_hash = ?")
        .bind(from_hash)
        .bind(to_hash)
        .fetch_one(&mut self.db)
        .await?;

        let delta_path_str: String = row.try_get("delta_path")?;
        let target_size: i64 = row.try_get("target_size").unwrap_or(1024); // Fallback if null
        let delta_path = PathBuf::from(delta_path_str);

        // let from_path = self.config.deployments_dir.join(from_hash);
        let to_path = self.config.deployments_dir.join(to_hash);

        let patch_data = fs::read(&delta_path)?;
        let from_data = vec![0u8]; // fs::read(&from_path)?;

        // bsdiff patch requires a Reader for patch, and Mutable slice for Output
        let mut patch_cursor = Cursor::new(&patch_data);
        let mut new_data = vec![0u8; target_size as usize];

        bsdiff::patch::patch(&from_data, &mut patch_cursor, &mut new_data)
        .map_err(|e| anyhow::anyhow!("Bspatch error: {:?}", e))?;

        fs::write(&to_path, &new_data)?;
        Ok(())
    }

    pub async fn deploy(&mut self, ref_name: &str) -> Result<()> {
        let mut tx = self.db.begin().await?;

        let row = sqlx::query("SELECT tree_hash FROM refs WHERE ref_name = ?")
        .bind(ref_name)
        .fetch_one(&mut *tx)
        .await?;

        let tree_hash: String = row.try_get("tree_hash")?;
        let deployment_path = self.config.deployments_dir.join(&tree_hash);

        fs::remove_file(&self.config.current_link).ok();

        if let Err(e) = symlink(&deployment_path, &self.config.current_link) {
            tx.rollback().await?;
            return Err(e.into());
        }

        // To avoid borrowing `self` while `tx` (borrow of `self.db`) is active,
        // we pass `&self.config` to the helper methods.
        // `setup_overlays_with_merge` and others are now static functions or take &Config.

        if let Err(e) = Self::setup_overlays_with_merge(&self.config) {
            tx.rollback().await?;
            fs::remove_file(&self.config.current_link).ok();
            return Err(e);
        }

        if let Err(e) = Self::update_bootloader(&self.config, &tree_hash) {
            tx.rollback().await?;
            return Err(e.into());
        }

        Self::handle_stateless_config(&self.config)?;
        Self::load_sysexts(&self.config)?;
        tx.commit().await?;
        Ok(())
    }

    // Changed to associated function accepting Config to avoid borrow issues with DB transaction
    fn setup_overlays_with_merge(config: &Config) -> Result<()> {
        for dir in &config.overlay_dirs {
            if dir == &PathBuf::from("/etc") {
                let base = config.current_link.join("usr/share/factory/etc");
                let current = PathBuf::from("/etc");
                let new = config.current_link.join("etc");

                for file in WalkDir::new(&new).into_iter().filter_map(Result::ok) {
                    if file.file_type().is_file() {
                        if let Ok(rel) = file.path().strip_prefix(&new) {
                            let base_file = base.join(rel);
                            let current_file = current.join(rel);
                            let new_file = new.join(rel);
                            if base_file.exists() && current_file.exists() {
                                let base_data = fs::read(&base_file)?;
                                let current_data = fs::read(&current_file)?;
                                let new_data = fs::read(&new_file)?;

                                // Used local helper instead of external crate due to errors
                                let merged = three_way_merge(&base_data, &current_data, &new_data);
                                fs::write(&current_file, &merged)?;
                            }
                        }
                    }
                }
            }

            // Mounting setup code (simplified)
            let _lower = config.current_link.join(dir.strip_prefix("/").unwrap_or(dir));
            let upper = PathBuf::from("/overlay_upper").join(dir.file_name().unwrap());
            let work = PathBuf::from("/overlay_work").join(dir.file_name().unwrap());
            fs::create_dir_all(&upper)?;
            fs::create_dir_all(&work)?;
        }
        Ok(())
    }

    fn update_bootloader(config: &Config, tree_hash: &str) -> Result<()> {
        Self::generate_initramfs(config, tree_hash)?;
        let root_flags = match config.partitioning {
            PartitioningType::Subvolumes => {
                if let FilesystemType::Btrfs = config.filesystem {
                    format!("rootflags=subvol={}", tree_hash)
                } else {
                    "".to_string()
                }
            }
            PartitioningType::ABPartitions => "root=/dev/sda2".to_string(),
        };
        match config.bootloader {
            BootloaderType::Grub => {
                let entry = format!("menuentry 'FastTree {}' {{ linux /vmlinuz root=/dev/sda1 {} initrd /initramfs }}", tree_hash, root_flags);
                let _ = fs::create_dir_all(config.boot_dir.join("grub"));
                let mut config_file = File::create(config.boot_dir.join("grub/grub.cfg"))?;
                config_file.write_all(entry.as_bytes())?;
            }
            BootloaderType::SystemdBoot => {
                let _ = fs::create_dir_all(config.boot_dir.join("loader/entries"));
                let entry_path = config.boot_dir.join(format!("loader/entries/fasttree-{}.conf", tree_hash));
                let mut file = File::create(&entry_path)?;
                file.write_all(format!("title FastTree {}\nlinux /vmlinuz\ninitrd /initramfs\noptions root=/dev/sda1 {}\n", tree_hash, root_flags).as_bytes())?;
            }
        }
        Ok(())
    }

    fn generate_initramfs(config: &Config, tree_hash: &str) -> Result<()> {
        let root = config.deployments_dir.join(tree_hash);
        // Using explicit PathBuf conversion for Cow error fix
        let root_str = root.to_string_lossy().to_string();

        Command::new("dracut")
        .arg("--kver").arg("5.10.0")
        .arg("--install").arg(root_str)
        .arg(config.boot_dir.join("initramfs"))
        .output()?;
        Ok(())
    }

    fn load_sysexts(config: &Config) -> Result<()> {
        for ext in fs::read_dir(&config.sysext_dir)? {
            let path = ext?.path();
            if path.extension() == Some("raw".as_ref()) {
                Command::new("systemd-sysext").arg("merge").arg(&path).output()?;
            }
        }
        Ok(())
    }

    pub async fn rollback(&mut self) -> Result<()> {
        let current_row = sqlx::query("SELECT tree_hash FROM refs WHERE ref_name = 'current'")
        .fetch_optional(&mut self.db)
        .await?;

        if let Some(current) = current_row {
            let current_hash: String = current.try_get("tree_hash")?;
            let tree_row = sqlx::query("SELECT previous_hash FROM trees WHERE tree_hash = ?")
            .bind(current_hash)
            .fetch_one(&mut self.db)
            .await?;

            let prev_hash: String = tree_row.try_get("previous_hash")?;
            if !prev_hash.is_empty() {
                sqlx::query("UPDATE refs SET tree_hash = ? WHERE ref_name = 'current'")
                .bind(&prev_hash)
                .execute(&mut self.db)
                .await?;
                self.deploy("current").await?;
            }
        }
        Ok(())
    }

    pub fn run_health_check(&self) -> Result<bool> {
        if let Some(script) = &self.config.health_check_script {
            let output = Command::new(script).output()?;
            if !output.status.success() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn handle_stateless_config(config: &Config) -> Result<()> {
        let factory = config.current_link.join("usr/share/factory");
        let etc = PathBuf::from("/etc");
        if factory.exists() {
            for entry in WalkDir::new(&factory).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    let rel = entry.path().strip_prefix(&factory)?;
                    let target = etc.join(rel);
                    if !target.exists() {
                        if let Some(parent) = target.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::copy(entry.path(), &target)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn install(&mut self, package: &str, ref_name: &str) -> Result<()> {
        let deps = self.resolve_dependencies(package).await?;
        let mut entries = Vec::new();

        let prev_row = sqlx::query("SELECT tree_hash FROM refs WHERE ref_name = ?")
        .bind(ref_name)
        .fetch_optional(&mut self.db)
        .await?;

        let prev_hash: Option<String> = match prev_row {
            Some(row) => Some(row.try_get("tree_hash")?),
            None => None,
        };

        if let Some(prev) = &prev_hash {
            let delta_row = sqlx::query("SELECT to_hash FROM deltas WHERE from_hash = ?")
            .bind(prev)
            .fetch_optional(&mut self.db)
            .await?;
            if let Some(delta) = delta_row {
                let to_hash: String = delta.try_get("to_hash")?;
                self.apply_delta(prev, &to_hash).await?;
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

        self.commit_tree(&tree_hash, ref_name, &deps, prev_hash.clone()).await?;

        if let Some(prev) = prev_hash {
            self.generate_delta(&prev, &tree_hash).await?;
        }

        self.deploy(ref_name).await?;
        if tree_root.exists() {
            // Rename might fail if cross-device, copy loop preferred usually but rename ok for same volume
            fs::rename(&tree_root, self.config.deployments_dir.join(&tree_hash))?;
        }
        Ok(())
    }

    pub async fn build_image(&mut self, _packages: &[String], _output: &Path, _format: ImageFormat) -> Result<()> {
        unimplemented!();
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ImageFormat {
    Img,
    Qcow2,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _config = Config {
        repo_url: "http://deb.debian.org/debian".to_string(),
        distro_type: DistroType::Apt,
        cas_dir: PathBuf::from("/var/lib/fasttree/objects"),
        db_path: PathBuf::from("/var/lib/fasttree/db.sqlite"),
        deployments_dir: PathBuf::from("/sysroot"),
        current_link: PathBuf::from("./current_test"), // Changed to local for safety in test
        boot_dir: PathBuf::from("/boot"),
        bootloader: BootloaderType::Grub,
        filesystem: FilesystemType::Btrfs,
        health_check_script: Some(PathBuf::from("/usr/bin/health-check.sh")),
        overlay_dirs: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
        var_volume: Some(PathBuf::from("/dev/sdb1"),),
        gpg_keyring: PathBuf::from("/etc/apt/trusted.gpg"),
        use_fsverity: true,
        use_ima: true,
        partitioning: PartitioningType::Subvolumes,
        sysext_dir: PathBuf::from("/var/lib/extensions"),
    };
    // let mut ft = FastTree::new(config).await?;
    // ft.install("nginx", "stable").await?;
    Ok(())
}
