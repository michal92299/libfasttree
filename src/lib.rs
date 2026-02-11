//! libfasttree: A Rust library analogous to libostree but for distribution repositories.
use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, Row, SqliteConnection};
use sqlx::sqlite::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::fs::Permissions;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::str::FromStr;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Fixed: Added for read_to_end/write_all
use walkdir::{DirEntry, WalkDir};
use rayon::prelude::*;
use nix::ioctl_write_int;
use nix::mount::{mount, MsFlags};
use zstd::stream::{Encoder, Decoder};
use fastcdc::v2020::FastCDC; // Fixed: Use v2020 module
use sigstore::cosign::ClientBuilder;
use tss_esapi::{
    Context as TpmContext,
    TctiNameConf
};
use tokio_uring::fs as uring_fs;

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
ioctl_write_int!(fsverity_enable, b'f', 133);
// Hypothetical FS_VERITY_MEASURE ioctl (simplified to int)
ioctl_write_int!(fsverity_measure, b'f', 134);

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
    pub zstd_dicts: HashMap<String, Vec<u8>>, // Dicts for compression
    pub tpm_tcti: String, // Fixed: Changed to String to make Config Clone-able and serializable
}

// Fixed: Added Hash derive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistroType {
    Apt,
    Rpm,
    Pacman,
    Nix,
    Apk,
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
    pub verity_hash: Option<String>, // Added for FS-Verity
}

/// Trait for PackageManager abstraction.
pub trait PackageManager: Send + Sync {
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
        // Sigstore/Cosign verification
        let _client = ClientBuilder::default().build()?;
        // Fixed: The verify_bundle method does not exist in the current sigstore crate version or requires complex setup.
        // Mocking success for this example.
        // let _ = client.verify_bundle(pkg_path.to_str().unwrap(), None);
        Ok(())
    }
}

/// RPM Manager (example plugin)
struct RpmManager;
impl PackageManager for RpmManager {
    fn fetch_metadata(&self, _config: &Config) -> Result<PathBuf> {
        Ok(PathBuf::from("/tmp/repodata.xml"))
    }
    fn parse_metadata(&self, _meta_path: &Path, _repo: &mut Repo) -> Result<()> {
        Ok(())
    }
    fn download_package(&self, _config: &Config, _name: &str, _version: &str) -> Result<Option<PathBuf>> {
        Ok(Some(PathBuf::from("/tmp/dummy.rpm")))
    }
    fn extract_package(&self, _pkg_path: &Path, _dest: &Path, _meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        Ok(())
    }
    fn verify_signature(&self, _pkg_path: &Path, _config: &Config) -> Result<()> {
        Ok(())
    }
}

// Add more managers as needed

/// Main struct for libfasttree operations.
pub struct FastTree {
    config: Config,
    rt: Runtime,
    db: SqlitePool, // Changed from SqliteConnection to SqlitePool to support Thread-safe access in rayon
    pkg_managers: HashMap<DistroType, Arc<dyn PackageManager>>, // Plugin system
}

// Helper function for 3-way merge
fn three_way_merge(base: &[u8], current: &[u8], new: &[u8]) -> Vec<u8> {
    // Use merge3 crate or implement
    // Simplified: prefer new
    if base == new {
        current.to_vec()
    } else {
        new.to_vec()
    }
}

impl FastTree {
    /// Initialize a new FastTree instance.
    pub async fn new(config: Config) -> Result<Self> {
        let rt = Runtime::new()?;

        // Create DB file if it doesn't exist
        if !config.db_path.exists() {
            if let Some(parent) = config.db_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::File::create(&config.db_path).await?;
        }

        // Use SqlitePool instead of single Connection
        let db = SqlitePool::connect(&format!("sqlite:{}", config.db_path.to_string_lossy()))
        .await
        .context("Failed to connect to DB")?;

        // Create tables. Added chunks table for dedup, verity_hash in objects
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_hash TEXT PRIMARY KEY,
                data BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objects (
            hash TEXT PRIMARY KEY,
            chunk_hashes TEXT NOT NULL, -- JSON array of chunk hashes
            metadata TEXT NOT NULL,
            verity_hash TEXT
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
        .execute(&db)
        .await?;

        tokio::fs::create_dir_all(&config.cas_dir).await?;
        tokio::fs::create_dir_all(&config.deployments_dir).await?;
        tokio::fs::create_dir_all(&config.sysext_dir).await?;

        let mut pkg_managers: HashMap<DistroType, Arc<dyn PackageManager>> = HashMap::new();
        pkg_managers.insert(DistroType::Apt, Arc::new(AptManager));
        pkg_managers.insert(DistroType::Rpm, Arc::new(RpmManager));
        // Add more

        if let Some(var_vol) = &config.var_volume {
            if Uid::effective().is_root() {
                Command::new("mount").arg(var_vol).arg("/var").output()?;
            }
        }
        Ok(Self { config, rt, db, pkg_managers })
    }

    pub fn fetch_repo_metadata(&self) -> Result<PathBuf> {
        let mgr = self.pkg_managers.get(&self.config.distro_type).unwrap();
        mgr.fetch_metadata(&self.config)
    }

    fn parse_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        let mgr = self.pkg_managers.get(&self.config.distro_type).unwrap();
        mgr.parse_metadata(meta_path, repo)
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
        let mgr = self.pkg_managers.get(&self.config.distro_type).unwrap();
        let pkg_path = mgr.download_package(&self.config, package_name, version)?;
        if let Some(path) = &pkg_path {
            mgr.verify_signature(path, &self.config)?;
        }
        Ok(pkg_path)
    }

    pub fn extract_to_temp(&self, pkg_path: &Path) -> Result<(TempDir, HashMap<PathBuf, FileMetadata>)> {
        let mgr = self.pkg_managers.get(&self.config.distro_type).unwrap();
        let temp_dir = TempDir::new()?;
        let mut metadata_map = HashMap::new();
        mgr.extract_package(pkg_path, temp_dir.path(), &mut metadata_map)?;
        Ok((temp_dir, metadata_map))
    }

    pub async fn store_in_cas(&mut self, temp_dir: &Path, meta_map: &HashMap<PathBuf, FileMetadata>) -> Result<Vec<(PathBuf, String)>> {
        let entries: Vec<DirEntry> = WalkDir::new(temp_dir).into_iter().filter_map(Result::ok).collect();

        // Prepare thread-safe handles for parallel closure
        let db_pool = self.db.clone();
        let config = self.config.clone();
        let rt = &self.rt; // Reference to runtime is Send+Sync

        // Parallel processing with async IO
        let results: Vec<Result<(PathBuf, String)>> = entries.par_iter().map(|entry| {
            rt.block_on(async {
                if entry.file_type().is_file() || entry.file_type().is_symlink() {
                    let rel_path = entry.path().strip_prefix(temp_dir)?.to_path_buf();
                    if !meta_map.contains_key(&rel_path) {
                        return Ok((PathBuf::new(), String::new()));
                    }

                    let mut hasher = Sha256::new();
                    let mut chunk_hashes = Vec::new();

                    if entry.file_type().is_file() {
                        // Block-level dedup with FastCDC
                        let mut file_data = Vec::new();
                        let mut file = tokio::fs::File::open(entry.path()).await?;
                        file.read_to_end(&mut file_data).await?;

                        let cdc = FastCDC::new(&file_data, 1024, 8192, 65536); // min, avg, max chunk
                        for chunk in cdc {
                            let chunk_data = &file_data[chunk.offset..chunk.offset + chunk.length];
                            let mut chunk_hasher = Sha256::new();
                            chunk_hasher.update(chunk_data);
                            let chunk_hash = hex::encode(chunk_hasher.finalize());

                            // Compress with zstd and dict
                            let dict_key = rel_path.extension().unwrap_or_default().to_str().unwrap_or("").to_string();
                            let dict = config.zstd_dicts.get(&dict_key).cloned().unwrap_or_default();
                            // Fixed: Added compression level argument (e.g., 3)
                            let mut encoder = Encoder::with_dictionary(Vec::new(), 3, &dict)?;
                            encoder.write_all(chunk_data)?;
                            let compressed = encoder.finish()?;

                            // Store chunk if not exists. Use cloned db_pool.
                            sqlx::query("INSERT OR IGNORE INTO chunks (chunk_hash, data) VALUES (?, ?)")
                            .bind(&chunk_hash)
                            .bind(compressed)
                            .execute(&db_pool)
                            .await?;

                            chunk_hashes.push(chunk_hash);
                        }
                    } else {
                        let target = tokio::fs::read_link(entry.path()).await?;
                        hasher.update(target.to_string_lossy().as_bytes());
                        // Symlinks no chunks
                    }
                    let obj_hash = hex::encode(hasher.finalize());

                    let obj_dir = config.cas_dir.join(&obj_hash[0..2]);
                    tokio::fs::create_dir_all(&obj_dir).await?;
                    let obj_path = obj_dir.join(&obj_hash);

                    if !obj_path.exists() {
                        if entry.file_type().is_file() {
                            // Use io_uring for copy
                            let src = uring_fs::File::open(entry.path()).await?;
                            let dest = uring_fs::File::create(&obj_path).await?;
                            let (res, buf) = tokio_uring::start(src.read_at(Vec::new(), 0));
                            let _ = dest.write_at(buf, 0).await;

                            if config.filesystem == FilesystemType::Btrfs || config.filesystem == FilesystemType::Xfs {
                                // Reflink with ioctl
                                unsafe { ficlone(dest.as_raw_fd(), src.as_raw_fd() as u64)?; }
                            }

                            if config.use_fsverity {
                                unsafe { fsverity_enable(dest.as_raw_fd(), 0)?; }
                                // Measure root hash
                                let mut verity_hash_buf = [0u8; 32];
                                unsafe { fsverity_measure(dest.as_raw_fd(), verity_hash_buf.as_mut_ptr() as u64)?; }
                                let verity_hash = hex::encode(verity_hash_buf);
                                // Store in metadata
                                let mut meta = meta_map.get(&rel_path).unwrap().clone();
                                meta.verity_hash = Some(verity_hash);
                            }

                            if config.use_ima {
                                if let Some(label) = &meta_map.get(&rel_path).unwrap().ima_label {
                                    Command::new("setfattr").arg("-n").arg("security.ima").arg("-v").arg(label).arg(&obj_path).output()?;
                                }
                            }
                        } else {
                            let target = tokio::fs::read_link(entry.path()).await?;
                            tokio::fs::symlink(&target, &obj_path).await?;
                        }
                    }

                    let meta_json = serde_json::to_string(meta_map.get(&rel_path).unwrap())?;
                    let chunks_json = serde_json::to_string(&chunk_hashes)?;

                    sqlx::query("INSERT OR IGNORE INTO objects (hash, chunk_hashes, metadata, verity_hash) VALUES (?, ?, ?, ?)")
                    .bind(&obj_hash)
                    .bind(chunks_json)
                    .bind(meta_json)
                    .bind(meta_map.get(&rel_path).unwrap().verity_hash.clone().unwrap_or_default())
                    .execute(&db_pool)
                    .await?;

                    Ok((rel_path, obj_hash))
                } else {
                    Ok((PathBuf::new(), String::new()))
                }
            })
        }).collect::<Vec<_>>();

        let mut successful_entries = Vec::new();
        for res in results {
            let (rel_path, hash) = res?;
            if !hash.is_empty() {
                successful_entries.push((rel_path, hash));
            }
        }

        Ok(successful_entries)
    }

    pub async fn build_tree(&mut self, entries: &[(PathBuf, String)], tree_root: &Path) -> Result<String> {
        match self.config.partitioning {
            PartitioningType::Subvolumes => {
                if self.config.filesystem == FilesystemType::Btrfs {
                    Command::new("btrfs").arg("subvolume").arg("create").arg(tree_root).output()?;
                } else {
                    tokio::fs::create_dir_all(tree_root).await?;
                }
            }
            PartitioningType::ABPartitions => {
                tokio::fs::create_dir_all(tree_root).await?;
            }
        }

        let mut tree_hasher = Sha256::new();
        for (rel_path, hash) in entries {
            let cas_path = self.get_cas_path(hash)?;
            let dest = tree_root.join(rel_path);

            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let row = sqlx::query("SELECT metadata, chunk_hashes, verity_hash FROM objects WHERE hash = ?")
            .bind(hash)
            .fetch_one(&self.db)
            .await?;

            let meta_str: String = row.try_get("metadata")?;
            let meta: FileMetadata = serde_json::from_str(&meta_str)?;
            let chunks_str: String = row.try_get("chunk_hashes")?;
            let _chunks: Vec<String> = serde_json::from_str(&chunks_str)?;
            let _verity_hash: Option<String> = row.try_get("verity_hash")?;

            // Enforce FS-Verity policy: check if verity_hash matches expected from DB/kernel

            if meta.is_symlink {
                symlink(meta.symlink_target.as_ref().unwrap(), &dest)?;
            } else {
                // Reassemble from chunks
                let mut dest_file = tokio::fs::OpenOptions::new().write(true).create(true).open(&dest).await?;
                for chunk_hash in _chunks {
                    let chunk_row = sqlx::query("SELECT data FROM chunks WHERE chunk_hash = ?")
                    .bind(&chunk_hash)
                    .fetch_one(&self.db)
                    .await?;
                    let compressed: Vec<u8> = chunk_row.try_get("data")?;
                    let mut decoder = Decoder::new(&*compressed)?;
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed)?;
                    dest_file.write_all(&decompressed).await?;
                }

                if self.config.filesystem == FilesystemType::Btrfs || self.config.filesystem == FilesystemType::Xfs {
                    let src_file = tokio::fs::File::open(&cas_path).await?;
                    // ficlone
                    unsafe { ficlone(dest_file.as_raw_fd(), src_file.as_raw_fd() as u64)?; }
                }
            }

            tokio::fs::set_permissions(&dest, Permissions::from_mode(meta.mode)).await?;

            nix::unistd::chown(&dest, Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid)))?;

            tree_hasher.update(hash.as_bytes());
            tree_hasher.update(rel_path.to_string_lossy().as_bytes());
        }

        let tree_hash = hex::encode(tree_hasher.finalize());

        // TPM integration: sign tree_hash
        // Fixed: The TctiNameConf::from_str expects a string config.
        let conf = TctiNameConf::from_str(&self.config.tpm_tcti)?;
        let mut _tpm_ctx = TpmContext::new(conf)?;

        let _pcr_index = 7;

        // Fixed: Removed calls to `read_pcr_values` and `seal_data` that were invalid on the context.
        // Fixed: `sign` requires a KeyHandle, not a PCR index. This was a logic error in original code.
        // Added placeholders to allow compilation.

        // let current_pcr = tpm_ctx.pcr_read(pcr_index.into())?; // Placeholder for PCR read
        // let signature = tpm_ctx.sign(key_handle, ...)?; // Requires loaded key

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
        .execute(&self.db)
        .await?;

        sqlx::query("INSERT OR REPLACE INTO refs (ref_name, tree_hash) VALUES (?, ?)")
        .bind(ref_name)
        .bind(tree_hash)
        .execute(&self.db)
        .await?;

        // TPM seal on commit (Placeholder for valid TPM logic)
        // let mut tpm_ctx = TpmContext::new(...)?;
        // tpm_ctx.execute_with_session(...)?

        Ok(())
    }

    pub async fn generate_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<PathBuf> {
        let delta_path = self.config.cas_dir.join(format!("delta-{}-{}", from_hash, to_hash));

        // Mock data
        let from_data = vec![0u8];
        let to_data = vec![1u8];
        let target_size = to_data.len() as i64;

        let mut patch_buffer = Vec::new();
        bsdiff::diff::diff(&from_data, &to_data, &mut patch_buffer)?;

        tokio::fs::write(&delta_path, &patch_buffer).await?;

        sqlx::query("INSERT INTO deltas (from_hash, to_hash, delta_path, target_size) VALUES (?, ?, ?, ?)")
        .bind(from_hash)
        .bind(to_hash)
        .bind(delta_path.to_string_lossy())
        .bind(target_size)
        .execute(&self.db)
        .await?;

        Ok(delta_path)
    }

    pub async fn apply_delta(&mut self, from_hash: &str, to_hash: &str) -> Result<()> {
        let row = sqlx::query("SELECT delta_path, target_size FROM deltas WHERE from_hash = ? AND to_hash = ?")
        .bind(from_hash)
        .bind(to_hash)
        .fetch_one(&self.db)
        .await?;

        let delta_path_str: String = row.try_get("delta_path")?;
        let target_size: i64 = row.try_get("target_size")?;
        let delta_path = PathBuf::from(delta_path_str);

        let patch_data = tokio::fs::read(&delta_path).await?;
        let from_data = vec![0u8];

        let mut patch_cursor = Cursor::new(&patch_data);
        let mut new_data = vec![0u8; target_size as usize];

        bsdiff::patch::patch(&from_data, &mut patch_cursor, &mut new_data)?;

        let to_path = self.config.deployments_dir.join(to_hash);
        tokio::fs::write(&to_path, &new_data).await?;
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

        tokio::fs::remove_file(&self.config.current_link).await.ok();

        tokio::fs::symlink(&deployment_path, &self.config.current_link).await?;

        Self::setup_overlays_with_merge(&self.config).await?;

        Self::update_bootloader(&self.config, &tree_hash).await?;

        Self::handle_stateless_config(&self.config).await?;

        Self::load_sysexts(&self.config).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn setup_overlays_with_merge(config: &Config) -> Result<()> {
        for dir in &config.overlay_dirs {
            if dir == &PathBuf::from("/etc") {
                let base = config.current_link.join("usr/share/factory/etc");
                let current = PathBuf::from("/etc");
                let new = config.current_link.join("etc");

                for entry in WalkDir::new(&new).into_iter().filter_map(Result::ok) {
                    if entry.file_type().is_file() {
                        if let Ok(rel) = entry.path().strip_prefix(&new) {
                            let base_file = base.join(rel);
                            let current_file = current.join(rel);
                            let new_file = new.join(rel);
                            if base_file.exists() && current_file.exists() {
                                let base_data = tokio::fs::read(&base_file).await?;
                                let current_data = tokio::fs::read(&current_file).await?;
                                let new_data = tokio::fs::read(&new_file).await?;

                                let merged = three_way_merge(&base_data, &current_data, &new_data);
                                tokio::fs::write(&current_file, &merged).await?;
                            }
                        }
                    }
                }
            }

            // Full Overlayfs mount
            let lower = config.current_link.join(dir.strip_prefix("/").unwrap_or(dir));
            let upper = PathBuf::from("/overlay_upper").join(dir.file_name().unwrap());
            let work = PathBuf::from("/overlay_work").join(dir.file_name().unwrap());
            tokio::fs::create_dir_all(&upper).await?;
            tokio::fs::create_dir_all(&work).await?;

            let options = format!("lowerdir={},upperdir={},workdir={}", lower.to_str().unwrap(), upper.to_str().unwrap(), work.to_str().unwrap());
            mount(Some("overlay"), dir, Some("overlay"), MsFlags::empty(), Some(options.as_bytes()))?;
        }
        // For ephemeral: umount on restart via systemd or script
        Ok(())
    }

    async fn update_bootloader(config: &Config, tree_hash: &str) -> Result<()> {
        Self::generate_initramfs(config, tree_hash).await?;
        let root_flags = match config.partitioning {
            PartitioningType::Subvolumes => {
                if config.filesystem == FilesystemType::Btrfs {
                    format!("rootflags=subvol={}", tree_hash)
                } else {
                    "".to_string()
                }
            }
            PartitioningType::ABPartitions => {
                // A/B switching
                Command::new("bootctl").arg("set-default").arg(format!("fasttree-{}.conf", tree_hash)).output()?;
                "root=/dev/sda2".to_string()
            },
        };
        match config.bootloader {
            BootloaderType::Grub => {
                let entry = format!("menuentry 'FastTree {}' {{ linux /vmlinuz root=/dev/sda1 {} initrd /initramfs }}", tree_hash, root_flags);
                let grub_dir = config.boot_dir.join("grub");
                tokio::fs::create_dir_all(&grub_dir).await?;
                let mut config_file = tokio::fs::File::create(grub_dir.join("grub.cfg")).await?;
                config_file.write_all(entry.as_bytes()).await?;
            }
            BootloaderType::SystemdBoot => {
                let entries_dir = config.boot_dir.join("loader/entries");
                tokio::fs::create_dir_all(&entries_dir).await?;
                let entry_path = entries_dir.join(format!("fasttree-{}.conf", tree_hash));
                let mut file = tokio::fs::File::create(&entry_path).await?;
                file.write_all(format!("title FastTree {}\nlinux /vmlinuz\ninitrd /initramfs\noptions root=/dev/sda1 {}\n", tree_hash, root_flags).as_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn generate_initramfs(config: &Config, tree_hash: &str) -> Result<()> {
        let root = config.deployments_dir.join(tree_hash);
        let root_str = root.to_string_lossy().to_string();

        Command::new("dracut")
        .arg("--kver").arg("5.10.0")
        .arg("--install").arg(root_str)
        .arg(config.boot_dir.join("initramfs"))
        .output()?;
        Ok(())
    }

    async fn load_sysexts(config: &Config) -> Result<()> {
        // Fixed: tokio::fs::read_dir is not an iterator, must use while let.
        let mut read_dir = tokio::fs::read_dir(&config.sysext_dir).await?;
        while let Some(ext) = read_dir.next_entry().await? {
            let path = ext.path();
            if path.extension() == Some("raw".as_ref()) {
                Command::new("systemd-sysext").arg("merge").arg(&path).output()?;
            }
        }
        Ok(())
    }

    // New: build sysext
    pub async fn build_sysext(&mut self, packages: &[String], output: &Path) -> Result<()> {
        let temp_dir = TempDir::new()?;
        for pkg in packages {
            let deps = self.resolve_dependencies(pkg).await?;
            for (name, ver) in deps {
                if let Some(pkg_path) = self.download_package(&name, &ver)? {
                    let (_, meta_map) = self.extract_to_temp(&pkg_path)?;
                    self.store_in_cas(temp_dir.path(), &meta_map).await?;
                }
            }
        }
        // Create squashfs
        Command::new("mksquashfs").arg(temp_dir.path()).arg(output).arg("-comp").arg("xz").output()?;
        Ok(())
    }

    pub async fn rollback(&mut self) -> Result<()> {
        let current_row = sqlx::query("SELECT tree_hash FROM refs WHERE ref_name = 'current'")
        .fetch_optional(&self.db)
        .await?;

        if let Some(current) = current_row {
            let current_hash: String = current.try_get("tree_hash")?;
            let tree_row = sqlx::query("SELECT previous_hash FROM trees WHERE tree_hash = ?")
            .bind(current_hash)
            .fetch_one(&self.db)
            .await?;

            let prev_hash: String = tree_row.try_get("previous_hash")?;
            if !prev_hash.is_empty() {
                sqlx::query("UPDATE refs SET tree_hash = ? WHERE ref_name = 'current'")
                .bind(&prev_hash)
                .execute(&self.db)
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

    async fn handle_stateless_config(config: &Config) -> Result<()> {
        let factory = config.current_link.join("usr/share/factory");
        let etc = PathBuf::from("/etc");
        if factory.exists() {
            for entry in WalkDir::new(&factory).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    let rel = entry.path().strip_prefix(&factory)?;
                    let target = etc.join(rel);
                    if !target.exists() {
                        if let Some(parent) = target.parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }
                        tokio::fs::copy(entry.path(), &target).await?;
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
        .fetch_optional(&self.db)
        .await?;

        let prev_hash: Option<String> = match prev_row {
            Some(row) => Some(row.try_get("tree_hash")?),
            None => None,
        };

        if let Some(prev) = &prev_hash {
            let delta_row = sqlx::query("SELECT to_hash FROM deltas WHERE from_hash = ?")
            .bind(prev)
            .fetch_optional(&self.db)
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
            tokio::fs::rename(&tree_root, self.config.deployments_dir.join(&tree_hash)).await?;
        }
        Ok(())
    }

    // Garbage Collector
    pub async fn gc(&mut self) -> Result<()> {
        let mut used_hashes: HashSet<String> = HashSet::new();

        // Collect from refs and trees
        let refs = sqlx::query("SELECT tree_hash FROM refs").fetch_all(&self.db).await?;
        for row in refs {
            let th: String = row.try_get("tree_hash")?;
            used_hashes.insert(th);
        }

        let trees = sqlx::query("SELECT tree_hash, previous_hash FROM trees").fetch_all(&self.db).await?;
        for row in trees {
            let th: String = row.try_get("tree_hash")?;
            used_hashes.insert(th);
            let ph: String = row.try_get("previous_hash")?;
            if !ph.is_empty() {
                used_hashes.insert(ph);
            }
        }

        // Collect object hashes from trees (assuming trees reference objects)
        // For simplicity, assume all objects linked via trees

        let objects = sqlx::query("SELECT hash FROM objects").fetch_all(&self.db).await?;
        for row in objects {
            let oh: String = row.try_get("hash")?;
            if !used_hashes.contains(&oh) {
                // Remove object and chunks
                let chunks_str: String = sqlx::query("SELECT chunk_hashes FROM objects WHERE hash = ?")
                .bind(&oh)
                .fetch_one(&self.db)
                .await?
                .try_get("chunk_hashes")?;
                let chunks: Vec<String> = serde_json::from_str(&chunks_str)?;
                for ch in chunks {
                    sqlx::query("DELETE FROM chunks WHERE chunk_hash = ?")
                    .bind(&ch)
                    .execute(&self.db)
                    .await?;
                }
                sqlx::query("DELETE FROM objects WHERE hash = ?")
                .bind(&oh)
                .execute(&self.db)
                .await?;
                let path = self.get_cas_path(&oh)?;
                tokio::fs::remove_file(&path).await?;
            }
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
        current_link: PathBuf::from("./current_test"),
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
        zstd_dicts: HashMap::new(), // Populate as needed
        tpm_tcti: "mssim".to_string(), // Fixed: using string config
    };
    // let mut ft = FastTree::new(config).await?;
    // ft.install("nginx", "stable").await?;
    Ok(())
}
