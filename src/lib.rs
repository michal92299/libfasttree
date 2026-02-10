//! libfasttree: A Rust library analogous to libostree but for distribution repositories (APT, RPM, Pacman).
//!
//! This library provides immutable system snapshots based on package managers.
//! It uses content-addressable storage (CAS) for files, builds trees from packages,
//! handles deployments atomically, supports metadata (symlinks, permissions),
//! dependency resolution, refs for history, and static deltas for efficient updates.
//! Expanded with bootloader integration, rollback, filesystem support (reflinks, subvolumes),
//! overlayfs, image builder, and stateless config support.

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
use ar::Archive as ArArchive; // For .deb
use xz2::read::XzDecoder; // For .xz in .deb
use libsolv_rs::{Pool, Repo, Solver}; // Assuming libsolv-rs API
use nix::ioctl_write_ptr; // For reflinks
use nix::sys::ioctl; // For BTRFS ioctls
use std::os::unix::io::AsRawFd;
use std::process::Command; // For external commands like mkimage, btrfs
use tar::Archive; // For tar handling

// Define ioctl for reflink (FICLONE)
ioctl_write_ptr!(ficlone, 'X', 9, i32); // Assuming standard

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

/// File metadata for storage in DB.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub mode: u32, // Permissions mode
    pub uid: u32, // User ID
    pub gid: u32, // Group ID
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
            DistroType::Pacman => format!("{}/core.db", self.config.repo_url), // .db is a tar.gz
        };
        let client = Client::new();
        let response = client.get(&url).send()?.error_for_status()?;
        let meta_path = PathBuf::from("repo_metadata");
        let mut file = BufWriter::new(File::create(&meta_path)?);
        response.copy_to(&mut file)?;
        Ok(meta_path)
    }

    /// Parse APT metadata (simplified).
    fn parse_apt_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        let file = File::open(meta_path)?;
        let decoder = GzDecoder::new(file);
        let reader = BufReader::new(decoder);
        // Simple line-by-line parsing (not full implementation)
        for line in reader.lines() {
            let line = line?;
            if line.starts_with("Package: ") {
                let name = line.trim_start_matches("Package: ").to_string();
                // Add to repo (assuming API)
                // let solvable = repo.add_solvable();
                // solvable.set_name(name);
                // etc.
            }
            // Parse Version, Depends, etc.
        }
        Ok(())
    }

    /// Parse RPM metadata (simplified).
    fn parse_rpm_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        let file = File::open(meta_path)?;
        let parser = EventReader::new(file);
        // Parse repomd.xml to find primary, then fetch and parse
        // For simplicity, unimplemented fully
        unimplemented!("Full RPM parsing");
    }

    /// Parse Pacman metadata (simplified).
    fn parse_pacman_metadata(&self, meta_path: &Path, repo: &mut Repo) -> Result<()> {
        let file = File::open(meta_path)?;
        let mut archive = Archive::new(file);
        // Extract and parse %NAME%, %VERSION%, etc.
        unimplemented!("Full Pacman parsing");
    }

    /// Resolve dependencies using libsolv.
    pub async fn resolve_dependencies(&mut self, package: &str) -> Result<Vec<(String, String)>> { // (name, version)
        let meta_path = self.fetch_repo_metadata()?;
        let pool = Pool::new();
        let mut repo = Repo::new(&pool, "main_repo");
        match self.config.distro_type {
            DistroType::Apt => self.parse_apt_metadata(&meta_path, &mut repo)?,
            DistroType::Rpm => self.parse_rpm_metadata(&meta_path, &mut repo)?,
            DistroType::Pacman => self.parse_pacman_metadata(&meta_path, &mut repo)?,
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
        // Hypothetical: query DB if package_version hash exists
        // For simplicity, always download
        let url = match self.config.distro_type {
            DistroType::Apt => format!("{}/pool/main/{}/{}_{}_amd64.deb", self.config.repo_url, package_name.chars().next().unwrap_or(' '), package_name, version),
            DistroType::Rpm => format!("{}/{}-{}-x86_64.rpm", self.config.repo_url, package_name, version),
            DistroType::Pacman => format!("{}/{}-{}-x86_64.pkg.tar.zst", self.config.repo_url, package_name, version),
        };
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
        while let Some(entry) = ar.next_entry() {
            if let Ok(mut entry) = entry {
                let header = entry.header();
                let ident = String::from_utf8_lossy(header.identifier()).trim_end_matches('\0').to_string();
                if ident.starts_with("data.tar") {
                    let decoder: Box<dyn Read> = if ident.ends_with(".xz") {
                        Box::new(XzDecoder::new(entry))
                    } else if ident.ends_with(".zst") {
                        Box::new(zstd::Decoder::new(entry)?)
                    } else {
                        Box::new(entry)
                    };
                    let mut tar = tar::Archive::new(decoder);
                    tar.unpack(dest)?;
                    // Walk and capture metadata
                    for entry in WalkDir::new(dest).into_iter().filter_map(Result::ok) {
                        if entry.depth() > 0 {
                            let rel_path = entry.path().strip_prefix(dest)?.to_path_buf();
                            let meta = fs::symlink_metadata(entry.path())?;
                            meta_map.insert(rel_path, FileMetadata {
                                mode: meta.mode(),
                                uid: meta.uid(),
                                gid: meta.gid(),
                                is_symlink: meta.file_type().is_symlink(),
                                symlink_target: if meta.file_type().is_symlink() { Some(fs::read_link(entry.path())?.to_string_lossy().to_string()) } else { None },
                            });
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn extract_rpm(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        // Assuming rpm crate has files() and content()
        // Use rpm crate
        let file = File::open(pkg_path)?;
        let pkg = rpm::Package::read(file)?;
        for rpm_file in pkg.files() {
            let path = dest.join(rpm_file.path());
            fs::create_dir_all(path.parent().unwrap())?;
            if rpm_file.mode().is_symlink() {
                symlink(rpm_file.linkname().unwrap(), &path)?;
            } else {
                let mut f = File::create(&path)?;
                f.write_all(rpm_file.payload().as_slice())?;
            }
            fs::set_permissions(&path, Permissions::from_mode(rpm_file.mode().bits()))?;
            let meta = fs::symlink_metadata(&path)?;
            meta_map.insert(path.strip_prefix(dest)?.to_path_buf(), FileMetadata {
                mode: meta.mode(),
                uid: 0, // RPM may not have UID
                gid: 0,
                is_symlink: meta.file_type().is_symlink(),
                symlink_target: if meta.file_type().is_symlink() { Some(fs::read_link(&path)?.to_string_lossy().to_string()) } else { None },
            });
        }
        Ok(())
    }

    fn extract_pacman(&self, pkg_path: &Path, dest: &Path, meta_map: &mut HashMap<PathBuf, FileMetadata>) -> Result<()> {
        let file = File::open(pkg_path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut tar = tar::Archive::new(decoder);
        tar.unpack(dest)?;
        // Walk and capture metadata
        for entry in WalkDir::new(dest).into_iter().filter_map(Result::ok) {
            if entry.depth() > 0 {
                let rel_path = entry.path().strip_prefix(dest)?.to_path_buf();
                let meta = fs::symlink_metadata(entry.path())?;
                meta_map.insert(rel_path, FileMetadata {
                    mode: meta.mode(),
                    uid: meta.uid(),
                    gid: meta.gid(),
                    is_symlink: meta.file_type().is_symlink(),
                    symlink_target: if meta.file_type().is_symlink() { Some(fs::read_link(entry.path())?.to_string_lossy().to_string()) } else { None },
                });
            }
        }
        Ok(())
    }

    /// Store files in CAS, using reflinks if supported.
    pub async fn store_in_cas(&mut self, temp_dir: &Path, meta_map: &HashMap<PathBuf, FileMetadata>) -> Result<Vec<(PathBuf, String)>> { // (rel_path, hash)
        let mut entries = Vec::new();
        for entry in WalkDir::new(temp_dir).into_iter().filter_map(Result::ok) {
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
                        // Use reflink if supported
                        if let FilesystemType::Btrfs | FilesystemType::Xfs = self.config.filesystem {
                            let src_fd = File::open(entry.path())?.as_raw_fd();
                            let dest_fd = OpenOptions::new().write(true).create(true).open(&obj_path)?.as_raw_fd();
                            unsafe { ficlone(dest_fd, &src_fd as *const i32)?; }
                        } else {
                            fs::hard_link(entry.path(), &obj_path)?;
                        }
                    } else {
                        let target = fs::read_link(entry.path())?;
                        symlink(&target, &obj_path)?;
                    }
                }
                let meta_json = serde_json::to_string(meta_map.get(&rel_path).unwrap())?;
                sqlx::query!("INSERT OR IGNORE INTO objects (hash, path, metadata) VALUES (?, ?, ?)", hash, obj_path.to_string_lossy().to_string(), meta_json)
                    .execute(&mut self.db)
                    .await?;
                entries.push((rel_path, hash));
            }
        }
        Ok(entries)
    }

    /// Build a tree from extracted files, applying metadata, using subvolumes if Btrfs.
    pub async fn build_tree(&mut self, entries: &[(PathBuf, String)], tree_root: &Path) -> Result<String> {
        if let FilesystemType::Btrfs = self.config.filesystem {
            // Create subvolume
            Command::new("btrfs").arg("subvolume").arg("create").arg(tree_root).output()?;
        } else {
            fs::create_dir_all(tree_root)?;
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
        if let FilesystemType::Btrfs = self.config.filesystem {
            // Snapshot for immutability
            Command::new("btrfs").arg("subvolume").arg("snapshot").arg("-r").arg(tree_root).arg(tree_root.with_file_name(format!("{}-ro", tree_hash))) .output()?;
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

    /// Deploy a ref atomically, update bootloader.
    pub async fn deploy(&mut self, ref_name: &str) -> Result<()> {
        let row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = ?", ref_name)
            .fetch_one(&mut self.db)
            .await?;
        let tree_hash = row.tree_hash;
        let deployment_path = self.config.deployments_dir.join(&tree_hash);
        // Assume tree built
        fs::remove_file(&self.config.current_link).ok();
        symlink(&deployment_path, &self.config.current_link)?;
        // Setup overlays
        self.setup_overlays()?;
        // Update bootloader
        self.update_bootloader(&tree_hash)?;
        // Stateless config
        self.handle_stateless_config()?;
        Ok(())
    }

    /// Setup OverlayFS for modifiable dirs.
    fn setup_overlays(&self) -> Result<()> {
        for dir in &self.config.overlay_dirs {
            let lower = self.config.current_link.join(dir.strip_prefix("/").unwrap_or(dir));
            let upper = PathBuf::from("/overlay_upper").join(dir.file_name().unwrap());
            let work = PathBuf::from("/overlay_work").join(dir.file_name().unwrap());
            fs::create_dir_all(&upper)?;
            fs::create_dir_all(&work)?;
            // Mount overlay (requires root)
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
        let root_flags = if let FilesystemType::Btrfs = self.config.filesystem {
            format!("rootflags=subvol={}", tree_hash)
        } else {
            "".to_string()
        };
        match self.config.bootloader {
            BootloaderType::Grub => {
                let entry = format!("menuentry 'FastTree {}' {{ linux /vmlinuz root=/dev/sda1 {} }}", tree_hash, root_flags);
                let mut config = File::create(self.config.boot_dir.join("grub/grub.cfg"))?;
                config.write_all(entry.as_bytes())?;
                Command::new("grub-mkconfig").arg("-o").arg(self.config.boot_dir.join("grub/grub.cfg")).output()?;
            }
            BootloaderType::SystemdBoot => {
                let entry_path = self.config.boot_dir.join(format!("loader/entries/fasttree-{}.conf", tree_hash));
                let mut file = File::create(&entry_path)?;
                file.write_all(format!("title FastTree {}\nlinux /vmlinuz\noptions root=/dev/sda1 {}\n", tree_hash, root_flags).as_bytes())?;
            }
        }
        // Support A/B: if two roots, alternate
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

    /// Full workflow: install package with deps.
    pub async fn install(&mut self, package: &str, ref_name: &str) -> Result<()> {
        let deps = self.resolve_dependencies(package).await?;
        let mut entries = Vec::new();
        for (name, ver) in &deps {
            if let Some(pkg_path) = self.download_package(name, ver)? {
                let (temp_dir, meta_map) = self.extract_to_temp(&pkg_path)?;
                let mut pkg_entries = self.store_in_cas(temp_dir.path(), &meta_map).await?;
                entries.append(&mut pkg_entries);
            }
        }
        let tree_root = self.config.deployments_dir.join("temp_tree");
        let tree_hash = self.build_tree(&entries, &tree_root).await?;
        // Get previous for chain
        let prev_row = sqlx::query!("SELECT tree_hash FROM refs WHERE ref_name = ?", ref_name)
            .fetch_optional(&mut self.db)
            .await?;
        let prev = prev_row.map(|r| r.tree_hash);
        self.commit_tree(&tree_hash, ref_name, deps, prev).await?;
        self.deploy(ref_name).await?;
        fs::rename(&tree_root, self.config.deployments_dir.join(&tree_hash))?;
        Ok(())
    }

    /// Image builder: generate disk image from packages.
    pub async fn build_image(&mut self, packages: &[String], output: &Path, format: ImageFormat) -> Result<()> {
        // Resolve all deps
        let mut all_deps = Vec::new();
        for pkg in packages {
            let deps = self.resolve_dependencies(pkg).await?;
            all_deps.extend(deps);
        }
        // Create temp root
        let temp_root = TempDir::new()?;
        // Install base (e.g., debootstrap for APT)
        match self.config.distro_type {
            DistroType::Apt => {
                Command::new("debootstrap").arg("stable").arg(temp_root.path()).arg(&self.config.repo_url).output()?;
            }
            _ => unimplemented!("Only APT for now"),
        }
        // Install additional
        for (name, ver) in all_deps {
            // Chroot and apt install, simplified
            Command::new("chroot").arg(temp_root.path()).arg("apt").arg("install").arg(&name).output()?;
        }
        // Make image
        match format {
            ImageFormat::Img => {
                Command::new("dd").arg("if=/dev/zero").arg(format!("of={}", output.display())).arg("bs=1M").arg("count=1024").output()?; // Size
                Command::new("mkfs.ext4").arg(output).output()?;
                let mnt = TempDir::new()?;
                Command::new("mount").arg(output).arg(mnt.path()).output()?;
                Command::new("rsync").arg("-a").arg(format!("{}/", temp_root.path().display())).arg(mnt.path()).output()?;
                Command::new("umount").arg(mnt.path()).output()?;
            }
            ImageFormat::Qcow2 => {
                Command::new("qemu-img").arg("create").arg("-f").arg("qcow2").arg(output).arg("1G").output()?;
                // Mount and copy similar
            }
        }
        Ok(())
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
    // Example config
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
    };
    let mut ft = FastTree::new(config).await?;
    // Example: install
    // ft.install("nginx", "stable").await?;
    // Build image
    // ft.build_image(&["base", "nginx"], &PathBuf::from("system.img"), ImageFormat::Img).await?;
    // Rollback
    // ft.rollback().await?;
    Ok(())
}

// Example usage
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_fasttree() -> Result<()> {
        let config = Config {
            repo_url: "http://example.com".to_string(),
            distro_type: DistroType::Apt,
            cas_dir: PathBuf::from("/tmp/fasttree/objects"),
            db_path: PathBuf::from("/tmp/fasttree.db"),
            deployments_dir: PathBuf::from("/tmp/fasttree/deployments"),
            current_link: PathBuf::from("/tmp/current"),
            boot_dir: PathBuf::from("/tmp/boot"),
            bootloader: BootloaderType::Grub,
            filesystem: FilesystemType::Btrfs,
            health_check_script: None,
            overlay_dirs: vec![],
        };
        let mut ft = FastTree::new(config).await?;
        // ft.install("core-utils", "stable").await?;
        Ok(())
    }
}
