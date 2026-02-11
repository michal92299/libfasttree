# libfasttree

[![Crates.io](https://img.shields.io/crates/v/libfasttree.svg)](https://crates.io/crates/libfasttree)
[![Docs.rs](https://docs.rs/libfasttree/badge.svg)](https://docs.rs/libfasttree)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust library inspired by libostree, designed for managing immutable system images based on distribution repositories. It provides features like content-addressed storage (CAS), dependency resolution, delta updates, overlays, and more, with a focus on security, efficiency, and extensibility.

## Features

- **Supply Chain Security**: Supports Sigstore/Cosign for keyless signing, FS-Verity for immutable files, and TPM integration for sealing keys based on system state.
- **Storage Efficiency**: Uses Zstandard compression with dictionaries, block-level deduplication via FastCDC, and a garbage collector for unused objects.
- **System Management**: Handles OverlayFS for ephemeral changes, Systemd-Sysext for dynamic extensions, and A/B partitioning for seamless updates.
- **Plugin System**: Extensible package managers via traits (e.g., APT, RPM, Nix, APK).
- **Async I/O**: Leverages Tokio and io_uring for high-performance operations on NVMe drives.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libfasttree = "0.0.1"
```

Note: This library requires root privileges for some operations (e.g., mounting, chown). It depends on various crates like sqlx, tokio, nix, and others—see `Cargo.toml` for the full list.

## Quick Start

### Configuration

Create a `Config` struct to initialize the library:

```rust
use libfasttree::{Config, DistroType, BootloaderType, FilesystemType, PartitioningType};
use std::path::PathBuf;
use tss_esapi::tcti::Tcti;

let config = Config {
    repo_url: "http://deb.debian.org/debian".to_string(),
    distro_type: DistroType::Apt,
    cas_dir: PathBuf::from("/var/lib/fasttree/objects"),
    db_path: PathBuf::from("/var/lib/fasttree/db.sqlite"),
    deployments_dir: PathBuf::from("/sysroot"),
    current_link: PathBuf::from("/ostree/current"),
    boot_dir: PathBuf::from("/boot"),
    bootloader: BootloaderType::SystemdBoot,
    filesystem: FilesystemType::Btrfs,
    health_check_script: Some(PathBuf::from("/usr/bin/health-check.sh")),
    overlay_dirs: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
    var_volume: Some(PathBuf::from("/dev/sdb1")),
    gpg_keyring: PathBuf::from("/etc/apt/trusted.gpg"),
    use_fsverity: true,
    use_ima: true,
    partitioning: PartitioningType::Subvolumes,
    sysext_dir: PathBuf::from("/var/lib/extensions"),
    zstd_dicts: std::collections::HashMap::new(), // Add dictionaries as needed
    tpm_tcti: Tcti::Tpmtis, // Configure TPM
};
```

### Initialization

```rust
use libfasttree::FastTree;
use tokio::runtime::Runtime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    Ok(())
}
```

## Mini Tutorials

### Tutorial 1: Installing a Package

Resolve dependencies, download, extract, store in CAS, build a tree, commit, and deploy:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    ft.install("nginx", "stable").await?;
    Ok(())
}
```

This handles dependency resolution using a solver (mocked with libsolv), verifies signatures with Sigstore, compresses with Zstd, deduplicates blocks, and deploys with overlays.

### Tutorial 2: Rolling Back

Rollback to the previous tree:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    ft.rollback().await?;
    Ok(())
}
```

### Tutorial 3: Garbage Collection

Clean up unused objects and chunks:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    ft.gc().await?;
    Ok(())
}
```

### Tutorial 4: Building a System Extension (Sysext)

Create a sysext image from packages:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    let packages = vec!["gdb".to_string(), "valgrind".to_string()];
    let output = std::path::Path::new("/tmp/debug-tools.sysext.raw");
    ft.build_sysext(&packages, output).await?;
    Ok(())
}
```

Load extensions via `systemd-sysext merge`.

### Tutorial 5: Deploying a Reference

Deploy a committed tree:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = /* ... */;
    let mut ft = FastTree::new(config).await?;
    ft.deploy("stable").await?;
    Ok(())
}
```

This sets up overlays, updates the bootloader, and handles stateless configs.

## Security Notes

- Use FS-Verity for immutable files: Files in CAS are protected at the filesystem level.
- TPM: Keys are sealed only if PCR values match expected system state.
- Signatures: Keyless with Sigstore for packages.

## Contributing

Contributions welcome! See [repository](https://github.com/michal92299/libfasttree) for issues and PRs.

## License

MIT - See [LICENSE](LICENSE) for details.
