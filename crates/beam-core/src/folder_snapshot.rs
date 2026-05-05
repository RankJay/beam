//! Folder snapshot manifest and local transfer (Phase 8): frozen tree shape, filters, partial outcomes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use glob::Pattern;

use crate::error::TransferError;
use crate::local_transfer::{DestinationConflictPolicy, LocalProvider, LocalReceiver};
use crate::manifest::manifest_from_plaintext_file;
use crate::manifest::OneFileManifest;

const SNAPSHOT_FORMAT_V1: u32 = 1;

/// Command-local include / exclude rules, recorded in the snapshot manifest (ADR 0041, 0042).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotFilters {
    /// If empty, every path that passes `exclude_globs` is included. Otherwise at least one pattern must match.
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
}

impl Default for SnapshotFilters {
    fn default() -> Self {
        Self {
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
        }
    }
}

/// Metadata that must not be restored blindly (ADR 0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DangerousMetadataFlags {
    pub is_symlink: bool,
}

/// One logical entry in the approved folder manifest (directories, files, symlinks).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FolderManifestEntry {
    Directory {
        rel_path: String,
    },
    File {
        rel_path: String,
        /// Frozen per-file manifest; chunk hashes fixed before any transfer bytes (ADR 0040, 0079).
        manifest: OneFileManifest,
    },
    Symlink {
        rel_path: String,
        /// Best-effort target for summaries; not transferred as content.
        target_display: Option<String>,
        dangerous: DangerousMetadataFlags,
    },
}

/// Top-level approved snapshot: full shape is present before chunk transfer starts (ADR 0040).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderSnapshotManifest {
    pub format_version: u32,
    pub root_label: String,
    pub filters: SnapshotFilters,
    pub entries: Vec<FolderManifestEntry>,
}

impl FolderSnapshotManifest {
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.format_version != SNAPSHOT_FORMAT_V1 {
            return Err(TransferError::InvalidManifest("unknown folder snapshot format_version"));
        }
        if self.root_label.is_empty() {
            return Err(TransferError::InvalidManifest("root_label must be non-empty"));
        }
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        for e in &self.entries {
            let rel = Self::entry_rel(e);
            if rel.is_empty() {
                return Err(TransferError::InvalidManifest("entry rel_path must be non-empty"));
            }
            if rel.contains('\\') {
                return Err(TransferError::InvalidManifest("entry paths must be posix-style"));
            }
            if seen.insert(rel.to_string(), ()).is_some() {
                return Err(TransferError::InvalidManifest("duplicate manifest path"));
            }
            if let FolderManifestEntry::File { manifest, .. } = e {
                manifest.validate()?;
            }
        }
        Ok(())
    }

    fn entry_rel(e: &FolderManifestEntry) -> &str {
        match e {
            FolderManifestEntry::Directory { rel_path }
            | FolderManifestEntry::File { rel_path, .. }
            | FolderManifestEntry::Symlink { rel_path, .. } => rel_path,
        }
    }

    /// Human-readable summary for receiver approval (counts and filter echo).
    #[must_use]
    pub fn approval_summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("folder_snapshot v{} root={}", self.format_version, self.root_label));
        if !self.filters.include_globs.is_empty() || !self.filters.exclude_globs.is_empty() {
            lines.push(format!(
                "filters: include={:?} exclude={:?}",
                self.filters.include_globs, self.filters.exclude_globs
            ));
        } else {
            lines.push("filters: none (all paths included)".to_string());
        }
        let mut dirs = 0_u32;
        let mut files = 0_u32;
        let mut symlinks = 0_u32;
        let mut bytes = 0_u64;
        for e in &self.entries {
            match e {
                FolderManifestEntry::Directory { .. } => dirs += 1,
                FolderManifestEntry::File { manifest, .. } => {
                    files += 1;
                    bytes = bytes.saturating_add(manifest.size);
                }
                FolderManifestEntry::Symlink { .. } => symlinks += 1,
            }
        }
        lines.push(format!(
            "entries: {} dirs, {} files ({} bytes), {} symlinks (not restored)",
            dirs, files, bytes, symlinks
        ));
        lines
    }
}

struct CompiledFilters {
    include: Vec<Pattern>,
    exclude: Vec<Pattern>,
}

impl CompiledFilters {
    fn new(f: &SnapshotFilters) -> Result<Self, TransferError> {
        let mut include = Vec::with_capacity(f.include_globs.len());
        for g in &f.include_globs {
            include.push(
                Pattern::new(g).map_err(|_| TransferError::InvalidManifest("invalid include glob"))?,
            );
        }
        let mut exclude = Vec::with_capacity(f.exclude_globs.len());
        for g in &f.exclude_globs {
            exclude.push(
                Pattern::new(g).map_err(|_| TransferError::InvalidManifest("invalid exclude glob"))?,
            );
        }
        Ok(Self { include, exclude })
    }

    fn is_visible(&self, rel_posix: &str) -> bool {
        for p in &self.exclude {
            if p.matches(rel_posix) {
                return false;
            }
        }
        if self.include.is_empty() {
            return true;
        }
        self.include.iter().any(|p| p.matches(rel_posix))
    }
}

fn to_posix_rel(path: &str) -> String {
    path.replace('\\', "/")
}

/// Build a full folder manifest: walks `source_root`, applies filters, commits per-file chunk hashes.
pub fn build_folder_snapshot_manifest(
    source_root: &Path,
    root_label: &str,
    filters: SnapshotFilters,
    chunk_size: u64,
) -> Result<FolderSnapshotManifest, TransferError> {
    if chunk_size == 0 {
        return Err(TransferError::InvalidChunkSize { chunk_size });
    }
    let meta = fs::metadata(source_root)?;
    if !meta.is_dir() {
        return Err(TransferError::NotADirectory(source_root.to_path_buf()));
    }
    if root_label.is_empty() {
        return Err(TransferError::InvalidManifest("root_label must be non-empty"));
    }

    let compiled = CompiledFilters::new(&filters)?;
    let mut collected = Vec::new();
    walk_tree(source_root, "", &compiled, &mut collected)?;

    collected.sort_by(|a, b| a.0.cmp(&b.0));

    let mut entries = Vec::with_capacity(collected.len());
    for (rel, kind) in collected {
        match kind {
            RawKind::Dir => entries.push(FolderManifestEntry::Directory { rel_path: rel }),
            RawKind::File => {
                let abs = join_rel(source_root, &rel);
                let manifest_path = format!("{}/{}", root_label.trim_end_matches('/'), rel);
                let manifest =
                    manifest_from_plaintext_file(&abs, &manifest_path, chunk_size)?;
                entries.push(FolderManifestEntry::File {
                    rel_path: rel,
                    manifest,
                });
            }
            RawKind::Symlink { target } => entries.push(FolderManifestEntry::Symlink {
                rel_path: rel,
                target_display: target,
                dangerous: DangerousMetadataFlags { is_symlink: true },
            }),
        }
    }

    let m = FolderSnapshotManifest {
        format_version: SNAPSHOT_FORMAT_V1,
        root_label: root_label.to_owned(),
        filters,
        entries,
    };
    m.validate()?;
    Ok(m)
}

enum RawKind {
    Dir,
    File,
    Symlink {
        target: Option<String>,
    },
}

fn join_rel(root: &Path, rel_posix: &str) -> PathBuf {
    rel_posix
        .split('/')
        .filter(|s| !s.is_empty())
        .fold(root.to_path_buf(), |acc, p| acc.join(p))
}

fn walk_tree(
    source_root: &Path,
    rel_prefix: &str,
    compiled: &CompiledFilters,
    out: &mut Vec<(String, RawKind)>,
) -> Result<(), TransferError> {
    let current_dir = join_rel(source_root, rel_prefix);

    let read = fs::read_dir(&current_dir)?;
    let mut names: Vec<std::ffi::OsString> = read
        .filter_map(|e| e.ok().map(|x| x.file_name()))
        .collect();
    names.sort();

    for name in names {
        let name_str = name.to_str().ok_or(TransferError::InvalidManifest(
            "path is not valid UTF-8",
        ))?;
        let rel = if rel_prefix.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel_prefix}/{name_str}")
        };
        let rel_posix = to_posix_rel(&rel);
        if !compiled.is_visible(&rel_posix) {
            continue;
        }

        let path = current_dir.join(&name);
        let symlink_meta = fs::symlink_metadata(&path)?;
        if symlink_meta.file_type().is_symlink() {
            let target = fs::read_link(&path).ok().and_then(|p| p.to_str().map(|s| s.to_string()));
            out.push((rel_posix, RawKind::Symlink { target }));
            continue;
        }
        if symlink_meta.is_dir() {
            out.push((rel_posix.clone(), RawKind::Dir));
            walk_tree(source_root, &rel_posix, compiled, out)?;
            continue;
        }
        if symlink_meta.is_file() {
            out.push((rel_posix, RawKind::File));
        }
    }

    Ok(())
}

/// Outcome for a single manifest entry after a folder transfer attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderEntryOutcome {
    Completed,
    /// Symlink or other dangerous entry — not materialized at destination (ADR 0012).
    SkippedDangerous,
    /// Transfer error for this entry (partial completion — other paths may still have completed).
    Failed(String),
}

/// Per-entry status for partial completion reporting (Phase 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSnapshotTransferReport {
    pub by_rel_path: BTreeMap<String, FolderEntryOutcome>,
}

/// Transfers an approved [`FolderSnapshotManifest`] locally: directories and regular files; symlinks skipped.
pub fn transfer_folder_snapshot_local(
    source_root: &Path,
    dest_root: &Path,
    snapshot: &FolderSnapshotManifest,
    staging_dir: &Path,
    conflict: DestinationConflictPolicy,
) -> Result<FolderSnapshotTransferReport, TransferError> {
    snapshot.validate()?;
    let meta = fs::metadata(source_root)?;
    if !meta.is_dir() {
        return Err(TransferError::NotADirectory(source_root.to_path_buf()));
    }

    fs::create_dir_all(dest_root)?;
    fs::create_dir_all(staging_dir)?;

    let mut report = FolderSnapshotTransferReport {
        by_rel_path: BTreeMap::new(),
    };

    for e in &snapshot.entries {
        match e {
            FolderManifestEntry::Directory { rel_path } => {
                let dest = join_rel(dest_root, rel_path);
                fs::create_dir_all(&dest)?;
                report
                    .by_rel_path
                    .insert(rel_path.clone(), FolderEntryOutcome::Completed);
            }
            FolderManifestEntry::Symlink { rel_path, .. } => {
                report
                    .by_rel_path
                    .insert(rel_path.clone(), FolderEntryOutcome::SkippedDangerous);
            }
            FolderManifestEntry::File {
                rel_path,
                manifest,
            } => {
                let abs_src = join_rel(source_root, rel_path);
                let dest_file = join_rel(dest_root, rel_path);
                if let Some(parent) = dest_file.parent() {
                    fs::create_dir_all(parent)?;
                }
                let staging = staging_dir.join(format!(
                    "{}.beam-staging",
                    rel_path.replace(['/', '\\'], "__")
                ));

                let xfer = (|| {
                    let provider = LocalProvider::with_frozen_file_manifest(abs_src, manifest.clone())?;
                    let mut receiver = LocalReceiver::new(
                        manifest.clone(),
                        staging.clone(),
                        dest_file.clone(),
                        conflict,
                    )?;
                    for chunk_index in 0..manifest.chunk_count {
                        let data = provider.read_chunk(chunk_index)?;
                        receiver.receive_chunk(chunk_index, &data)?;
                    }
                    receiver.finalize()?;
                    Ok::<(), TransferError>(())
                })();

                match xfer {
                    Ok(()) => {
                        report
                            .by_rel_path
                            .insert(rel_path.clone(), FolderEntryOutcome::Completed);
                    }
                    Err(err) => {
                        let _ = fs::remove_file(&staging);
                        report.by_rel_path.insert(
                            rel_path.clone(),
                            FolderEntryOutcome::Failed(err.to_string()),
                        );
                    }
                }
            }
        }
    }

    Ok(report)
}
