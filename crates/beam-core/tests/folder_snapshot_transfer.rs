//! Phase 8: folder snapshot manifest, filters, partial completion, symlink policy.

#![forbid(unsafe_code)]

use std::io::Write;

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::folder_snapshot::{
    build_folder_snapshot_manifest, transfer_folder_snapshot_local, FolderEntryOutcome,
    FolderManifestEntry, SnapshotFilters,
};
use beam_core::local_transfer::DestinationConflictPolicy;

#[test]
fn nested_tree_empty_dir_and_files_round_trip() {
    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("a/empty")).expect("mkdir");
    std::fs::write(src.join("a/x.txt"), b"hello").expect("write");
    std::fs::write(src.join("root.bin"), b"z").expect("write");

    let dest = dir.path().join("dest");
    let staging = dir.path().join("staging");

    let snap = build_folder_snapshot_manifest(
        &src,
        "bundle",
        SnapshotFilters::default(),
        DEFAULT_CHUNK_SIZE,
    )
    .expect("manifest");

    let lines = snap.approval_summary_lines();
    assert!(
        lines.iter().any(|l| l.contains("filters: none")),
        "summary={lines:?}"
    );

    transfer_folder_snapshot_local(
        &src,
        &dest,
        &snap,
        &staging,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("transfer");

    assert_eq!(
        std::fs::read(dest.join("a/x.txt")).expect("read"),
        b"hello"
    );
    assert_eq!(
        std::fs::read(dest.join("root.bin")).expect("read"),
        b"z"
    );
    assert!(dest.join("a/empty").is_dir());
}

#[test]
fn exclude_removes_path_from_manifest() {
    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("keep.txt"), b"k").expect("write");
    std::fs::write(src.join("drop.tmp"), b"d").expect("write");

    let snap = build_folder_snapshot_manifest(
        &src,
        "b",
        SnapshotFilters {
            include_globs: vec![],
            exclude_globs: vec!["*.tmp".to_string()],
        },
        256,
    )
    .expect("manifest");

    let paths: Vec<&str> = snap
        .entries
        .iter()
        .filter_map(|e| match e {
            FolderManifestEntry::File { rel_path, .. } => Some(rel_path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(paths, vec!["keep.txt"]);

    let dest = dir.path().join("out");
    let staging = dir.path().join("st");
    transfer_folder_snapshot_local(
        &src,
        &dest,
        &snap,
        &staging,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("transfer");
    assert!(dest.join("keep.txt").exists());
    assert!(!dest.join("drop.tmp").exists());
}

#[test]
fn include_only_matching_files() {
    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("a.log"), b"l").expect("write");
    std::fs::write(src.join("b.txt"), b"t").expect("write");

    let snap = build_folder_snapshot_manifest(
        &src,
        "b",
        SnapshotFilters {
            include_globs: vec!["*.log".to_string()],
            exclude_globs: vec![],
        },
        256,
    )
    .expect("manifest");

    let paths: Vec<&str> = snap
        .entries
        .iter()
        .filter_map(|e| match e {
            FolderManifestEntry::File { rel_path, .. } => Some(rel_path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(paths, vec!["a.log"]);
}

#[cfg(unix)]
#[test]
fn symlink_is_skipped_and_not_restored() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("real.txt"), b"r").expect("write");
    symlink(src.join("real.txt"), src.join("link.txt")).expect("symlink");

    let snap = build_folder_snapshot_manifest(
        &src,
        "b",
        SnapshotFilters::default(),
        256,
    )
    .expect("manifest");

    assert_eq!(snap.entries.len(), 2, "file + symlink entries");

    let dest = dir.path().join("out");
    let staging = dir.path().join("st");
    let report = transfer_folder_snapshot_local(
        &src,
        &dest,
        &snap,
        &staging,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("transfer");

    assert_eq!(
        report.by_rel_path.get("link.txt"),
        Some(&FolderEntryOutcome::SkippedDangerous)
    );
    assert!(!dest.join("link.txt").exists());
    assert_eq!(
        std::fs::read(dest.join("real.txt")).expect("read"),
        b"r"
    );
}

#[test]
fn one_corrupt_file_does_not_block_other_completion() {
    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("good.bin"), vec![7_u8; 400]).expect("write");
    std::fs::write(src.join("bad.bin"), vec![9_u8; 400]).expect("write");

    let snap =
        build_folder_snapshot_manifest(&src, "b", SnapshotFilters::default(), 128).expect("manifest");

    // Mutate bad.bin after snapshot — same size, different bytes; approved snapshot unchanged.
    let bad_path = src.join("bad.bin");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(&bad_path)
        .expect("open");
    f.write_all(&[1_u8; 400]).expect("rewrite");
    drop(f);

    let dest = dir.path().join("out");
    let staging = dir.path().join("st");
    let report = transfer_folder_snapshot_local(
        &src,
        &dest,
        &snap,
        &staging,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("report ok");

    let good = report.by_rel_path.get("good.bin");
    let bad = report.by_rel_path.get("bad.bin");
    assert_eq!(good, Some(&FolderEntryOutcome::Completed));
    match bad {
        Some(FolderEntryOutcome::Failed(msg)) => {
            assert!(
                msg.contains("verification") || msg.contains("Blake3") || msg.contains("chunk"),
                "unexpected: {msg}"
            );
        }
        _ => panic!("expected bad.bin failed, got {bad:?}"),
    }
    assert_eq!(
        std::fs::read(dest.join("good.bin")).expect("read good"),
        vec![7_u8; 400]
    );
}

#[test]
fn frozen_manifest_rejects_size_change_before_transfer() {
    let dir = tempfile::TempDir::new().expect("temp");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("only.txt"), b"abc").expect("write");

    let snap =
        build_folder_snapshot_manifest(&src, "b", SnapshotFilters::default(), 64).expect("manifest");
    std::fs::write(src.join("only.txt"), b"abcd").expect("grow file");

    let dest = dir.path().join("out");
    let staging = dir.path().join("st");
    let report = transfer_folder_snapshot_local(
        &src,
        &dest,
        &snap,
        &staging,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("report");

    match report.by_rel_path.get("only.txt") {
        Some(FolderEntryOutcome::Failed(msg)) => {
            assert!(msg.contains("source changed") || msg.contains("size"), "{msg}");
        }
        o => panic!("expected failure for size drift: {o:?}"),
    }
    assert!(!dest.join("only.txt").exists());
}
