//! Phase 1 local one-file harness: drives provider/receiver without a network.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use beam_core::{
    chunking::{chunk_count_for_size, DEFAULT_CHUNK_SIZE},
    local_transfer::{
        transfer_one_file_local, DestinationConflictPolicy, LocalProvider, LocalReceiver,
    },
    manifest::{manifest_from_plaintext_file, ChunkHashCommitment},
    TransferError,
};

#[test]
fn harness_empty_small_one_and_multi_chunk_and_default_recorded_on_manifest() {
    let chunk_size = 16u64;

    let dir = TempDir::new().expect("temp dir");
    let staging_dir = TempDir::new().expect("temp staging");

    assert_empty_roundtrip(dir.path(), staging_dir.path(), chunk_size);

    fs::write(dir.path().join("tiny.bin"), [0xfe]).expect("write tiny");
    assert_manifest_roundtrip(
        &dir.path().join("tiny.bin"),
        &staging_dir.path().join("st"),
        dir.path(),
        chunk_size,
    );

    let one_chunk = vec![0xabu8; chunk_size as usize];
    fs::write(dir.path().join("one.bin"), &one_chunk).expect("write one");
    assert_manifest_roundtrip(
        &dir.path().join("one.bin"),
        &staging_dir.path().join("st-one"),
        dir.path(),
        chunk_size,
    );

    let multi = vec![0xabu8; chunk_size as usize * 3 + 5];
    fs::write(dir.path().join("multi.bin"), &multi).expect("write multi");
    assert_manifest_roundtrip(
        &dir.path().join("multi.bin"),
        &staging_dir.path().join("st-multi"),
        dir.path(),
        chunk_size,
    );

    fs::write(
        dir.path().join("default.chunk"),
        b"records size on manifest",
    )
    .expect("write body");
    let dest = dir.path().join("out-default.chunk");
    let staging = staging_dir.path().join("st-default.chunk");
    transfer_one_file_local(
        &dir.path().join("default.chunk"),
        &staging,
        &dest,
        "default.chunk",
        DEFAULT_CHUNK_SIZE,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("default chunk pipeline");

    assert_eq!(
        fs::read(&dest).expect("read dest"),
        b"records size on manifest".to_vec()
    );
    let dst = manifest_from_plaintext_file(&dest, "x", DEFAULT_CHUNK_SIZE)
        .expect("dest manifest rebuild");
    assert_eq!(dst.chunk_size, DEFAULT_CHUNK_SIZE);
}

fn assert_manifest_roundtrip(src: &Path, staging_file: &Path, extract_dir: &Path, chunk_size: u64) {
    let file_name = src.file_name().expect("basename");
    let dest = extract_dir.join("out").join(file_name);
    let parent = dest.parent().expect("parent");
    fs::create_dir_all(parent).expect("dest parent");

    transfer_one_file_local(
        src,
        staging_file,
        &dest,
        file_name.to_str().expect("utf8 basename"),
        chunk_size,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("pipeline");

    let expect = fs::read(src).expect("expected bytes");
    let got = fs::read(dest).expect("received bytes");
    assert_eq!(expect, got);

    assert_eq!(
        chunk_count_for_size(expect.len() as u64, chunk_size),
        manifest_from_plaintext_file(src, "check", chunk_size)
            .expect("rehash manifest")
            .chunk_count
    );
}

fn assert_empty_roundtrip(dir: &Path, staging_parent: &Path, chunk_size: u64) {
    let empty = dir.join("empty.bin");
    fs::write(&empty, []).expect("empty file");

    let staging = staging_parent.join("st-empty.bin");
    let dest = dir.join("out-empty.bin");
    transfer_one_file_local(
        &empty,
        &staging,
        &dest,
        "empty.bin",
        chunk_size,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("empty pipeline");

    assert_eq!(fs::metadata(dest).expect("dest meta").len(), 0);
}

#[test]
fn corrupted_payload_fails_verification() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("a.bin");
    fs::write(&src, [1, 2, 3, 4]).expect("bytes");

    let chunk_size = 2u64;
    let provider = LocalProvider::from_file(&src, "a.bin", chunk_size).expect("provider manifest");
    let mut receiver = LocalReceiver::new(
        provider.manifest().clone(),
        dir.path().join("st.bin"),
        dir.path().join("out.bin"),
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("receiver");

    let mut bad = provider.read_chunk(0).expect("chunk0");
    bad[0] ^= 0xff;
    assert!(matches!(
        receiver.receive_chunk(0, &bad),
        Err(TransferError::ChunkVerificationFailed { index: 0 })
    ));

    let chunk_size = 2u64;
    let provider = LocalProvider::from_file(&src, "a.bin", chunk_size).expect("provider manifest");
    let mut receiver = LocalReceiver::new(
        provider.manifest().clone(),
        dir.path().join("st.bin"),
        dir.path().join("out.bin"),
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("receiver");

    let mut bad = provider.read_chunk(0).expect("chunk0");
    bad[0] ^= 0xff;
    assert!(matches!(
        receiver.receive_chunk(0, &bad),
        Err(TransferError::ChunkVerificationFailed { index: 0 })
    ));

    receiver
        .receive_chunk(1, &provider.read_chunk(1).expect("chunk 1 payload"))
        .expect("good second chunk verifies");
}

#[test]
fn partial_receive_does_not_create_final_destination() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging temp");
    let src = dir.path().join("p.bin");
    fs::write(&src, [0x11; 42]).expect("bytes");

    let chunk_size = 10u64;
    let provider = LocalProvider::from_file(&src, "p.bin", chunk_size).expect("provider");

    assert!(provider.manifest().chunk_count > 1);

    let dest_path = dir.path().join("final.bin");
    {
        let mut receiver = LocalReceiver::new(
            provider.manifest().clone(),
            staging_dir.path().join("part-staged.bin"),
            dest_path.clone(),
            DestinationConflictPolicy::FailIfExists,
        )
        .expect("receiver");

        receiver
            .receive_chunk(0, &provider.read_chunk(0).expect("chunk0"))
            .expect("first chunk writes");
        // drop without finalize; must not populate final path via rename rules
    }

    assert!(
        !dest_path.exists(),
        "partial transfer without finalize must leave final path untouched"
    );
}

#[test]
fn destination_conflict_is_refused() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let src = dir.path().join("x.bin");
    fs::write(&src, b"nope").expect("bytes");

    let dest = dir.path().join("out.bin");
    fs::write(&dest, b"existing").expect("pre-create");

    assert!(matches!(
        transfer_one_file_local(
            &src,
            &staging_dir.path().join("s.bin"),
            &dest,
            "x.bin",
            4096,
            DestinationConflictPolicy::FailIfExists
        ),
        Err(TransferError::DestinationExists(ref p))
        if *p == dest
    ));
}

#[test]
fn pending_chunk_hashes_are_not_received() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("pending.bin");
    fs::write(&src, b"abcd").expect("bytes");

    let mut manifest = manifest_from_plaintext_file(&src, "pending.bin", 2).expect("manifest");
    manifest.chunk_hashes[0] = ChunkHashCommitment::Pending;

    let mut recv = LocalReceiver::new(
        manifest,
        dir.path().join("pending-st"),
        dir.path().join("pending-out"),
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("receiver");

    assert!(matches!(
        recv.receive_chunk(0, b"xx"),
        Err(TransferError::HashNotCommitted { index: 0 })
    ));
}
