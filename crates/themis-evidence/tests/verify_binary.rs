//! Integration test for the themis-verify binary.
//!
//! Generates a valid SealedPacket, writes it to disk, runs the
//! `themis-verify` binary via `std::process::Command`, and asserts
//! exit code 0 in <30s.

use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;
use themis_evidence::packet::{EvidenceService, SealedPacket};
use themis_evidence::timestamp::MockTimestampAuthority;

fn tsa() -> std::sync::Arc<dyn themis_evidence::timestamp::TimestampAuthority> {
    std::sync::Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"))
}

#[tokio::test]
async fn themis_verify_binary_accepts_a_valid_packet() {
    let tmp = TempDir::new().unwrap();
    let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
    let packet = svc.seal("inv-001", "hello world", None).await.unwrap();

    // Write the packet to disk.
    let packet_path = tmp.path().join("packet.json");
    let json = serde_json::to_string_pretty(&packet).unwrap();
    std::fs::write(&packet_path, &json).unwrap();

    // The signature file's contents aren't read by the binary (it
    // uses the embedded one) but the binary requires the file
    // to exist. We just write the packet's signature as a
    // stand-in.
    let sig_path = tmp.path().join("signature.hex");
    std::fs::write(&sig_path, &packet.signature_hex).unwrap();

    // Locate the binary: `cargo run` puts it at
    // `target/debug/themis-verify` (or `target/release/...` for
    // --release). We use `env!("CARGO_BIN_EXE_themis-verify")`
    // so cargo wires the path automatically.
    let bin = env!("CARGO_BIN_EXE_themis-verify");

    let start = std::time::Instant::now();
    let output = Command::new(bin)
        .arg(&packet_path)
        .arg(&sig_path)
        .output()
        .expect("failed to execute themis-verify");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(30),
        "themis-verify took {elapsed:?} (>30s)"
    );
    assert!(
        output.status.success(),
        "themis-verify exited {:?} — stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("signature valid"));
    assert!(stdout.contains("tenant_id:     stark"));
}

#[test]
fn themis_verify_binary_rejects_tampered_packet() {
    let tmp = TempDir::new().unwrap();
    // Build a packet via the in-process API so we don't need a
    // tokio runtime in this sync test.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
    let mut packet: SealedPacket = rt.block_on(async { svc.seal("inv-001", "x", None).await.unwrap() });
    // Tamper the payload.
    packet.payload_canonical_json = b"\"TAMPERED\"".to_vec();

    let packet_path = tmp.path().join("packet.json");
    std::fs::write(&packet_path, serde_json::to_string(&packet).unwrap()).unwrap();
    let sig_path = tmp.path().join("signature.hex");
    std::fs::write(&sig_path, &packet.signature_hex).unwrap();

    let bin = env!("CARGO_BIN_EXE_themis-verify");
    let output = Command::new(bin)
        .arg(&packet_path)
        .arg(&sig_path)
        .output()
        .expect("failed to execute themis-verify");

    // Exit code 2 on signature mismatch.
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signature verification failed"));
}
