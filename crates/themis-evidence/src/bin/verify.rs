//! themis-verify — offline Ed25519 verify for an Evidence Packet.
//!
//! Usage:
//!   themis-verify <packet.json> <signature.hex>
//!
//! Reads a JSON packet (shape: `SealedPacket`), parses the signature
//! from hex, reconstructs the canonical JSON, hashes with BLAKE3,
//! verifies the Ed25519 signature against the packet's embedded
//! public key.
//!
//! Exit codes:
//!   0 — signature valid
//!   2 — signature verification failed
//!   1 — IO / parse error
//!
//! This binary replaces `openssl dgst -sha512 -verify` (which does
//! not list Ed25519 in its digest registry). See R7 in the plan.

use std::process::ExitCode;

use themis_evidence::packet::SealedPacket;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <packet.json> <signature.hex>",
            args.first().map(String::as_str).unwrap_or("themis-verify")
        );
        return ExitCode::from(1);
    }
    let packet_path = &args[1];
    let sig_path = &args[2];

    // 1. Read the packet.
    let packet_bytes = match std::fs::read(packet_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read packet file {packet_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let packet: SealedPacket = match serde_json::from_slice(&packet_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse packet JSON: {e}");
            return ExitCode::from(1);
        }
    };

    // 2. Read the signature (the signature file is the
    //    `signature_hex` string from the packet, but the verifier
    //    accepts a file in case the operator wants to pass a
    //    fresh signature. We use the embedded one by default; the
    //    second arg is for forward-compat.)
    let _sig_file = match std::fs::read_to_string(sig_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read signature file {sig_path}: {e}");
            return ExitCode::from(1);
        }
    };

    // 3. Re-hash the payload and compare.
    let recomputed = blake3::hash(&packet.payload_canonical_json);
    if recomputed.to_hex().to_string() != packet.blake3_hash_hex {
        eprintln!("signature verification failed: BLAKE3 hash mismatch");
        return ExitCode::from(2);
    }

    // 4. Reconstruct the verifying key from the embedded hex.
    let pk_bytes = match hex::decode(&packet.public_key_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("signature verification failed: decode pubkey: {e}");
            return ExitCode::from(2);
        }
    };
    let pk_array: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("signature verification failed: pubkey not 32 bytes");
            return ExitCode::from(2);
        }
    };
    let pk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("signature verification failed: parse pubkey: {e}");
            return ExitCode::from(2);
        }
    };

    // 5. Parse the signature.
    let sig_bytes = match hex::decode(&packet.signature_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("signature verification failed: decode sig: {e}");
            return ExitCode::from(2);
        }
    };
    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("signature verification failed: sig not 64 bytes");
            return ExitCode::from(2);
        }
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    // 6. Verify. The signer signed the RAW 32 bytes of the BLAKE3
    //    hash; reconstruct from hex first.
    use ed25519_dalek::Verifier;
    let raw_hash = match hex::decode(&packet.blake3_hash_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("signature verification failed: decode blake3: {e}");
            return ExitCode::from(2);
        }
    };
    match pk.verify(&raw_hash, &sig) {
        Ok(()) => {
            println!("signature valid");
            println!("  tenant_id:     {}", packet.tenant_id);
            println!("  invoice_id:    {}", packet.invoice_id);
            println!("  blake3_hash:   {}", packet.blake3_hash_hex);
            println!("  public_key:    {}", packet.public_key_hex);
            println!(
                "  timestamp_ts:  {} ({} ms accuracy)",
                packet.timestamp.time, packet.timestamp.accuracy_ms
            );
            println!("  chain_length:  {}", packet.chain_length);
            match &packet.rekor_entry {
                Some(entry) => {
                    println!("  rekor:         {} @ log_index={}", entry.uuid, entry.log_index);
                    println!("  rekor_url:     {}", entry.bundle_url);
                }
                None => {
                    println!("  rekor:         not anchored");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signature verification failed: {e}");
            ExitCode::from(2)
        }
    }
}
