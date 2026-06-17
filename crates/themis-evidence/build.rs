//! Compile the vendored Rekor v2 .proto into a tonic/prost module.
//!
//! tonic-prost-build 0.14 names the output file after the proto
//! package (`dev.sigstore.rekor.v2.rs`), which Rust's `mod` resolver
//! can't address directly (dots aren't valid in module names). We
//! rename the file to `dev_sigstore_rekor_v2.rs` so the
//! `pub mod dev_sigstore_rekor_v2;` declaration in
//! `src/rekor_v2.rs` resolves cleanly.
//!
//! See `proto/rekor/v2/rekor.proto` for the rationale of the
//! trimmed surface (no googleapis dependency).

use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    let dotted = Path::new(&out_dir).join("dev.sigstore.rekor.v2.rs");
    let underscored = Path::new(&out_dir).join("dev_sigstore_rekor_v2.rs");

    tonic_prost_build::configure()
        .compile_protos(&["proto/rekor/v2/rekor.proto"], &["proto/rekor/v2"])?;

    if dotted.exists() && !underscored.exists() {
        fs::rename(&dotted, &underscored)?;
    }
    Ok(())
}
