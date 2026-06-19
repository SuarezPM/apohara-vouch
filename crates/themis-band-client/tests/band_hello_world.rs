//! `band_hello_world` — integration test for the per-agent
//! WebSocket bridge (Story Ola-A / AC7).
//!
//! Skipped unless `BAND_AGENT_EXTRACTOR_ID` and
//! `BAND_AGENT_EXTRACTOR_API_KEY` are set in the environment
//! AND `THEMIS_BAND_LIVE=1`. When the env vars are missing the
//! test prints "skipped" and exits 0 so CI stays green.
//!
//! Steps:
//!   1. Spawn `scripts/run_agent.py` via `SocketHandle::spawn`.
//!   2. Wait for the `room:joined` event on stdout (with timeout).
//!   3. Call `post_message("echo")` — the Python shim writes
//!      `{"op":"post_message","body":"echo"}` to stdin, the WS
//!      forwards it, the Band server echoes the message back as
//!      a `room:new_msg` event.
//!   4. Receive the echo and assert `body == "echo"`.
//!   5. Shut down cleanly (Drop on the handle kills the subprocess).

use std::time::Duration;

use themis_band_client::socket::SocketHandle;

fn live_band_available() -> bool {
    std::env::var("BAND_AGENT_EXTRACTOR_ID")
        .ok()
        .map(|v| !v.is_empty())
        .unwrap_or(false)
        && std::env::var("BAND_AGENT_EXTRACTOR_API_KEY")
            .ok()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        && std::env::var("THEMIS_BAND_LIVE").unwrap_or_default() == "1"
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn band_hello_world_echo() {
    if !live_band_available() {
        eprintln!(
            "skipped: BAND_AGENT_EXTRACTOR_ID/BAND_AGENT_EXTRACTOR_API_KEY not set \
             or THEMIS_BAND_LIVE!=1"
        );
        return;
    }
    let python_bin = std::env::var("THEMIS_BAND_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let shim_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("run_agent.py");
    let agent_id = std::env::var("BAND_AGENT_EXTRACTOR_ID").unwrap();
    let api_key = std::env::var("BAND_AGENT_EXTRACTOR_API_KEY").unwrap();
    let room_id = format!("themis-test-{}", uuid::Uuid::new_v4().simple());

    let mut handle = SocketHandle::spawn(
        &python_bin,
        shim_path.to_str().unwrap(),
        &agent_id,
        &api_key,
        &room_id,
        "wss://app.band.ai/api/v1/socket/websocket",
    )
    .expect("SocketHandle::spawn must succeed when env vars are set");

    // Wait up to 30s for the `room:joined` event.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut joined = false;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), handle.recv_event()).await {
            Ok(Some(ev)) => {
                if ev.event == "room:joined" {
                    eprintln!(
                        "[band_hello_world] joined room {} public_url={:?}",
                        ev.payload["room_id"], ev.payload["public_url"]
                    );
                    joined = true;
                    break;
                }
                eprintln!("[band_hello_world] pre-join event: {:?}", ev.event);
            }
            Ok(None) => {
                eprintln!("[band_hello_world] stdout closed before join");
                break;
            }
            Err(_) => continue, // poll again
        }
    }
    assert!(joined, "did not receive room:joined within 30s");

    // Post one echo message and wait for the echo.
    let message_id = handle
        .post_message("hello from themis-band-client integration test")
        .await
        .expect("post_message must succeed against a live Band room");
    eprintln!("[band_hello_world] posted message_id={message_id}");

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut echoed = false;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), handle.recv_event()).await {
            Ok(Some(ev)) => {
                if ev.event == "room:new_msg" {
                    let body = ev
                        .payload
                        .get("body")
                        .and_then(|b| b.as_str())
                        .unwrap_or("");
                    if body.contains("hello from themis-band-client") {
                        echoed = true;
                        eprintln!("[band_hello_world] received echo: ts_ms={}", ev.ts_ms);
                        break;
                    }
                }
            }
            _ => continue,
        }
    }
    assert!(echoed, "did not receive echo of posted message within 15s");
    // Clean shutdown via Drop.
    drop(handle);
}
