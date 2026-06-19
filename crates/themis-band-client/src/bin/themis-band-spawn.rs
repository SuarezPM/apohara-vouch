//! `themis-band-spawn` — operator binary that spawns all 6 THEMIS
//! agents as Band WebSocket subprocesses and prints a JSON status
//! line every 1s with per-agent event counts and the public room
//! URL.
//!
//! Usage:
//!   source ~/.config/apohara/secrets.env
//!   themis-band-spawn --room-id <chatroom-uuid> [--seconds 60]

use std::time::Duration;

use themis_band_client::fleet::BandFleet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut room_id: Option<String> = None;
    let mut seconds: u64 = 60;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--room-id" => {
                room_id = args.get(i + 1).cloned();
                i += 2;
            }
            "--seconds" => {
                seconds = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(60);
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: themis-band-spawn --room-id <uuid> [--seconds 60]\n\n\
                     Reads BAND_AGENT_<NAME>_ID + BAND_AGENT_<NAME>_API_KEY from\n\
                     the environment (source ~/.config/apohara/secrets.env)."
                );
                return Ok(());
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    let room_id =
        room_id.ok_or_else(|| Box::<dyn std::error::Error>::from("--room-id is required"))?;

    let shim_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("run_agent.py");
    let python_bin = std::env::var("THEMIS_BAND_PYTHON").unwrap_or_else(|_| "python3".to_string());

    let fleet = BandFleet::spawn_all(&python_bin, shim_path.to_str().unwrap(), &room_id)?;
    eprintln!(
        "[themis-band-spawn] room={} public_url={} agents={}",
        fleet.room_id,
        fleet.public_url,
        fleet.agents_connected()
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let m = fleet.metrics();
        println!(
            "{}",
            serde_json::json!({
                "elapsed_s": seconds - deadline.saturating_duration_since(std::time::Instant::now()).as_secs(),
                "ws_events_total": m.ws_events_total,
                "agents_connected": m.agents_connected,
                "room_id": m.room_id,
                "per_agent": m.per_agent,
            })
        );
    }
    let final_metrics = fleet.metrics();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "final": final_metrics,
        }))?
    );
    Ok(())
}
