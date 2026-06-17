//! EventBus — broadcast events from the orchestrator to live
//! subscribers (the SSE handler, future websocket integrations, ...).
//!
//! Uses `tokio::sync::broadcast` so subscribers don't block the
//! publisher. A slow subscriber that lags past the broadcast
//! buffer drops events; the orchestrator doesn't wait for it.

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Domain events the orchestrator emits. Each is JSON-serialized
/// for SSE.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// An agent is about to start processing.
    AgentStarted {
        /// The run id (one per `process_invoice` call).
        run_id: Uuid,
        /// The agent name (e.g. "extractor", "fraud_auditor").
        agent: String,
    },
    /// An agent finished. The cost is in USD *cents* (integer to
    /// avoid float rounding in the wire format).
    AgentCompleted {
        /// The run id.
        run_id: Uuid,
        /// The agent name.
        agent: String,
        /// USD cents billed (1 cent = $0.01).
        cost_usd_cents: u32,
        /// Tokens in (prompt).
        tokens_in: u32,
        /// Tokens out (completion).
        tokens_out: u32,
    },
    /// BAAAR HALT fired. The orchestrator posts the full reason to
    /// the Band room; the event carries a summary.
    BaaarHalt {
        /// The run id.
        run_id: Uuid,
        /// The reason as a stable string (e.g. "risk_score_exceeded",
        /// "secret_leak_detected", ...).
        reason: String,
        /// The agent that triggered the halt.
        agent: String,
    },
    /// The Evidence Packet has been sealed (signed + timestamped).
    EvidenceSealed {
        /// The run id.
        run_id: Uuid,
        /// The Evidence Packet's UUID.
        packet_id: Uuid,
    },
    /// The full run finished (terminal state reached).
    RunFinished {
        /// The run id.
        run_id: Uuid,
    },
    /// Announces the LLM provider + model that will serve the next
    /// run. Emitted once per `POST /invoices` (before the orchestrator
    /// starts walking the agent chain) so the SSE-fed frontend can
    /// show a live "model badge" — the visible signal that the demo
    /// is hitting a real provider (or the mock fallback) right now.
    ProviderActive {
        /// The run id this announcement belongs to.
        run_id: Uuid,
        /// Model id (e.g. `"Qwen/Qwen3-Coder-30B-A3B-Instruct"` for
        /// a real backend, `"mock-fallback"` for the mock).
        model_id: String,
    },
    /// Two agents disagreed on the risk assessment and the
    /// BaaarV2Gate escalated the run. The frontend renders this
    /// as a visible "DISPUTE" badge with a flash animation;
    /// the judge's eye catches the dispute resolving in real
    /// time. This is the wow moment of the demo: agents argue,
    /// the coordinator rules, the run halts.
    AgentDispute {
        /// The run id.
        run_id: Uuid,
        /// First agent (e.g. "fraud_auditor").
        agent_a: String,
        /// First agent's risk_score (0.0..=1.0).
        risk_a: f32,
        /// Second agent (e.g. "gaap_classifier").
        agent_b: String,
        /// Second agent's risk_score (0.0..=1.0).
        risk_b: f32,
        /// Absolute difference (|a - b|); trigger when > 0.3.
        delta: f32,
        /// The coordinator's ruling: "halt" (default) or
        /// "approve" (when the gate's confidence is high
        /// enough to override the dispute).
        ruling: String,
    },
}

impl Event {
    /// Stable type identifier (matches the serde tag).
    pub fn type_str(&self) -> &'static str {
        match self {
            Event::AgentStarted { .. } => "agent_started",
            Event::AgentCompleted { .. } => "agent_completed",
            Event::BaaarHalt { .. } => "baaar_halt",
            Event::EvidenceSealed { .. } => "evidence_sealed",
            Event::RunFinished { .. } => "run_finished",
            Event::ProviderActive { .. } => "provider_active",
            Event::AgentDispute { .. } => "agent_dispute",
        }
    }
}

/// The EventBus. Wraps a tokio broadcast channel; the orchestrator
/// holds one EventBus, the SSE handler holds a receiver from
/// `subscribe()`.
#[derive(Debug)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    /// New bus with the given broadcast buffer size. A subscriber
    /// that lags past `buffer` events drops events; a value of
    /// 1024 is plenty for a single-run SSE consumer.
    pub fn new(buffer: usize) -> Self {
        let (tx, _rx) = broadcast::channel(buffer);
        Self { tx }
    }

    /// Subscribe to events. Returns a `broadcast::Receiver<Event>`.
    /// Multiple subscribers can register (e.g. SSE + audit log).
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Publish an event to all current subscribers. Non-blocking;
    /// subscribers that are slow drop events.
    pub fn publish(&self, event: Event) {
        // `send` returns Result<_, SendError<Event>> — we ignore
        // the error (no subscribers at the moment is fine).
        let _ = self.tx.send(event);
    }

    /// Number of active subscribers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_receive_single_event() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(Event::AgentStarted {
            run_id: Uuid::new_v4(),
            agent: "extractor".to_string(),
        });
        let event = rx.recv().await.unwrap();
        assert_eq!(event.type_str(), "agent_started");
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_event() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        bus.publish(Event::RunFinished {
            run_id: Uuid::new_v4(),
        });
        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.type_str(), "run_finished");
        assert_eq!(e2.type_str(), "run_finished");
    }

    #[tokio::test]
    async fn no_subscribers_publish_does_not_panic() {
        let bus = EventBus::new(16);
        // No subscribers.
        bus.publish(Event::RunFinished {
            run_id: Uuid::new_v4(),
        });
        // No assertion — just verify no panic.
    }

    #[tokio::test]
    async fn receiver_count_increments_on_subscribe() {
        let bus = EventBus::new(16);
        assert_eq!(bus.receiver_count(), 0);
        let _r1 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);
        let _r2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);
    }

    #[tokio::test]
    async fn event_serializes_to_json_with_type_tag() {
        let ev = Event::AgentCompleted {
            run_id: Uuid::new_v4(),
            agent: "fraud_auditor".to_string(),
            cost_usd_cents: 42,
            tokens_in: 1200,
            tokens_out: 220,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "agent_completed");
        assert_eq!(json["agent"], "fraud_auditor");
        assert_eq!(json["cost_usd_cents"], 42);
    }

    #[tokio::test]
    async fn baaar_halt_event_carries_reason() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(Event::BaaarHalt {
            run_id: Uuid::new_v4(),
            reason: "risk_score_exceeded".to_string(),
            agent: "fraud_auditor".to_string(),
        });
        let ev = rx.recv().await.unwrap();
        match ev {
            Event::BaaarHalt { reason, agent, .. } => {
                assert_eq!(reason, "risk_score_exceeded");
                assert_eq!(agent, "fraud_auditor");
            }
            _ => panic!("expected BaaarHalt"),
        }
    }

    #[tokio::test]
    async fn provider_active_event_carries_model_id() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let run_id = Uuid::new_v4();
        bus.publish(Event::ProviderActive {
            run_id,
            model_id: "Qwen/Qwen3-Coder-30B-A3B-Instruct".to_string(),
        });
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.type_str(), "provider_active");
        match ev {
            Event::ProviderActive { model_id, .. } => {
                assert_eq!(model_id, "Qwen/Qwen3-Coder-30B-A3B-Instruct");
            }
            _ => panic!("expected ProviderActive"),
        }
        // JSON shape: tagged with `type: "provider_active"` and
        // carries the model_id field.
        let v = serde_json::to_value(&Event::ProviderActive {
            run_id,
            model_id: "mock-fallback".to_string(),
        })
        .unwrap();
        assert_eq!(v["type"], "provider_active");
        assert_eq!(v["model_id"], "mock-fallback");
    }
}
