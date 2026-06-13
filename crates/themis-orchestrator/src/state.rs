//! InvoiceState + StateMachine + Transition.
//!
//! The state machine drives a single invoice through 9 stages
//! (Received → … → Done) or terminates at Halted via BAAAR. It's a
//! pure state machine: no I/O, no async. The `Orchestrator` is the
//! thing that performs work at each state (see `orchestrator.rs`).

use thiserror::Error;

/// The 10 states an invoice can be in during processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvoiceState {
    /// Invoice was just received; no work done yet.
    Received,
    /// Extractor agent is parsing raw bytes.
    Extracting,
    /// PO Matcher is comparing against the purchase-order DB.
    Matching,
    /// Fraud Auditor is producing a risk assessment.
    Auditing,
    /// GAAP Classifier is mapping line items.
    Classifying,
    /// Provenance Signer is sealing the packet.
    Signing,
    /// Demo Narrator is producing a 1-paragraph summary.
    Narrating,
    /// Regression Tester is re-verifying the signature + hash.
    Validating,
    /// All stages complete; packet is final.
    Done,
    /// BAAAR HALT fired (or some other unrecoverable failure).
    Halted,
}

impl InvoiceState {
    /// The next state in the happy path. `Done` and `Halted` are
    /// terminal — calling `next()` on them returns `None`.
    pub fn next(&self) -> Option<InvoiceState> {
        match self {
            InvoiceState::Received => Some(InvoiceState::Extracting),
            InvoiceState::Extracting => Some(InvoiceState::Matching),
            InvoiceState::Matching => Some(InvoiceState::Auditing),
            InvoiceState::Auditing => Some(InvoiceState::Classifying),
            InvoiceState::Classifying => Some(InvoiceState::Signing),
            InvoiceState::Signing => Some(InvoiceState::Narrating),
            InvoiceState::Narrating => Some(InvoiceState::Validating),
            InvoiceState::Validating => Some(InvoiceState::Done),
            InvoiceState::Done | InvoiceState::Halted => None,
        }
    }

    /// Stable string identifier (used in Evidence Packet + telemetry).
    pub fn as_str(&self) -> &'static str {
        match self {
            InvoiceState::Received => "received",
            InvoiceState::Extracting => "extracting",
            InvoiceState::Matching => "matching",
            InvoiceState::Auditing => "auditing",
            InvoiceState::Classifying => "classifying",
            InvoiceState::Signing => "signing",
            InvoiceState::Narrating => "narrating",
            InvoiceState::Validating => "validating",
            InvoiceState::Done => "done",
            InvoiceState::Halted => "halted",
        }
    }
}

/// What triggered the transition. `Advance` is the happy path;
/// `Halt(BaaarReason)` and `Fail(String)` both terminate the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Move to the next sequential state.
    Advance,
    /// BAAAR halt with a specific reason (e.g. RiskScoreExceeded).
    Halt(themis_agents::baaar::BaaarReason),
    /// Non-BAAAR failure (e.g. LLM error propagated).
    Fail(String),
}

/// State-machine errors.
#[derive(Debug, Error)]
pub enum StateError {
    /// Tried to advance a terminal state (Done or Halted).
    #[error("cannot advance terminal state: {0:?}")]
    TerminalState(InvoiceState),
    /// Tried to transition to a state that's not the current's next.
    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Current state when the invalid transition was attempted.
        from: InvoiceState,
        /// The state the caller tried to move to.
        to: InvoiceState,
    },
}

/// The state machine. Tracks the current state + a history of
/// (state, timestamp_ms) pairs so the Evidence Packet can surface
/// "time spent in each state" telemetry.
#[derive(Debug, Clone)]
pub struct StateMachine {
    state: InvoiceState,
    history: Vec<(InvoiceState, i64)>,
}

impl StateMachine {
    /// New state machine in `Received`.
    pub fn new() -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            state: InvoiceState::Received,
            history: vec![(InvoiceState::Received, now)],
        }
    }

    /// New state machine starting in a given state (for tests).
    pub fn starting_at(state: InvoiceState) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            state,
            history: vec![(state, now)],
        }
    }

    /// Current state.
    pub fn current(&self) -> InvoiceState {
        self.state
    }

    /// History of visited (state, timestamp_ms) pairs.
    pub fn history(&self) -> &[(InvoiceState, i64)] {
        &self.history
    }

    /// Apply a transition. Returns the new state on success.
    /// `Advance` moves to the next sequential state; `Halt` and
    /// `Fail` move directly to `Halted` and preserve the reason in
    /// the history entry's `state` field is not enough — callers
    /// wanting the halt reason should also call `halt_reason()`.
    pub fn transition(&mut self, t: Transition) -> Result<InvoiceState, StateError> {
        // Terminal states can't move at all.
        if self.state == InvoiceState::Done || self.state == InvoiceState::Halted {
            return Err(StateError::TerminalState(self.state));
        }

        let new_state = match t {
            Transition::Advance => self
                .state
                .next()
                .ok_or(StateError::TerminalState(self.state))?,
            Transition::Halt(_) | Transition::Fail(_) => InvoiceState::Halted,
        };

        self.state = new_state;
        self.history
            .push((new_state, chrono::Utc::now().timestamp_millis()));
        Ok(new_state)
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_in_received() {
        let sm = StateMachine::new();
        assert_eq!(sm.current(), InvoiceState::Received);
        assert_eq!(sm.history().len(), 1);
    }

    #[test]
    fn happy_path_full_traversal() {
        let mut sm = StateMachine::new();
        let expected = [
            InvoiceState::Extracting,
            InvoiceState::Matching,
            InvoiceState::Auditing,
            InvoiceState::Classifying,
            InvoiceState::Signing,
            InvoiceState::Narrating,
            InvoiceState::Validating,
            InvoiceState::Done,
        ];
        for exp in &expected {
            let actual = sm.transition(Transition::Advance).unwrap();
            assert_eq!(actual, *exp);
        }
        assert_eq!(sm.current(), InvoiceState::Done);
        // history: Received + 8 advances = 9 entries.
        assert_eq!(sm.history().len(), 9);
    }

    #[test]
    fn halt_from_auditing_terminates_immediately() {
        let mut sm = StateMachine::new();
        sm.transition(Transition::Advance).unwrap(); // Extracting
        sm.transition(Transition::Advance).unwrap(); // Matching
        sm.transition(Transition::Advance).unwrap(); // Auditing
        let new = sm
            .transition(Transition::Halt(
                themis_agents::baaar::BaaarReason::RiskScoreExceeded,
            ))
            .unwrap();
        assert_eq!(new, InvoiceState::Halted);
        // Cannot advance from Halted.
        assert!(matches!(
            sm.transition(Transition::Advance),
            Err(StateError::TerminalState(InvoiceState::Halted))
        ));
    }

    #[test]
    fn fail_from_any_state_goes_to_halted() {
        let mut sm = StateMachine::new();
        sm.transition(Transition::Advance).unwrap(); // Extracting
        let new = sm
            .transition(Transition::Fail("LLM down".to_string()))
            .unwrap();
        assert_eq!(new, InvoiceState::Halted);
    }

    #[test]
    fn terminal_state_cannot_advance() {
        let mut sm = StateMachine::starting_at(InvoiceState::Done);
        let err = sm.transition(Transition::Advance).unwrap_err();
        assert!(matches!(err, StateError::TerminalState(InvoiceState::Done)));
    }

    #[test]
    fn history_accumulates_timestamps() {
        let mut sm = StateMachine::new();
        sm.transition(Transition::Advance).unwrap();
        sm.transition(Transition::Advance).unwrap();
        let h = sm.history();
        assert_eq!(h.len(), 3);
        // Timestamps should be monotonically non-decreasing.
        assert!(h[0].1 <= h[1].1);
        assert!(h[1].1 <= h[2].1);
    }

    #[test]
    fn invoice_state_next_chain() {
        let chain = [
            InvoiceState::Received,
            InvoiceState::Extracting,
            InvoiceState::Matching,
            InvoiceState::Auditing,
            InvoiceState::Classifying,
            InvoiceState::Signing,
            InvoiceState::Narrating,
            InvoiceState::Validating,
            InvoiceState::Done,
        ];
        for w in chain.windows(2) {
            assert_eq!(w[0].next(), Some(w[1]));
        }
        assert_eq!(InvoiceState::Done.next(), None);
        assert_eq!(InvoiceState::Halted.next(), None);
    }

    #[test]
    fn state_as_str_is_stable() {
        assert_eq!(InvoiceState::Received.as_str(), "received");
        assert_eq!(InvoiceState::Halted.as_str(), "halted");
        assert_eq!(InvoiceState::Done.as_str(), "done");
    }
}
