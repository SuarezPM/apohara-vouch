//! Featherless OpenClaw adapter.
//!
//! Honors Featherless's kickoff claim: "agent infrastructure
//! platform". When `FEATHERLESS_OPENCLAW_URL` is set, the
//! orchestrator routes the 8-agent chain through a running
//! OpenClaw sandbox via its HTTP API (port 8080 by default,
//! per Featherless docs). The adapter is a thin HTTP client:
//! POSTs each agent's system+user prompt to OpenClaw's chat
//! endpoint, gets the response, and returns it as an
//! `LlmResponse`.
//!
//! When `FEATHERLESS_OPENCLAW_URL` is unset (default), the
//! orchestrator uses the in-process `FeatherlessBackend`. The
//! adapter is opt-in; the demo path stays in-process.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use themis_agents::decision::AgentError;
use themis_agents::llm::{LlmBackend, LlmRequest, LlmResponse};

/// HTTP client for a running Featherless OpenClaw sandbox.
/// Each `complete()` call is a POST to the OpenClaw chat endpoint
/// with the agent's prompt; the response is the LLM's reply.
pub struct OpenClawBackend {
    /// Base URL of the OpenClaw sandbox (e.g.
    /// `http://localhost:18780`).
    base_url: String,
    /// HTTP client (reused).
    client: reqwest::Client,
    /// Model name to send to OpenClaw (e.g.
    /// `featherless-ai/Qwen/Qwen3-Coder-30B-A3B-Instruct`).
    model: String,
    /// Static id returned in `LlmResponse.model_id` so the
    /// frontend badge can show "featherless-openclaw".
    label: &'static str,
}

impl std::fmt::Debug for OpenClawBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenClawBackend")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("label", &self.label)
            .finish()
    }
}

impl OpenClawBackend {
    /// New backend pointing at a running OpenClaw sandbox.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest Client builder should not fail"),
            model: model.into(),
            label: "featherless-openclaw",
        }
    }
}

#[derive(Serialize)]
struct OpenClawChatRequest {
    model: String,
    messages: Vec<OpenClawMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct OpenClawMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenClawChatResponse {
    content: String,
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

#[async_trait]
impl LlmBackend for OpenClawBackend {
    fn model_id(&self) -> &'static str {
        self.label
    }

    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, AgentError> {
        let body = OpenClawChatRequest {
            model: self.model.clone(),
            messages: vec![
                OpenClawMessage { role: "system".into(), content: req.system_prompt },
                OpenClawMessage { role: "user".into(), content: req.user_prompt },
            ],
            max_tokens: req.max_tokens,
            temperature: req.temperature,
        };
        let url = format!("{}/v1/chat/completions", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AgentError::LlmUnavailable(format!("OpenClaw network: {e}"))
            })?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentError::LlmUnavailable(format!(
                "OpenClaw {status}: {}", &body.chars().take(200).collect::<String>()
            )));
        }
        let parsed: OpenClawChatResponse = resp
            .json()
            .await
            .map_err(|e| AgentError::LlmMalformedPayload(format!("OpenClaw parse: {e}")))?;
        Ok(LlmResponse {
            text: parsed.content,
            input_tokens: parsed.input_tokens,
            output_tokens: parsed.output_tokens,
            model_id: self.model.clone(),
            finish_reason: themis_agents::llm::FinishReason::Stop,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openclaw_label_is_featherless_openclaw() {
        let backend = OpenClawBackend::new("http://localhost:18780", "Qwen/Qwen3-Coder-30B-A3B-Instruct");
        assert_eq!(backend.model_id(), "featherless-openclaw");
    }

    #[test]
    fn openclaw_serializes_request_correctly() {
        // The struct-level assertion: serialize the request the
        // way the backend would, verify the JSON shape.
        let req = OpenClawChatRequest {
            model: "Qwen/Qwen3-Coder-30B-A3B-Instruct".to_string(),
            messages: vec![
                OpenClawMessage { role: "system".into(), content: "you are a fraud auditor".into() },
                OpenClawMessage { role: "user".into(), content: "assess this".into() },
            ],
            max_tokens: 64,
            temperature: 0.0,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "Qwen/Qwen3-Coder-30B-A3B-Instruct");
        assert_eq!(json["messages"][0]["role"], "system");
        assert_eq!(json["messages"][1]["role"], "user");
        assert_eq!(json["max_tokens"], 64);
        assert_eq!(json["temperature"], 0.0);
    }

    #[test]
    fn openclaw_deserializes_response() {
        let body = json!({
            "content": "ok",
            "input_tokens": 11,
            "output_tokens": 7
        });
        let parsed: OpenClawChatResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.content, "ok");
        assert_eq!(parsed.input_tokens, 11);
        assert_eq!(parsed.output_tokens, 7);
    }
}
